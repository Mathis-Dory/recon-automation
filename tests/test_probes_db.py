"""Tests for recon/probes_db.py — DB banner probes mocked at the socket layer."""

import struct

from recon import probes_db


class _FakeSocket:
    """A drop-in replacement for the socket returned by socket.create_connection."""

    def __init__(self, recv_chunks, send_capture=None):
        self._recv = list(recv_chunks)
        self.sent = []
        self.closed = False
        self._send_capture = send_capture

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        if not self._recv:
            return b""
        return self._recv.pop(0)

    def sendall(self, data):
        self.sent.append(data)
        if self._send_capture is not None:
            self._send_capture.append(data)

    def close(self):
        self.closed = True


def _patch_connect(monkeypatch, fake_sock):
    monkeypatch.setattr(probes_db, "_connect", lambda ip, port, timeout=4.0: fake_sock)


def test_probe_mysql_extracts_version(monkeypatch):
    # Greeting: 3-byte length, 1-byte seq, protocol=10, "5.7.31-log\0", junk
    body = b"\x0a5.7.31-log\x00" + b"\x00" * 32
    pkt = struct.pack("<I", len(body))[:3] + b"\x00" + body
    fake = _FakeSocket([pkt])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_mysql("10.0.0.1") == "MySQL 5.7.31-log"
    assert fake.closed is True


def test_probe_mysql_returns_empty_on_failed_connection(monkeypatch):
    monkeypatch.setattr(probes_db, "_connect", lambda ip, port, timeout=4.0: None)
    assert probes_db.probe_mysql("10.0.0.1") == ""


def test_probe_postgres_reports_ssl_supported(monkeypatch):
    fake = _FakeSocket([b"S"])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_postgres("10.0.0.1") == "PostgreSQL (SSL supported)"


def test_probe_postgres_reports_ssl_not_supported(monkeypatch):
    fake = _FakeSocket([b"N"])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_postgres("10.0.0.1") == "PostgreSQL (SSL not supported)"


def test_probe_postgres_handles_unknown_reply(monkeypatch):
    fake = _FakeSocket([b"X"])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_postgres("10.0.0.1") == "PostgreSQL"


def test_probe_mssql_returns_label_when_response_truncated(monkeypatch):
    fake = _FakeSocket([b"\x04\x01\x00\x10\x00\x00\x00\x00short"])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_mssql("10.0.0.1") == "MSSQL"


def test_probe_mongo_extracts_version(monkeypatch):
    # We don't bother building a real BSON reply; the regex looks for
    # \x02version\x00<4-byte len><digits>\x00
    body = b"\x02version\x00\x06\x00\x00\x004.4.6\x00"
    pkt = b"\x00" * 16 + body
    fake = _FakeSocket([pkt])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_mongo("10.0.0.1") == "MongoDB 4.4.6"


def test_probe_mongo_falls_back_to_label_without_version(monkeypatch):
    fake = _FakeSocket([b"\x00" * 32])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_mongo("10.0.0.1") == "MongoDB"


def test_probe_redis_authenticated_branch(monkeypatch):
    fake = _FakeSocket([b"-NOAUTH Authentication required\r\n"])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_redis("10.0.0.1") == "Redis (authenticated)"


def test_probe_redis_unauth_extracts_version(monkeypatch):
    fake = _FakeSocket(
        [b"+PONG\r\n", b"$60\r\n# Server\r\nredis_version:6.0.10\r\nredis_mode:standalone\r\n"]
    )
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_redis("10.0.0.1") == "Redis 6.0.10 (unauth)"


def test_probe_redis_no_response_returns_empty(monkeypatch):
    fake = _FakeSocket([b""])
    _patch_connect(monkeypatch, fake)
    assert probes_db.probe_redis("10.0.0.1") == ""


def test_probe_db_dispatches_by_port(monkeypatch):
    calls = []

    def fake_mysql(ip, port=3306, timeout=4.0):
        calls.append(("mysql", ip, port))
        return "MySQL 8.0"

    monkeypatch.setitem(probes_db.PORT_TO_PROBE, 3306, fake_mysql)
    assert probes_db.probe_db("1.1.1.1", 3306) == "MySQL 8.0"
    assert calls == [("mysql", "1.1.1.1", 3306)]


def test_probe_db_unknown_port_returns_empty():
    assert probes_db.probe_db("1.1.1.1", 9999) == ""


def test_probe_db_integrates_into_dispatch_table():
    """probe-db rides on the orchestrator's same table-driven dispatch."""
    from recon import cli_enum

    open_ports = {("10.0.0.1", 3306), ("10.0.0.1", 80)}
    fns = {
        "ftp": lambda ip, p: "",
        "banner": lambda ip, p: "",
        "web": lambda ip, p: "title",
        "smb": lambda ip: None,
        "db": lambda ip, p: f"DB-on-{p}",
    }
    res = cli_enum.dispatch_probes(open_ports, web_ports=[80], probe_fns=fns)
    assert res[("10.0.0.1", 3306)]["finding"] == "DB-on-3306"
    assert res[("10.0.0.1", 80)]["http_title"] == "title"
