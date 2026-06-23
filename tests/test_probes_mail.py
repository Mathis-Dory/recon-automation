"""Tests for recon/probes_mail.py — mocked at the socket layer."""

from recon import probes_mail


class _FakeSocket:
    """Replays a list of bytes chunks for recv(); captures sent data."""

    def __init__(self, recv_chunks):
        self._recv = list(recv_chunks)
        self.sent = []
        self.closed = False

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        if not self._recv:
            return b""
        return self._recv.pop(0)

    def sendall(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True


def _patch_connect(monkeypatch, fake_sock):
    monkeypatch.setattr(probes_mail, "_connect", lambda ip, port, timeout=4.0: fake_sock)


def test_probe_smtp_extracts_banner_and_capabilities(monkeypatch):
    fake = _FakeSocket(
        [
            b"220 mail.example.com ESMTP Postfix\r\n",
            b"250-mail.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 HELP\r\n",
        ]
    )
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_smtp("10.0.0.1", 25)
    assert result.startswith("SMTP(25):")
    assert "mail.example.com ESMTP Postfix" in result
    assert "STARTTLS" in result
    assert "AUTH offered" in result
    assert fake.closed is True


def test_probe_smtp_no_starttls(monkeypatch):
    fake = _FakeSocket(
        [
            b"220 mx.local ESMTP\r\n",
            b"250-mx.local\r\n250-PIPELINING\r\n250 HELP\r\n",
        ]
    )
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_smtp("10.0.0.1", 25)
    assert "STARTTLS" not in result
    assert "AUTH offered" not in result


def test_probe_smtp_returns_empty_on_connection_failure(monkeypatch):
    monkeypatch.setattr(probes_mail, "_connect", lambda ip, port, timeout=4.0: None)
    assert probes_mail.probe_smtp("10.0.0.1", 25) == ""


def test_probe_smtp_handles_non_220_greeting(monkeypatch):
    fake = _FakeSocket([b"421 Service unavailable\r\n"])
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_smtp("10.0.0.1", 25)
    assert "421 Service unavailable" in result


def test_probe_imap_extracts_banner_and_capabilities(monkeypatch):
    fake = _FakeSocket(
        [
            b"* OK [CAPABILITY IMAP4rev1] Dovecot ready\r\n",
            b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN\r\na1 OK Capability completed\r\n",
        ]
    )
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_imap("10.0.0.1", 143)
    assert result.startswith("IMAP(143):")
    assert "Dovecot" in result
    assert "STARTTLS" in result
    assert "AUTH offered" in result


def test_probe_imap_handles_unexpected_greeting(monkeypatch):
    fake = _FakeSocket([b"* BYE host unavailable\r\n"])
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_imap("10.0.0.1", 143)
    assert "BYE" in result


def test_probe_pop_extracts_banner_and_capabilities(monkeypatch):
    fake = _FakeSocket(
        [
            b"+OK POP3 ready Dovecot\r\n",
            b"+OK\r\nUSER\r\nSTLS\r\nTOP\r\n.\r\n",
        ]
    )
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_pop("10.0.0.1", 110)
    assert result.startswith("POP3(110):")
    assert "Dovecot" in result
    assert "STLS" in result
    assert "USER" in result


def test_probe_pop_no_stls(monkeypatch):
    fake = _FakeSocket(
        [
            b"+OK POP3 ready\r\n",
            b"+OK\r\nUSER\r\nTOP\r\n.\r\n",
        ]
    )
    _patch_connect(monkeypatch, fake)
    result = probes_mail.probe_pop("10.0.0.1", 110)
    assert "STLS" not in result
    assert "USER" in result


def test_probe_mail_dispatches_by_port(monkeypatch):
    """probe_mail's port → handler routing."""
    smtp_calls, imap_calls, pop_calls = [], [], []
    monkeypatch.setattr(
        probes_mail, "probe_smtp", lambda ip, p, **_kw: smtp_calls.append(p) or "smtp"
    )
    monkeypatch.setattr(
        probes_mail, "probe_imap", lambda ip, p, **_kw: imap_calls.append(p) or "imap"
    )
    monkeypatch.setattr(probes_mail, "probe_pop", lambda ip, p, **_kw: pop_calls.append(p) or "pop")
    assert probes_mail.probe_mail("1.1.1.1", 25) == "smtp"
    assert probes_mail.probe_mail("1.1.1.1", 587) == "smtp"
    assert probes_mail.probe_mail("1.1.1.1", 143) == "imap"
    assert probes_mail.probe_mail("1.1.1.1", 993) == "imap"
    assert probes_mail.probe_mail("1.1.1.1", 110) == "pop"
    assert probes_mail.probe_mail("1.1.1.1", 995) == "pop"
    assert probes_mail.probe_mail("1.1.1.1", 9999) == ""
    assert smtp_calls == [25, 587]
    assert imap_calls == [143, 993]
    assert pop_calls == [110, 995]


def test_probe_mail_integrates_into_dispatch_table():
    from recon import cli_enum

    open_ports = {("10.0.0.1", 25), ("10.0.0.1", 80)}
    fns = {
        "ftp": lambda ip, p: "",
        "banner": lambda ip, p: "",
        "web": lambda ip, p: "title",
        "smb": lambda ip: None,
        "db": lambda ip, p: "",
        "mail": lambda ip, p: f"MAIL-{p}",
    }
    res = cli_enum.dispatch_probes(open_ports, web_ports=[80], probe_fns=fns)
    assert res[("10.0.0.1", 25)]["finding"] == "MAIL-25"
    assert res[("10.0.0.1", 80)]["http_title"] == "title"
