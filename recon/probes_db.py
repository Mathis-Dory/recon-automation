"""Database service probes — unauthenticated banner / handshake reads.

All five DBs are probed with raw TCP. Each function returns a single-line
finding string ("MySQL 5.7.31" / "Redis 6.0.10 unauth") or ``""`` on failure.

Thread-safe: each call creates its own socket and never mutates module state.
"""

import re
import socket
import struct


def _connect(ip: str, port: int, timeout: float = 4.0) -> socket.socket | None:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        return s
    except OSError:
        return None


def probe_mysql(ip: str, port: int = 3306, timeout: float = 4.0) -> str:
    """Read MySQL's initial Server Greeting and return 'MySQL <version>'."""
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        # Server sends the greeting unsolicited.
        data = sock.recv(256)
    except OSError:
        return ""
    finally:
        sock.close()
    if len(data) < 6:
        return ""
    # Layout: 3-byte length, 1-byte seq, 1-byte protocol, then null-terminated version.
    proto = data[4]
    if proto != 0x0A:  # protocol 10 is the only one in production use
        return ""
    end = data.find(b"\x00", 5)
    if end < 6:
        return ""
    version = data[5:end].decode("latin-1", "replace").strip()
    return f"MySQL {version}" if version else "MySQL (unknown version)"


def probe_postgres(ip: str, port: int = 5432, timeout: float = 4.0) -> str:
    """Send a Postgres SSLRequest and report whether SSL is offered."""
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        # SSLRequest: length=8, code=80877103
        sock.sendall(struct.pack("!II", 8, 80877103))
        resp = sock.recv(1)
    except OSError:
        return ""
    finally:
        sock.close()
    if resp == b"S":
        return "PostgreSQL (SSL supported)"
    if resp == b"N":
        return "PostgreSQL (SSL not supported)"
    return "PostgreSQL"


def probe_mssql(ip: str, port: int = 1433, timeout: float = 4.0) -> str:
    """Send a TDS prelogin and parse the version bytes from the response."""
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    # Minimal TDS prelogin: header (8 bytes) + one option (VERSION=0) + terminator.
    # Header: type=18 (prelogin), status=01, length=2 bytes, spid=0, packetid=0, window=0
    payload = bytes.fromhex(
        "00"  # token: VERSION
        "0006"  # offset (from packet start, after header)
        "0006"  # length
        "ff"  # terminator
        "0000000000"  # VERSION value placeholder (we just send zeros)
        "00"  # trailing
    )
    header = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(payload), 0, 0, 0)
    try:
        sock.sendall(header + payload)
        data = sock.recv(512)
    except OSError:
        return ""
    finally:
        sock.close()
    if len(data) < 14 or data[0] != 0x04:  # 0x04 = TDS response
        return "MSSQL"
    # Search for VERSION token (0x00) in the options section; first version is bytes after offset.
    # Pragmatic: hunt for the first plausible major.minor.build pattern.
    body = data[8:]
    idx = 0
    while idx < len(body) - 6:
        if body[idx] == 0x00:  # VERSION token
            try:
                ver_off = int.from_bytes(body[idx + 1 : idx + 3], "big") - 8
                if 0 <= ver_off <= len(body) - 6:
                    maj, minr = body[ver_off], body[ver_off + 1]
                    build = int.from_bytes(body[ver_off + 2 : ver_off + 4], "big")
                    return f"MSSQL {maj}.{minr}.{build}"
            except (IndexError, ValueError):
                pass
            break
        if body[idx] == 0xFF:  # terminator
            break
        idx += 5
    return "MSSQL"


_MONGO_OP_QUERY = 2004
_MONGO_RESPONSE_TO = 1


def probe_mongo(ip: str, port: int = 27017, timeout: float = 4.0) -> str:
    """Send MongoDB's legacy isMaster query and report on the response."""
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    # BSON for {ismaster: 1}: \x10ismaster\x00\x01\x00\x00\x00\x00 wrapped in a doc.
    bson_doc = b"\x10ismaster\x00\x01\x00\x00\x00\x00"
    bson_doc = struct.pack("<I", len(bson_doc) + 5) + bson_doc + b"\x00"
    # OP_QUERY: header(16) + flags(4) + fullCollName + skip(4) + return(4) + query
    coll = b"admin.$cmd\x00"
    body = struct.pack("<I", 0) + coll + struct.pack("<II", 0, 1) + bson_doc
    header = struct.pack("<IIII", 16 + len(body), 1, 0, _MONGO_OP_QUERY)
    try:
        sock.sendall(header + body)
        data = sock.recv(1024)
    except OSError:
        return ""
    finally:
        sock.close()
    if len(data) < 16:
        return ""
    # Best-effort: look for "version" key in the BSON reply body.
    m = re.search(rb"\x02version\x00[\x00-\xff]{4}([0-9.]+?)\x00", data)
    if m:
        return f"MongoDB {m.group(1).decode('latin-1')}"
    return "MongoDB"


def probe_redis(ip: str, port: int = 6379, timeout: float = 4.0) -> str:
    """Issue Redis PING; if it works, request INFO server for version."""
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        ping = sock.recv(64)
        if not ping.startswith(b"+PONG"):
            if ping.startswith(b"-NOAUTH") or ping.startswith(b"-WRONG"):
                return "Redis (authenticated)"
            return ""
        sock.sendall(b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n")
        info = sock.recv(4096).decode("latin-1", "replace")
    except OSError:
        return "Redis"
    finally:
        sock.close()
    m = re.search(r"redis_version:([0-9.]+)", info)
    return f"Redis {m.group(1)} (unauth)" if m else "Redis (unauth)"


PORT_TO_PROBE = {
    3306: probe_mysql,
    5432: probe_postgres,
    1433: probe_mssql,
    27017: probe_mongo,
    6379: probe_redis,
}


def probe_db(ip: str, port: int) -> str:
    """Dispatch the appropriate per-DB probe based on port; return banner or ''."""
    fn = PORT_TO_PROBE.get(port)
    if fn is None:
        return ""
    return fn(ip, port)
