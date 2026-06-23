"""Mail service probes — banner + STARTTLS capability for SMTP/IMAP/POP3.

All pure TCP, no new dependencies. Each function returns a single-line
finding ("Postfix; STARTTLS" / "Dovecot IMAP4rev1") or "" on failure.
"""

import contextlib
import socket
import ssl

_SMTP_PORTS = {25, 465, 587}
_IMAP_PORTS = {143, 993}
_POP_PORTS = {110, 995}
_IMPLICIT_TLS = {465, 993, 995}


def _connect(ip: str, port: int, timeout: float = 4.0) -> socket.socket | None:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        if port in _IMPLICIT_TLS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            return ctx.wrap_socket(s, server_hostname=ip)
        return s
    except OSError:
        return None


def _readline(sock: socket.socket, max_bytes: int = 4096) -> str:
    buf = b""
    while b"\r\n" not in buf and len(buf) < max_bytes:
        try:
            chunk = sock.recv(512)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf.decode("latin-1", "replace").rstrip()


def _read_multi(sock: socket.socket, terminator: bytes, max_bytes: int = 8192) -> str:
    buf = b""
    while terminator not in buf and len(buf) < max_bytes:
        try:
            chunk = sock.recv(512)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
    return buf.decode("latin-1", "replace")


def probe_smtp(ip: str, port: int, timeout: float = 4.0) -> str:
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        banner = _readline(sock)
        if not banner.startswith("220"):
            return banner or "SMTP"
        # EHLO to discover STARTTLS / AUTH mechanisms
        sock.sendall(b"EHLO probe.local\r\n")
        ehlo = _read_multi(sock, b"\r\n250 ")
        bits = [banner.split(" ", 1)[1] if " " in banner else "SMTP"]
        if "STARTTLS" in ehlo.upper():
            bits.append("STARTTLS")
        if "AUTH" in ehlo.upper():
            bits.append("AUTH offered")
        return f"SMTP({port}): " + "; ".join(bits)
    except OSError:
        return "SMTP"
    finally:
        with contextlib.suppress(OSError):
            sock.sendall(b"QUIT\r\n")
        sock.close()


def probe_imap(ip: str, port: int, timeout: float = 4.0) -> str:
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        banner = _readline(sock)
        if not banner.startswith("* OK"):
            return banner or "IMAP"
        sock.sendall(b"a1 CAPABILITY\r\n")
        caps = _read_multi(sock, b"a1 OK")
        bits = [banner.split("* OK", 1)[1].strip() if "* OK" in banner else "IMAP"]
        if "STARTTLS" in caps.upper():
            bits.append("STARTTLS")
        if "AUTH=" in caps.upper():
            bits.append("AUTH offered")
        return f"IMAP({port}): " + "; ".join(bits)
    except OSError:
        return "IMAP"
    finally:
        with contextlib.suppress(OSError):
            sock.sendall(b"a2 LOGOUT\r\n")
        sock.close()


def probe_pop(ip: str, port: int, timeout: float = 4.0) -> str:
    sock = _connect(ip, port, timeout)
    if sock is None:
        return ""
    try:
        banner = _readline(sock)
        if not banner.startswith("+OK"):
            return banner or "POP3"
        sock.sendall(b"CAPA\r\n")
        caps = _read_multi(sock, b"\r\n.\r\n")
        bits = [banner.split("+OK", 1)[1].strip() if "+OK" in banner else "POP3"]
        if "STLS" in caps.upper():
            bits.append("STLS")
        if "USER" in caps.upper():
            bits.append("USER")
        return f"POP3({port}): " + "; ".join(bits)
    except OSError:
        return "POP3"
    finally:
        with contextlib.suppress(OSError):
            sock.sendall(b"QUIT\r\n")
        sock.close()


def probe_mail(ip: str, port: int) -> str:
    """Dispatch by port: SMTP / IMAP / POP3 banner + capability summary."""
    if port in _SMTP_PORTS:
        return probe_smtp(ip, port)
    if port in _IMAP_PORTS:
        return probe_imap(ip, port)
    if port in _POP_PORTS:
        return probe_pop(ip, port)
    return ""
