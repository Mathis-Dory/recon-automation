"""TLS certificate probe — subject / SAN / issuer / expiry.

Uses stdlib ``ssl``. Runs against web ports; appends to the row's `finding`
column alongside `probe-web-basic` so SANs are visible next to the page title.

Returns a single-line summary or ``""`` on failure / non-TLS port.
"""

import socket
import ssl
from datetime import datetime, timezone


def _maybe_handshake(ip: str, port: int, timeout: float = 4.0):
    """Open a TCP+TLS connection; return the peer certificate dict or None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                return tls.getpeercert()
    except (OSError, ssl.SSLError, ValueError):
        return None


_DN_SHORT = {
    "commonName": "CN",
    "organizationName": "O",
    "organizationalUnitName": "OU",
    "localityName": "L",
    "countryName": "C",
}


def _short_dn(parts):
    """Convert ssl's nested-tuple DN to 'CN=foo, O=bar'.

    Accepts either ssl's long form (``commonName``) or its abbreviation
    (``CN``); the latter shows up in tests that build DN fixtures by hand.
    """
    flat = {}
    for rdn in parts or ():
        for attr, value in rdn:
            short = _DN_SHORT.get(attr, attr)
            flat.setdefault(short, value)
    keys = ["CN", "O", "OU", "L", "C"]
    return ", ".join(f"{k}={flat[k]}" for k in keys if k in flat)


def _parse_notafter(text: str):
    """Parse the cert's notAfter (RFC 2822-ish: 'Apr  1 12:00:00 2027 GMT')."""
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(text, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def probe_tls_cert(ip: str, port: int, timeout: float = 4.0) -> str:
    """Return 'cert: CN=foo; SAN: a.com,b.com; expires <YYYY-MM-DD> (<N>d)' or ''.

    Best-effort: ports that don't speak TLS return "" (the connection fails).
    """
    cert = _maybe_handshake(ip, port, timeout)
    if not cert:
        return ""
    subject = _short_dn(cert.get("subject")) or "?"
    issuer = _short_dn(cert.get("issuer")) or "?"
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]

    bits = [f"cert: {subject}"]
    if sans:
        bits.append("SAN: " + ",".join(sans[:8]) + (f" (+{len(sans) - 8} more)" if len(sans) > 8 else ""))
    if issuer and issuer != subject:
        bits.append(f"issuer: {issuer}")
    not_after = cert.get("notAfter")
    if not_after:
        dt = _parse_notafter(not_after)
        if dt is not None:
            now = datetime.now(timezone.utc)
            days = (dt - now).days
            bits.append(f"expires {dt.strftime('%Y-%m-%d')} ({days}d)")
    return "; ".join(bits)
