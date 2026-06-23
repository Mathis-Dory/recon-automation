"""Tests for recon/probes_tls.py — TLS cert probe with the handshake mocked."""

from datetime import datetime, timedelta, timezone

from recon import probes_tls


def _cert(subject="example.com", sans=("example.com", "www.example.com"),
          issuer="Let's Encrypt", days_until=90):
    expiry = datetime.now(timezone.utc) + timedelta(days=days_until)
    return {
        "subject": (((b"commonName", subject) if isinstance(subject, bytes)
                     else ("commonName", subject),),),
        "issuer": ((("commonName", issuer),),),
        "subjectAltName": tuple(("DNS", s) for s in sans),
        "notAfter": expiry.strftime("%b %d %H:%M:%S %Y GMT"),
    }


def test_probe_tls_cert_renders_cn_san_issuer_and_expiry(monkeypatch):
    monkeypatch.setattr(probes_tls, "_maybe_handshake",
                        lambda ip, port, timeout=4.0: _cert())
    out = probes_tls.probe_tls_cert("10.0.0.1", 443)
    assert "cert: CN=example.com" in out
    assert "SAN: example.com,www.example.com" in out
    assert "issuer: CN=Let's Encrypt" in out
    assert "expires " in out
    assert "(89d)" in out or "(90d)" in out  # rounding tolerance


def test_probe_tls_cert_truncates_san_list(monkeypatch):
    sans = tuple(f"host{i}.example.com" for i in range(12))
    monkeypatch.setattr(probes_tls, "_maybe_handshake",
                        lambda ip, port, timeout=4.0: _cert(sans=sans))
    out = probes_tls.probe_tls_cert("10.0.0.1", 443)
    assert "(+4 more)" in out


def test_probe_tls_cert_returns_empty_on_handshake_failure(monkeypatch):
    monkeypatch.setattr(probes_tls, "_maybe_handshake",
                        lambda ip, port, timeout=4.0: None)
    assert probes_tls.probe_tls_cert("10.0.0.1", 8080) == ""


def test_probe_tls_cert_handles_unparseable_notafter(monkeypatch):
    cert = _cert()
    cert["notAfter"] = "garbage"
    monkeypatch.setattr(probes_tls, "_maybe_handshake",
                        lambda ip, port, timeout=4.0: cert)
    out = probes_tls.probe_tls_cert("10.0.0.1", 443)
    assert "cert: CN=example.com" in out
    assert "expires" not in out


def test_short_dn_picks_cn_first():
    parts = ((("organizationName", "Acme"), ("commonName", "foo")),)
    assert probes_tls._short_dn(parts) == "CN=foo, O=Acme"


def test_short_dn_empty_returns_empty():
    assert probes_tls._short_dn(None) == ""
    assert probes_tls._short_dn(()) == ""
