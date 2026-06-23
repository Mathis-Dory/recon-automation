"""Tests for recon/probes_web.py — web-deep fingerprint with `requests` mocked."""

from unittest.mock import MagicMock

import pytest

from recon import probes_web


def _resp(status_code=200, headers=None, text="", content=b""):
    r = MagicMock()
    r.status_code = status_code
    r.headers = headers or {}
    r.text = text
    r.content = content
    return r


def _router(routes):
    """Build a fake `requests.get` that maps URL → response."""
    def fake_get(url, **_kw):
        for suffix, resp in routes.items():
            if url.endswith(suffix):
                return resp
        return _resp(404, {}, "", b"")
    return fake_get


def test_probe_web_deep_renders_server_headers():
    getter = _router({
        "/": _resp(200, {"Server": "nginx/1.18", "X-Powered-By": "PHP/8.1"}),
        "/robots.txt": _resp(404),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "server=nginx/1.18" in out
    assert "powered=PHP/8.1" in out


def test_probe_web_deep_records_redirect():
    getter = _router({
        "/": _resp(301, {"Server": "Apache", "Location": "https://example.com/"}),
        "/robots.txt": _resp(404),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "redirect→https://example.com/" in out


def test_probe_web_deep_extracts_session_cookie_marker():
    getter = _router({
        "/": _resp(200, {"Server": "Apache", "Set-Cookie": "PHPSESSID=abc; path=/"}),
        "/robots.txt": _resp(404),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "PHPSESSID" in out


def test_probe_web_deep_extracts_generator_meta():
    body = '<html><head><meta name="generator" content="WordPress 6.4.1"></head></html>'
    getter = _router({
        "/": _resp(200, {"Server": "nginx"}, text=body),
        "/robots.txt": _resp(404),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "generator=WordPress 6.4.1" in out


def test_probe_web_deep_parses_robots_paths():
    robots = "User-agent: *\nDisallow: /admin\nDisallow: /api/private\nAllow: /\nDisallow: /backup\n"
    getter = _router({
        "/": _resp(200, {}),
        "/robots.txt": _resp(200, {"Content-Type": "text/plain"}, text=robots),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "robots: /admin,/api/private,/backup" in out


def test_probe_web_deep_caps_robots_paths_at_five():
    paths = "\n".join(f"Disallow: /p{i}" for i in range(12))
    getter = _router({
        "/": _resp(200, {}),
        "/robots.txt": _resp(200, {}, text=paths),
        "/favicon.ico": _resp(404),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    # 5 paths joined
    assert out.count("/p") == 5


def test_probe_web_deep_hashes_favicon():
    getter = _router({
        "/": _resp(200, {}),
        "/robots.txt": _resp(404),
        "/favicon.ico": _resp(200, {}, content=b"\x00\x01\x02" * 64),
    })
    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=getter)
    assert "favicon: sha256:" in out


def test_probe_web_deep_returns_empty_when_root_unreachable():
    import requests

    def boom(url, **_kw):
        raise requests.RequestException("connection refused")

    out = probes_web.probe_web_deep("10.0.0.1", 80, getter=boom)
    assert out == ""


def test_probe_web_deep_picks_https_for_known_ports():
    """The _url helper picks the right scheme; pure logic, no network."""
    assert probes_web._url("10.0.0.1", 80).startswith("http://")
    assert probes_web._url("10.0.0.1", 443).startswith("https://")
    assert probes_web._url("10.0.0.1", 8443).startswith("https://")
    assert probes_web._url("10.0.0.1", 8080).startswith("http://")
