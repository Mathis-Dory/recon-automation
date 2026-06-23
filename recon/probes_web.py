"""Deeper HTTP fingerprint — server header, tech hints, robots.txt, favicon.

Wraps `requests` (already a top-level dep). Returns a single-line finding
ready to append to the row alongside the basic-title probe.
"""

import hashlib
import re

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_HTTPS_PORTS = {443, 446, 8443, 8888}


def _url(ip: str, port: int, path: str = "/") -> str:
    scheme = "https" if port in _HTTPS_PORTS else "http"
    return f"{scheme}://{ip}:{port}{path}"


def _server_signature(headers) -> str:
    parts = []
    server = headers.get("Server")
    powered = headers.get("X-Powered-By")
    via = headers.get("Via")
    if server:
        parts.append(f"server={server}")
    if powered:
        parts.append(f"powered={powered}")
    if via:
        parts.append(f"via={via}")
    return "; ".join(parts)


def _robots_paths(text: str) -> str:
    """Return up to 5 unique 'Disallow:' / 'Allow:' paths."""
    paths = []
    for line in text.splitlines():
        m = re.match(r"\s*(Disallow|Allow):\s*(\S+)", line, re.IGNORECASE)
        if m:
            p = m.group(2)
            if p and p != "/" and p not in paths:
                paths.append(p)
                if len(paths) == 5:
                    break
    return ",".join(paths)


def probe_web_deep(ip: str, port: int, timeout: float = 4.0, getter=requests.get) -> str:
    """Issue a few GETs and stitch the results into a single finding line."""
    pieces = []
    try:
        resp = getter(_url(ip, port, "/"), timeout=timeout, verify=False,
                      allow_redirects=False)
    except requests.RequestException:
        return ""
    sig = _server_signature(resp.headers)
    if sig:
        pieces.append(sig)
    if 300 <= resp.status_code < 400:
        loc = resp.headers.get("Location")
        if loc:
            pieces.append(f"redirect→{loc}")
    # Body-side tech hints (Set-Cookie names, generator metas)
    tech = []
    cookies = resp.headers.get("Set-Cookie", "")
    for marker in ("PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "laravel_session"):
        if marker in cookies:
            tech.append(marker)
    body = (resp.text or "")[:8192]
    m = re.search(r'<meta\s+name=[\'"]generator[\'"]\s+content=[\'"]([^\'"]+)', body, re.IGNORECASE)
    if m:
        tech.append(f"generator={m.group(1)}")
    if tech:
        pieces.append("tech: " + ",".join(tech))
    # robots.txt
    try:
        robots = getter(_url(ip, port, "/robots.txt"), timeout=timeout, verify=False,
                        allow_redirects=False)
        if robots.status_code == 200 and "Disallow" in robots.text or "Allow" in robots.text:
            paths = _robots_paths(robots.text)
            if paths:
                pieces.append(f"robots: {paths}")
    except requests.RequestException:
        pass
    # Favicon hash
    try:
        fav = getter(_url(ip, port, "/favicon.ico"), timeout=timeout, verify=False,
                     allow_redirects=False)
        if fav.status_code == 200 and fav.content:
            digest = hashlib.sha256(fav.content).hexdigest()[:16]
            pieces.append(f"favicon: sha256:{digest}")
    except requests.RequestException:
        pass
    return "; ".join(pieces)
