"""Per-service auth-less probes: FTP anon, SMB null/guest, banners, web title."""
import re
import socket
import ftplib
import subprocess

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HTTPS_PORTS = {443, 8443}


def extract_title(html):
    """Return the trimmed <title> contents, or '' if none."""
    m = _TITLE_RE.search(html or "")
    return m.group(1).strip() if m else ""


def probe_web_title(ip, port, timeout=5, getter=requests.get):
    """GET the root URL and return the page title (or '')."""
    scheme = "https" if port in _HTTPS_PORTS else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        resp = getter(url, timeout=timeout, verify=False, allow_redirects=True)
        return extract_title(resp.text)
    except Exception:
        return ""


def probe_banner(ip, port, timeout=5, sock_factory=socket.create_connection):
    """Connect and read a service banner (SSH/Telnet)."""
    try:
        with sock_factory((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(256)
        return data.decode("latin-1", "replace").strip()
    except Exception:
        return ""


def probe_ftp_anon(ip, port=21, timeout=5, ftp_factory=ftplib.FTP):
    """Try anonymous FTP login; return a finding string or None."""
    ftp = ftp_factory()
    try:
        ftp.connect(ip, port, timeout)
        ftp.login()  # defaults to anonymous/anonymous@
        try:
            listing = ftp.nlst()
            has_listing = "yes" if listing else "no"
        except Exception:
            has_listing = "no"
        try:
            ftp.quit()
        except Exception:
            pass
        return f"FTP ANON OK (listing: {has_listing})"
    except Exception:
        return None


def probe_smb(ip, runner=subprocess.run):
    """Test SMB null/guest via netexec; return a finding summary or None."""
    cmd = ["nxc", "smb", ip, "-u", "", "-p", "", "--shares"]
    try:
        result = runner(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return None
    out = (result.stdout or "") + (result.stderr or "")
    if "[+]" not in out:
        return None
    shares = [
        ln for ln in out.splitlines()
        if ("READ" in ln or "WRITE" in ln) and "[+]" not in ln
    ]
    label = "GUEST" if "(guest)" in out.lower() else "NULL"
    return f"SMB {label} OK: {len(shares)} shares"
