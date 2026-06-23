"""External-tool probes — wrap nxc/showmount with timeouts and parse output.

These probes reach out to system binaries (``nxc``, ``showmount``) and parse
their stdout. Each returns "" on missing binary, timeout, or non-success — never
raises. ``nxc`` is already required by the smb stage; ``showmount`` is a soft
requirement on probe-nfs.
"""

import re
import shutil
import subprocess
from typing import Optional


def _run(cmd: list, timeout: float = 30.0) -> Optional[str]:
    """Run `cmd` with capture; return combined stdout+stderr, or None on failure."""
    if shutil.which(cmd[0]) is None:
        return None
    try:
        result = subprocess.run(cmd, capture_output=True, text=True,
                                timeout=timeout, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return None
    return (result.stdout or "") + (result.stderr or "")


_LDAP_DOMAIN = re.compile(r"\(domain:([^)]+)\)")
_LDAP_FUNC = re.compile(r"Functional Level[: ]+(\S+)", re.IGNORECASE)
_NAMING_CTX = re.compile(r"(?:naming|defaultNamingContext)[^\n]*?(DC=[A-Za-z0-9,=. _-]+)", re.IGNORECASE)


def probe_ldap(ip: str, port: int) -> str:
    """Use `nxc ldap` for anon-bind + RootDSE summary."""
    out = _run(["nxc", "ldap", ip, "-u", "", "-p", ""])
    if not out:
        return ""
    bits = []
    m = _LDAP_DOMAIN.search(out)
    if m:
        bits.append(f"domain={m.group(1).strip()}")
    m = _LDAP_FUNC.search(out)
    if m:
        bits.append(f"level={m.group(1)}")
    m = _NAMING_CTX.search(out)
    if m:
        bits.append(f"naming={m.group(1)}")
    if "[+]" in out and not bits:
        bits.append("LDAP reachable")
    if not bits:
        return ""
    return f"LDAP({port}): " + "; ".join(bits)


_RDP_NLA = re.compile(r"NLA[: ]+([^\s,]+)", re.IGNORECASE)
_RDP_OS = re.compile(r"(?:Windows[^)\n]*)", re.IGNORECASE)


def probe_rdp(ip: str, port: int) -> str:
    """Use `nxc rdp` for NLA / OS / cert hostname."""
    out = _run(["nxc", "rdp", ip])
    if not out:
        return ""
    bits = []
    m = _RDP_NLA.search(out)
    if m:
        bits.append(f"NLA={m.group(1)}")
    m = _RDP_OS.search(out)
    if m:
        bits.append(f"os={m.group(0)}")
    if "[+]" in out and not bits:
        bits.append("RDP reachable")
    if not bits:
        return ""
    return f"RDP({port}): " + "; ".join(bits)


_NFS_EXPORT = re.compile(r"^(/\S+)\s+(.*)$", re.MULTILINE)


def probe_nfs(ip: str, port: int) -> str:
    """Use `showmount -e` to list NFS exports.

    Returns up to 5 exports as ``path -> clients``. Soft requirement:
    when ``showmount`` is absent the probe returns "" silently.
    """
    out = _run(["showmount", "-e", "--no-headers", ip], timeout=15.0)
    if not out:
        # showmount -e prints headers even with --no-headers on some Linux distros
        out = _run(["showmount", "-e", ip], timeout=15.0)
    if not out:
        return ""
    exports = []
    for m in _NFS_EXPORT.finditer(out):
        path, clients = m.group(1), m.group(2).strip()
        if path == "/path" or path.startswith("/Export"):  # header rows
            continue
        exports.append(f"{path} -> {clients}")
        if len(exports) == 5:
            break
    if not exports:
        return ""
    return f"NFS({port}): " + " | ".join(exports)


def probe_winrm(ip: str, port: int) -> str:
    """Use `nxc winrm` to confirm reachability and pick up the protocol mode."""
    out = _run(["nxc", "winrm", ip])
    if not out:
        return ""
    if "[+]" not in out:
        return ""
    # nxc winrm prints e.g. "WINRM 10.0.0.1 5985 HOSTNAME [*] Windows 10..."
    m = re.search(r"\[\*\]\s+(.*)", out)
    extra = m.group(1).strip() if m else ""
    return f"WinRM({port}): reachable" + (f"; {extra}" if extra else "")
