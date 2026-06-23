"""SMB depth via ``nxc smb`` — signing audit, password policy, anonymous RID brute.

These three probes layer on top of the null/guest check already done by
``probe-smb``. They share the soft ``nxc`` requirement and are per-host
(deduplicated by IP in the dispatch loop).
"""

import re

from recon import probes_external

_SIGNING_LINE = re.compile(r"signing:\s*(True|False)", re.IGNORECASE)
_PASSPOL_BLOCK = re.compile(
    r"(Minimum password length:\s*\d+|Account lockout.*?\n|Password (history|complexity).*?\n)",
    re.IGNORECASE,
)
_RID_USER = re.compile(r"\d+:\s*([\w$.-]+)\s*\((SidTypeUser|SidTypeGroup)\)", re.IGNORECASE)


def probe_smb_signing(ip: str) -> str:
    """Run a fast `nxc smb` and report whether SMB signing is required.

    Signing=False ⇒ relay-eligible host (engagement-relevant). Uses --no-progress
    to keep the output compact and parseable.
    """
    out = probes_external._run(["nxc", "smb", ip])
    if not out:
        return ""
    match = _SIGNING_LINE.search(out)
    if not match:
        return ""
    signing = match.group(1)
    if signing.lower() == "false":
        return "SMB signing: NOT required (relay-eligible)"
    return "SMB signing: required"


def probe_smb_passpol(ip: str) -> str:
    """Pull the host's password policy via `nxc smb --pass-pol`.

    The output is rendered into a single line that names the most actionable
    fields (length, lockout, complexity, history).
    """
    out = probes_external._run(["nxc", "smb", ip, "-u", "", "-p", "", "--pass-pol"])
    if not out or "[+]" not in out:
        return ""
    bits = []
    for m in _PASSPOL_BLOCK.finditer(out):
        bits.append(m.group(1).strip().rstrip("."))
        if len(bits) >= 4:
            break
    if not bits:
        return ""
    return "SMB pass-pol: " + " | ".join(bits)


def probe_smb_rid(ip: str) -> str:
    """Anonymous RID brute via `nxc smb --rid-brute`.

    Returns up to 8 discovered principals (users + groups) as a comma-joined list.
    Falls back to "" if anon brute is rejected.
    """
    out = probes_external._run(
        ["nxc", "smb", ip, "-u", "", "-p", "", "--rid-brute", "1000"], timeout=60.0
    )
    if not out:
        return ""
    # Count all unique principals first, then truncate the visible list.
    seen, principals = set(), []
    for m in _RID_USER.finditer(out):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        principals.append(name)
    if not principals:
        return ""
    extra = "" if len(principals) <= 8 else f" (+{len(principals) - 8})"
    return "SMB RID-brute: " + ",".join(principals[:8]) + extra
