"""Tests for recon/probes_external.py — nxc / showmount wrappers mocked."""

import subprocess
from unittest.mock import MagicMock

from recon import probes_external


def _patch_run(monkeypatch, output):
    """Make probes_external._run return `output` regardless of cmd."""
    monkeypatch.setattr(probes_external, "_run", lambda cmd, timeout=30.0: output)


def _patch_run_per_cmd(monkeypatch, by_first_arg):
    """Branch _run by the binary name (cmd[0])."""
    def fake(cmd, timeout=30.0):
        return by_first_arg.get(cmd[0])
    monkeypatch.setattr(probes_external, "_run", fake)


def test_run_returns_none_when_binary_missing(monkeypatch):
    monkeypatch.setattr(probes_external.shutil, "which", lambda name: None)
    assert probes_external._run(["bogus", "arg"]) is None


def test_run_returns_combined_output(monkeypatch):
    monkeypatch.setattr(probes_external.shutil, "which", lambda name: "/usr/bin/" + name)
    result = MagicMock(stdout="out", stderr="err")

    def fake_run(cmd, **_kw):
        return result

    monkeypatch.setattr(probes_external.subprocess, "run", fake_run)
    assert probes_external._run(["true"]) == "outerr"


def test_run_handles_timeout(monkeypatch):
    monkeypatch.setattr(probes_external.shutil, "which", lambda name: "/usr/bin/true")

    def boom(cmd, **_kw):
        raise subprocess.TimeoutExpired(cmd=cmd[0], timeout=1)

    monkeypatch.setattr(probes_external.subprocess, "run", boom)
    assert probes_external._run(["true"]) is None


def test_probe_ldap_renders_domain_and_naming(monkeypatch):
    fake = (
        "LDAP        10.0.0.5      389    DC01-WIN          [*] Windows Server 2019 "
        "Build 17763 (name:DC01-WIN) (domain:corp.local)\n"
        "LDAP        10.0.0.5      389    DC01-WIN          [+] corp.local\\\n"
        "defaultNamingContext: DC=corp,DC=local\n"
    )
    _patch_run(monkeypatch, fake)
    out = probes_external.probe_ldap("10.0.0.5", 389)
    assert "domain=corp.local" in out
    assert "naming=DC=corp,DC=local" in out


def test_probe_ldap_returns_empty_when_no_output(monkeypatch):
    _patch_run(monkeypatch, None)
    assert probes_external.probe_ldap("10.0.0.5", 389) == ""


def test_probe_ldap_falls_back_to_reachable_label(monkeypatch):
    _patch_run(monkeypatch, "LDAP 10.0.0.5 389 - [+] reachable\n")
    out = probes_external.probe_ldap("10.0.0.5", 389)
    assert "LDAP reachable" in out


def test_probe_rdp_renders_nla_and_os(monkeypatch):
    fake = (
        "RDP         10.0.0.5      3389   - "
        "[*] Windows 10 Enterprise NLA: True\n"
        "RDP         10.0.0.5      3389   - [+] reachable\n"
    )
    _patch_run(monkeypatch, fake)
    out = probes_external.probe_rdp("10.0.0.5", 3389)
    assert "NLA=True" in out
    assert "os=Windows 10" in out


def test_probe_rdp_returns_empty_when_no_indicator(monkeypatch):
    _patch_run(monkeypatch, "RDP 10.0.0.5 3389 - [-] not reachable\n")
    assert probes_external.probe_rdp("10.0.0.5", 3389) == ""


def test_probe_nfs_lists_exports(monkeypatch):
    fake = "/srv/share *\n/data 10.0.0.0/8\n/scratch 192.168.1.0/24\n"
    _patch_run(monkeypatch, fake)
    out = probes_external.probe_nfs("10.0.0.5", 2049)
    assert "/srv/share -> *" in out
    assert "/data -> 10.0.0.0/8" in out
    assert "/scratch -> 192.168.1.0/24" in out


def test_probe_nfs_caps_at_five_exports(monkeypatch):
    fake = "\n".join(f"/path{i} *" for i in range(12)) + "\n"
    _patch_run(monkeypatch, fake)
    out = probes_external.probe_nfs("10.0.0.5", 2049)
    assert out.count("/path") == 5


def test_probe_nfs_returns_empty_when_showmount_missing(monkeypatch):
    _patch_run(monkeypatch, None)
    assert probes_external.probe_nfs("10.0.0.5", 2049) == ""


def test_probe_nfs_tries_fallback_invocation(monkeypatch):
    calls = []

    def fake(cmd, timeout=30.0):
        calls.append(cmd)
        if "--no-headers" in cmd:
            return None  # first attempt fails
        return "/srv *\n"  # fallback succeeds

    monkeypatch.setattr(probes_external, "_run", fake)
    out = probes_external.probe_nfs("10.0.0.5", 2049)
    assert "/srv -> *" in out
    assert any("--no-headers" in c for c in calls)
    assert any("--no-headers" not in c for c in calls)


def test_probe_winrm_returns_label_when_reachable(monkeypatch):
    fake = "WINRM       10.0.0.5      5985   HOSTNAME  [*] Windows Server 2019 [+] reachable\n"
    _patch_run(monkeypatch, fake)
    out = probes_external.probe_winrm("10.0.0.5", 5985)
    assert "WinRM(5985): reachable" in out
    assert "Windows Server 2019" in out


def test_probe_winrm_returns_empty_when_not_reachable(monkeypatch):
    _patch_run(monkeypatch, "WINRM 10.0.0.5 5985 - [-] not reachable\n")
    assert probes_external.probe_winrm("10.0.0.5", 5985) == ""
