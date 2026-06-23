"""Tests for recon/probes_smb_depth.py — nxc smb depth probes."""

from recon import probes_smb_depth


def _patch_run(monkeypatch, output):
    from recon import probes_external

    monkeypatch.setattr(probes_external, "_run", lambda cmd, timeout=30.0: output)


def test_probe_smb_signing_flags_relay_eligible(monkeypatch):
    _patch_run(
        monkeypatch, "SMB         10.0.0.5      445    DC01   [*] Windows 10 (signing:False)\n"
    )
    out = probes_smb_depth.probe_smb_signing("10.0.0.5")
    assert "NOT required" in out
    assert "relay-eligible" in out


def test_probe_smb_signing_reports_required(monkeypatch):
    _patch_run(
        monkeypatch, "SMB         10.0.0.5      445    DC01   [*] Windows 10 (signing:True)\n"
    )
    out = probes_smb_depth.probe_smb_signing("10.0.0.5")
    assert "required" in out
    assert "NOT" not in out


def test_probe_smb_signing_returns_empty_without_match(monkeypatch):
    _patch_run(monkeypatch, "SMB connection refused\n")
    assert probes_smb_depth.probe_smb_signing("10.0.0.5") == ""


def test_probe_smb_signing_returns_empty_on_missing_nxc(monkeypatch):
    _patch_run(monkeypatch, None)
    assert probes_smb_depth.probe_smb_signing("10.0.0.5") == ""


def test_probe_smb_passpol_renders_block(monkeypatch):
    fake = (
        "SMB         10.0.0.5      445    DC01   [+] corp.local\\:\n"
        "Minimum password length: 12\n"
        "Account lockout threshold: 5\n"
        "Password complexity: enabled\n"
    )
    _patch_run(monkeypatch, fake)
    out = probes_smb_depth.probe_smb_passpol("10.0.0.5")
    assert out.startswith("SMB pass-pol:")
    assert "Minimum password length: 12" in out
    assert "Account lockout threshold: 5" in out


def test_probe_smb_passpol_returns_empty_without_plus_marker(monkeypatch):
    _patch_run(monkeypatch, "SMB 10.0.0.5 445 - [-] auth required\n")
    assert probes_smb_depth.probe_smb_passpol("10.0.0.5") == ""


def test_probe_smb_rid_returns_user_list(monkeypatch):
    fake = (
        "SMB         10.0.0.5      445    DC01   [+] corp.local\\:\n"
        "500: Administrator (SidTypeUser)\n"
        "501: Guest (SidTypeUser)\n"
        "513: Domain Users (SidTypeGroup)\n"
        "1000: bob.smith (SidTypeUser)\n"
    )
    _patch_run(monkeypatch, fake)
    out = probes_smb_depth.probe_smb_rid("10.0.0.5")
    assert out.startswith("SMB RID-brute:")
    assert "Administrator" in out
    assert "Guest" in out
    assert "bob.smith" in out


def test_probe_smb_rid_caps_at_eight_and_reports_extras(monkeypatch):
    lines = ["[+] corp.local\\:"] + [f"{1000 + i}: user{i} (SidTypeUser)" for i in range(12)]
    _patch_run(monkeypatch, "\n".join(lines) + "\n")
    out = probes_smb_depth.probe_smb_rid("10.0.0.5")
    listed = out.split(":", 1)[1].strip()
    assert listed.startswith("user0,user1,user2,user3,user4,user5,user6,user7")
    assert "+4" in out


def test_probe_smb_rid_returns_empty_on_no_match(monkeypatch):
    _patch_run(monkeypatch, "STATUS_ACCESS_DENIED\n")
    assert probes_smb_depth.probe_smb_rid("10.0.0.5") == ""
