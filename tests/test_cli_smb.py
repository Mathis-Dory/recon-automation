from recon import cli_smb


def test_parse_nxc_smb():
    text = (
        "SMB  10.0.0.10  445  DC01  [*] Windows Server 2019 "
        "(name:DC01) (domain:lab.local) (signing:True) (SMBv1:False)\n"
    )
    parsed = cli_smb.parse_nxc_smb(text)
    assert parsed["10.0.0.10"]["host"] == "DC01"
    assert parsed["10.0.0.10"]["signing"] == "True"
    assert parsed["10.0.0.10"]["smbv1"] == "False"
    assert "Windows Server 2019" in parsed["10.0.0.10"]["os"]


def test_smb_rows_combine():
    parsed = {"10.0.0.10": {"host": "DC01", "os": "Windows Server 2019",
                             "signing": "True", "smbv1": "False", "domain": "lab.local"}}
    findings = {"10.0.0.10": "SMB NULL OK: 3 shares"}
    rows = cli_smb.smb_rows(parsed, findings)
    assert rows[0]["ip"] == "10.0.0.10"
    assert rows[0]["port"] == 445
    assert "SMB NULL OK" in rows[0]["finding"]
    assert "SMBv1:False" in rows[0]["finding"]
