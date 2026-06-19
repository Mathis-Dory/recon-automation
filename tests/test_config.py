import pytest
from recon import common


def _write_cfg(tmp_path, body):
    p = tmp_path / "config.ini"
    p.write_text(body)
    return str(p)


def test_load_full_config(tmp_path):
    path = _write_cfg(tmp_path, (
        "[nessus]\n"
        "url = https://nessus.lab:8834\n"
        "access_key = AAA\n"
        "secret_key = BBB\n"
        "template = Advanced Scan\n"
    ))
    cfg = common.load_nessus_config(path)
    assert cfg == {
        "url": "https://nessus.lab:8834",
        "access_key": "AAA",
        "secret_key": "BBB",
        "template": "Advanced Scan",
    }


def test_defaults_applied(tmp_path):
    path = _write_cfg(tmp_path, "[nessus]\naccess_key = A\nsecret_key = B\n")
    cfg = common.load_nessus_config(path)
    assert cfg["url"] == "https://localhost:8834"
    assert cfg["template"] == "Basic Network Scan"


def test_missing_file_raises():
    with pytest.raises(FileNotFoundError):
        common.load_nessus_config("/nonexistent/config.ini")


def test_missing_keys_raises(tmp_path):
    path = _write_cfg(tmp_path, "[nessus]\nurl = https://x:8834\n")
    with pytest.raises(ValueError):
        common.load_nessus_config(path)
