from recon import nuclei, common


def test_targets_from_enum(tmp_path):
    rows = [
        {"ip": "10.0.0.1", "port": 8080, "state": "open", "service": "http", "finding": ""},
        {"ip": "10.0.0.2", "port": 443, "state": "open", "service": "https", "finding": ""},
        {"ip": "10.0.0.3", "port": 22, "state": "open", "service": "ssh", "finding": ""},
    ]
    path = str(tmp_path / "enum.xlsx")
    common.write_enum_workbook(rows, path)
    urls = nuclei.targets_from_enum(path)
    assert "http://10.0.0.1:8080" in urls
    assert "https://10.0.0.2:443" in urls
    assert all("10.0.0.3" not in u for u in urls)  # ssh excluded


def test_build_nuclei_cmd():
    cmd = nuclei.build_nuclei_cmd("/tmp/t.txt", "/tmp/o.jsonl")
    assert "-l" in cmd and "/tmp/t.txt" in cmd
    assert "-severity" in cmd and "medium,high,critical" in cmd
    assert "-jsonl" in cmd
    assert "/tmp/o.jsonl" in cmd


def test_build_nuclei_cmd_custom_bin():
    cmd = nuclei.build_nuclei_cmd("/tmp/t.txt", "/tmp/o.jsonl", nuclei_bin="/home/u/go/bin/nuclei")
    assert cmd[0] == "/home/u/go/bin/nuclei"


def test_ensure_nuclei_found():
    def which(name):
        return "/usr/bin/nuclei"
    assert nuclei.ensure_nuclei(which=which) == "/usr/bin/nuclei"
