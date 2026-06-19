from recon import enum_core, common


def test_is_web_port():
    assert enum_core.is_web_port(8080, common.DEFAULT_WEB_PORTS)
    assert not enum_core.is_web_port(22, common.DEFAULT_WEB_PORTS)


def test_build_rows_sorted_and_merged():
    open_ports = {("10.0.0.2", 80), ("10.0.0.1", 21)}
    nmap_info = {
        ("10.0.0.2", 80): {"state": "open", "service": "http", "version": "nginx 1.0"},
        ("10.0.0.1", 21): {"state": "open", "service": "ftp", "version": ""},
    }
    probe_results = {
        ("10.0.0.2", 80): {"http_title": "Home", "finding": ""},
        ("10.0.0.1", 21): {"http_title": "", "finding": "FTP ANON OK (listing: no)"},
    }
    rows = enum_core.build_rows(open_ports, nmap_info, probe_results)
    assert [r["ip"] for r in rows] == ["10.0.0.1", "10.0.0.2"]
    assert rows[0]["finding"] == "FTP ANON OK (listing: no)"
    assert rows[1]["http_title"] == "Home"
    assert "nginx" in rows[1]["service"]


def test_build_rows_handles_missing_nmap_info():
    rows = enum_core.build_rows({("10.0.0.1", 23)}, {}, {})
    assert rows[0]["state"] == "open"
    assert rows[0]["service"] == ""
