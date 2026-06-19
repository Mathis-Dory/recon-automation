from recon import scan


def test_parse_masscan_list():
    text = (
        "#masscan\n"
        "open tcp 80 10.0.0.1 1700000000\n"
        "open tcp 445 10.0.0.2 1700000000\n"
    )
    assert scan.parse_masscan_list(text) == {("10.0.0.1", 80), ("10.0.0.2", 445)}


def test_run_masscan_builds_command_and_parses():
    captured = {}

    class Result:
        stdout = "open tcp 22 10.0.0.5 1700000000\n"
        returncode = 0

    def fake_runner(cmd, **kwargs):
        captured["cmd"] = cmd
        return Result()

    out = scan.run_masscan(["10.0.0.5"], [22, 80], rate=500, runner=fake_runner)
    assert out == {("10.0.0.5", 22)}
    assert "masscan" in captured["cmd"][0]
    assert "-p22,80" in captured["cmd"]
    assert "500" in captured["cmd"]


def test_parse_nmap_grepable():
    text = (
        "# Nmap\n"
        "Host: 10.0.0.1 ()\tPorts: 80/open/tcp//http//Apache httpd 2.4.52/\n"
    )
    parsed = scan.parse_nmap_grepable(text)
    assert parsed[("10.0.0.1", 80)]["service"] == "http"
    assert parsed[("10.0.0.1", 80)]["state"] == "open"
    assert "Apache" in parsed[("10.0.0.1", 80)]["version"]
