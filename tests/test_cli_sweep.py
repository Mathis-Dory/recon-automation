from recon import cli_sweep


def test_parse_nmap_up_hosts():
    text = (
        "Host: 10.0.0.1 ()\tStatus: Up\n"
        "Host: 10.0.0.2 ()\tStatus: Down\n"
        "Host: 10.0.0.3 ()\tStatus: Up\n"
    )
    assert cli_sweep.parse_nmap_up_hosts(text) == ["10.0.0.1", "10.0.0.3"]


def test_run_sweep_uses_runner():
    class Result:
        stdout = "Host: 10.0.0.5 ()\tStatus: Up\n"
        returncode = 0

    captured = {}

    def runner(cmd, **kwargs):
        captured["cmd"] = cmd
        return Result()

    out = cli_sweep.run_sweep(["10.0.0.0/24"], runner=runner)
    assert out == ["10.0.0.5"]
    assert "nmap" in captured["cmd"][0]
    assert "-sn" in captured["cmd"]
