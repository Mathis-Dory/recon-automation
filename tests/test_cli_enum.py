from recon import cli_enum


def test_dispatch_probes_routes_by_port():
    open_ports = {("10.0.0.1", 21), ("10.0.0.1", 22), ("10.0.0.1", 8080), ("10.0.0.1", 445)}
    calls = []
    fns = {
        "ftp": lambda ip, port: "FTP ANON OK (listing: no)",
        "banner": lambda ip, port: f"banner:{port}",
        "web": lambda ip, port: f"title:{port}",
        "smb": lambda ip: "SMB NULL OK: 2 shares",
    }
    res = cli_enum.dispatch_probes(open_ports, web_ports=[8080], probe_fns=fns)
    assert res[("10.0.0.1", 21)]["finding"] == "FTP ANON OK (listing: no)"
    assert res[("10.0.0.1", 22)]["finding"] == "banner:22"
    assert res[("10.0.0.1", 8080)]["http_title"] == "title:8080"
    # SMB finding attached to one of the smb ports
    smb_findings = [res[("10.0.0.1", 445)]["finding"]]
    assert "SMB NULL OK" in smb_findings[0]


def test_dispatch_probes_propagates_keyboard_interrupt():
    """KI in a worker bubbles up so the orchestrator can write its 130 manifest."""
    import pytest

    open_ports = {("10.0.0.1", 21), ("10.0.0.1", 8080)}

    def boom(ip, port=None):
        raise KeyboardInterrupt

    fns = {"ftp": boom, "banner": boom, "web": boom, "smb": lambda ip: None}
    with pytest.raises(KeyboardInterrupt):
        cli_enum.dispatch_probes(open_ports, web_ports=[8080], probe_fns=fns)


def test_arg_parser_accepts_inputs():
    parser = cli_enum.build_arg_parser()
    args = parser.parse_args(["-r", "10.0.0.0/30", "-o", "out.xlsx"])
    assert args.range == "10.0.0.0/30"
    assert args.output == "out.xlsx"


def test_dispatch_probes_skips_disabled():
    open_ports = {("10.0.0.1", 21), ("10.0.0.1", 22), ("10.0.0.1", 8080), ("10.0.0.1", 445)}
    fns = {
        "ftp": lambda ip, port: "FTP ANON OK",
        "banner": lambda ip, port: f"banner:{port}",
        "web": lambda ip, port: f"title:{port}",
        "smb": lambda ip: "SMB NULL OK",
    }
    res = cli_enum.dispatch_probes(
        open_ports,
        web_ports=[8080],
        probe_fns=fns,
        disabled_probes={"probe-ftp", "probe-smb"},
    )
    assert res[("10.0.0.1", 21)]["finding"] == ""  # ftp skipped
    assert res[("10.0.0.1", 22)]["finding"] == "banner:22"
    assert res[("10.0.0.1", 8080)]["http_title"] == "title:8080"
    assert res[("10.0.0.1", 445)]["finding"] == ""  # smb skipped


def test_dispatch_probes_unknown_disabled_names_are_ignored():
    open_ports = {("10.0.0.1", 21)}
    fns = {
        "ftp": lambda ip, port: "FTP ANON OK",
        "banner": lambda ip, port: "",
        "web": lambda ip, port: "",
        "smb": lambda ip: None,
    }
    res = cli_enum.dispatch_probes(
        open_ports,
        web_ports=[],
        probe_fns=fns,
        disabled_probes={"probe-bogus"},
    )
    assert res[("10.0.0.1", 21)]["finding"] == "FTP ANON OK"


def test_cli_enum_parses_disable_probes_csv():
    parser = cli_enum.build_arg_parser()
    args = parser.parse_args(["--disable-probes", "probe-ftp,probe-smb", "-t", "10.0.0.1"])
    assert args.disable_probes == "probe-ftp,probe-smb"


def test_cli_enum_concurrency_default_and_override():
    import pytest

    parser = cli_enum.build_arg_parser()
    assert parser.parse_args(["-t", "10.0.0.1"]).concurrency == 32
    assert parser.parse_args(["-t", "10.0.0.1", "--concurrency", "8"]).concurrency == 8
    with pytest.raises(SystemExit):
        parser.parse_args(["-t", "10.0.0.1", "--concurrency", "0"])
    with pytest.raises(SystemExit):
        parser.parse_args(["-t", "10.0.0.1", "--concurrency", "-3"])


def test_dispatch_probes_smb_deduped_under_concurrency():
    """A host with both 139 and 445 gets exactly one SMB probe call."""
    open_ports = {("10.0.0.1", 139), ("10.0.0.1", 445), ("10.0.0.2", 445)}
    smb_calls = []

    def smb_probe(ip):
        smb_calls.append(ip)
        return f"SMB ok for {ip}"

    fns = {
        "ftp": lambda ip, port: "",
        "banner": lambda ip, port: "",
        "web": lambda ip, port: "",
        "smb": smb_probe,
    }
    cli_enum.dispatch_probes(open_ports, web_ports=[], probe_fns=fns, concurrency=4)
    assert sorted(smb_calls) == ["10.0.0.1", "10.0.0.2"]


def test_dispatch_probes_concurrency_one_runs_sequentially():
    """concurrency=1 still produces correct results (degenerate case)."""
    open_ports = {("10.0.0.1", 21), ("10.0.0.2", 8080)}
    fns = {
        "ftp": lambda ip, port: f"ftp:{ip}",
        "banner": lambda ip, port: "",
        "web": lambda ip, port: f"title:{ip}",
        "smb": lambda ip: None,
    }
    res = cli_enum.dispatch_probes(open_ports, web_ports=[8080], probe_fns=fns, concurrency=1)
    assert res[("10.0.0.1", 21)]["finding"] == "ftp:10.0.0.1"
    assert res[("10.0.0.2", 8080)]["http_title"] == "title:10.0.0.2"


def test_dispatch_probes_records_per_probe_exception():
    """An exception in one probe sets that row's finding, doesn't break others."""
    open_ports = {("10.0.0.1", 21), ("10.0.0.2", 21)}

    def ftp(ip, port):
        if ip == "10.0.0.1":
            raise RuntimeError("connection refused")
        return "FTP ok"

    fns = {
        "ftp": ftp,
        "banner": lambda ip, port: "",
        "web": lambda ip, port: "",
        "smb": lambda ip: None,
    }
    res = cli_enum.dispatch_probes(open_ports, web_ports=[], probe_fns=fns, concurrency=4)
    assert "probe error" in res[("10.0.0.1", 21)]["finding"]
    assert "connection refused" in res[("10.0.0.1", 21)]["finding"]
    assert res[("10.0.0.2", 21)]["finding"] == "FTP ok"


def test_dispatch_probes_no_jobs_returns_empty_rows():
    """Open ports with all probes disabled produces only the default-empty rows."""
    open_ports = {("10.0.0.1", 21)}
    fns = {
        "ftp": lambda ip, port: "FTP",
        "banner": lambda ip, port: "",
        "web": lambda ip, port: "",
        "smb": lambda ip: None,
    }
    res = cli_enum.dispatch_probes(
        open_ports, web_ports=[], probe_fns=fns, disabled_probes={"probe-ftp"}
    )
    assert res[("10.0.0.1", 21)] == {"http_title": "", "finding": ""}
