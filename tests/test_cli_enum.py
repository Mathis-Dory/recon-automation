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


def test_arg_parser_accepts_inputs():
    parser = cli_enum.build_arg_parser()
    args = parser.parse_args(["-r", "10.0.0.0/30", "-o", "out.xlsx"])
    assert args.range == "10.0.0.0/30"
    assert args.output == "out.xlsx"
