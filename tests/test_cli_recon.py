from recon import cli_recon


def test_plan_stages_defaults():
    args = cli_recon.build_arg_parser().parse_args(["-n", "job", "-r", "10.0.0.0/24"])
    assert cli_recon.plan_stages(args) == ["sweep", "enum", "nuclei"]


def test_target_args_ignores_empty_hosts_file(tmp_path):
    import argparse
    args = cli_recon.build_arg_parser().parse_args(["-n", "j", "-t", "10.0.0.1"])
    empty = tmp_path / "live-hosts.txt"
    empty.write_text("")
    # empty file -> falls through to passthrough -t
    assert cli_recon._target_args(args, str(empty)) == ["-t", "10.0.0.1"]
    nonempty = tmp_path / "h.txt"
    nonempty.write_text("10.0.0.9\n")
    assert cli_recon._target_args(args, str(nonempty)) == ["-iL", str(nonempty)]


def test_plan_stages_with_optionals_and_skips():
    args = cli_recon.build_arg_parser().parse_args(
        ["-n", "job", "-r", "10.0.0.0/24", "--nessus", "--smb", "--no-nuclei"]
    )
    assert cli_recon.plan_stages(args) == ["sweep", "enum", "nessus", "smb"]
