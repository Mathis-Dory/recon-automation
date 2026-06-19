from recon import cli_recon


def test_plan_stages_defaults():
    args = cli_recon.build_arg_parser().parse_args(["-n", "job", "-r", "10.0.0.0/24"])
    assert cli_recon.plan_stages(args) == ["sweep", "enum", "nuclei"]


def test_plan_stages_with_optionals_and_skips():
    args = cli_recon.build_arg_parser().parse_args(
        ["-n", "job", "-r", "10.0.0.0/24", "--nessus", "--smb", "--no-nuclei"]
    )
    assert cli_recon.plan_stages(args) == ["sweep", "enum", "nessus", "smb"]
