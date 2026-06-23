import json
import os
import shutil

import pytest

from recon import cli_recon


def _argv_for(name, range_):
    return ["-n", name, "-r", range_]


@pytest.fixture
def stub_tools_present(monkeypatch):
    """Make shutil.which report nmap/masscan/nxc as present.

    The orchestrator auto-skips modules whose Tool() prereqs are absent. CI
    runners don't have these binaries; tests that mock cli_*.main want the
    orchestrator to actually call those mocks instead of skipping the stage.
    """
    original_which = shutil.which
    stubbed = {"nmap", "masscan", "nxc"}
    monkeypatch.setattr(
        shutil, "which",
        lambda name: f"/usr/bin/{name}" if name in stubbed else original_which(name),
    )


def test_parser_includes_stage_and_module_flags(tmp_path):
    parser = cli_recon.build_arg_parser()
    args = parser.parse_args(_argv_for("job", "10.0.0.0/30"))
    # stage flags
    assert args.no_sweep is False
    assert args.no_enum is False
    assert args.no_nuclei is False
    assert args.no_nessus is False
    assert args.no_smb is False
    # module flags
    assert args.no_probe_ftp is False
    assert args.no_probe_ssh is False
    assert args.no_probe_web_basic is False
    assert args.no_probe_smb is False


def test_target_args_ignores_empty_hosts_file(tmp_path):
    args = cli_recon.build_arg_parser().parse_args(["-n", "j", "-t", "10.0.0.1"])
    empty = tmp_path / "live-hosts.txt"
    empty.write_text("")
    assert cli_recon._target_args(args, str(empty)) == ["-t", "10.0.0.1"]
    nonempty = tmp_path / "h.txt"
    nonempty.write_text("10.0.0.9\n")
    assert cli_recon._target_args(args, str(nonempty)) == ["-iL", str(nonempty)]


def test_orchestrator_runs_all_default_on_stages(tmp_path, monkeypatch, stub_tools_present):
    """Default invocation: every stage runs (or auto-skips with a reason)."""
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])

    calls = []

    def fake_main(stage, argv):
        calls.append((stage, list(argv)))
        # write the expected output artifact so the orchestrator's chaining works
        if stage == "sweep":
            idx = argv.index("-o")
            with open(argv[idx + 1], "w") as fh:
                fh.write("10.0.0.1\n")
        if stage == "enum":
            idx = argv.index("-o")
            open(argv[idx + 1], "w").close()
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", lambda a: fake_main("sweep", a))
    monkeypatch.setattr("recon.cli_enum.main", lambda a: fake_main("enum", a))
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: fake_main("nuclei", a))
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: fake_main("nessus", a))
    monkeypatch.setattr("recon.cli_smb.main", lambda a: fake_main("smb", a))

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])
    assert rc in (0, 1)  # may be 1 if nessus/smb prereqs are skipped — that's OK here

    stages_called = [s for s, _ in calls]
    assert "sweep" in stages_called
    assert "enum" in stages_called
    assert "nuclei" in stages_called

    manifest = json.loads((outdir / "run.json").read_text())
    assert manifest["engagement"] == "eng"
    assert {s["name"] for s in manifest["stages"]} >= {"sweep", "enum", "nuclei"}


def test_orchestrator_passes_disable_probes_to_enum(tmp_path, monkeypatch, stub_tools_present):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    captured = {}

    def fake_sweep(argv):
        idx = argv.index("-o")
        with open(argv[idx + 1], "w") as fh:
            fh.write("10.0.0.1\n")
        return 0

    def fake_enum(argv):
        captured["enum_argv"] = list(argv)
        idx = argv.index("-o")
        open(argv[idx + 1], "w").close()
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", fake_sweep)
    monkeypatch.setattr("recon.cli_enum.main", fake_enum)
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_smb.main", lambda a: 0)

    cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30",
                    "--no-probe-ftp", "--no-probe-smb"])

    assert "--disable-probes" in captured["enum_argv"]
    csv_idx = captured["enum_argv"].index("--disable-probes")
    csv = set(captured["enum_argv"][csv_idx + 1].split(","))
    assert csv == {"probe-ftp", "probe-smb"}


def test_orchestrator_auto_skips_module_with_missing_prereqs(tmp_path, monkeypatch):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    # Force nessus skip by clobbering config_loader path to a non-existent file.
    monkeypatch.setattr("recon.common.DEFAULT_CONFIG_PATH",
                        str(tmp_path / "nope.ini"))
    # Force smb-mass skip by removing nxc from PATH.
    import shutil
    original_which = shutil.which
    monkeypatch.setattr(
        shutil, "which",
        lambda name: None if name == "nxc" else original_which(name),
    )

    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").write("10.0.0.1\n"), 0)[1])
    monkeypatch.setattr("recon.cli_enum.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").close() or 0))
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: 0)
    nessus_called = []
    smb_called = []
    monkeypatch.setattr("recon.cli_nessus.main",
                        lambda a: nessus_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_smb.main",
                        lambda a: smb_called.append(a) or 0)

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])

    assert nessus_called == [], "nessus should be skipped when config missing"
    assert smb_called == [], "smb-mass should be skipped when nxc not on PATH"
    assert rc == 0

    manifest = json.loads((outdir / "run.json").read_text())
    nessus_stage = next(s for s in manifest["stages"] if s["name"] == "nessus")
    smb_stage = next(s for s in manifest["stages"] if s["name"] == "smb")
    assert nessus_stage["status"] == "skipped"
    assert smb_stage["status"] == "skipped"
    reasons = [m["reason"] for m in nessus_stage["modules_skipped"]]
    assert any("access_key" in r for r in reasons)


def test_orchestrator_target_parse_error_exits_2(tmp_path, monkeypatch):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name, root=None: str(tmp_path / "eng"))

    def boom(*_args):
        raise ValueError("no targets")

    monkeypatch.setattr("recon.common.parse_targets", boom)
    rc = cli_recon.main(["-n", "eng", "-r", "bogus"])
    assert rc == 2


def test_orchestrator_exits_2_when_targets_out_of_scope(tmp_path, monkeypatch):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.5", "192.168.1.10"])
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.0/24\n")  # 192.168.1.10 is OUT of scope
    sweep_called = []
    monkeypatch.setattr("recon.cli_sweep.main", lambda a: sweep_called.append(a) or 0)

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/24",
                         "--scope-file", str(scope)])

    assert rc == 2
    assert sweep_called == [], "no stage should run when targets are out of scope"


def test_orchestrator_scope_file_missing_exits_2(tmp_path, monkeypatch):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name, root=None: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.5"])
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/24",
                         "--scope-file", str(tmp_path / "nope.txt")])
    assert rc == 2


def test_resume_skips_completed_sweep_and_enum(tmp_path, monkeypatch, stub_tools_present):
    """With --resume and a prior run.json showing sweep/enum ok, only nuclei runs."""
    import json
    outdir = tmp_path / "eng"
    outdir.mkdir()
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets", lambda r, t, i: ["10.0.0.1"])

    # Seed prior run.json + artifacts on disk.
    (outdir / "live-hosts.txt").write_text("10.0.0.1\n")
    (outdir / "enum.xlsx").write_text("placeholder")
    (outdir / "run.json").write_text(json.dumps({
        "engagement": "eng",
        "started_at": "2026-06-23T00:00:00Z",
        "finished_at": None,
        "targets": {"count": 1, "source": "-r 10.0.0.0/30"},
        "stages": [
            {"name": "sweep", "status": "ok", "elapsed_s": 1.0,
             "modules_run": ["sweep"], "modules_skipped": [], "exit_code": 0},
            {"name": "enum", "status": "ok", "elapsed_s": 2.5,
             "modules_run": ["masscan"], "modules_skipped": [], "exit_code": 0},
        ],
        "exit_code": None,
    }))

    sweep_called = []
    enum_called = []
    nuclei_called = []
    monkeypatch.setattr("recon.cli_sweep.main", lambda a: sweep_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_enum.main", lambda a: enum_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: nuclei_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_smb.main", lambda a: 0)

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--resume"])
    assert rc == 0
    assert sweep_called == [], "completed sweep should be skipped under --resume"
    assert enum_called == [], "completed enum should be skipped under --resume"
    assert len(nuclei_called) == 1, "nuclei was not previously complete and should run"

    # Manifest preserves the prior stage records.
    manifest = json.loads((outdir / "run.json").read_text())
    stage_names = [s["name"] for s in manifest["stages"]]
    assert stage_names.count("sweep") == 1
    assert stage_names.count("enum") == 1


def test_resume_reruns_stage_when_artifact_missing(tmp_path, monkeypatch, stub_tools_present):
    """status=ok in manifest but artifact deleted from disk → stage re-runs."""
    import json
    outdir = tmp_path / "eng"
    outdir.mkdir()
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets", lambda r, t, i: ["10.0.0.1"])

    # Manifest says sweep was ok, but live-hosts.txt is missing.
    (outdir / "run.json").write_text(json.dumps({
        "engagement": "eng",
        "started_at": "2026-06-23T00:00:00Z",
        "finished_at": None,
        "targets": {"count": 1, "source": "-r 10.0.0.0/30"},
        "stages": [
            {"name": "sweep", "status": "ok", "elapsed_s": 1.0,
             "modules_run": ["sweep"], "modules_skipped": [], "exit_code": 0},
        ],
        "exit_code": None,
    }))

    def fake_sweep(argv):
        idx = argv.index("-o")
        with open(argv[idx + 1], "w") as fh:
            fh.write("")  # empty → short-circuit
        return 0

    sweep_called = []

    def wrapper(a):
        sweep_called.append(a)
        return fake_sweep(a)

    monkeypatch.setattr("recon.cli_sweep.main", wrapper)
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--resume"])
    assert rc == 0
    assert len(sweep_called) == 1, "sweep should re-run when artifact is missing"


def test_no_resume_flag_overwrites_prior_run_json(tmp_path, monkeypatch, stub_tools_present):
    """Without --resume, prior run.json is overwritten with a fresh stages list."""
    import json
    outdir = tmp_path / "eng"
    outdir.mkdir()
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets", lambda r, t, i: ["10.0.0.1"])
    (outdir / "run.json").write_text(json.dumps({
        "engagement": "eng",
        "stages": [{"name": "sweep", "status": "ok", "elapsed_s": 1.0,
                    "modules_run": ["sweep"], "modules_skipped": [], "exit_code": 0}],
        "exit_code": None,
    }))
    (outdir / "live-hosts.txt").write_text("10.0.0.1\n")

    sweep_called = []
    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: sweep_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_enum.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").close() or 0))
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_smb.main", lambda a: 0)

    cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])  # no --resume
    assert len(sweep_called) == 1, "without --resume, sweep should run from scratch"


def test_orchestrator_in_scope_targets_proceed(tmp_path, monkeypatch, stub_tools_present):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets", lambda r, t, i: ["10.0.0.5"])
    scope = tmp_path / "scope.txt"
    scope.write_text("10.0.0.0/24\n")

    def fake_sweep(argv):
        idx = argv.index("-o")
        with open(argv[idx + 1], "w") as fh:
            fh.write("")  # empty → short-circuit
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", fake_sweep)
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/24",
                         "--scope-file", str(scope)])
    assert rc == 0  # sweep ran and short-circuited cleanly


def test_list_modules_prints_table_and_exits_zero(capsys):
    rc = cli_recon.main(["--list-modules"])
    assert rc == 0
    out = capsys.readouterr().out
    # spot-check a row per stage
    assert "sweep" in out
    assert "probe-ftp" in out
    assert "nuclei" in out
    assert "nessus" in out
    assert "smb-mass" in out
    # header
    assert "name" in out and "stage" in out and "default" in out


def test_dry_run_prints_plan_and_exits_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name, root=None: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    # nothing should actually run
    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: pytest.fail("sweep should not run in dry-run"))
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "planned stages" in out.lower()
    assert "enabled modules" in out.lower()
    # default-on probes should appear
    assert "probe-ftp" in out


def test_dry_run_shows_auto_skip_reasons(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name, root=None: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    monkeypatch.setattr("recon.common.DEFAULT_CONFIG_PATH",
                        str(tmp_path / "nope.ini"))
    import shutil
    original_which = shutil.which
    monkeypatch.setattr(
        shutil, "which",
        lambda name: None if name == "nxc" else original_which(name),
    )
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "nessus" in out
    assert "access_key" in out or "nessus.access_key" in out
    assert "smb-mass" in out
    assert "nxc" in out


def test_subparser_dispatches_sweep(monkeypatch):
    captured = {}

    def fake(argv):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", fake)
    rc = cli_recon.main(["sweep", "-r", "10.0.0.0/30", "-o", "/tmp/x"])
    assert rc == 0
    assert captured["argv"] == ["-r", "10.0.0.0/30", "-o", "/tmp/x"]


def test_subparser_dispatches_enum(monkeypatch):
    captured = {}

    def fake(argv):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr("recon.cli_enum.main", fake)
    rc = cli_recon.main(["enum", "-t", "10.0.0.1", "-o", "/tmp/e.xlsx"])
    assert rc == 0
    assert captured["argv"] == ["-t", "10.0.0.1", "-o", "/tmp/e.xlsx"]


def test_subparser_propagates_exit_code(monkeypatch):
    monkeypatch.setattr("recon.cli_nuclei.main", lambda argv: 7)
    rc = cli_recon.main(["nuclei", "-iL", "/tmp/h.txt"])
    assert rc == 7


def test_orchestrator_propagates_sweep_failure_with_empty_hosts(tmp_path, monkeypatch, stub_tools_present):
    """If sweep exits non-zero but writes an empty hosts file, overall exit must be 1 (not 0)."""
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name, root=None: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])

    enum_called = []
    nuclei_called = []
    nessus_called = []
    smb_called = []

    def fake_sweep(argv):
        # write an empty hosts file and return non-zero
        idx = argv.index("-o")
        with open(argv[idx + 1], "w") as fh:
            fh.write("")
        return 1

    monkeypatch.setattr("recon.cli_sweep.main", fake_sweep)
    monkeypatch.setattr("recon.cli_enum.main", lambda a: enum_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: nuclei_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: nessus_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_smb.main", lambda a: smb_called.append(a) or 0)

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])
    assert rc == 1, f"expected exit 1 when sweep fails, got {rc}"
    assert enum_called == [], "enum should not be invoked after sweep short-circuit"
    assert nuclei_called == [], "nuclei should not be invoked after sweep short-circuit"
    assert nessus_called == [], "nessus should not be invoked after sweep short-circuit"
    assert smb_called == [], "smb should not be invoked after sweep short-circuit"


def test_unknown_subcommand_falls_through_to_orchestrator(monkeypatch, tmp_path, stub_tools_present):
    """`pt-recon -n foo -r ...` (no subcommand) still works as before."""
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name, root=None: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").write("") or 0))
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])
    assert rc == 0  # sweep with empty result short-circuits


class _FakeStream:
    def __init__(self, is_tty):
        self._tty = is_tty
        self.buf = []

    def isatty(self):
        return self._tty

    def write(self, s):
        self.buf.append(s)

    def flush(self):
        pass

    def getvalue(self):
        return "".join(self.buf)


def test_meta_subcommands_dispatch(monkeypatch):
    status_calls, diff_calls = [], []
    monkeypatch.setattr("recon.cli_status.main",
                        lambda argv: status_calls.append(list(argv)) or 0)
    monkeypatch.setattr("recon.cli_diff.main",
                        lambda argv: diff_calls.append(list(argv)) or 0)
    assert cli_recon.main(["status", "acme"]) == 0
    assert status_calls == [["acme"]]
    assert cli_recon.main(["diff", "a", "b"]) == 0
    assert diff_calls == [["a", "b"]]


def test_banner_prints_when_stream_is_a_tty():
    fake = _FakeStream(is_tty=True)
    cli_recon._print_banner(stream=fake)
    out = fake.getvalue()
    # Tagline is plain text; the figlet header is ASCII art with no literal "pt-recon" substring.
    assert "pentest recon automation" in out
    assert "v" in out  # version line present


def test_banner_suppressed_when_stream_is_not_tty():
    fake = _FakeStream(is_tty=False)
    cli_recon._print_banner(stream=fake)
    assert fake.getvalue() == ""
