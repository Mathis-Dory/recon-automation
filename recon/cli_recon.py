"""pt-recon: orchestrate registered modules across recon stages.

Default invocation (no subcommand) runs every enabled stage in order
(sweep → enum → nuclei → nessus → smb), with auto-skip on missing
prerequisites per the umbrella design spec §9.1.
"""
import os
import sys
import time
import argparse
import logging

from recon import common
from recon import cli_sweep, cli_enum, cli_nuclei, cli_nessus, cli_smb
from recon.modules import (
    _DEFAULT_REGISTRY,
    register_argparse_flags,
    evaluate_enabled,
    check_requirements,
    Skip,
)
from recon.manifest import RunManifest, attach_run_log
from recon import __version__


# Stages this phase actually executes (feedback and report land in later phases).
_PHASE_1_STAGES = ["sweep", "enum", "nuclei", "nessus", "smb"]

_BANNER = r"""
        _
  _ __ | |_      _ __ ___  ___ ___  _ __
 | '_ \| __|____| '__/ _ \/ __/ _ \| '_ \
 | |_) | ||_____| | |  __/ (_| (_) | | | |
 | .__/ \__|    |_|  \___|\___\___/|_| |_|
 |_|
                pentest recon automation
                       v{version}
"""


def _print_banner(stream=None):
    """Print the banner to `stream` (default stderr) when it's a TTY.

    No-op for pipes, redirects, CI, and pytest's capsys — so test/script output
    stays pristine. Injectable for tests.
    """
    stream = stream if stream is not None else sys.stderr
    if not stream.isatty():
        return
    stream.write(_BANNER.format(version=__version__))
    stream.flush()

# Map stage → callable main(argv) -> int. Subparser dispatch in Task 10 reuses this.
# Lambdas dereference the module attribute at call time so monkeypatching works in tests.
_STAGE_MAIN = {
    "sweep": lambda a: cli_sweep.main(a),
    "enum": lambda a: cli_enum.main(a),
    "nuclei": lambda a: cli_nuclei.main(a),
    "nessus": lambda a: cli_nessus.main(a),
    "smb": lambda a: cli_smb.main(a),
}


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-recon",
        description="Recon orchestrator (registry-driven).",
        epilog=(
            "subcommands (ad-hoc per-stage runs):\n"
            "  pt-recon sweep  ARGS    run only the sweep stage\n"
            "  pt-recon enum   ARGS    run only the enum stage\n"
            "  pt-recon nuclei ARGS    run only the nuclei stage\n"
            "  pt-recon nessus ARGS    run only the nessus stage\n"
            "  pt-recon smb    ARGS    run only the smb stage\n"
            "\n"
            "exit codes:\n"
            "  0   every attempted stage succeeded\n"
            "  1   ≥1 stage exited non-zero\n"
            "  2   argument / target / config error\n"
            "  130 interrupted (Ctrl-C)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-n", "--name", help="engagement name (required unless --list-modules)")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("--outdir", dest="outdir",
                        help="engagement output root (default: $PT_RECON_OUTPUT or ~/tools/recon/output)")
    parser.add_argument("--scope-file", dest="scope_file",
                        help="allow-list of CIDRs (one per line; # comments); abort if any target is outside")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="print planned stages, enabled modules, and skip reasons; do not run anything")
    parser.add_argument("--list-modules", dest="list_modules", action="store_true",
                        help="print the registry as a table and exit")
    register_argparse_flags(parser, _DEFAULT_REGISTRY)
    return parser


def _target_args(args, hosts_file):
    """Prefer the swept hosts file if present and non-empty, else pass through -r/-t/-iL."""
    if hosts_file and os.path.exists(hosts_file) and os.path.getsize(hosts_file) > 0:
        return ["-iL", hosts_file]
    passthrough = []
    if args.range:
        passthrough += ["-r", args.range]
    if args.targets:
        passthrough += ["-t", args.targets]
    if args.infile:
        passthrough += ["-iL", args.infile]
    return passthrough


def _enum_argv(args, hosts_file, enum_xlsx, enabled_modules):
    argv = _target_args(args, hosts_file) + ["-o", enum_xlsx]
    # Pass probes that were disabled by the operator so cli_enum can skip them.
    all_probe_names = {m.name for m in _DEFAULT_REGISTRY.iter(stage="enum")
                       if m.name.startswith("probe-")}
    disabled = sorted(all_probe_names - enabled_modules)
    if disabled:
        argv += ["--disable-probes", ",".join(disabled)]
    return argv


def _build_stage_argv(stage, args, hosts_file, enum_xlsx, outdir, enabled_modules):
    if stage == "sweep":
        return _target_args(args, None) + ["-o", hosts_file]
    if stage == "enum":
        return _enum_argv(args, hosts_file, enum_xlsx, enabled_modules)
    if stage == "nuclei":
        argv = ["-o", os.path.join(outdir, "nuclei.jsonl")]
        if os.path.exists(enum_xlsx):
            argv += ["--from-enum", enum_xlsx]
        else:
            argv += _target_args(args, hosts_file)
        return argv
    if stage == "nessus":
        return _target_args(args, hosts_file) + ["-n", args.name]
    if stage == "smb":
        return _target_args(args, hosts_file) + ["-o", os.path.join(outdir, "smb.xlsx")]
    raise ValueError(f"unknown stage: {stage}")


def _render_req(req):
    from recon.modules import Tool, ConfigKey, Soft
    if isinstance(req, Tool):
        return f"tool:{req.name}"
    if isinstance(req, ConfigKey):
        return f"config:{req.section}.{req.key}"
    if isinstance(req, Soft):
        return f"soft({_render_req(req.inner)})"
    return repr(req)


def _print_module_table():
    cols = ("name", "stage", "default", "togglable", "requires")
    rows = [cols]
    for m in _DEFAULT_REGISTRY.iter():
        reqs = ", ".join(_render_req(r) for r in m.requires) or "—"
        rows.append((
            m.name, m.stage,
            "on" if m.default_on else "off",
            "yes" if m.togglable else "no",
            reqs,
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(cols))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    for i, row in enumerate(rows):
        print(fmt.format(*row))
        if i == 0:
            print("  ".join("-" * w for w in widths))


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in _STAGE_MAIN:
        stage = argv[0]
        return _STAGE_MAIN[stage](argv[1:])
    args = build_arg_parser().parse_args(argv)
    _print_banner()

    if args.list_modules:
        _print_module_table()
        return 0
    if not args.name:
        print("error: -n/--name is required (unless --list-modules is used)",
              file=sys.stderr)
        return 2

    log = common.get_logger("pt-recon")

    outdir = common.engagement_dir(args.name, root=args.outdir)
    hosts_file = os.path.join(outdir, "live-hosts.txt")
    enum_xlsx = os.path.join(outdir, "enum.xlsx")

    # Resolve target list for the manifest.
    try:
        targets = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error("target parse error: %s", exc)
        return 2

    # Enforce scope file before any stage runs.
    if args.scope_file:
        try:
            scope_nets = common.load_scope(args.scope_file)
        except (ValueError, FileNotFoundError) as exc:
            log.error("scope file error: %s", exc)
            return 2
        out_of_scope = [ip for ip in targets if not common.targets_in_scope(ip, scope_nets)]
        if out_of_scope:
            shown = ", ".join(out_of_scope[:5])
            extra = "" if len(out_of_scope) <= 5 else f" (+{len(out_of_scope) - 5} more)"
            log.error("targets out of scope: %s%s", shown, extra)
            return 2

    targets_source = " ".join(
        flag for flag in (
            f"-r {args.range}" if args.range else None,
            f"-t {args.targets}" if args.targets else None,
            f"-iL {args.infile}" if args.infile else None,
        ) if flag
    )

    enabled_global = evaluate_enabled(args, _DEFAULT_REGISTRY)

    if args.dry_run:
        print("planned stages:")
        for stage in _PHASE_1_STAGES:
            stage_mods = [m for m in _DEFAULT_REGISTRY.iter(stage=stage)
                          if m.name in enabled_global]
            if not stage_mods:
                print(f"  {stage}: (skipped — disabled)")
                continue
            runnable, skip_reasons = [], []
            for m in stage_mods:
                check = check_requirements(m)
                if isinstance(check, Skip):
                    skip_reasons.append((m.name, check.reason))
                else:
                    runnable.append(m.name)
            if runnable:
                print(f"  {stage}: would run {', '.join(runnable)}")
            for n, r in skip_reasons:
                print(f"    skip {n}: {r}")
            if not runnable and not skip_reasons:
                print(f"  {stage}: (skipped — disabled)")
        print()
        print("enabled modules:", ", ".join(sorted(enabled_global)) or "(none)")
        return 0

    manifest = RunManifest(args.name, outdir, len(targets), targets_source)
    log_handler = attach_run_log(os.path.join(outdir, "run.log"))

    log.info("engagement '%s' → %s", args.name, outdir)
    log.info("enabled modules: %s", ", ".join(sorted(enabled_global)) or "(none)")

    overall_rc = 0
    try:
        for stage in _PHASE_1_STAGES:
            stage_modules = [m for m in _DEFAULT_REGISTRY.iter(stage=stage)
                             if m.name in enabled_global]
            modules_skipped = []

            if not stage_modules:
                log.info("=== stage: %s (skipped — disabled) ===", stage)
                manifest.add_stage(stage, "skipped", 0.0, [], [], None)
                continue

            # Auto-skip modules whose prereqs fail.
            runnable = []
            for m in stage_modules:
                check = check_requirements(m)
                if isinstance(check, Skip):
                    log.warning("%s skipped: %s", m.name, check.reason)
                    modules_skipped.append({"name": m.name, "reason": check.reason})
                else:
                    runnable.append(m)

            if not runnable:
                log.info("=== stage: %s (skipped — all modules unmet) ===", stage)
                manifest.add_stage(stage, "skipped", 0.0, [], modules_skipped, None)
                continue

            log.info("=== stage: %s ===", stage)
            stage_argv = _build_stage_argv(
                stage, args, hosts_file, enum_xlsx, outdir, enabled_global,
            )
            start = time.monotonic()
            rc = _STAGE_MAIN[stage](stage_argv)
            elapsed = time.monotonic() - start

            status = "ok" if rc == 0 else "error"
            if rc:
                overall_rc = 1
                log.warning("stage %s exited %s", stage, rc)
            manifest.add_stage(
                stage, status, elapsed,
                modules_run=[m.name for m in runnable],
                modules_skipped=modules_skipped,
                exit_code=rc,
            )

            # Sweep short-circuit: zero live hosts → bail out cleanly.
            if stage == "sweep" and os.path.exists(hosts_file) and \
                    os.path.getsize(hosts_file) == 0:
                log.info("sweep found no live hosts; stopping")
                manifest.set_exit_code(overall_rc)
                return overall_rc

        manifest.set_exit_code(overall_rc)
        log.info("recon complete: %s (exit %s)", outdir, overall_rc)
        return overall_rc
    except KeyboardInterrupt:
        log.warning("interrupted")
        manifest.set_exit_code(130)
        return 130
    finally:
        # Detach log handler so subsequent runs don't accumulate file handles.
        for name in list(logging.Logger.manager.loggerDict):
            if name.startswith("pt-"):
                logging.getLogger(name).removeHandler(log_handler)
        log_handler.close()


if __name__ == "__main__":
    sys.exit(main())
