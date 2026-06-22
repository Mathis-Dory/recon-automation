"""pt-recon: orchestrate sweep → enum → nuclei (+ optional nessus/smb).

Runs the recon stages in order, writing all artifacts under the engagement
directory returned by ``common.engagement_dir(name)``:

  * ``live-hosts.txt`` — output of the sweep stage; consumed by later stages.
  * ``enum.xlsx``      — output of the enum stage; consumed by nuclei.
  * ``nuclei.jsonl``   — output of the nuclei stage.
  * ``smb.xlsx``       — output of the optional smb stage.

If the sweep stage finds zero live hosts, the orchestrator exits 0 without
running later stages. Otherwise, the exit code is non-zero if any stage
returned non-zero, and 0 if every stage succeeded.
"""
import os
import sys
import argparse

from recon import common
from recon import cli_sweep, cli_enum, cli_nuclei, cli_nessus, cli_smb


def plan_stages(args):
    """Return ordered enabled stages."""
    stages = []
    if not args.no_sweep:
        stages.append("sweep")
    if not args.no_enum:
        stages.append("enum")
    if not args.no_nuclei:
        stages.append("nuclei")
    if args.nessus:
        stages.append("nessus")
    if args.smb:
        stages.append("smb")
    return stages


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-recon",
        description=(
            "Orchestrate the recon stages: sweep → enum → nuclei, "
            "with optional nessus and smb stages."
        ),
        epilog=(
            "examples:\n"
            "  pt-recon -n acme -r 10.0.0.0/24\n"
            "  pt-recon -n acme -iL targets.txt --nessus --smb\n"
            "  pt-recon -n acme -t 10.0.0.5,10.0.0.6 --no-nuclei\n"
            "\n"
            "stages:\n"
            "  sweep   nmap -sn ping sweep → live-hosts.txt\n"
            "  enum    masscan + nmap -sV + probes → enum.xlsx\n"
            "  nuclei  nuclei against enum web targets → nuclei.jsonl\n"
            "  nessus  (opt-in) launch a Nessus scan via REST API\n"
            "  smb     (opt-in) netexec SMB mass-recon → smb.xlsx\n"
            "\n"
            "exit codes:\n"
            "  0  every enabled stage succeeded (or sweep found no hosts)\n"
            "  1  at least one stage exited non-zero\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-n", "--name", required=True,
                        help="engagement name; artifacts go under the engagement directory")
    parser.add_argument("-r", "--range", dest="range",
                        help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)")
    parser.add_argument("-t", "--targets", dest="targets",
                        help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6")
    parser.add_argument("-iL", "--input-list", dest="infile",
                        help="file with one target per line")
    parser.add_argument("--no-sweep", action="store_true",
                        help="skip the sweep stage; later stages use -r/-t/-iL directly")
    parser.add_argument("--no-enum", action="store_true",
                        help="skip the enum stage; nuclei will fall back to -r/-t/-iL")
    parser.add_argument("--no-nuclei", action="store_true",
                        help="skip the nuclei stage")
    parser.add_argument("--nessus", action="store_true",
                        help="also launch a Nessus scan (requires config)")
    parser.add_argument("--smb", action="store_true",
                        help="also run SMB mass-recon → smb.xlsx")
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


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-recon")
    outdir = common.engagement_dir(args.name)
    stages = plan_stages(args)
    log.info("engagement '%s' → %s; stages: %s", args.name, outdir, ", ".join(stages))

    hosts_file = os.path.join(outdir, "live-hosts.txt")
    enum_xlsx = os.path.join(outdir, "enum.xlsx")

    failed = []
    for stage in stages:
        log.info("=== stage: %s ===", stage)
        if stage == "sweep":
            rc = cli_sweep.main(_target_args(args, None) + ["-o", hosts_file])
            if os.path.exists(hosts_file) and os.path.getsize(hosts_file) == 0:
                log.info("sweep found no live hosts; stopping")
                return 0
        elif stage == "enum":
            rc = cli_enum.main(_target_args(args, hosts_file) + ["-o", enum_xlsx])
        elif stage == "nuclei":
            nuclei_argv = ["-o", os.path.join(outdir, "nuclei.jsonl")]
            if os.path.exists(enum_xlsx):
                nuclei_argv += ["--from-enum", enum_xlsx]
            else:
                nuclei_argv += _target_args(args, hosts_file)
            rc = cli_nuclei.main(nuclei_argv)
        elif stage == "nessus":
            rc = cli_nessus.main(_target_args(args, hosts_file) + ["-n", args.name])
        elif stage == "smb":
            rc = cli_smb.main(_target_args(args, hosts_file) + ["-o", os.path.join(outdir, "smb.xlsx")])
        if rc:
            log.warning("stage %s exited %s", stage, rc)
            failed.append(stage)
    log.info("recon complete: %s", outdir)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
