"""pt-recon: orchestrate sweep → enum → nuclei (+ optional nessus/smb)."""
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
    parser = argparse.ArgumentParser(prog="pt-recon", description="Recon orchestrator.")
    parser.add_argument("-n", "--name", required=True, help="engagement name")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("--no-sweep", action="store_true")
    parser.add_argument("--no-enum", action="store_true")
    parser.add_argument("--no-nuclei", action="store_true")
    parser.add_argument("--nessus", action="store_true", help="also launch a Nessus scan")
    parser.add_argument("--smb", action="store_true", help="also run SMB mass-recon")
    return parser


def _target_args(args, hosts_file):
    """Prefer the swept hosts file if present, else pass through -r/-t/-iL."""
    if hosts_file and os.path.exists(hosts_file):
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

    for stage in stages:
        log.info("=== stage: %s ===", stage)
        if stage == "sweep":
            cli_sweep.main(_target_args(args, None) + ["-o", hosts_file])
        elif stage == "enum":
            cli_enum.main(_target_args(args, hosts_file) + ["-o", enum_xlsx])
        elif stage == "nuclei":
            nuclei_argv = ["-o", os.path.join(outdir, "nuclei.jsonl")]
            if os.path.exists(enum_xlsx):
                nuclei_argv += ["--from-enum", enum_xlsx]
            else:
                nuclei_argv += _target_args(args, hosts_file)
            cli_nuclei.main(nuclei_argv)
        elif stage == "nessus":
            cli_nessus.main(_target_args(args, hosts_file) + ["-n", args.name])
        elif stage == "smb":
            cli_smb.main(_target_args(args, hosts_file) + ["-o", os.path.join(outdir, "smb.xlsx")])
    log.info("recon complete: %s", outdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
