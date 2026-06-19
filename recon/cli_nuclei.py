"""pt-nuclei: run nuclei against targets or enum output → JSONL."""
import os
import sys
import subprocess
import argparse

from recon import common, nuclei


def collect_targets(args):
    """Build the target URL/host list from enum output and/or -r/-t/-iL."""
    targets = []
    if args.from_enum:
        targets.extend(nuclei.targets_from_enum(args.from_enum))
    if args.range or args.targets or args.infile:
        targets.extend(common.parse_targets(args.range, args.targets, args.infile))
    if not targets:
        raise ValueError("no targets: pass --from-enum and/or -r/-t/-iL")
    seen, deduped = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            deduped.append(t)
    return deduped


def build_arg_parser():
    parser = argparse.ArgumentParser(prog="pt-nuclei", description="Run nuclei → JSONL.")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("--from-enum", dest="from_enum", help="enum .xlsx to derive web targets")
    parser.add_argument("-o", "--output", dest="output", default="nuclei.jsonl", help="JSONL output")
    parser.add_argument("--severity", default="medium,high,critical", help="severity filter")
    parser.add_argument("--rate-limit", dest="rate_limit", help="nuclei -rate-limit")
    parser.add_argument("--tags", help="nuclei -tags")
    parser.add_argument("--templates", help="nuclei -t templates path")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-nuclei")
    try:
        targets = collect_targets(args)
    except (ValueError, FileNotFoundError) as exc:
        log.error(str(exc))
        return 2

    nuclei_bin = nuclei.ensure_nuclei()
    targets_file = args.output + ".targets.txt"
    with open(targets_file, "w") as fh:
        fh.write("\n".join(targets) + "\n")

    extra = []
    if args.rate_limit:
        extra += ["-rate-limit", args.rate_limit]
    if args.tags:
        extra += ["-tags", args.tags]
    if args.templates:
        extra += ["-t", args.templates]
    cmd = nuclei.build_nuclei_cmd(targets_file, args.output, args.severity, extra, nuclei_bin=nuclei_bin)
    log.info("running: %s", " ".join(cmd))
    result = subprocess.run(cmd)
    log.info("nuclei exit=%s; output=%s", result.returncode, args.output)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
