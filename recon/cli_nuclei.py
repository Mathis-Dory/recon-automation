"""pt-nuclei: run nuclei against targets or enum output → JSONL.

Builds a deduplicated target list from one or more sources (``--from-enum``
parses an enum workbook for web URLs; ``-r/-t/-iL`` add raw hosts), writes
the list to ``<output>.targets.txt`` next to the JSONL output, then invokes
the nuclei binary via :func:`recon.nuclei.ensure_nuclei`.

Severity, tag, template, and rate-limit flags are passed straight through to
nuclei. The exit code mirrors nuclei's own exit code, so a non-zero result
means nuclei itself reported an error.
"""
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
    parser = argparse.ArgumentParser(
        prog="pt-nuclei",
        description="Run nuclei against an enum workbook and/or raw targets, writing JSONL.",
        epilog=(
            "examples:\n"
            "  pt-nuclei --from-enum enum.xlsx -o nuclei.jsonl\n"
            "  pt-nuclei -iL live-hosts.txt --severity high,critical\n"
            "  pt-nuclei -r 10.0.0.0/24 --tags cve,exposure --rate-limit 50\n"
            "\n"
            "exit codes:\n"
            "  0  nuclei completed successfully\n"
            "  2  no targets supplied (--from-enum and/or -r/-t/-iL required)\n"
            "  *  any other code is propagated from nuclei itself\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-r", "--range", dest="range",
                        help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)")
    parser.add_argument("-t", "--targets", dest="targets",
                        help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6")
    parser.add_argument("-iL", "--input-list", dest="infile",
                        help="file with one target per line")
    parser.add_argument("--from-enum", dest="from_enum",
                        help="enum .xlsx to derive web targets from (may be combined with -r/-t/-iL)")
    parser.add_argument("-o", "--output", dest="output", default="nuclei.jsonl",
                        help="JSONL output path (default: nuclei.jsonl)")
    parser.add_argument("--severity", default="medium,high,critical",
                        help="nuclei -severity filter (default: medium,high,critical)")
    parser.add_argument("--rate-limit", dest="rate_limit",
                        help="passed to nuclei -rate-limit (requests/sec)")
    parser.add_argument("--tags",
                        help="passed to nuclei -tags (comma-separated)")
    parser.add_argument("--templates",
                        help="passed to nuclei -t (templates path or pattern)")
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
