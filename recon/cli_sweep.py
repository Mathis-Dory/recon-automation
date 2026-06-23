"""pt-sweep: live-host discovery → hosts file.

Runs ``nmap -sn`` against the supplied targets and writes the IPs whose nmap
status is ``Up`` to ``--output`` (default ``live-hosts.txt``), one per line.
Targets come from ``-r`` (CIDR or dashed range), ``-t`` (comma-separated IPs),
or ``-iL`` (file with one IP per line); the flags may be combined.

If no hosts are up the output file is created empty (no trailing newline) so
downstream tools can detect this with a size check.
"""

import argparse
import subprocess
import sys

from recon import common


def parse_nmap_up_hosts(text):
    """Return IPs marked 'Status: Up' from nmap -sn -oG output."""
    hosts = []
    for line in text.splitlines():
        if line.startswith("Host:") and "Status: Up" in line:
            hosts.append(line.split()[1])
    return hosts


def run_sweep(hosts, runner=subprocess.run):
    """Run an nmap ping sweep; return live IPs."""
    cmd = ["nmap", "-sn", "-oG", "-", *hosts]
    result = runner(cmd, capture_output=True, text=True)
    return parse_nmap_up_hosts(result.stdout)


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-sweep",
        description="Live-host discovery via nmap -sn → newline-delimited hosts file.",
        epilog=(
            "examples:\n"
            "  pt-sweep -r 10.0.0.0/24 -o live.txt\n"
            "  pt-sweep -iL scope.txt\n"
            "  pt-sweep -t 10.0.0.5,10.0.0.6,10.0.0.7\n"
            "\n"
            "exit codes:\n"
            "  0  sweep ran (output written, possibly empty)\n"
            "  2  invalid targets / missing input file\n"
            "  3  required external tool (nmap) not on PATH\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-r", "--range", dest="range", help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)"
    )
    parser.add_argument(
        "-t", "--targets", dest="targets", help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6"
    )
    parser.add_argument("-iL", "--input-list", dest="infile", help="file with one target per line")
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        default="live-hosts.txt",
        help="output path for live hosts (default: live-hosts.txt)",
    )
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-sweep")
    try:
        common.require_tools(["nmap"])
    except RuntimeError as exc:
        log.error(str(exc))
        return 3
    try:
        hosts = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error(str(exc))
        return 2
    live = run_sweep(hosts)
    with open(args.output, "w") as fh:
        fh.write("\n".join(live) + ("\n" if live else ""))
    log.info("%d/%d hosts up; wrote %s", len(live), len(hosts), args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())
