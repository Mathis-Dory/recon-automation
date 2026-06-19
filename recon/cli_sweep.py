"""pt-sweep: live-host discovery → hosts file."""
import sys
import subprocess
import argparse

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
    parser = argparse.ArgumentParser(prog="pt-sweep", description="Live-host discovery.")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("-o", "--output", dest="output", default="live-hosts.txt", help="output file")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-sweep")
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
