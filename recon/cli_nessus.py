"""pt-nessus: launch a Nessus scan via the REST API.

Reads Nessus URL and API keys from ``~/.config/pentest-recon/config.ini``
(see :func:`recon.common.load_nessus_config`), resolves the template, creates
the scan against the resolved target list, and (unless ``--no-launch``) starts
it. With ``--wait`` the command polls the scan status every 15 seconds and
returns once it reaches a terminal state (completed/canceled/aborted).

The scan UI URL is logged on creation so it can be opened from a terminal.
"""

import argparse
import sys
import time

from recon import common
from recon.nessus import NessusClient


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-nessus",
        description="Create and (by default) launch a Nessus scan via the REST API.",
        epilog=(
            "examples:\n"
            "  pt-nessus -n acme -iL live-hosts.txt\n"
            "  pt-nessus -n acme -r 10.0.0.0/24 --template 'Basic Network Scan' --wait\n"
            "  pt-nessus -n acme -t 10.0.0.5 --no-launch\n"
            "\n"
            "config:\n"
            "  ~/.config/pentest-recon/config.ini (mode 0600) with url, access_key,\n"
            "  secret_key, and optional template.\n"
            "\n"
            "exit codes:\n"
            "  0  scan created (and launched / completed if requested)\n"
            "  1  Nessus API error\n"
            "  2  config file missing or invalid\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-n", "--name", required=True, help="scan name as it will appear in the Nessus UI"
    )
    parser.add_argument(
        "-r", "--range", dest="range", help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)"
    )
    parser.add_argument(
        "-t", "--targets", dest="targets", help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6"
    )
    parser.add_argument("-iL", "--input-list", dest="infile", help="file with one target per line")
    parser.add_argument(
        "--template", help="Nessus template name (default: from config, else 'Basic Network Scan')"
    )
    parser.add_argument(
        "--folder", type=int, default=None, help="numeric Nessus folder id to place the scan in"
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="poll scan status every 15s until it reaches a terminal state",
    )
    parser.add_argument(
        "--no-launch", action="store_true", help="create the scan but do not start it"
    )
    return parser


def run(args, config, client):
    log = common.get_logger("pt-nessus")
    hosts = common.parse_targets(args.range, args.targets, args.infile)
    targets = ",".join(hosts)
    template = args.template or config.get("template", "Basic Network Scan")
    uuid = client.find_template(template)
    scan_id = client.create_scan(args.name, targets, uuid, folder_id=args.folder)
    ui = f"{config['url']}/#/scans/reports/{scan_id}"
    log.info("created scan id=%s (%s)", scan_id, ui)
    if args.no_launch:
        log.info("created without launch (--no-launch)")
        return 0
    client.launch(scan_id)
    log.info("launched scan id=%s", scan_id)
    if args.wait:
        while True:
            st = client.status(scan_id)
            log.info("status: %s", st)
            if st in ("completed", "canceled", "aborted"):
                break
            time.sleep(15)
    return 0


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-nessus")
    try:
        config = common.load_nessus_config()
    except (FileNotFoundError, ValueError) as exc:
        log.error("config error: %s", exc)
        return 2
    client = NessusClient(config["url"], config["access_key"], config["secret_key"])
    try:
        return run(args, config, client)
    except Exception as exc:
        log.error("nessus error: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
