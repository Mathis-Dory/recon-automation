"""pt-nessus: launch a Nessus scan via the REST API."""
import sys
import time
import argparse

from recon import common
from recon.nessus import NessusClient


def build_arg_parser():
    parser = argparse.ArgumentParser(prog="pt-nessus", description="Launch a Nessus scan.")
    parser.add_argument("-n", "--name", required=True, help="scan name")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("--template", help="template name (default from config)")
    parser.add_argument("--folder", type=int, default=None, help="Nessus folder id")
    parser.add_argument("--wait", action="store_true", help="poll until completion")
    parser.add_argument("--no-launch", action="store_true", help="create but do not launch")
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
