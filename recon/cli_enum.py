"""pt-enum: enumerate services, fingerprint web, export Excel."""
import sys
import argparse

from recon import common, scan, probes, enum_core

SMB_PORTS = {139, 445}


def dispatch_probes(open_ports, web_ports, probe_fns=None):
    """Route each open port to its probe; return per-(ip,port) results."""
    fns = probe_fns or {
        "ftp": probes.probe_ftp_anon,
        "banner": probes.probe_banner,
        "web": probes.probe_web_title,
        "smb": probes.probe_smb,
    }
    results = {key: {"http_title": "", "finding": ""} for key in open_ports}
    smb_done = set()
    for ip, port in open_ports:
        try:
            if port == 21:
                finding = fns["ftp"](ip, port)
                if finding:
                    results[(ip, port)]["finding"] = finding
            elif port in (22, 23):
                results[(ip, port)]["finding"] = fns["banner"](ip, port)
            elif port in web_ports:
                results[(ip, port)]["http_title"] = fns["web"](ip, port)
            elif port in SMB_PORTS and ip not in smb_done:
                smb_done.add(ip)
                finding = fns["smb"](ip)
                if finding:
                    results[(ip, port)]["finding"] = finding
        except Exception as exc:  # never abort the whole run
            results[(ip, port)]["finding"] = f"probe error: {exc}"
    return results


def build_arg_parser():
    parser = argparse.ArgumentParser(prog="pt-enum", description="Service enumeration + web fingerprint to Excel.")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("-o", "--output", dest="output", default="enum.xlsx", help="output .xlsx path")
    parser.add_argument("--ports", dest="ports", help="custom port set, e.g. 22,80,8000-8100")
    parser.add_argument("--web-ports", dest="web_ports", help="override web ports")
    parser.add_argument("--rate", dest="rate", type=int, default=1000, help="masscan rate")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-enum")
    try:
        hosts = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error(str(exc))
        return 2

    ports = common.parse_ports(args.ports) if args.ports else common.default_enum_ports()
    web_ports = common.parse_ports(args.web_ports) if args.web_ports else common.DEFAULT_WEB_PORTS

    log.info("masscan: %d hosts x %d ports (rate %d)", len(hosts), len(ports), args.rate)
    open_ports = scan.run_masscan(hosts, ports, rate=args.rate)
    log.info("masscan found %d open ports", len(open_ports))
    if not open_ports:
        common.write_enum_workbook([], args.output)
        log.info("no open ports; wrote empty report to %s", args.output)
        return 0

    nmap_info = scan.run_nmap_sv(open_ports)
    probe_results = dispatch_probes(open_ports, web_ports)
    rows = enum_core.build_rows(open_ports, nmap_info, probe_results)
    out = common.write_enum_workbook(rows, args.output)
    anon = sum(1 for r in rows if any(m in r["finding"].upper() for m in ("ANON", "NULL", "GUEST")))
    log.info("wrote %d rows (%d anon/null) to %s", len(rows), anon, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
