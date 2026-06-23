"""pt-enum: enumerate services, fingerprint web, export Excel.

Pipeline:
  1. Resolve targets from -r / -t / -iL.
  2. ``masscan`` at the requested rate to find open ports.
  3. ``nmap -sV`` to grab service/version banners for those open ports.
  4. Per-protocol probes (FTP anon, SSH/Telnet banner, HTTP title, SMB null/guest).
  5. Write an Excel workbook (one row per open ip:port) to ``--output``.

If masscan finds zero open ports the workbook is still written (empty) so the
orchestrator can chain reliably. Probes run in parallel via a thread pool sized
by ``--concurrency``; per-host SMB is pre-deduplicated so a single SMB call
covers both ports 139 and 445. Per-probe errors are recorded per row rather
than aborting the run; ``KeyboardInterrupt`` cancels in-flight probes cleanly.
"""
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from recon import common, scan, probes, enum_core

SMB_PORTS = {139, 445}


def _build_probe_jobs(open_ports, web_ports, fns, disabled):
    """Pre-dispatch planner: return a list of (key, field, callable) jobs.

    Each `(ip, port)` produces at most one job. SMB is deduplicated per IP
    (only the first SMB port encountered enqueues a job).
    """
    jobs = []
    smb_seen = set()
    for ip, port in open_ports:
        if port == 21 and "probe-ftp" not in disabled:
            jobs.append(((ip, port), "finding", lambda ip=ip, port=port: fns["ftp"](ip, port)))
        elif port in (22, 23) and "probe-ssh" not in disabled:
            jobs.append(((ip, port), "finding", lambda ip=ip, port=port: fns["banner"](ip, port)))
        elif port in web_ports and "probe-web-basic" not in disabled:
            jobs.append(((ip, port), "http_title", lambda ip=ip, port=port: fns["web"](ip, port)))
        elif port in SMB_PORTS and ip not in smb_seen and "probe-smb" not in disabled:
            smb_seen.add(ip)
            jobs.append(((ip, port), "finding", lambda ip=ip: fns["smb"](ip)))
    return jobs


def dispatch_probes(open_ports, web_ports, probe_fns=None, disabled_probes=None,
                    concurrency=32):
    """Route each open port to its probe; return per-(ip,port) results.

    `disabled_probes`, when given, is an iterable of registry probe names
    (`probe-ftp`, `probe-ssh`, `probe-web-basic`, `probe-smb`) that should
    be silently skipped — the corresponding row stays at the default empty
    finding/http_title.

    `concurrency` controls the thread pool size for probe execution. Probes
    are I/O-bound, so a value of 32 is a reasonable default; values <= 1
    fall back to sequential execution (useful for debugging).
    """
    fns = probe_fns or {
        "ftp": probes.probe_ftp_anon,
        "banner": probes.probe_banner,
        "web": probes.probe_web_title,
        "smb": probes.probe_smb,
    }
    disabled = set(disabled_probes or [])
    results = {key: {"http_title": "", "finding": ""} for key in open_ports}
    jobs = _build_probe_jobs(open_ports, web_ports, fns, disabled)
    if not jobs:
        return results

    max_workers = max(1, min(concurrency, len(jobs)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(call): (key, field) for key, field, call in jobs}
        try:
            for fut in as_completed(futures):
                key, field = futures[fut]
                try:
                    value = fut.result()
                except Exception as exc:  # never abort the whole run
                    results[key]["finding"] = f"probe error: {exc}"
                    continue
                if value:
                    results[key][field] = value
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            for key, _ in futures.values():
                if not results[key]["finding"] and not results[key]["http_title"]:
                    results[key]["finding"] = "INTERRUPTED"
            raise
    return results


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-enum",
        description=(
            "Service enumeration: masscan → nmap -sV → per-protocol probes → "
            "Excel report."
        ),
        epilog=(
            "examples:\n"
            "  pt-enum -iL live-hosts.txt -o enum.xlsx\n"
            "  pt-enum -r 10.0.0.0/24 --ports 22,80,443,8000-8100\n"
            "  pt-enum -t 10.0.0.5 --rate 5000 --web-ports 80,443,8080,8443\n"
            "\n"
            "exit codes:\n"
            "  0  workbook written (may be empty if no open ports were found)\n"
            "  1  masscan failed at runtime\n"
            "  2  invalid targets / missing input file\n"
            "  3  required external tool (masscan or nmap) not on PATH\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-r", "--range", dest="range",
                        help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)")
    parser.add_argument("-t", "--targets", dest="targets",
                        help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6")
    parser.add_argument("-iL", "--input-list", dest="infile",
                        help="file with one target per line")
    parser.add_argument("-o", "--output", dest="output", default="enum.xlsx",
                        help="output .xlsx path (default: enum.xlsx)")
    parser.add_argument("--ports", dest="ports",
                        help="ports to scan, e.g. 22,80,8000-8100 (default: built-in enum set)")
    parser.add_argument("--web-ports", dest="web_ports",
                        help="ports treated as HTTP for the web probe (default: built-in web set)")
    parser.add_argument("--rate", dest="rate", type=int, default=1000,
                        help="masscan packet rate in pps (default: 1000)")
    parser.add_argument("--concurrency", dest="concurrency", type=_positive_int, default=32,
                        help="probe thread pool size (default: 32; minimum 1)")
    parser.add_argument("--disable-probes", dest="disable_probes", default="",
                        help="comma-separated registry probe names to skip (advanced; "
                             "set automatically by pt-recon)")
    return parser


def _positive_int(s):
    """argparse type: int >= 1."""
    try:
        n = int(s)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"expected integer, got {s!r}")
    if n < 1:
        raise argparse.ArgumentTypeError(f"must be >= 1, got {n}")
    return n


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-enum")
    try:
        common.require_tools(["masscan", "nmap"])
    except RuntimeError as exc:
        log.error(str(exc))
        return 3
    try:
        hosts = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error(str(exc))
        return 2

    ports = common.parse_ports(args.ports) if args.ports else common.default_enum_ports()
    web_ports = common.parse_ports(args.web_ports) if args.web_ports else common.DEFAULT_WEB_PORTS

    log.info("masscan: %d hosts x %d ports (rate %d)", len(hosts), len(ports), args.rate)
    try:
        open_ports = scan.run_masscan(hosts, ports, rate=args.rate)
    except RuntimeError as exc:
        log.error(str(exc))
        return 1
    log.info("masscan found %d open ports", len(open_ports))
    if not open_ports:
        common.write_enum_workbook([], args.output)
        log.info("no open ports; wrote empty report to %s", args.output)
        return 0

    nmap_info = scan.run_nmap_sv(open_ports)
    disabled = {p.strip() for p in (args.disable_probes or "").split(",") if p.strip()}
    probe_results = dispatch_probes(open_ports, web_ports,
                                    disabled_probes=disabled,
                                    concurrency=args.concurrency)
    rows = enum_core.build_rows(open_ports, nmap_info, probe_results)
    out = common.write_enum_workbook(rows, args.output)
    anon = sum(1 for r in rows if any(m in r["finding"].upper() for m in ("ANON", "NULL", "GUEST")))
    log.info("wrote %d rows (%d anon/null) to %s", len(rows), anon, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
