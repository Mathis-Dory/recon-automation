"""pt-enum: enumerate services, fingerprint web, export Excel.

Pipeline:
  1. Resolve targets from -r / -t / -iL.
  2. ``masscan`` at the requested rate to find open ports.
  3. ``nmap -sV`` to grab service/version banners for those open ports.
  4. Per-protocol probes routed through PROBE_TABLE: ftp/ssh/web/smb (built-in)
     plus db/mail/tls-cert/web-deep/ldap/rdp/nfs/winrm/smb-depth (phase 3).
  5. Write an Excel workbook (one row per open ip:port) to ``--output``.

If masscan finds zero open ports the workbook is still written (empty) so the
orchestrator can chain reliably. Probes run in parallel via a thread pool sized
by ``--concurrency``. Multiple probes can target the same (ip, port); their
``finding`` values are concatenated with " | ". Per-host probes (probe-smb and
the nxc-depth probes) are deduplicated by IP. Per-probe errors are recorded
per row; ``KeyboardInterrupt`` cancels in-flight probes cleanly.
"""

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

from recon import common, enum_core, probes, scan

SMB_PORTS = {139, 445}


@dataclass(frozen=True)
class ProbeSpec:
    """How a probe attaches to the dispatch loop."""

    name: str  # registry name (e.g. "probe-ftp")
    ports: Optional[set]  # explicit port set, or None for "web_ports"
    field: str  # "finding" or "http_title"
    fn_key: str  # key into the probe_fns dict
    per_host: bool = False  # dedupe by IP (first matching port wins)
    append: bool = False  # join with " | " instead of overwriting

    def matches_port(self, port, web_ports):
        if self.ports is None:
            return port in web_ports
        return port in self.ports


# Probe dispatch table. Ports=None means "use the web_ports set passed in".
# `fn_key` is looked up in the `probe_fns` dict in dispatch_probes.
PROBE_TABLE = (
    ProbeSpec("probe-ftp", {21}, "finding", "ftp"),
    ProbeSpec("probe-ssh", {22, 23}, "finding", "banner"),
    ProbeSpec("probe-web-basic", None, "http_title", "web"),
    ProbeSpec("probe-smb", SMB_PORTS, "finding", "smb", per_host=True),
)


def _build_probe_jobs(open_ports, web_ports, fns, disabled, table):
    """Pre-dispatch planner: return a list of (key, field, append, callable) jobs."""
    jobs = []
    per_host_seen = {}  # probe_name -> set of IPs already enqueued
    for ip, port in open_ports:
        for spec in table:
            if spec.name in disabled or spec.fn_key not in fns:
                continue
            if not spec.matches_port(port, web_ports):
                continue
            if spec.per_host:
                seen = per_host_seen.setdefault(spec.name, set())
                if ip in seen:
                    continue
                seen.add(ip)
                jobs.append(((ip, port), spec.field, spec.append,
                             _bind(spec.fn_key, fns, ip, None)))
            else:
                jobs.append(((ip, port), spec.field, spec.append,
                             _bind(spec.fn_key, fns, ip, port)))
    return jobs


def _bind(fn_key, fns, ip, port) -> Callable:
    """Build a zero-arg thunk that calls fns[fn_key](ip) or fns[fn_key](ip, port)."""
    if port is None:
        return lambda: fns[fn_key](ip)
    return lambda: fns[fn_key](ip, port)


def dispatch_probes(open_ports, web_ports, probe_fns=None, disabled_probes=None, concurrency=32,
                    table=None):
    """Route each open port to its probe(s); return per-(ip,port) results.

    Multiple probes may target the same (ip, port). Probes with `append=True`
    concatenate to the row's `finding` with " | "; others overwrite.

    `disabled_probes`, when given, is an iterable of registry probe names to
    silently skip. `concurrency` sizes the thread pool (default 32; >=1).
    `table` is the PROBE_TABLE to consult — defaults to the module-level one.
    """
    fns = probe_fns or {
        "ftp": probes.probe_ftp_anon,
        "banner": probes.probe_banner,
        "web": probes.probe_web_title,
        "smb": probes.probe_smb,
    }
    disabled = set(disabled_probes or [])
    table = table if table is not None else PROBE_TABLE
    results = {key: {"http_title": "", "finding": ""} for key in open_ports}
    jobs = _build_probe_jobs(open_ports, web_ports, fns, disabled, table)
    if not jobs:
        return results

    max_workers = max(1, min(concurrency, len(jobs)))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(call): (key, field, append) for key, field, append, call in jobs}
        try:
            for fut in as_completed(futures):
                key, field, append = futures[fut]
                try:
                    value = fut.result()
                except Exception as exc:  # never abort the whole run
                    results[key]["finding"] = f"probe error: {exc}"
                    continue
                if not value:
                    continue
                if append and results[key][field]:
                    results[key][field] = results[key][field] + " | " + value
                else:
                    results[key][field] = value
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            for key, _, _ in futures.values():
                if not results[key]["finding"] and not results[key]["http_title"]:
                    results[key]["finding"] = "INTERRUPTED"
            raise
    return results


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-enum",
        description=(
            "Service enumeration: masscan → nmap -sV → per-protocol probes → Excel report."
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
        default="enum.xlsx",
        help="output .xlsx path (default: enum.xlsx)",
    )
    parser.add_argument(
        "--ports",
        dest="ports",
        help="ports to scan, e.g. 22,80,8000-8100 (default: built-in enum set)",
    )
    parser.add_argument(
        "--web-ports",
        dest="web_ports",
        help="ports treated as HTTP for the web probe (default: built-in web set)",
    )
    parser.add_argument(
        "--rate",
        dest="rate",
        type=int,
        default=1000,
        help="masscan packet rate in pps (default: 1000)",
    )
    parser.add_argument(
        "--concurrency",
        dest="concurrency",
        type=_positive_int,
        default=32,
        help="probe thread pool size (default: 32; minimum 1)",
    )
    parser.add_argument(
        "--disable-probes",
        dest="disable_probes",
        default="",
        help="comma-separated registry probe names to skip (advanced; "
        "set automatically by pt-recon)",
    )
    return parser


def _positive_int(s):
    """argparse type: int >= 1."""
    try:
        n = int(s)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"expected integer, got {s!r}") from exc
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
    probe_results = dispatch_probes(
        open_ports, web_ports, disabled_probes=disabled, concurrency=args.concurrency
    )
    rows = enum_core.build_rows(open_ports, nmap_info, probe_results)
    out = common.write_enum_workbook(rows, args.output)
    anon = sum(1 for r in rows if any(m in r["finding"].upper() for m in ("ANON", "NULL", "GUEST")))
    log.info("wrote %d rows (%d anon/null) to %s", len(rows), anon, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
