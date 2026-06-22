"""pt-smb: netexec SMB mass-recon to Excel.

Runs ``nxc smb`` against every resolved target, parses the host-discovery
lines into per-IP host/os/domain/signing/SMBv1 fields, then runs the SMB null-
session / guest probe for each host. Findings and signing/SMBv1 metadata are
merged into an :func:`recon.common.write_enum_workbook`-shaped workbook so the
output can be combined with ``pt-enum`` results.
"""
import re
import sys
import subprocess
import argparse

from recon import common, probes

_SMB_LINE = re.compile(
    r"SMB\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\d+\s+(?P<host>\S+)\s+\[\*\]\s+(?P<os>.*)"
)


def parse_nxc_smb(text):
    """Parse nxc smb host-discovery lines into {ip: {...}}."""
    out = {}
    for line in text.splitlines():
        m = _SMB_LINE.search(line)
        if not m:
            continue
        os_blob = m.group("os")
        def grab(key):
            mm = re.search(rf"{key}:([^)]+)\)", os_blob)
            return mm.group(1).strip() if mm else ""
        out[m.group("ip")] = {
            "host": m.group("host"),
            "os": re.split(r"\s+\(", os_blob)[0].strip(),
            "domain": grab("domain"),
            "signing": grab("signing"),
            "smbv1": grab("SMBv1"),
        }
    return out


def smb_rows(parsed, findings):
    """Build ENUM_COLUMNS-shaped rows from SMB host info + null/guest findings."""
    rows = []
    for ip, info in parsed.items():
        detail = f"signing:{info.get('signing')} SMBv1:{info.get('smbv1')}"
        null = findings.get(ip, "")
        finding = f"{null} | {detail}" if null else detail
        rows.append({
            "ip": ip,
            "port": 445,
            "state": "open",
            "http_title": info.get("host", ""),
            "service": info.get("os", ""),
            "finding": finding,
        })
    return rows


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-smb",
        description="SMB mass-recon via netexec (nxc) + null/guest probe → Excel.",
        epilog=(
            "examples:\n"
            "  pt-smb -iL live-hosts.txt -o smb.xlsx\n"
            "  pt-smb -r 10.0.0.0/24\n"
            "  pt-smb -t 10.0.0.5,10.0.0.6\n"
            "\n"
            "exit codes:\n"
            "  0  workbook written (may be empty if no SMB hosts responded)\n"
            "  2  invalid targets / missing input file\n"
            "  3  required external tool (nxc) not on PATH\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-r", "--range", dest="range",
                        help="CIDR (10.0.0.0/24) or dashed range (10.0.0.1-10)")
    parser.add_argument("-t", "--targets", dest="targets",
                        help="comma-separated IPs, e.g. 10.0.0.5,10.0.0.6")
    parser.add_argument("-iL", "--input-list", dest="infile",
                        help="file with one target per line")
    parser.add_argument("-o", "--output", dest="output", default="smb.xlsx",
                        help="output .xlsx path (default: smb.xlsx)")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-smb")
    try:
        common.require_tools(["nxc"])
    except RuntimeError as exc:
        log.error(str(exc))
        return 3
    try:
        hosts = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error(str(exc))
        return 2
    result = subprocess.run(
        ["nxc", "smb", *hosts], capture_output=True, text=True
    )
    parsed = parse_nxc_smb(result.stdout + result.stderr)
    findings = {}
    for ip in parsed:
        finding = probes.probe_smb(ip)
        if finding:
            findings[ip] = finding
    rows = smb_rows(parsed, findings)
    out = common.write_enum_workbook(rows, args.output)
    log.info("wrote %d SMB hosts to %s", len(rows), out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
