"""pt-smb: netexec SMB mass-recon to Excel."""
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
    parser = argparse.ArgumentParser(prog="pt-smb", description="netexec SMB mass-recon to Excel.")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    parser.add_argument("-o", "--output", dest="output", default="smb.xlsx", help="output .xlsx")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-smb")
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
