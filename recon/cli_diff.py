"""pt-recon diff: compare two engagements' results."""
import argparse
import json
import os
import sys

from recon import common


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-recon diff",
        description="Compare two engagements: new hosts, new services, new nuclei findings.",
    )
    parser.add_argument("a", help="baseline engagement name")
    parser.add_argument("b", help="newer engagement name to diff against the baseline")
    parser.add_argument("--outdir", dest="outdir",
                        help="engagement output root (overrides $PT_RECON_OUTPUT and default)")
    return parser


def _read_hosts(outdir):
    path = os.path.join(outdir, "live-hosts.txt")
    if not os.path.exists(path):
        return set()
    with open(path) as fh:
        return {ln.strip() for ln in fh if ln.strip()}


def _read_services(outdir):
    """Return {(ip, port)} from enum.xlsx if present."""
    path = os.path.join(outdir, "enum.xlsx")
    if not os.path.exists(path):
        return set()
    import openpyxl
    wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
    ws = wb.active
    services = set()
    rows = ws.iter_rows(values_only=True)
    header = next(rows, None)
    if not header:
        return services
    try:
        ip_idx = header.index("ip")
        port_idx = header.index("port")
    except ValueError:
        return services
    for row in rows:
        if row[ip_idx] and row[port_idx] is not None:
            services.add((str(row[ip_idx]), int(row[port_idx])))
    return services


def _read_nuclei(outdir):
    """Return list of (host, template_id, severity, matched_at) from nuclei.jsonl."""
    path = os.path.join(outdir, "nuclei.jsonl")
    if not os.path.exists(path):
        return []
    findings = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            findings.append((
                obj.get("host", ""),
                obj.get("template-id") or obj.get("templateID") or "",
                (obj.get("info") or {}).get("severity", ""),
                obj.get("matched-at") or obj.get("matchedAt") or "",
            ))
    return findings


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    outdir_a = common.engagement_dir(args.a, root=args.outdir)
    outdir_b = common.engagement_dir(args.b, root=args.outdir)

    if not os.path.exists(os.path.join(outdir_a, "run.json")):
        print(f"warning: {args.a} has no run.json", file=sys.stderr)
    if not os.path.exists(os.path.join(outdir_b, "run.json")):
        print(f"warning: {args.b} has no run.json", file=sys.stderr)

    hosts_a, hosts_b = _read_hosts(outdir_a), _read_hosts(outdir_b)
    new_hosts = sorted(hosts_b - hosts_a)
    dropped_hosts = sorted(hosts_a - hosts_b)

    services_a, services_b = _read_services(outdir_a), _read_services(outdir_b)
    new_services = sorted(services_b - services_a)

    nuclei_a, nuclei_b = _read_nuclei(outdir_a), _read_nuclei(outdir_b)
    keys_a = {(host, tpl) for host, tpl, _, _ in nuclei_a}
    new_nuclei = [f for f in nuclei_b if (f[0], f[1]) not in keys_a]

    print(f"diff: {args.a} -> {args.b}")
    print()
    print(f"hosts: {len(hosts_a)} → {len(hosts_b)}  (+{len(new_hosts)} new, -{len(dropped_hosts)} gone)")
    if new_hosts:
        print("  new hosts:")
        for ip in new_hosts:
            print(f"    {ip}")
    if dropped_hosts:
        print("  no longer responding:")
        for ip in dropped_hosts:
            print(f"    {ip}")
    print()
    print(f"services: {len(services_a)} → {len(services_b)}  (+{len(new_services)} new)")
    if new_services:
        print("  new (ip, port):")
        for ip, port in new_services:
            print(f"    {ip}:{port}")
    print()
    print(f"nuclei findings: {len(nuclei_a)} → {len(nuclei_b)}  (+{len(new_nuclei)} new)")
    if new_nuclei:
        print("  new findings:")
        for host, tpl, sev, matched in new_nuclei:
            print(f"    [{sev}] {tpl} @ {host} ({matched})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
