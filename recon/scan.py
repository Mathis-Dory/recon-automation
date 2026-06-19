"""Wrappers around masscan and nmap with parseable output."""
import subprocess


def parse_masscan_list(text):
    """Parse masscan -oL output into a set of (ip, port)."""
    found = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open" and parts[1] == "tcp":
            found.add((parts[3], int(parts[2])))
    return found


def run_masscan(hosts, ports, rate=1000, runner=subprocess.run):
    """Run masscan and return open (ip, port) pairs. Raises RuntimeError on failure."""
    port_csv = ",".join(str(p) for p in ports)
    cmd = ["masscan", f"-p{port_csv}", "--rate", str(rate), "-oL", "-", *hosts]
    result = runner(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"masscan failed (exit {result.returncode}): {stderr or 'no stderr output'}. "
            "masscan needs root for raw sockets — re-run with sudo."
        )
    return parse_masscan_list(result.stdout)


def parse_nmap_grepable(text):
    """Parse nmap -oG output into {(ip, port): {state, service, version}}."""
    out = {}
    for line in text.splitlines():
        if not line.startswith("Host:") or "Ports:" not in line:
            continue
        ip = line.split()[1]
        ports_blob = line.split("Ports:", 1)[1]
        for entry in ports_blob.split(","):
            fields = entry.strip().split("/")
            if len(fields) < 5:
                continue
            port = int(fields[0])
            state = fields[1]
            service = fields[4]
            version = fields[6] if len(fields) > 6 else ""
            out[(ip, port)] = {"state": state, "service": service, "version": version}
    return out


def run_nmap_sv(ip_ports, runner=subprocess.run):
    """Run nmap -sV over discovered (ip, port) pairs; return parsed dict."""
    if not ip_ports:
        return {}
    ips = sorted({ip for ip, _ in ip_ports})
    ports = sorted({p for _, p in ip_ports})
    port_csv = ",".join(str(p) for p in ports)
    cmd = ["nmap", "-sV", "-Pn", "-p", port_csv, "-oG", "-", *ips]
    result = runner(cmd, capture_output=True, text=True)
    return parse_nmap_grepable(result.stdout)
