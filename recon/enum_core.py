"""Assemble enum rows from scan results and probe outputs."""

import ipaddress


def is_web_port(port, web_ports):
    return port in web_ports


def build_rows(open_ports, nmap_info, probe_results):
    """Combine scan + probe data into sorted row dicts."""
    rows = []
    for ip, port in open_ports:
        info = nmap_info.get((ip, port), {})
        probe = probe_results.get((ip, port), {})
        service = info.get("service", "")
        version = info.get("version", "")
        service_text = f"{service} {version}".strip() if version else service
        rows.append(
            {
                "ip": ip,
                "port": port,
                "state": info.get("state", "open"),
                "http_title": probe.get("http_title", ""),
                "service": service_text,
                "finding": probe.get("finding", ""),
            }
        )
    rows.sort(key=lambda r: (ipaddress.ip_address(r["ip"]), r["port"]))
    return rows
