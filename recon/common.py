"""Shared helpers: target/port parsing, config, Excel/JSON, output, logging."""

import ipaddress


def expand_range(spec):
    """Expand one target token into a list of IP strings."""
    spec = spec.strip()
    if "/" in spec:
        net = ipaddress.ip_network(spec, strict=False)
        return [str(h) for h in net.hosts()]
    if "-" in spec:
        left, right = spec.split("-", 1)
        left = left.strip()
        start = ipaddress.ip_address(left)
        if "." in right:
            end = ipaddress.ip_address(right.strip())
        else:
            prefix = left.rsplit(".", 1)[0]
            end = ipaddress.ip_address(f"{prefix}.{right.strip()}")
        if int(end) < int(start):
            raise ValueError(f"range end before start: {spec}")
        return [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
    return [str(ipaddress.ip_address(spec))]


def parse_targets(range_=None, targets=None, infile=None):
    """Merge -r / -t / -iL inputs into a sorted, de-duplicated IP list."""
    tokens = []
    if range_:
        tokens.append(range_)
    if targets:
        tokens.extend(t for t in targets.split(",") if t.strip())
    if infile:
        with open(infile) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    tokens.append(line)
    hosts = set()
    for tok in tokens:
        hosts.update(expand_range(tok))
    if not hosts:
        raise ValueError("no targets resolved from -r/-t/-iL")
    return sorted(hosts, key=lambda ip: ipaddress.ip_address(ip))


DEFAULT_WEB_PORTS = [
    80, 81, 88, 443, 8080, 8081, 8443, 8888,
    9000, 9001, 9090, 8000, 8008, 8090, 7001, 10000,
]

SERVICE_PORTS = {
    "ftp": [21],
    "ssh": [22],
    "telnet": [23],
    "smb": [139, 445],
}


def parse_ports(spec):
    """Parse '80,443,8000-8002' into a sorted, de-duplicated int list."""
    ports = set()
    for tok in spec.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if "-" in tok:
            a, b = tok.split("-", 1)
            lo, hi = int(a), int(b)
            rng = range(lo, hi + 1)
        else:
            rng = [int(tok)]
        for p in rng:
            if not 1 <= p <= 65535:
                raise ValueError(f"port out of range: {p}")
            ports.add(p)
    if not ports:
        raise ValueError("no ports parsed")
    return sorted(ports)


def default_enum_ports():
    """Sorted union of all service ports and the default web ports."""
    ports = set(DEFAULT_WEB_PORTS)
    for plist in SERVICE_PORTS.values():
        ports.update(plist)
    return sorted(ports)
