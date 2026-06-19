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
