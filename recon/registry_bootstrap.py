"""Side-effect-only module: registers built-in recon modules on import.

Imported by `recon/__init__.py` so that `from recon.modules import _DEFAULT_REGISTRY`
returns a registry populated with every module in the spec's phase-1 taxonomy.
"""

from recon.modules import _DEFAULT_REGISTRY, ConfigKey, Module, Soft, Tool

_BUILTINS = [
    Module(name="sweep", stage="sweep", help="nmap ping sweep", requires=[Tool("nmap")]),
    Module(
        name="masscan",
        stage="enum",
        help="masscan port discovery",
        requires=[Tool("masscan")],
        togglable=False,
    ),
    Module(
        name="nmap-sv",
        stage="enum",
        help="nmap service/version detection",
        requires=[Tool("nmap")],
        togglable=False,
    ),
    Module(name="probe-ftp", stage="enum", help="FTP anonymous login check"),
    Module(name="probe-ssh", stage="enum", help="SSH/Telnet banner grab"),
    Module(name="probe-web-basic", stage="enum", help="HTTP <title> fetch"),
    Module(
        name="probe-smb",
        stage="enum",
        help="SMB null/guest session check",
        requires=[Soft(Tool("nxc"))],
    ),
    Module(name="nuclei", stage="nuclei", help="nuclei template scan"),
    Module(
        name="nessus",
        stage="nessus",
        help="Nessus REST scan",
        requires=[ConfigKey("nessus", "access_key"), ConfigKey("nessus", "secret_key")],
        default_on=True,
    ),
    Module(
        name="smb-mass",
        stage="smb",
        help="netexec SMB mass-recon",
        requires=[Tool("nxc")],
        default_on=True,
    ),
]


for _m in _BUILTINS:
    _DEFAULT_REGISTRY.register(_m)
