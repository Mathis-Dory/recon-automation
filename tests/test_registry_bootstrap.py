import recon  # noqa: F401 — ensures bootstrap import side effect runs
from recon.modules import _DEFAULT_REGISTRY, ConfigKey, Soft, Tool

_EXPECTED = {
    "sweep",
    "masscan",
    "nmap-sv",
    "probe-ftp",
    "probe-ssh",
    "probe-web-basic",
    "probe-smb",
    "nuclei",
    "nessus",
    "smb-mass",
}


def test_builtin_modules_registered():
    names = set(_DEFAULT_REGISTRY.names())
    assert _EXPECTED.issubset(names), f"missing: {_EXPECTED - names}"


def test_sweep_requires_nmap():
    assert Tool("nmap") in _DEFAULT_REGISTRY.get("sweep").requires


def test_masscan_not_togglable():
    assert _DEFAULT_REGISTRY.get("masscan").togglable is False
    assert Tool("masscan") in _DEFAULT_REGISTRY.get("masscan").requires


def test_nmap_sv_not_togglable():
    assert _DEFAULT_REGISTRY.get("nmap-sv").togglable is False


def test_probe_smb_has_soft_nxc():
    assert Soft(Tool("nxc")) in _DEFAULT_REGISTRY.get("probe-smb").requires


def test_nessus_requires_config_keys():
    reqs = _DEFAULT_REGISTRY.get("nessus").requires
    assert ConfigKey("nessus", "access_key") in reqs
    assert ConfigKey("nessus", "secret_key") in reqs


def test_smb_mass_requires_nxc_hard():
    assert Tool("nxc") in _DEFAULT_REGISTRY.get("smb-mass").requires


def test_nessus_and_smb_default_on():
    # Phase-1 flip: nessus and smb are now default-on (auto-skip if prereqs missing).
    assert _DEFAULT_REGISTRY.get("nessus").default_on is True
    assert _DEFAULT_REGISTRY.get("smb-mass").default_on is True


def test_all_module_stages_are_valid():
    from recon.modules import STAGES

    for m in _DEFAULT_REGISTRY.iter():
        assert m.stage in STAGES
