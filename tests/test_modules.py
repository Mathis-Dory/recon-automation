import pytest
from recon.modules import Module, Tool, ConfigKey, Soft, STAGES


def test_stages_constant():
    assert STAGES == ["sweep", "enum", "feedback", "nuclei", "nessus", "smb", "report"]


def test_module_dataclass_defaults():
    m = Module(name="probe-ftp", stage="enum", help="FTP anon login check")
    assert m.name == "probe-ftp"
    assert m.stage == "enum"
    assert m.help == "FTP anon login check"
    assert m.requires == []
    assert m.default_on is True
    assert m.togglable is True
    assert m.run is None


def test_module_dataclass_explicit_fields():
    m = Module(
        name="nessus",
        stage="nessus",
        help="Nessus REST scan",
        requires=[ConfigKey("nessus", "access_key")],
        default_on=True,
        togglable=True,
    )
    assert m.requires == [ConfigKey("nessus", "access_key")]


def test_requirement_equality_and_hash():
    assert Tool("nmap") == Tool("nmap")
    assert Tool("nmap") != Tool("masscan")
    assert ConfigKey("nessus", "access_key") == ConfigKey("nessus", "access_key")
    assert Soft(Tool("showmount")) == Soft(Tool("showmount"))
    # Frozen dataclasses must be hashable for set membership.
    assert {Tool("nmap"), Tool("nmap")} == {Tool("nmap")}
