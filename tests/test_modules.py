import pytest
from recon.modules import Module, Tool, ConfigKey, Soft, STAGES, Registry, module


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


def test_registry_register_and_get():
    r = Registry()
    m = Module(name="sweep", stage="sweep", help="ping sweep")
    r.register(m)
    assert r.get("sweep") is m
    assert r.has("sweep") is True


def test_registry_duplicate_name_raises():
    r = Registry()
    r.register(Module(name="sweep", stage="sweep", help="x"))
    with pytest.raises(ValueError, match="duplicate"):
        r.register(Module(name="sweep", stage="sweep", help="y"))


def test_registry_unknown_stage_raises():
    r = Registry()
    with pytest.raises(ValueError, match="unknown stage"):
        r.register(Module(name="x", stage="bogus", help="x"))


def test_registry_iter_filters_by_stage():
    r = Registry()
    r.register(Module(name="probe-ftp", stage="enum", help="ftp"))
    r.register(Module(name="probe-ssh", stage="enum", help="ssh"))
    r.register(Module(name="nuclei", stage="nuclei", help="nuclei"))
    enum_names = [m.name for m in r.iter(stage="enum")]
    assert enum_names == ["probe-ftp", "probe-ssh"]
    all_names = [m.name for m in r.iter()]
    assert set(all_names) == {"probe-ftp", "probe-ssh", "nuclei"}


def test_module_decorator_registers_and_stores_run():
    r = Registry()

    @module(name="x", stage="sweep", help="x stage", registry=r)
    def runner():
        return "ok"

    m = r.get("x")
    assert m.run is runner
    assert m.help == "x stage"
    assert m.default_on is True
