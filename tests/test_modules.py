import pytest

from recon.modules import (
    STAGES,
    ConfigKey,
    Module,
    Ok,
    Registry,
    Skip,
    Soft,
    Tool,
    check_requirements,
    module,
)


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


def test_check_no_requirements_returns_ok():
    m = Module(name="x", stage="sweep", help="x")
    assert isinstance(check_requirements(m, config_loader=lambda: {}), Ok)


def test_check_missing_tool_returns_skip(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    m = Module(name="x", stage="sweep", help="x", requires=[Tool("nope")])
    result = check_requirements(m, config_loader=lambda: {})
    assert isinstance(result, Skip)
    assert "nope" in result.reason
    assert "PATH" in result.reason


def test_check_present_tool_returns_ok(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/" + name)
    m = Module(name="x", stage="sweep", help="x", requires=[Tool("nmap")])
    assert isinstance(check_requirements(m, config_loader=lambda: {}), Ok)


def test_check_missing_config_key_returns_skip():
    m = Module(name="x", stage="nessus", help="x", requires=[ConfigKey("nessus", "access_key")])
    result = check_requirements(m, config_loader=lambda: {})
    assert isinstance(result, Skip)
    assert "nessus" in result.reason and "access_key" in result.reason


def test_check_present_config_key_returns_ok():
    m = Module(name="x", stage="nessus", help="x", requires=[ConfigKey("nessus", "access_key")])
    loader = lambda: {"nessus": {"access_key": "abc"}}
    assert isinstance(check_requirements(m, config_loader=loader), Ok)


def test_soft_requirement_never_skips(monkeypatch):
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: None)
    m = Module(name="x", stage="enum", help="x", requires=[Soft(Tool("showmount"))])
    assert isinstance(check_requirements(m, config_loader=lambda: {}), Ok)


import argparse

from recon.modules import evaluate_enabled, register_argparse_flags


def _fresh_registry() -> Registry:
    r = Registry()
    r.register(Module(name="sweep", stage="sweep", help="ping sweep"))
    r.register(Module(name="masscan", stage="enum", help="masscan", togglable=False))
    r.register(Module(name="probe-ftp", stage="enum", help="ftp anon"))
    r.register(Module(name="probe-ssh", stage="enum", help="ssh banner"))
    r.register(Module(name="probe-ptr", stage="enum", help="reverse dns", default_on=False))
    r.register(Module(name="nuclei", stage="nuclei", help="nuclei"))
    return r


def test_register_flags_adds_expected_args():
    parser = argparse.ArgumentParser()
    r = _fresh_registry()
    register_argparse_flags(parser, r)
    args = parser.parse_args([])
    # stage flags
    assert args.no_sweep is False
    assert args.no_enum is False
    assert args.no_nuclei is False
    # module flags
    assert args.no_probe_ftp is False
    assert args.no_probe_ssh is False
    assert args.probe_ptr is False
    # non-togglable modules get no flag
    assert not hasattr(args, "no_masscan")
    # single-module stages: no separate --no-<module> for module that matches stage
    assert not hasattr(args, "no_sweep_module")
    assert not hasattr(args, "no_nuclei_module")


def test_evaluate_default_enables_all_default_on():
    parser = argparse.ArgumentParser()
    r = _fresh_registry()
    register_argparse_flags(parser, r)
    args = parser.parse_args([])
    enabled = evaluate_enabled(args, r)
    assert enabled == {"sweep", "masscan", "probe-ftp", "probe-ssh", "nuclei"}


def test_evaluate_stage_flag_disables_all_modules_in_stage():
    parser = argparse.ArgumentParser()
    r = _fresh_registry()
    register_argparse_flags(parser, r)
    args = parser.parse_args(["--no-enum"])
    enabled = evaluate_enabled(args, r)
    assert "masscan" not in enabled
    assert "probe-ftp" not in enabled
    assert "probe-ssh" not in enabled
    assert "sweep" in enabled
    assert "nuclei" in enabled


def test_evaluate_module_flag_disables_one_module():
    parser = argparse.ArgumentParser()
    r = _fresh_registry()
    register_argparse_flags(parser, r)
    args = parser.parse_args(["--no-probe-ftp"])
    enabled = evaluate_enabled(args, r)
    assert "probe-ftp" not in enabled
    assert "probe-ssh" in enabled


def test_evaluate_default_off_module_enabled_by_flag():
    parser = argparse.ArgumentParser()
    r = _fresh_registry()
    register_argparse_flags(parser, r)
    args = parser.parse_args(["--probe-ptr"])
    enabled = evaluate_enabled(args, r)
    assert "probe-ptr" in enabled
