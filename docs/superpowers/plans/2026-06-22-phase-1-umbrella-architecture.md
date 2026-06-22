# Phase 1 — Umbrella Architecture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land the umbrella architecture from `docs/superpowers/specs/2026-06-22-recon-modules-umbrella-design.md` — a module registry, registry-driven flag generation in `pt-recon`, subparser routing for ad-hoc per-stage runs, `run.json` / `run.log` per engagement, `nessus` and `smb` flipped default-on with auto-skip on missing prerequisites, and the per-tool `bin/pt-*` binaries deleted. No new probes in this phase.

**Architecture:** Add `recon/modules.py` exposing a `Module` dataclass, `Requirement` union (`Tool`, `ConfigKey`, `Soft`), a `Registry` class, and a `@module(...)` decorator. Register the existing stages and probes in a side-effect-only `recon/registry_bootstrap.py` that `recon/__init__.py` imports on package load. Rewire `cli_recon.py` to generate argparse flags from the registry, iterate stages with auto-skip on missing prereqs, and emit a `run.json` manifest plus a `run.log` tee via `recon/manifest.py`. Extend `cli_enum.main` with a `--disable-probes` flag so the orchestrator can communicate which probes to skip when stage `enum` runs.

**Tech Stack:** Python 3 (stdlib `argparse`, `dataclasses`, `logging`, `json`, `configparser`, `shutil`), pytest. No new dependencies.

## Global Constraints

- All existing tests must remain green; existing `cli_*.main(argv)` signatures keep working for callers that don't pass new flags.
- No new dependencies beyond what's already pinned (stdlib + `requests` + `openpyxl`).
- Auto-skip rule (spec §9.1): missing non-`Soft` prerequisite → exactly one `[WARN] <module> skipped: <reason>` log line, record `status=skipped` with `reason` in `run.json`, do not invoke the module, do not fail the enclosing stage.
- Orchestrator exit codes (spec §9.2): `0` every attempted stage succeeded; `1` ≥1 stage exited non-zero; `2` argument/target/config error before any stage ran; `130` Ctrl-C.
- Subcommand exit codes (spec §9.3) inherit the contracts documented in each `cli_*.py`'s docstring and `--help` epilog.
- Module flag names are kebab-case, taken verbatim from the registry `name`. Stage flag is `--no-<stage>`.
- After this phase, the only binary on PATH is `pt-recon`. The pre-existing `pt-sweep`, `pt-enum`, `pt-nuclei`, `pt-nessus`, `pt-smb` shims are deleted; subcommand replacements are `pt-recon sweep`, `pt-recon enum`, etc.

---

### Task 1: Module dataclass and Requirement types

**Files:**
- Create: `recon/modules.py`
- Test: `tests/test_modules.py` (new)

**Interfaces:**
- Consumes: nothing (foundational).
- Produces: `STAGES: list[str]`, `Tool`, `ConfigKey`, `Soft` (frozen dataclasses), `Requirement` (Union alias), `Module` dataclass with fields `name: str`, `stage: str`, `help: str`, `requires: list[Requirement] = []`, `default_on: bool = True`, `togglable: bool = True`, `run: Optional[Callable] = None`.

- [ ] **Step 1: Write the failing test**

Write `tests/test_modules.py`:

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_modules.py -v`
Expected: ImportError on `from recon.modules import ...` (file doesn't exist yet).

- [ ] **Step 3: Create `recon/modules.py`**

```python
"""Module registry primitives: dataclass, requirement types, and constants."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional, Union


STAGES = ["sweep", "enum", "feedback", "nuclei", "nessus", "smb", "report"]


@dataclass(frozen=True)
class Tool:
    name: str


@dataclass(frozen=True)
class ConfigKey:
    section: str
    key: str


@dataclass(frozen=True)
class Soft:
    inner: Union["Tool", "ConfigKey"]


Requirement = Union[Tool, ConfigKey, Soft]


@dataclass
class Module:
    name: str
    stage: str
    help: str
    requires: List[Requirement] = field(default_factory=list)
    default_on: bool = True
    togglable: bool = True
    run: Optional[Callable] = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_modules.py -v`
Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add recon/modules.py tests/test_modules.py
git commit -m "feat(recon): add module dataclass and requirement primitives"
```

---

### Task 2: Registry class and @module decorator

**Files:**
- Modify: `recon/modules.py`
- Modify: `tests/test_modules.py`

**Interfaces:**
- Consumes: `Module`, `STAGES` from Task 1.
- Produces:
  - `class Registry` with methods `register(module: Module) -> None`, `get(name: str) -> Module`, `iter(stage: Optional[str] = None) -> Iterable[Module]`, `has(name: str) -> bool`, `names() -> list[str]`.
  - Module-level `_DEFAULT_REGISTRY: Registry`.
  - `module(*, name, stage, help, requires=None, default_on=True, togglable=True, registry=None)` decorator factory that wraps a callable and registers it on the target registry, setting `module.run = wrapped_fn`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_modules.py`:

```python
from recon.modules import Registry, module


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_modules.py -v`
Expected: ImportError on `from recon.modules import Registry, module`.

- [ ] **Step 3: Extend `recon/modules.py`**

Append at the end of the file:

```python
class Registry:
    """In-process registry of recon modules keyed by name."""

    def __init__(self) -> None:
        self._modules: dict[str, Module] = {}

    def register(self, mod: Module) -> None:
        if mod.stage not in STAGES:
            raise ValueError(f"unknown stage: {mod.stage}")
        if mod.name in self._modules:
            raise ValueError(f"duplicate module name: {mod.name}")
        self._modules[mod.name] = mod

    def get(self, name: str) -> Module:
        return self._modules[name]

    def has(self, name: str) -> bool:
        return name in self._modules

    def names(self) -> List[str]:
        return list(self._modules)

    def iter(self, stage: Optional[str] = None):
        for m in self._modules.values():
            if stage is None or m.stage == stage:
                yield m


_DEFAULT_REGISTRY = Registry()


def module(*, name: str, stage: str, help: str,
           requires: Optional[List[Requirement]] = None,
           default_on: bool = True, togglable: bool = True,
           registry: Optional[Registry] = None):
    """Decorator: register the wrapped function as a recon module."""
    def decorator(fn: Callable) -> Callable:
        mod = Module(
            name=name,
            stage=stage,
            help=help,
            requires=list(requires or []),
            default_on=default_on,
            togglable=togglable,
            run=fn,
        )
        target = registry or _DEFAULT_REGISTRY
        target.register(mod)
        return fn
    return decorator
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_modules.py -v`
Expected: 8 tests pass (4 new + 4 from Task 1).

- [ ] **Step 5: Commit**

```bash
git add recon/modules.py tests/test_modules.py
git commit -m "feat(recon): add Registry class and @module decorator"
```

---

### Task 3: Requirement checks (auto-skip semantics)

**Files:**
- Modify: `recon/modules.py`
- Modify: `tests/test_modules.py`

**Interfaces:**
- Consumes: `Module`, `Tool`, `ConfigKey`, `Soft` from earlier tasks.
- Produces:
  - `@dataclass class Ok: pass`
  - `@dataclass class Skip: reason: str`
  - `check_requirements(mod: Module, config_loader: Optional[Callable[[], dict]] = None) -> Ok | Skip` — first failing non-`Soft` requirement wins; soft requirements never produce `Skip`.
  - `_default_config_loader()` — reads `common.DEFAULT_CONFIG_PATH` via `configparser` into a `{section: {key: value}}` dict; returns `{}` if file missing.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_modules.py`:

```python
from recon.modules import Ok, Skip, check_requirements


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
    m = Module(name="x", stage="nessus", help="x",
               requires=[ConfigKey("nessus", "access_key")])
    result = check_requirements(m, config_loader=lambda: {})
    assert isinstance(result, Skip)
    assert "nessus" in result.reason and "access_key" in result.reason


def test_check_present_config_key_returns_ok():
    m = Module(name="x", stage="nessus", help="x",
               requires=[ConfigKey("nessus", "access_key")])
    loader = lambda: {"nessus": {"access_key": "abc"}}
    assert isinstance(check_requirements(m, config_loader=loader), Ok)


def test_soft_requirement_never_skips(monkeypatch):
    import shutil
    monkeypatch.setattr(shutil, "which", lambda name: None)
    m = Module(name="x", stage="enum", help="x",
               requires=[Soft(Tool("showmount"))])
    assert isinstance(check_requirements(m, config_loader=lambda: {}), Ok)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_modules.py -v`
Expected: ImportError on `from recon.modules import Ok, Skip, check_requirements`.

- [ ] **Step 3: Extend `recon/modules.py`**

Add the following at module scope (place above `_DEFAULT_REGISTRY`):

```python
import shutil
import configparser
from pathlib import Path


@dataclass
class Ok:
    """Requirement check passed."""


@dataclass
class Skip:
    """Requirement check failed — the module should be skipped."""
    reason: str


def _check_one(req: Requirement, config_loader: Callable[[], dict]) -> Optional[Skip]:
    if isinstance(req, Soft):
        return None  # soft requirements never produce Skip
    if isinstance(req, Tool):
        if shutil.which(req.name) is None:
            return Skip(f"{req.name} not on PATH")
        return None
    if isinstance(req, ConfigKey):
        cfg = config_loader()
        section = cfg.get(req.section, {})
        if not section.get(req.key):
            return Skip(f"config {req.section}.{req.key} missing or empty")
        return None
    raise TypeError(f"unknown requirement type: {type(req).__name__}")


def _default_config_loader() -> dict:
    from recon import common  # local import to avoid cycle at module load
    path = Path(common.DEFAULT_CONFIG_PATH)
    if not path.exists():
        return {}
    cp = configparser.ConfigParser()
    cp.read(path)
    return {s: dict(cp.items(s)) for s in cp.sections()}


def check_requirements(mod: Module,
                       config_loader: Optional[Callable[[], dict]] = None):
    loader = config_loader or _default_config_loader
    for req in mod.requires:
        result = _check_one(req, loader)
        if result is not None:
            return result
    return Ok()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_modules.py -v`
Expected: 14 tests pass (6 new + 8 prior).

- [ ] **Step 5: Commit**

```bash
git add recon/modules.py tests/test_modules.py
git commit -m "feat(recon): add requirement checks with auto-skip semantics"
```

---

### Task 4: Argparse flag registration and enabled-set evaluation

**Files:**
- Modify: `recon/modules.py`
- Modify: `tests/test_modules.py`

**Interfaces:**
- Consumes: `Registry`, `Module`, `STAGES`.
- Produces:
  - `register_argparse_flags(parser: argparse.ArgumentParser, registry: Registry) -> None` — adds `--no-<stage>` for every stage present in the registry, plus `--no-<name>` for every togglable, `default_on=True` module whose name differs from its stage, and `--<name>` for every togglable, `default_on=False` module.
  - `evaluate_enabled(args: argparse.Namespace, registry: Registry) -> set[str]` — returns the set of module names that should run after applying parsed-arg overrides.

Flag-attribute conventions: argparse converts dashes to underscores. `--no-foo-bar` → `args.no_foo_bar`. `--foo-bar` → `args.foo_bar`. Non-togglable modules get no flag at all.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_modules.py`:

```python
import argparse
from recon.modules import register_argparse_flags, evaluate_enabled


def _fresh_registry() -> Registry:
    r = Registry()
    r.register(Module(name="sweep", stage="sweep", help="ping sweep"))
    r.register(Module(name="masscan", stage="enum", help="masscan", togglable=False))
    r.register(Module(name="probe-ftp", stage="enum", help="ftp anon"))
    r.register(Module(name="probe-ssh", stage="enum", help="ssh banner"))
    r.register(Module(name="probe-ptr", stage="enum", help="reverse dns",
                      default_on=False))
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_modules.py -v`
Expected: ImportError on `from recon.modules import register_argparse_flags, evaluate_enabled`.

- [ ] **Step 3: Extend `recon/modules.py`**

Add imports at the top if not already present:

```python
import argparse  # noqa: F401  (used in type hint on register_argparse_flags)
```

Add at the end of the file:

```python
def _stage_attr(stage: str) -> str:
    return f"no_{stage.replace('-', '_')}"


def _module_attr(name: str, default_on: bool) -> str:
    prefix = "no_" if default_on else ""
    return f"{prefix}{name.replace('-', '_')}"


def register_argparse_flags(parser, registry: Registry) -> None:
    """Add stage and module toggle flags to `parser` from `registry`."""
    stages_seen = {m.stage for m in registry.iter()}
    for stage in STAGES:
        if stage in stages_seen:
            parser.add_argument(
                f"--no-{stage}",
                action="store_true",
                help=f"skip the {stage} stage entirely",
            )
    for m in registry.iter():
        if not m.togglable:
            continue
        if m.name == m.stage:
            continue  # stage flag already covers it
        if m.default_on:
            parser.add_argument(
                f"--no-{m.name}",
                action="store_true",
                dest=_module_attr(m.name, True),
                help=f"skip {m.name}: {m.help}",
            )
        else:
            parser.add_argument(
                f"--{m.name}",
                action="store_true",
                dest=_module_attr(m.name, False),
                help=f"enable {m.name}: {m.help}",
            )


def evaluate_enabled(args, registry: Registry) -> set:
    """Return the set of module names that should run, given parsed args."""
    enabled = {m.name for m in registry.iter() if m.default_on}
    for stage in STAGES:
        if getattr(args, _stage_attr(stage), False):
            for m in registry.iter(stage=stage):
                enabled.discard(m.name)
    for m in registry.iter():
        if not m.togglable or m.name == m.stage:
            continue
        flagged = getattr(args, _module_attr(m.name, m.default_on), False)
        if m.default_on and flagged:
            enabled.discard(m.name)
        elif not m.default_on and flagged:
            enabled.add(m.name)
    return enabled
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_modules.py -v`
Expected: 19 tests pass (5 new + 14 prior).

- [ ] **Step 5: Commit**

```bash
git add recon/modules.py tests/test_modules.py
git commit -m "feat(recon): generate argparse flags and evaluate enabled set from registry"
```

---

### Task 5: Bootstrap — register the ten built-in modules

**Files:**
- Create: `recon/registry_bootstrap.py`
- Modify: `recon/__init__.py`
- Test: `tests/test_registry_bootstrap.py` (new)

**Interfaces:**
- Consumes: `Module`, `Tool`, `ConfigKey`, `Soft`, `_DEFAULT_REGISTRY` from `recon.modules`.
- Produces: side effect of registering ten built-in modules in `_DEFAULT_REGISTRY` on first import of the `recon` package. The set is: `sweep`, `masscan`, `nmap-sv`, `probe-ftp`, `probe-ssh`, `probe-web-basic`, `probe-smb`, `nuclei`, `nessus`, `smb-mass`.

Default-on, togglable, requirements per spec §6.

- [ ] **Step 1: Write the failing test**

Create `tests/test_registry_bootstrap.py`:

```python
import recon  # noqa: F401 — ensures bootstrap import side effect runs
from recon.modules import _DEFAULT_REGISTRY, Tool, ConfigKey, Soft


_EXPECTED = {
    "sweep", "masscan", "nmap-sv",
    "probe-ftp", "probe-ssh", "probe-web-basic", "probe-smb",
    "nuclei", "nessus", "smb-mass",
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_registry_bootstrap.py -v`
Expected: `test_builtin_modules_registered` fails — the default registry is empty.

- [ ] **Step 3: Create `recon/registry_bootstrap.py`**

```python
"""Side-effect-only module: registers built-in recon modules on import.

Imported by `recon/__init__.py` so that `from recon.modules import _DEFAULT_REGISTRY`
returns a registry populated with every module in the spec's phase-1 taxonomy.
"""
from recon.modules import Module, Tool, ConfigKey, Soft, _DEFAULT_REGISTRY


_BUILTINS = [
    Module(name="sweep", stage="sweep",
           help="nmap ping sweep",
           requires=[Tool("nmap")]),
    Module(name="masscan", stage="enum",
           help="masscan port discovery",
           requires=[Tool("masscan")],
           togglable=False),
    Module(name="nmap-sv", stage="enum",
           help="nmap service/version detection",
           requires=[Tool("nmap")],
           togglable=False),
    Module(name="probe-ftp", stage="enum",
           help="FTP anonymous login check"),
    Module(name="probe-ssh", stage="enum",
           help="SSH/Telnet banner grab"),
    Module(name="probe-web-basic", stage="enum",
           help="HTTP <title> fetch"),
    Module(name="probe-smb", stage="enum",
           help="SMB null/guest session check",
           requires=[Soft(Tool("nxc"))]),
    Module(name="nuclei", stage="nuclei",
           help="nuclei template scan"),
    Module(name="nessus", stage="nessus",
           help="Nessus REST scan",
           requires=[ConfigKey("nessus", "access_key"),
                     ConfigKey("nessus", "secret_key")]),
    Module(name="smb-mass", stage="smb",
           help="netexec SMB mass-recon",
           requires=[Tool("nxc")]),
]


for _m in _BUILTINS:
    _DEFAULT_REGISTRY.register(_m)
```

- [ ] **Step 4: Modify `recon/__init__.py`**

Replace contents with:

```python
"""Pentest recon automation suite."""
__version__ = "0.1.0"

from recon import registry_bootstrap  # noqa: F401  (registers built-in modules)
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/test_registry_bootstrap.py tests/test_modules.py -v`
Expected: all tests in both files pass (9 new + 19 prior = 28 tests).

- [ ] **Step 6: Run the full suite to confirm no regressions**

Run: `python -m pytest -q`
Expected: all tests pass (57 prior + 28 new = 85 tests).

- [ ] **Step 7: Commit**

```bash
git add recon/__init__.py recon/registry_bootstrap.py tests/test_registry_bootstrap.py
git commit -m "feat(recon): register ten built-in modules; flip nessus/smb default-on"
```

---

### Task 6: Run manifest and run-log tee

**Files:**
- Create: `recon/manifest.py`
- Test: `tests/test_manifest.py` (new)

**Interfaces:**
- Consumes: stdlib only.
- Produces:
  - `class RunManifest`:
    - `__init__(self, engagement: str, outdir: str, targets_count: int, targets_source: str, *, clock: Optional[Callable[[], datetime]] = None)`
    - `add_stage(self, name: str, status: str, elapsed_s: float, modules_run: list[str], modules_skipped: list[dict], exit_code: Optional[int]) -> None` (writes incrementally)
    - `set_exit_code(self, code: int) -> None`
    - `write(self) -> None`
    - `path: str` attribute (the JSON file path)
  - `attach_run_log(path: str, logger_prefix: str = "pt-") -> logging.FileHandler` — adds an INFO-level FileHandler to every existing logger whose name starts with `logger_prefix`; idempotent for the same `path`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_manifest.py`:

```python
import json
from datetime import datetime

from recon.manifest import RunManifest, attach_run_log
from recon import common


def test_manifest_write_creates_json(tmp_path):
    m = RunManifest(
        engagement="acme",
        outdir=str(tmp_path),
        targets_count=5,
        targets_source="-r 10.0.0.0/30",
        clock=lambda: datetime(2026, 6, 22, 14, 0, 0),
    )
    m.add_stage("sweep", "ok", 1.5,
                modules_run=["sweep"], modules_skipped=[], exit_code=0)
    m.set_exit_code(0)
    data = json.loads((tmp_path / "run.json").read_text())
    assert data["engagement"] == "acme"
    assert data["targets"] == {"count": 5, "source": "-r 10.0.0.0/30"}
    assert data["stages"][0]["name"] == "sweep"
    assert data["stages"][0]["status"] == "ok"
    assert data["stages"][0]["modules_run"] == ["sweep"]
    assert data["stages"][0]["exit_code"] == 0
    assert data["exit_code"] == 0
    assert data["started_at"].startswith("2026-06-22T14:00:00")
    assert data["finished_at"].startswith("2026-06-22T14:00:00")


def test_manifest_records_skipped_modules(tmp_path):
    m = RunManifest("acme", str(tmp_path), 1, "-t 1.1.1.1",
                    clock=lambda: datetime(2026, 6, 22))
    m.add_stage(
        "nessus", "skipped", 0.0,
        modules_run=[],
        modules_skipped=[{"name": "nessus",
                          "reason": "config nessus.access_key missing or empty"}],
        exit_code=None,
    )
    m.set_exit_code(0)
    data = json.loads((tmp_path / "run.json").read_text())
    skipped = data["stages"][0]["modules_skipped"]
    assert skipped == [{"name": "nessus",
                        "reason": "config nessus.access_key missing or empty"}]


def test_manifest_writes_incrementally(tmp_path):
    """After add_stage but before set_exit_code, run.json should already exist."""
    m = RunManifest("acme", str(tmp_path), 1, "-t 1.1.1.1",
                    clock=lambda: datetime(2026, 6, 22))
    assert not (tmp_path / "run.json").exists()
    m.add_stage("sweep", "ok", 0.1, ["sweep"], [], 0)
    assert (tmp_path / "run.json").exists()
    data = json.loads((tmp_path / "run.json").read_text())
    assert data["exit_code"] is None  # not yet set


def test_attach_run_log_writes_log_lines(tmp_path):
    log_path = str(tmp_path / "run.log")
    logger = common.get_logger("pt-attachtest")
    handler = attach_run_log(log_path, logger_prefix="pt-")
    try:
        logger.info("hello from attachtest")
        handler.flush()
        content = (tmp_path / "run.log").read_text()
        assert "hello from attachtest" in content
        assert "pt-attachtest" in content
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_attach_run_log_is_idempotent_for_same_path(tmp_path):
    log_path = str(tmp_path / "run.log")
    logger = common.get_logger("pt-idemtest")
    h1 = attach_run_log(log_path, logger_prefix="pt-")
    h2 = attach_run_log(log_path, logger_prefix="pt-")
    try:
        # Only one FileHandler with this baseFilename should remain on the logger.
        same_path = [h for h in logger.handlers
                     if isinstance(h, type(h1))
                     and getattr(h, "baseFilename", None) == h1.baseFilename]
        assert len(same_path) == 1
    finally:
        for h in (h1, h2):
            try:
                logger.removeHandler(h)
                h.close()
            except Exception:
                pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_manifest.py -v`
Expected: ImportError on `from recon.manifest import RunManifest, attach_run_log`.

- [ ] **Step 3: Create `recon/manifest.py`**

```python
"""Run manifest (run.json) writer and orchestrator-log tee."""
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class RunManifest:
    """Incrementally-written run.json describing one orchestrator invocation."""

    def __init__(self, engagement: str, outdir: str,
                 targets_count: int, targets_source: str,
                 *, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._clock = clock or datetime.utcnow
        self.path = os.path.join(outdir, "run.json")
        self._data: Dict = {
            "engagement": engagement,
            "started_at": _iso(self._clock()),
            "finished_at": None,
            "targets": {"count": targets_count, "source": targets_source},
            "stages": [],
            "exit_code": None,
        }
        # Write a placeholder so a Ctrl-C before the first stage still leaves a file.
        self.write()

    def add_stage(self, name: str, status: str, elapsed_s: float,
                  modules_run: List[str],
                  modules_skipped: List[Dict[str, str]],
                  exit_code: Optional[int]) -> None:
        self._data["stages"].append({
            "name": name,
            "status": status,
            "elapsed_s": round(float(elapsed_s), 2),
            "modules_run": list(modules_run),
            "modules_skipped": list(modules_skipped),
            "exit_code": exit_code,
        })
        self.write()

    def set_exit_code(self, code: int) -> None:
        self._data["exit_code"] = code
        self._data["finished_at"] = _iso(self._clock())
        self.write()

    def write(self) -> None:
        with open(self.path, "w") as fh:
            json.dump(self._data, fh, indent=2, sort_keys=False)


def attach_run_log(path: str, logger_prefix: str = "pt-") -> logging.FileHandler:
    """Attach an INFO FileHandler to every existing logger whose name starts with prefix.

    Idempotent: if a logger already has a FileHandler with the same baseFilename,
    no second handler is added to that logger.
    """
    handler = logging.FileHandler(path, mode="w")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    for name in list(logging.Logger.manager.loggerDict):
        if not name.startswith(logger_prefix):
            continue
        logger = logging.getLogger(name)
        already = any(
            isinstance(h, logging.FileHandler)
            and getattr(h, "baseFilename", None) == handler.baseFilename
            for h in logger.handlers
        )
        if not already:
            logger.addHandler(handler)
    return handler
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_manifest.py -v`
Expected: 5 tests pass.

- [ ] **Step 5: Run full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add recon/manifest.py tests/test_manifest.py
git commit -m "feat(recon): add RunManifest writer and attach_run_log tee"
```

---

### Task 7: Probe dispatch consults a skip set; cli_enum gains `--disable-probes`

**Files:**
- Modify: `recon/cli_enum.py`
- Modify: `tests/test_cli_enum.py`

**Interfaces:**
- Consumes: nothing new (registry not imported here — the orchestrator passes the skip set explicitly via `--disable-probes`).
- Produces:
  - `dispatch_probes(open_ports, web_ports, probe_fns=None, disabled_probes=None)` — new optional `disabled_probes: Optional[Iterable[str]]` parameter. When a probe's registry name is in the set, the probe is silently not invoked for any matching port (the row's `finding` / `http_title` stays at the default empty string).
  - `cli_enum.main` accepts a new `--disable-probes <csv>` flag and passes the parsed set through to `dispatch_probes`. Default is `None` (run all probes).
  - Recognized probe names: `probe-ftp`, `probe-ssh`, `probe-web-basic`, `probe-smb`. Unknown names are ignored (the orchestrator may pass a superset).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli_enum.py`:

```python
def test_dispatch_probes_skips_disabled():
    open_ports = {("10.0.0.1", 21), ("10.0.0.1", 22), ("10.0.0.1", 8080), ("10.0.0.1", 445)}
    fns = {
        "ftp": lambda ip, port: "FTP ANON OK",
        "banner": lambda ip, port: f"banner:{port}",
        "web": lambda ip, port: f"title:{port}",
        "smb": lambda ip: "SMB NULL OK",
    }
    res = cli_enum.dispatch_probes(
        open_ports, web_ports=[8080], probe_fns=fns,
        disabled_probes={"probe-ftp", "probe-smb"},
    )
    assert res[("10.0.0.1", 21)]["finding"] == ""   # ftp skipped
    assert res[("10.0.0.1", 22)]["finding"] == "banner:22"
    assert res[("10.0.0.1", 8080)]["http_title"] == "title:8080"
    assert res[("10.0.0.1", 445)]["finding"] == ""  # smb skipped


def test_dispatch_probes_unknown_disabled_names_are_ignored():
    open_ports = {("10.0.0.1", 21)}
    fns = {
        "ftp": lambda ip, port: "FTP ANON OK",
        "banner": lambda ip, port: "",
        "web": lambda ip, port: "",
        "smb": lambda ip: None,
    }
    res = cli_enum.dispatch_probes(
        open_ports, web_ports=[], probe_fns=fns,
        disabled_probes={"probe-bogus"},
    )
    assert res[("10.0.0.1", 21)]["finding"] == "FTP ANON OK"


def test_cli_enum_parses_disable_probes_csv():
    parser = cli_enum.build_arg_parser()
    args = parser.parse_args(["--disable-probes", "probe-ftp,probe-smb",
                              "-t", "10.0.0.1"])
    assert args.disable_probes == "probe-ftp,probe-smb"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_enum.py -v`
Expected: `test_dispatch_probes_skips_disabled` fails with a `TypeError` (unexpected keyword `disabled_probes`); `test_cli_enum_parses_disable_probes_csv` fails because `--disable-probes` isn't defined.

- [ ] **Step 3: Update `recon/cli_enum.py`**

Replace `dispatch_probes` with this version (note the new parameter and per-probe skip checks):

```python
def dispatch_probes(open_ports, web_ports, probe_fns=None, disabled_probes=None):
    """Route each open port to its probe; return per-(ip,port) results.

    `disabled_probes`, when given, is an iterable of registry probe names
    (`probe-ftp`, `probe-ssh`, `probe-web-basic`, `probe-smb`) that should
    be silently skipped — the corresponding row stays at the default empty
    finding/http_title.
    """
    fns = probe_fns or {
        "ftp": probes.probe_ftp_anon,
        "banner": probes.probe_banner,
        "web": probes.probe_web_title,
        "smb": probes.probe_smb,
    }
    disabled = set(disabled_probes or [])
    results = {key: {"http_title": "", "finding": ""} for key in open_ports}
    smb_done = set()
    for ip, port in open_ports:
        try:
            if port == 21 and "probe-ftp" not in disabled:
                finding = fns["ftp"](ip, port)
                if finding:
                    results[(ip, port)]["finding"] = finding
            elif port in (22, 23) and "probe-ssh" not in disabled:
                results[(ip, port)]["finding"] = fns["banner"](ip, port)
            elif port in web_ports and "probe-web-basic" not in disabled:
                results[(ip, port)]["http_title"] = fns["web"](ip, port)
            elif port in SMB_PORTS and ip not in smb_done and "probe-smb" not in disabled:
                smb_done.add(ip)
                finding = fns["smb"](ip)
                if finding:
                    results[(ip, port)]["finding"] = finding
        except KeyboardInterrupt:
            results[(ip, port)]["finding"] = "INTERRUPTED"
            break
        except Exception as exc:  # never abort the whole run
            results[(ip, port)]["finding"] = f"probe error: {exc}"
    return results
```

Add a flag to `build_arg_parser` immediately after the existing `--rate` line:

```python
    parser.add_argument("--disable-probes", dest="disable_probes", default="",
                        help="comma-separated registry probe names to skip (advanced; "
                             "set automatically by pt-recon)")
```

Update the `main` function to pass the parsed set through. Inside `main`, replace the existing line:

```python
    probe_results = dispatch_probes(open_ports, web_ports)
```

with:

```python
    disabled = {p.strip() for p in (args.disable_probes or "").split(",") if p.strip()}
    probe_results = dispatch_probes(open_ports, web_ports, disabled_probes=disabled)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_enum.py -v`
Expected: all tests in `test_cli_enum.py` pass (existing tests + 3 new).

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add recon/cli_enum.py tests/test_cli_enum.py
git commit -m "feat(pt-enum): --disable-probes flag and per-probe skip in dispatch"
```

---

### Task 8: Rewire `cli_recon` orchestrator around the registry

**Files:**
- Modify: `recon/cli_recon.py`
- Modify: `tests/test_cli_recon.py`

**Interfaces:**
- Consumes: `recon.modules.{_DEFAULT_REGISTRY, register_argparse_flags, evaluate_enabled, check_requirements, Ok, Skip, STAGES}`, `recon.manifest.{RunManifest, attach_run_log}`.
- Produces:
  - Rewritten `cli_recon.main(argv)` that:
    - Builds the parser with target flags (`-n/-r/-t/-iL`), then `register_argparse_flags(parser, _DEFAULT_REGISTRY)`.
    - Resolves the engagement dir via `common.engagement_dir(args.name)`.
    - Initializes `RunManifest` (using `common.parse_targets` to compute target count for the manifest; if `parse_targets` raises, return `2`).
    - Calls `attach_run_log(os.path.join(outdir, "run.log"))`.
    - Computes the enabled set via `evaluate_enabled(args, registry)`.
    - For each stage in `STAGES` (excluding `feedback` and `report` which aren't implemented in phase 1):
      - If no enabled module belongs to that stage → record a `skipped` stage row, continue.
      - For each enabled module in the stage, run `check_requirements`. If any non-soft requirement fails, log `[WARN] <module> skipped: <reason>`, drop it from the stage's enabled set, and record it in the stage's `modules_skipped` list.
      - If after pruning the stage has zero enabled modules → record `skipped`, continue.
      - Otherwise invoke the existing `cli_<stage>.main(argv)` with the appropriate argv (see helpers below) and record `status` based on exit code.
    - For stage `enum`: also pass `--disable-probes <csv>` derived from registry probe-names NOT in the enabled set (i.e. probes that were explicitly disabled by the operator).
  - The legacy `plan_stages` and `_target_args` functions are kept (the latter is reused by the new orchestrator; the former is deleted since callers now rely on the registry).

- [ ] **Step 1: Rewrite the failing tests to match the new contract**

Replace the entire contents of `tests/test_cli_recon.py` with:

```python
import json
import os

import pytest

from recon import cli_recon


def _argv_for(name, range_):
    return ["-n", name, "-r", range_]


def test_parser_includes_stage_and_module_flags(tmp_path):
    parser = cli_recon.build_arg_parser()
    args = parser.parse_args(_argv_for("job", "10.0.0.0/30"))
    # stage flags
    assert args.no_sweep is False
    assert args.no_enum is False
    assert args.no_nuclei is False
    assert args.no_nessus is False
    assert args.no_smb is False
    # module flags
    assert args.no_probe_ftp is False
    assert args.no_probe_ssh is False
    assert args.no_probe_web_basic is False
    assert args.no_probe_smb is False


def test_target_args_ignores_empty_hosts_file(tmp_path):
    args = cli_recon.build_arg_parser().parse_args(["-n", "j", "-t", "10.0.0.1"])
    empty = tmp_path / "live-hosts.txt"
    empty.write_text("")
    assert cli_recon._target_args(args, str(empty)) == ["-t", "10.0.0.1"]
    nonempty = tmp_path / "h.txt"
    nonempty.write_text("10.0.0.9\n")
    assert cli_recon._target_args(args, str(nonempty)) == ["-iL", str(nonempty)]


def test_orchestrator_runs_all_default_on_stages(tmp_path, monkeypatch):
    """Default invocation: every stage runs (or auto-skips with a reason)."""
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])

    calls = []

    def fake_main(stage, argv):
        calls.append((stage, list(argv)))
        # write the expected output artifact so the orchestrator's chaining works
        if stage == "sweep":
            idx = argv.index("-o")
            with open(argv[idx + 1], "w") as fh:
                fh.write("10.0.0.1\n")
        if stage == "enum":
            idx = argv.index("-o")
            open(argv[idx + 1], "w").close()
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", lambda a: fake_main("sweep", a))
    monkeypatch.setattr("recon.cli_enum.main", lambda a: fake_main("enum", a))
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: fake_main("nuclei", a))
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: fake_main("nessus", a))
    monkeypatch.setattr("recon.cli_smb.main", lambda a: fake_main("smb", a))

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])
    assert rc in (0, 1)  # may be 1 if nessus/smb prereqs are skipped — that's OK here

    stages_called = [s for s, _ in calls]
    assert "sweep" in stages_called
    assert "enum" in stages_called
    assert "nuclei" in stages_called

    manifest = json.loads((outdir / "run.json").read_text())
    assert manifest["engagement"] == "eng"
    assert {s["name"] for s in manifest["stages"]} >= {"sweep", "enum", "nuclei"}


def test_orchestrator_passes_disable_probes_to_enum(tmp_path, monkeypatch):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    captured = {}

    def fake_sweep(argv):
        idx = argv.index("-o")
        with open(argv[idx + 1], "w") as fh:
            fh.write("10.0.0.1\n")
        return 0

    def fake_enum(argv):
        captured["enum_argv"] = list(argv)
        idx = argv.index("-o")
        open(argv[idx + 1], "w").close()
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", fake_sweep)
    monkeypatch.setattr("recon.cli_enum.main", fake_enum)
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_nessus.main", lambda a: 0)
    monkeypatch.setattr("recon.cli_smb.main", lambda a: 0)

    cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30",
                    "--no-probe-ftp", "--no-probe-smb"])

    assert "--disable-probes" in captured["enum_argv"]
    csv_idx = captured["enum_argv"].index("--disable-probes")
    csv = set(captured["enum_argv"][csv_idx + 1].split(","))
    assert csv == {"probe-ftp", "probe-smb"}


def test_orchestrator_auto_skips_module_with_missing_prereqs(tmp_path, monkeypatch):
    outdir = tmp_path / "eng"
    monkeypatch.setattr("recon.common.engagement_dir", lambda name: str(outdir))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    # Force nessus skip by clobbering config_loader path to a non-existent file.
    monkeypatch.setattr("recon.common.DEFAULT_CONFIG_PATH",
                        str(tmp_path / "nope.ini"))
    # Force smb-mass skip by removing nxc from PATH.
    import shutil
    original_which = shutil.which
    monkeypatch.setattr(
        shutil, "which",
        lambda name: None if name == "nxc" else original_which(name),
    )

    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").write("10.0.0.1\n"), 0)[1])
    monkeypatch.setattr("recon.cli_enum.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").close() or 0))
    monkeypatch.setattr("recon.cli_nuclei.main", lambda a: 0)
    nessus_called = []
    smb_called = []
    monkeypatch.setattr("recon.cli_nessus.main",
                        lambda a: nessus_called.append(a) or 0)
    monkeypatch.setattr("recon.cli_smb.main",
                        lambda a: smb_called.append(a) or 0)

    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])

    assert nessus_called == [], "nessus should be skipped when config missing"
    assert smb_called == [], "smb-mass should be skipped when nxc not on PATH"
    assert rc == 0

    manifest = json.loads((outdir / "run.json").read_text())
    nessus_stage = next(s for s in manifest["stages"] if s["name"] == "nessus")
    smb_stage = next(s for s in manifest["stages"] if s["name"] == "smb")
    assert nessus_stage["status"] == "skipped"
    assert smb_stage["status"] == "skipped"
    reasons = [m["reason"] for m in nessus_stage["modules_skipped"]]
    assert any("access_key" in r for r in reasons)


def test_orchestrator_target_parse_error_exits_2(tmp_path, monkeypatch):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name: str(tmp_path / "eng"))

    def boom(*_args):
        raise ValueError("no targets")

    monkeypatch.setattr("recon.common.parse_targets", boom)
    rc = cli_recon.main(["-n", "eng", "-r", "bogus"])
    assert rc == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_recon.py -v`
Expected: multiple failures (new tests + the now-removed `plan_stages` API).

- [ ] **Step 3: Rewrite `recon/cli_recon.py`**

Replace the file contents with:

```python
"""pt-recon: orchestrate registered modules across recon stages.

Default invocation (no subcommand) runs every enabled stage in order
(sweep → enum → nuclei → nessus → smb), with auto-skip on missing
prerequisites per the umbrella design spec §9.1.
"""
import os
import sys
import time
import argparse
import logging

from recon import common
from recon import cli_sweep, cli_enum, cli_nuclei, cli_nessus, cli_smb
from recon.modules import (
    _DEFAULT_REGISTRY,
    register_argparse_flags,
    evaluate_enabled,
    check_requirements,
    Ok, Skip, STAGES,
)
from recon.manifest import RunManifest, attach_run_log


# Stages this phase actually executes (feedback and report land in later phases).
_PHASE_1_STAGES = ["sweep", "enum", "nuclei", "nessus", "smb"]

# Map stage → callable main(argv) -> int. Subparser dispatch in Task 10 reuses this.
_STAGE_MAIN = {
    "sweep": cli_sweep.main,
    "enum": cli_enum.main,
    "nuclei": cli_nuclei.main,
    "nessus": cli_nessus.main,
    "smb": cli_smb.main,
}


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="pt-recon",
        description="Recon orchestrator (registry-driven).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-n", "--name", required=True, help="engagement name")
    parser.add_argument("-r", "--range", dest="range", help="CIDR or dashed range")
    parser.add_argument("-t", "--targets", dest="targets", help="comma-separated IPs")
    parser.add_argument("-iL", "--input-list", dest="infile", help="file of targets")
    register_argparse_flags(parser, _DEFAULT_REGISTRY)
    return parser


def _target_args(args, hosts_file):
    """Prefer the swept hosts file if present and non-empty, else pass through -r/-t/-iL."""
    if hosts_file and os.path.exists(hosts_file) and os.path.getsize(hosts_file) > 0:
        return ["-iL", hosts_file]
    passthrough = []
    if args.range:
        passthrough += ["-r", args.range]
    if args.targets:
        passthrough += ["-t", args.targets]
    if args.infile:
        passthrough += ["-iL", args.infile]
    return passthrough


def _enum_argv(args, hosts_file, enum_xlsx, enabled_modules):
    argv = _target_args(args, hosts_file) + ["-o", enum_xlsx]
    # Pass probes that were disabled by the operator so cli_enum can skip them.
    all_probe_names = {m.name for m in _DEFAULT_REGISTRY.iter(stage="enum")
                       if m.name.startswith("probe-")}
    disabled = sorted(all_probe_names - enabled_modules)
    if disabled:
        argv += ["--disable-probes", ",".join(disabled)]
    return argv


def _build_stage_argv(stage, args, hosts_file, enum_xlsx, outdir, enabled_modules):
    if stage == "sweep":
        return _target_args(args, None) + ["-o", hosts_file]
    if stage == "enum":
        return _enum_argv(args, hosts_file, enum_xlsx, enabled_modules)
    if stage == "nuclei":
        argv = ["-o", os.path.join(outdir, "nuclei.jsonl")]
        if os.path.exists(enum_xlsx):
            argv += ["--from-enum", enum_xlsx]
        else:
            argv += _target_args(args, hosts_file)
        return argv
    if stage == "nessus":
        return _target_args(args, hosts_file) + ["-n", args.name]
    if stage == "smb":
        return _target_args(args, hosts_file) + ["-o", os.path.join(outdir, "smb.xlsx")]
    raise ValueError(f"unknown stage: {stage}")


def main(argv=None):
    args = build_arg_parser().parse_args(argv)
    log = common.get_logger("pt-recon")

    outdir = common.engagement_dir(args.name)
    hosts_file = os.path.join(outdir, "live-hosts.txt")
    enum_xlsx = os.path.join(outdir, "enum.xlsx")

    # Resolve target list for the manifest.
    try:
        targets = common.parse_targets(args.range, args.targets, args.infile)
    except (ValueError, FileNotFoundError) as exc:
        log.error("target parse error: %s", exc)
        return 2

    targets_source = " ".join(
        flag for flag in (
            f"-r {args.range}" if args.range else None,
            f"-t {args.targets}" if args.targets else None,
            f"-iL {args.infile}" if args.infile else None,
        ) if flag
    )

    manifest = RunManifest(args.name, outdir, len(targets), targets_source)
    log_handler = attach_run_log(os.path.join(outdir, "run.log"))

    enabled_global = evaluate_enabled(args, _DEFAULT_REGISTRY)
    log.info("engagement '%s' → %s", args.name, outdir)
    log.info("enabled modules: %s", ", ".join(sorted(enabled_global)) or "(none)")

    overall_rc = 0
    try:
        for stage in _PHASE_1_STAGES:
            stage_modules = [m for m in _DEFAULT_REGISTRY.iter(stage=stage)
                             if m.name in enabled_global]
            modules_skipped = []

            if not stage_modules:
                log.info("=== stage: %s (skipped — disabled) ===", stage)
                manifest.add_stage(stage, "skipped", 0.0, [], [], None)
                continue

            # Auto-skip modules whose prereqs fail.
            runnable = []
            for m in stage_modules:
                check = check_requirements(m)
                if isinstance(check, Skip):
                    log.warning("%s skipped: %s", m.name, check.reason)
                    modules_skipped.append({"name": m.name, "reason": check.reason})
                else:
                    runnable.append(m)

            if not runnable:
                log.info("=== stage: %s (skipped — all modules unmet) ===", stage)
                manifest.add_stage(stage, "skipped", 0.0, [], modules_skipped, None)
                continue

            log.info("=== stage: %s ===", stage)
            stage_argv = _build_stage_argv(
                stage, args, hosts_file, enum_xlsx, outdir, enabled_global,
            )
            start = time.monotonic()
            rc = _STAGE_MAIN[stage](stage_argv)
            elapsed = time.monotonic() - start

            status = "ok" if rc == 0 else "error"
            if rc:
                overall_rc = 1
                log.warning("stage %s exited %s", stage, rc)
            manifest.add_stage(
                stage, status, elapsed,
                modules_run=[m.name for m in runnable],
                modules_skipped=modules_skipped,
                exit_code=rc,
            )

            # Sweep short-circuit: zero live hosts → bail out cleanly.
            if stage == "sweep" and os.path.exists(hosts_file) and \
                    os.path.getsize(hosts_file) == 0:
                log.info("sweep found no live hosts; stopping")
                manifest.set_exit_code(0)
                return 0

        manifest.set_exit_code(overall_rc)
        log.info("recon complete: %s (exit %s)", outdir, overall_rc)
        return overall_rc
    except KeyboardInterrupt:
        log.warning("interrupted")
        manifest.set_exit_code(130)
        return 130
    finally:
        # Detach log handler so subsequent runs don't accumulate file handles.
        for name in list(logging.Logger.manager.loggerDict):
            if name.startswith("pt-"):
                logging.getLogger(name).removeHandler(log_handler)
        log_handler.close()


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_recon.py -v`
Expected: all tests in `test_cli_recon.py` pass.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add recon/cli_recon.py tests/test_cli_recon.py
git commit -m "feat(pt-recon): registry-driven orchestrator with auto-skip and run manifest"
```

---

### Task 9: `--dry-run` and `--list-modules`

**Files:**
- Modify: `recon/cli_recon.py`
- Modify: `tests/test_cli_recon.py`

**Interfaces:**
- Consumes: parser from Task 8, registry, `check_requirements`.
- Produces:
  - New top-level flags `--dry-run` (boolean) and `--list-modules` (boolean).
  - `--list-modules` prints a fixed-width table of `name | stage | default | togglable | requires` to stdout and exits `0`.
  - `--dry-run` (with `-n`/`-r` etc. parsed normally) prints "planned stages", "enabled modules", and "would skip (reason)" sections to stdout and exits `0`. No subprocess invocations; no engagement dir mutation beyond `engagement_dir(name)` (which only creates the directory).

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli_recon.py`:

```python
def test_list_modules_prints_table_and_exits_zero(capsys):
    rc = cli_recon.main(["--list-modules"])
    assert rc == 0
    out = capsys.readouterr().out
    # spot-check a row per stage
    assert "sweep" in out
    assert "probe-ftp" in out
    assert "nuclei" in out
    assert "nessus" in out
    assert "smb-mass" in out
    # header
    assert "name" in out and "stage" in out and "default" in out


def test_dry_run_prints_plan_and_exits_zero(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    # nothing should actually run
    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: pytest.fail("sweep should not run in dry-run"))
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "planned stages" in out.lower()
    assert "enabled modules" in out.lower()
    # default-on probes should appear
    assert "probe-ftp" in out


def test_dry_run_shows_auto_skip_reasons(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    monkeypatch.setattr("recon.common.DEFAULT_CONFIG_PATH",
                        str(tmp_path / "nope.ini"))
    import shutil
    original_which = shutil.which
    monkeypatch.setattr(
        shutil, "which",
        lambda name: None if name == "nxc" else original_which(name),
    )
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30", "--dry-run"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "nessus" in out
    assert "access_key" in out or "nessus.access_key" in out
    assert "smb-mass" in out
    assert "nxc" in out
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_recon.py::test_list_modules_prints_table_and_exits_zero tests/test_cli_recon.py::test_dry_run_prints_plan_and_exits_zero tests/test_cli_recon.py::test_dry_run_shows_auto_skip_reasons -v`
Expected: failures because `--list-modules` / `--dry-run` aren't defined.

- [ ] **Step 3: Add the flags and handlers to `recon/cli_recon.py`**

In `build_arg_parser`, after the existing target flags but before `register_argparse_flags`, add:

```python
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="print planned stages, enabled modules, and skip reasons; do not run anything")
    parser.add_argument("--list-modules", dest="list_modules", action="store_true",
                        help="print the registry as a table and exit")
```

Make `-n/--name` no longer `required=True`, since `--list-modules` doesn't need it. Change:

```python
    parser.add_argument("-n", "--name", required=True, help="engagement name")
```

to:

```python
    parser.add_argument("-n", "--name", help="engagement name (required unless --list-modules)")
```

In `main`, immediately after `args = build_arg_parser().parse_args(argv)`, before the logger line, add:

```python
    if args.list_modules:
        _print_module_table()
        return 0
    if not args.name:
        print("error: -n/--name is required (unless --list-modules is used)",
              file=sys.stderr)
        return 2
```

Add the two helpers above `main`:

```python
def _print_module_table():
    cols = ("name", "stage", "default", "togglable", "requires")
    rows = [cols]
    for m in _DEFAULT_REGISTRY.iter():
        reqs = ", ".join(_render_req(r) for r in m.requires) or "—"
        rows.append((
            m.name, m.stage,
            "on" if m.default_on else "off",
            "yes" if m.togglable else "no",
            reqs,
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(cols))]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    for i, row in enumerate(rows):
        print(fmt.format(*row))
        if i == 0:
            print("  ".join("-" * w for w in widths))


def _render_req(req):
    from recon.modules import Tool, ConfigKey, Soft
    if isinstance(req, Tool):
        return f"tool:{req.name}"
    if isinstance(req, ConfigKey):
        return f"config:{req.section}.{req.key}"
    if isinstance(req, Soft):
        return f"soft({_render_req(req.inner)})"
    return repr(req)
```

In `main`, after the `enabled_global = evaluate_enabled(...)` line, add the dry-run short-circuit:

```python
    if args.dry_run:
        print("planned stages:")
        for stage in _PHASE_1_STAGES:
            stage_mods = [m for m in _DEFAULT_REGISTRY.iter(stage=stage)
                          if m.name in enabled_global]
            if not stage_mods:
                print(f"  {stage}: (skipped — disabled)")
                continue
            runnable, skip_reasons = [], []
            for m in stage_mods:
                check = check_requirements(m)
                if isinstance(check, Skip):
                    skip_reasons.append((m.name, check.reason))
                else:
                    runnable.append(m.name)
            if runnable:
                print(f"  {stage}: would run {', '.join(runnable)}")
            for n, r in skip_reasons:
                print(f"    skip {n}: {r}")
            if not runnable and not skip_reasons:
                print(f"  {stage}: (skipped — disabled)")
        print()
        print("enabled modules:", ", ".join(sorted(enabled_global)) or "(none)")
        return 0
```

(This short-circuit must run *before* `manifest = RunManifest(...)` so dry-run leaves no artifacts on disk. Move the `RunManifest` and `attach_run_log` lines to immediately after the dry-run check.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_recon.py -v`
Expected: all tests in `test_cli_recon.py` pass.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add recon/cli_recon.py tests/test_cli_recon.py
git commit -m "feat(pt-recon): --dry-run and --list-modules"
```

---

### Task 10: Subparser routing for ad-hoc per-stage runs

**Files:**
- Modify: `recon/cli_recon.py`
- Modify: `tests/test_cli_recon.py`

**Interfaces:**
- Consumes: `_STAGE_MAIN` (from Task 8); existing `cli_<stage>.build_arg_parser` is not used here — subparser delegates by simply passing the remaining argv straight to `cli_<stage>.main`.
- Produces: subcommand dispatch in `cli_recon.main` so that `pt-recon sweep ARGS...`, `pt-recon enum ARGS...`, `pt-recon nuclei ARGS...`, `pt-recon nessus ARGS...`, `pt-recon smb ARGS...` invoke the corresponding `cli_<stage>.main(ARGS)` unchanged and return its exit code.

Implementation approach: peek at `argv[0]` before the orchestrator parser runs. If it matches a known subcommand, dispatch and return.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_cli_recon.py`:

```python
def test_subparser_dispatches_sweep(monkeypatch):
    captured = {}

    def fake(argv):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr("recon.cli_sweep.main", fake)
    rc = cli_recon.main(["sweep", "-r", "10.0.0.0/30", "-o", "/tmp/x"])
    assert rc == 0
    assert captured["argv"] == ["-r", "10.0.0.0/30", "-o", "/tmp/x"]


def test_subparser_dispatches_enum(monkeypatch):
    captured = {}

    def fake(argv):
        captured["argv"] = list(argv)
        return 0

    monkeypatch.setattr("recon.cli_enum.main", fake)
    rc = cli_recon.main(["enum", "-t", "10.0.0.1", "-o", "/tmp/e.xlsx"])
    assert rc == 0
    assert captured["argv"] == ["-t", "10.0.0.1", "-o", "/tmp/e.xlsx"]


def test_subparser_propagates_exit_code(monkeypatch):
    monkeypatch.setattr("recon.cli_nuclei.main", lambda argv: 7)
    rc = cli_recon.main(["nuclei", "-iL", "/tmp/h.txt"])
    assert rc == 7


def test_unknown_subcommand_falls_through_to_orchestrator(monkeypatch, tmp_path):
    """`pt-recon -n foo -r ...` (no subcommand) still works as before."""
    monkeypatch.setattr("recon.common.engagement_dir",
                        lambda name: str(tmp_path / "eng"))
    monkeypatch.setattr("recon.common.parse_targets",
                        lambda r, t, i: ["10.0.0.1"])
    monkeypatch.setattr("recon.cli_sweep.main",
                        lambda a: (open(a[a.index("-o") + 1], "w").write("") or 0))
    rc = cli_recon.main(["-n", "eng", "-r", "10.0.0.0/30"])
    assert rc == 0  # sweep with empty result short-circuits
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_recon.py::test_subparser_dispatches_sweep tests/test_cli_recon.py::test_subparser_dispatches_enum tests/test_cli_recon.py::test_subparser_propagates_exit_code -v`
Expected: failures — `cli_recon.main(["sweep", ...])` currently tries to parse with the orchestrator parser and fails.

- [ ] **Step 3: Add the subcommand short-circuit to `recon/cli_recon.py`**

Replace the first lines of `main` (currently `args = build_arg_parser().parse_args(argv)`) with:

```python
def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in _STAGE_MAIN:
        stage = argv[0]
        return _STAGE_MAIN[stage](argv[1:])
    args = build_arg_parser().parse_args(argv)
```

Update the parser's epilog so `pt-recon --help` documents the subcommands. In `build_arg_parser`, replace the `argparse.ArgumentParser(...)` call with:

```python
    parser = argparse.ArgumentParser(
        prog="pt-recon",
        description="Recon orchestrator (registry-driven).",
        epilog=(
            "subcommands (ad-hoc per-stage runs):\n"
            "  pt-recon sweep  ARGS    run only the sweep stage\n"
            "  pt-recon enum   ARGS    run only the enum stage\n"
            "  pt-recon nuclei ARGS    run only the nuclei stage\n"
            "  pt-recon nessus ARGS    run only the nessus stage\n"
            "  pt-recon smb    ARGS    run only the smb stage\n"
            "\n"
            "exit codes:\n"
            "  0   every attempted stage succeeded\n"
            "  1   ≥1 stage exited non-zero\n"
            "  2   argument / target / config error\n"
            "  130 interrupted (Ctrl-C)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_recon.py -v`
Expected: all tests in `test_cli_recon.py` pass.

- [ ] **Step 5: Run the full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add recon/cli_recon.py tests/test_cli_recon.py
git commit -m "feat(pt-recon): subcommand dispatch (sweep/enum/nuclei/nessus/smb)"
```

---

### Task 11: Delete per-tool binaries; update README

**Files:**
- Delete: `bin/pt-sweep`
- Delete: `bin/pt-enum`
- Delete: `bin/pt-nuclei`
- Delete: `bin/pt-nessus`
- Delete: `bin/pt-smb`
- Modify: `README.md`

**Interfaces:** none — UX-only change.

- [ ] **Step 1: Delete the five wrapper scripts**

Run:

```bash
git rm bin/pt-sweep bin/pt-enum bin/pt-nuclei bin/pt-nessus bin/pt-smb
```

- [ ] **Step 2: Update `README.md`**

Open `README.md`. Replace the tools list block:

```markdown
Tools (symlinked into `../../go-tools/bin/` with a `pt-` prefix):
- `pt-enum`   — service enumeration + web fingerprint → Excel
- `pt-nessus` — launch a Nessus scan via the REST API
- `pt-nuclei` — run nuclei → JSONL
- `pt-smb`    — netexec SMB mass-recon → Excel
- `pt-sweep`  — live-host discovery → hosts file
- `pt-recon`  — orchestrate the above
```

with:

```markdown
Tool: `pt-recon` — registry-driven recon orchestrator. All stages are
default-on (auto-skip if their prerequisites are missing).

Stages are exposed as subcommands for ad-hoc per-stage use:
- `pt-recon sweep`  — live-host discovery → hosts file
- `pt-recon enum`   — service enumeration + web fingerprint → Excel
- `pt-recon nuclei` — run nuclei → JSONL
- `pt-recon nessus` — launch a Nessus scan via the REST API
- `pt-recon smb`    — netexec SMB mass-recon → Excel

Run `pt-recon --list-modules` to inspect the registry; `pt-recon --dry-run`
shows what would run for the current target set.
```

- [ ] **Step 3: Run the full suite**

Run: `python -m pytest -q`
Expected: all tests pass.

- [ ] **Step 4: Verify `pt-recon --help` and `pt-recon --list-modules` work end-to-end**

Run: `bin/pt-recon --help`
Expected: shows orchestrator description, stage and module flags, subcommand block, exit-code block.

Run: `bin/pt-recon --list-modules`
Expected: 10-row table of registered modules.

Run: `bin/pt-recon sweep --help`
Expected: pt-sweep's own help (Task 10 dispatch passes through).

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "chore: drop per-tool bin/pt-* shims; update README for single-binary UX"
```

---

## Self-Review

**1. Spec coverage check**

| Spec §12 phase-1 bullet                            | Plan task(s)            |
| -------------------------------------------------- | ----------------------- |
| Add `modules.py` with `@module`, Module, Requirement types | Tasks 1, 2              |
| Convert existing functionality to registered modules        | Task 5                  |
| Rewire `cli_recon.py` to generate flags + iterate registry  | Tasks 4, 8              |
| Add subparser routing                                       | Task 10                 |
| Add `--dry-run`, `--list-modules`                           | Task 9                  |
| Add `run.json`, `run.log`                                   | Tasks 6, 8              |
| Flip `nessus` / `smb` default-on; auto-skip                 | Tasks 3, 5, 8           |
| Delete `bin/pt-*` (per-tool shims)                          | Task 11                 |
| Tests for registry / dispatch / generated flags / auto-skip / exit codes | Tasks 1–10 (TDD per task) |
| No new probes in this phase                                 | (enforced by scope)     |

All bullets accounted for.

**2. Placeholder scan**

No `TBD` / `TODO` / `implement later` strings. Every step contains the exact code or command to run.

**3. Type/signature consistency**

- `Module` fields and their default values are introduced in Task 1 and used identically in every later task.
- `check_requirements(mod, config_loader=None) -> Ok | Skip` introduced in Task 3, called identically in Tasks 8 and 9.
- `register_argparse_flags(parser, registry)` and `evaluate_enabled(args, registry) -> set[str]` introduced in Task 4, called identically in Tasks 8 and 9.
- `RunManifest(engagement, outdir, targets_count, targets_source, *, clock=None)` constructor introduced in Task 6, called identically in Task 8.
- `dispatch_probes(open_ports, web_ports, probe_fns=None, disabled_probes=None)` introduced in Task 7, called identically in Task 8 (which builds the CSV passed via `--disable-probes`).
- `_STAGE_MAIN` mapping introduced in Task 8, reused unchanged in Task 10.

All signatures consistent across tasks.
