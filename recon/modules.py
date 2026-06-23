"""Module registry primitives: dataclass, requirement types, and constants."""

from __future__ import annotations

import argparse  # noqa: F401  (used in type hint on register_argparse_flags)
import configparser
import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

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
    inner: Tool | ConfigKey


Requirement = Tool | ConfigKey | Soft


@dataclass
class Ok:
    """Requirement check passed."""


@dataclass
class Skip:
    """Requirement check failed — the module should be skipped."""

    reason: str


def _check_one(req: Requirement, config_loader: Callable[[], dict]) -> Skip | None:
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


def check_requirements(mod: Module, config_loader: Callable[[], dict] | None = None):
    loader = config_loader or _default_config_loader
    for req in mod.requires:
        result = _check_one(req, loader)
        if result is not None:
            return result
    return Ok()


@dataclass
class Module:
    name: str
    stage: str
    help: str
    requires: list[Requirement] = field(default_factory=list)
    default_on: bool = True
    togglable: bool = True
    run: Callable | None = None


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

    def names(self) -> list[str]:
        return list(self._modules)

    def iter(self, stage: str | None = None):
        for m in self._modules.values():
            if stage is None or m.stage == stage:
                yield m


_DEFAULT_REGISTRY = Registry()


def module(
    *,
    name: str,
    stage: str,
    help: str,
    requires: list[Requirement] | None = None,
    default_on: bool = True,
    togglable: bool = True,
    registry: Registry | None = None,
):
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
