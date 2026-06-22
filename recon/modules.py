"""Module registry primitives: dataclass, requirement types, and constants."""
from __future__ import annotations

import shutil
import configparser
from pathlib import Path
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


@dataclass
class Module:
    name: str
    stage: str
    help: str
    requires: List[Requirement] = field(default_factory=list)
    default_on: bool = True
    togglable: bool = True
    run: Optional[Callable] = None


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
