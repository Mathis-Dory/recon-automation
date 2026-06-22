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
