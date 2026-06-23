"""Run manifest (run.json) writer and orchestrator-log tee."""
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_clock() -> datetime:
    return datetime.now(timezone.utc)


class RunManifest:
    """Incrementally-written run.json describing one orchestrator invocation."""

    def __init__(self, engagement: str, outdir: str,
                 targets_count: int, targets_source: str,
                 *, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._clock = clock or _default_clock
        self.path = os.path.join(outdir, "run.json")
        self._data: Dict = {
            "engagement": engagement,
            "started_at": _iso(self._clock()),
            "finished_at": None,
            "targets": {"count": targets_count, "source": targets_source},
            "stages": [],
            "exit_code": None,
        }
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
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w") as fh:
            json.dump(self._data, fh, indent=2, sort_keys=False)


def attach_run_log(path: str, logger_prefix: str = "pt-") -> logging.FileHandler:
    """Attach an INFO FileHandler to every existing logger whose name starts with prefix.

    Idempotent: if a logger already has a FileHandler with the same baseFilename,
    no second handler is added to that logger.
    """
    handler = logging.FileHandler(path, mode="w")
    handler.setLevel(logging.INFO)
    handler.setFormatter(logging.Formatter("[%(levelname).4s] %(name)s: %(message)s"))
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
