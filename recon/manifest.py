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


# Artifact each stage writes; used by --resume to confirm completion on disk.
STAGE_ARTIFACTS = {
    "sweep": "live-hosts.txt",
    "enum": "enum.xlsx",
    "nuclei": "nuclei.jsonl",
    "smb": "smb.xlsx",
    # nessus has no local artifact — completion relies on status alone
}


class RunManifest:
    """Incrementally-written run.json describing one orchestrator invocation."""

    def __init__(self, engagement: str, outdir: str,
                 targets_count: int, targets_source: str,
                 *, clock: Optional[Callable[[], datetime]] = None) -> None:
        self._clock = clock or _default_clock
        self.outdir = outdir
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

    @classmethod
    def from_existing(cls, engagement: str, outdir: str,
                      targets_count: int, targets_source: str,
                      *, clock: Optional[Callable[[], datetime]] = None) -> "RunManifest":
        """Load any prior run.json under `outdir`, preserving its stages list.

        If no run.json exists, behaves like the normal constructor — a fresh
        manifest is written. Useful for ``--resume``: prior stage records are
        kept; subsequent ``add_stage`` calls replace records by name.
        """
        path = os.path.join(outdir, "run.json")
        if not os.path.exists(path):
            return cls(engagement, outdir, targets_count, targets_source, clock=clock)
        inst = cls.__new__(cls)
        inst._clock = clock or _default_clock
        inst.outdir = outdir
        inst.path = path
        try:
            with open(path) as fh:
                inst._data = json.load(fh)
        except (OSError, ValueError):
            # Corrupt or unreadable — fall back to a fresh manifest.
            return cls(engagement, outdir, targets_count, targets_source, clock=clock)
        # Refresh the targets metadata for the new run while keeping stage history.
        inst._data["engagement"] = engagement
        inst._data["targets"] = {"count": targets_count, "source": targets_source}
        inst._data["exit_code"] = None
        inst._data["finished_at"] = None
        inst._data.setdefault("stages", [])
        return inst

    def is_stage_complete(self, name: str) -> bool:
        """True iff a prior record for `name` is `status=ok` AND its artifact exists.

        Stages with no on-disk artifact (e.g. nessus) require only the status check.
        """
        record = next((s for s in self._data["stages"] if s.get("name") == name), None)
        if record is None or record.get("status") != "ok":
            return False
        artifact = STAGE_ARTIFACTS.get(name)
        if artifact is None:
            return True
        return os.path.exists(os.path.join(self.outdir, artifact))

    def add_stage(self, name: str, status: str, elapsed_s: float,
                  modules_run: List[str],
                  modules_skipped: List[Dict[str, str]],
                  exit_code: Optional[int]) -> None:
        record = {
            "name": name,
            "status": status,
            "elapsed_s": round(float(elapsed_s), 2),
            "modules_run": list(modules_run),
            "modules_skipped": list(modules_skipped),
            "exit_code": exit_code,
        }
        # Replace any prior record for the same stage (resume re-run case).
        stages = self._data["stages"]
        for i, prior in enumerate(stages):
            if prior.get("name") == name:
                stages[i] = record
                break
        else:
            stages.append(record)
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
