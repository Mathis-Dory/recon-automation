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


def test_manifest_writes_placeholder_on_init(tmp_path):
    """RunManifest.__init__ should immediately write a placeholder run.json with stages: [] and exit_code: null."""
    m = RunManifest("acme", str(tmp_path), 1, "-t 1.1.1.1",
                    clock=lambda: datetime(2026, 6, 22))
    assert (tmp_path / "run.json").exists()
    data = json.loads((tmp_path / "run.json").read_text())
    assert data["stages"] == []
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


def test_attach_run_log_formats_warning_as_warn(tmp_path):
    """run.log must use [WARN] (4 chars) not [WARNING] per spec §9.1."""
    log_path = str(tmp_path / "run.log")
    logger = common.get_logger("pt-warntest")
    handler = attach_run_log(log_path, logger_prefix="pt-")
    try:
        logger.warning("hi")
        handler.flush()
        content = (tmp_path / "run.log").read_text()
        assert "[WARN]" in content
        assert "[WARNING]" not in content
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
