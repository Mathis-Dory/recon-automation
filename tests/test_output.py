import os
import logging
from recon import common


def test_engagement_dir_created(tmp_path):
    d = common.engagement_dir("job1", root=str(tmp_path))
    assert os.path.isdir(d)
    assert d.rstrip("/").endswith("job1")


def test_engagement_dir_respects_outdir_arg(tmp_path, monkeypatch):
    monkeypatch.delenv("PT_RECON_OUTPUT", raising=False)
    d = common.engagement_dir("acme", root=str(tmp_path / "vault"))
    assert d == os.path.join(str(tmp_path / "vault"), "acme")
    assert os.path.isdir(d)


def test_engagement_dir_respects_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("PT_RECON_OUTPUT", str(tmp_path / "from-env"))
    d = common.engagement_dir("acme")
    assert d == os.path.join(str(tmp_path / "from-env"), "acme")
    assert os.path.isdir(d)


def test_engagement_dir_falls_back_to_default(monkeypatch, tmp_path):
    monkeypatch.delenv("PT_RECON_OUTPUT", raising=False)
    monkeypatch.setattr(common, "DEFAULT_OUTPUT_ROOT", str(tmp_path / "default"))
    d = common.engagement_dir("acme")
    assert d == os.path.join(str(tmp_path / "default"), "acme")


def test_outdir_arg_overrides_env_var(tmp_path, monkeypatch):
    monkeypatch.setenv("PT_RECON_OUTPUT", str(tmp_path / "ignored"))
    d = common.engagement_dir("acme", root=str(tmp_path / "winner"))
    assert d == os.path.join(str(tmp_path / "winner"), "acme")
    assert not os.path.exists(tmp_path / "ignored")


def test_engagement_dir_expands_user_in_default(monkeypatch, tmp_path):
    monkeypatch.delenv("PT_RECON_OUTPUT", raising=False)
    monkeypatch.setattr(common, "DEFAULT_OUTPUT_ROOT", "~/__fake_engagement_root__")
    monkeypatch.setenv("HOME", str(tmp_path))
    d = common.engagement_dir("acme")
    assert d.startswith(str(tmp_path / "__fake_engagement_root__"))


def test_get_logger_no_duplicate_handlers():
    log1 = common.get_logger("recon.test")
    n = len(log1.handlers)
    log2 = common.get_logger("recon.test")
    assert log1 is log2
    assert len(log2.handlers) == n
    assert isinstance(log1, logging.Logger)
