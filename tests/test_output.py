import os
import logging
from recon import common


def test_engagement_dir_created(tmp_path):
    d = common.engagement_dir("job1", root=str(tmp_path))
    assert os.path.isdir(d)
    assert d.rstrip("/").endswith("job1")


def test_get_logger_no_duplicate_handlers():
    log1 = common.get_logger("recon.test")
    n = len(log1.handlers)
    log2 = common.get_logger("recon.test")
    assert log1 is log2
    assert len(log2.handlers) == n
    assert isinstance(log1, logging.Logger)
