import pytest
from recon import cli_nuclei, common


def test_collect_targets_from_enum(tmp_path):
    rows = [{"ip": "10.0.0.1", "port": 80, "state": "open", "service": "http", "finding": ""}]
    path = str(tmp_path / "enum.xlsx")
    common.write_enum_workbook(rows, path)
    args = cli_nuclei.build_arg_parser().parse_args(["--from-enum", path])
    targets = cli_nuclei.collect_targets(args)
    assert "http://10.0.0.1:80" in targets


def test_collect_targets_from_range():
    args = cli_nuclei.build_arg_parser().parse_args(["-t", "10.0.0.1,10.0.0.2"])
    targets = cli_nuclei.collect_targets(args)
    assert targets == ["10.0.0.1", "10.0.0.2"]


def test_collect_targets_none_raises():
    args = cli_nuclei.build_arg_parser().parse_args([])
    with pytest.raises(ValueError):
        cli_nuclei.collect_targets(args)
