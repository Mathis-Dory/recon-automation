import pytest
from recon import common


def test_expand_single_ip():
    assert common.expand_range("10.0.0.5") == ["10.0.0.5"]


def test_expand_cidr():
    assert common.expand_range("10.0.0.0/30") == [
        "10.0.0.1", "10.0.0.2",
    ]


def test_expand_dashed_full():
    assert common.expand_range("10.0.0.1-10.0.0.3") == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]


def test_expand_dashed_short():
    assert common.expand_range("10.0.0.1-3") == [
        "10.0.0.1", "10.0.0.2", "10.0.0.3",
    ]


def test_parse_targets_merges_and_dedups(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("10.0.0.9\n# comment\n\n10.0.0.1\n")
    out = common.parse_targets(
        range_="10.0.0.1-2", targets="10.0.0.9,10.0.0.5", infile=str(f)
    )
    assert out == ["10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.9"]


def test_parse_targets_empty_raises():
    with pytest.raises(ValueError):
        common.parse_targets()
