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


def test_load_scope_parses_cidrs_and_comments(tmp_path):
    f = tmp_path / "scope.txt"
    f.write_text(
        "# engagement scope\n"
        "10.0.0.0/24\n"
        "\n"
        "192.168.1.0/28  # vlan-admin\n"
    )
    nets = common.load_scope(str(f))
    assert [str(n) for n in nets] == ["10.0.0.0/24", "192.168.1.0/28"]


def test_load_scope_empty_file_returns_empty_list(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("# just a comment\n\n")
    assert common.load_scope(str(f)) == []


def test_load_scope_rejects_bad_cidr(tmp_path):
    f = tmp_path / "bad.txt"
    f.write_text("not-a-cidr\n")
    with pytest.raises(ValueError):
        common.load_scope(str(f))


def test_targets_in_scope_true_when_inside_any_net():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("192.168.1.0/28")]
    assert common.targets_in_scope("10.0.0.5", nets) is True
    assert common.targets_in_scope("192.168.1.10", nets) is True


def test_targets_in_scope_false_when_outside_all_nets():
    import ipaddress
    nets = [ipaddress.ip_network("10.0.0.0/24")]
    assert common.targets_in_scope("11.0.0.5", nets) is False
    assert common.targets_in_scope("192.168.1.10", nets) is False


def test_targets_in_scope_empty_nets_is_false():
    assert common.targets_in_scope("10.0.0.5", []) is False
