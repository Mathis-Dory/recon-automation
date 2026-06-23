import pytest

from recon import common


def test_default_web_ports_contents():
    assert common.DEFAULT_WEB_PORTS == [
        80,
        81,
        88,
        443,
        446,
        8080,
        8081,
        8082,
        8083,
        8085,
        8443,
        8888,
        9000,
        9001,
        9090,
        8000,
        8008,
        8090,
        8182,
        8281,
        7001,
        10000,
    ]


def test_parse_ports_list_and_range():
    assert common.parse_ports("80,443,8000-8002") == [80, 443, 8000, 8001, 8002]


def test_parse_ports_dedups():
    assert common.parse_ports("80,80,443") == [80, 443]


def test_parse_ports_rejects_bad():
    with pytest.raises(ValueError):
        common.parse_ports("80,abc")
    with pytest.raises(ValueError):
        common.parse_ports("70000")


def test_default_enum_ports_includes_service_and_web():
    ports = common.default_enum_ports()
    for p in (21, 22, 23, 139, 445, 80, 443, 10000):
        assert p in ports
    assert ports == sorted(ports)
