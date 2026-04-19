import pytest

from cryptologik_cli.tls_utils import parse_tls_target


def test_parse_hostname_defaults_to_443():
    host, port = parse_tls_target("example.com")
    assert host == "example.com"
    assert port == 443


def test_parse_hostname_with_port():
    host, port = parse_tls_target("example.com:8443")
    assert host == "example.com"
    assert port == 8443


def test_parse_ipv4_with_port():
    host, port = parse_tls_target("127.0.0.1:9443")
    assert host == "127.0.0.1"
    assert port == 9443


def test_parse_bracketed_ipv6_default_port():
    host, port = parse_tls_target("[2001:db8::1]")
    assert host == "2001:db8::1"
    assert port == 443


def test_parse_bracketed_ipv6_with_port():
    host, port = parse_tls_target("[2001:db8::1]:10443")
    assert host == "2001:db8::1"
    assert port == 10443


@pytest.mark.parametrize("bad", ["", "   ", ":443", "example.com:0", "example.com:70000", "[2001:db8::1"])
def test_parse_invalid_targets(bad):
    with pytest.raises(ValueError):
        parse_tls_target(bad)
