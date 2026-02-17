"""Utils tests aligned with current utils API."""

from amadioha import utils


def test_is_valid_ip():
    assert utils.is_valid_ip("192.168.1.1") is True
    assert utils.is_valid_ip("255.255.255.255") is True
    assert utils.is_valid_ip("0.0.0.0") is True
    assert utils.is_valid_ip("256.1.1.1") is False
    assert utils.is_valid_ip("invalid") is False
    assert utils.is_valid_ip("192.168.1") is False
