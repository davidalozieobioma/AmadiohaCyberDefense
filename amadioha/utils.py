"""Utility helpers for Amadioha."""

import ipaddress


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False
