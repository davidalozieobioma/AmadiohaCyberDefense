from amadioha import network_scanner


def fake_scan_port(target, port, timeout):
    # Simulate ports 22 and 80 being open
    if port in (22, 80):
        return port
    return None


def test_scan_range_monkeypatch(monkeypatch):
    monkeypatch.setattr(
        network_scanner, "scan_port", fake_scan_port
    )
    # Keep the call arguments on multiple lines to satisfy line-length checks
    open_ports = network_scanner.scan_range_concurrent(
        "127.0.0.1",
        20,
        85,
        0.1,
        workers=5,
    )
    assert 22 in open_ports
    assert 80 in open_ports
