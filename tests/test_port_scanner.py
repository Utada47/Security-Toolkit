import socket
import threading
import pytest
from sectoolkit.port_scanner import scan_port, scan_ports, scan_common_ports, COMMON_PORTS


@pytest.fixture
def open_port():
    """Spin up a real local TCP server on an OS-assigned free port."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))  # port 0 = let the OS pick a free port
    server.listen(1)
    port = server.getsockname()[1]

    stop_flag = threading.Event()

    def accept_loop():
        server.settimeout(0.2)
        while not stop_flag.is_set():
            try:
                conn, _ = server.accept()
                conn.close()
            except socket.timeout:
                continue
            except OSError:
                break

    thread = threading.Thread(target=accept_loop, daemon=True)
    thread.start()

    yield port

    stop_flag.set()
    server.close()
    thread.join(timeout=1)


@pytest.fixture
def closed_port():
    """Ask the OS for a genuinely free port, then release it immediately.

    We deliberately do NOT use 'open_port + 1' as a stand-in for a closed
    port: on Windows, high ephemeral ports (49152+) can be silently
    reserved by Hyper-V/WSL for NAT port-forwarding, so an adjacent port
    number is not reliably closed there. Asking the OS directly for a free
    port (and releasing it right before the test) is portable and avoids
    that flakiness.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def test_scan_port_detects_open_port(open_port):
    assert scan_port("127.0.0.1", open_port, timeout=1) is True


def test_scan_port_detects_closed_port(closed_port):
    assert scan_port("127.0.0.1", closed_port, timeout=0.5) is False


def test_scan_ports_returns_correct_status_for_each_port(open_port, closed_port):
    results = scan_ports("127.0.0.1", [open_port, closed_port], timeout=0.5)

    assert results[open_port] is True
    assert results[closed_port] is False


def test_scan_ports_handles_empty_list():
    assert scan_ports("127.0.0.1", [], timeout=0.5) == {}


def test_common_ports_dict_has_expected_entries():
    assert COMMON_PORTS[22] == "SSH"
    assert COMMON_PORTS[443] == "HTTPS"
    assert COMMON_PORTS[80] == "HTTP"


def test_scan_common_ports_only_returns_open_ones(monkeypatch):
    # Simulate only port 22 and 443 being open, rest closed.
    def fake_scan_ports(host, ports, timeout=1.0, max_workers=50):
        return {p: (p in (22, 443)) for p in ports}

    monkeypatch.setattr("sectoolkit.port_scanner.scan_ports", fake_scan_ports)

    results = scan_common_ports("somehost")

    assert results == {22: "SSH", 443: "HTTPS"}
