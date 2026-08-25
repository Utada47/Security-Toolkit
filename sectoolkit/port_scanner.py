"""TCP port scanner for checking which ports are open on a host.

Intended for scanning systems you own or are explicitly authorized to
test (e.g. auditing your own server's exposed services). Scanning hosts
you don't have permission to test may be illegal depending on your
jurisdiction — this tool doesn't gate that, the same way a screwdriver
doesn't check whose door you're opening.
"""
import socket
import concurrent.futures

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    27017: "MongoDB",
}


def scan_port(host: str, port: int, timeout: float = 1.0) -> bool:
    """Return True if the port is open (accepts a TCP connection)."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def scan_ports(host: str, ports: list, timeout: float = 1.0, max_workers: int = 50) -> dict:
    """Scan multiple ports concurrently. Returns {port: is_open}.

    Concurrency keeps scanning a reasonable port range fast — scanning
    sequentially with a 1s timeout per port would make even the ~16
    COMMON_PORTS entries take up to 16 seconds on a host that drops
    packets instead of actively refusing them.
    """
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            results[port] = future.result()
    return results


def scan_common_ports(host: str, timeout: float = 1.0) -> dict:
    """Scan the well-known COMMON_PORTS list and return open ones with labels."""
    results = scan_ports(host, list(COMMON_PORTS.keys()), timeout=timeout)
    return {
        port: COMMON_PORTS[port]
        for port, is_open in sorted(results.items())
        if is_open
    }
