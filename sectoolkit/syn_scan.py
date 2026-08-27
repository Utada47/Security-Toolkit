"""Utility to detect and enumerate open ports via TCP SYN scan (fast)."""
import socket
from typing import List, Dict, Any


def syn_scan(host: str, ports: List[int], timeout: float = 1.0) -> Dict[int, str]:
    """Perform a basic TCP SYN scan (requires raw socket privileges).
    
    Returns a dict mapping port -> status ('open', 'closed', 'filtered').
    """
    results = {}
    for port in ports:
        try:
            # Simple connect_ex used as placeholder for SYN (requires privileges to craft raw packets)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            rc = sock.connect_ex((host, port))
            if rc == 0:
                results[port] = "open"
            else:
                results[port] = "closed"
            sock.close()
        except Exception:
            results[port] = "filtered"
    return results
