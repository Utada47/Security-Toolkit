"""Simple ICMP ping sweep utility (requires admin privileges)."""
import socket
import struct
import time
from typing import List, Dict, Any

ICMP_ECHO_REQUEST = 8
ICMP_ECHO_REPLY = 0

def checksum(source_string: bytes) -> int:
    """Calculate checksum for ICMP packet."""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id: int) -> bytes:
    """Create an ICMP echo request packet with given ID."""
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = struct.pack('d', time.time())
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, 1)
    return header + data


def ping(host: str, timeout: float = 1.0) -> bool:
    """Send one ICMP echo request and return True if reply received."""
    try:
        icmp = socket.getprotobyname('icmp')
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp) as sock:
            sock.settimeout(timeout)
            pid = os.getpid() & 0xFFFF
            packet = create_packet(pid)
            sock.sendto(packet, (host, 1))
            start = time.time()
            while True:
                rec_packet, addr = sock.recvfrom(1024)
                icmp_header = rec_packet[20:28]
                _type, code, _checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
                if p_id == pid and _type == ICMP_ECHO_REPLY:
                    return True
                if time.time() - start > timeout:
                    return False
    except Exception:
        return False


def ping_sweep(network: str, timeout: float = 1.0) -> Dict[str, Any]:
    """Sweep a /24 network (e.g., '192.168.1.0') and return dict of host -> reachable bool."""
    base = network.rstrip('.0')
    results = {}
    for i in range(1, 255):
        host = f"{base}.{i}"
        results[host] = ping(host, timeout)
    return results
