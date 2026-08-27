"""DNS security checks, including recursion detection."""
import socket
import struct
from typing import Dict, Any


def dns_query(host: str, port: int = 53) -> bytes:
    """Create a simple DNS query (A record for example.com) with recursion desired flag."""
    transaction_id = b"\x12\x34"  # arbitrary
    flags = b"\x01\x00"  # standard query, recursion desired
    qdcount = b"\x00\x01"  # one question
    ancount = b"\x00\x00"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    header = transaction_id + flags + qdcount + ancount + nscount + arcount
    # query for example.com A
    query_name = b"\x07example\x03com\x00"
    qtype = b"\x00\x01"  # A
    qclass = b"\x00\x01"  # IN
    question = query_name + qtype + qclass
    return header + question


def parse_dns_response(response: bytes) -> Dict[str, Any]:
    """Parse DNS response flags to check recursion available (RA)."""
    if len(response) < 12:
        return {"error": "Response too short"}
    flags = response[2:4]
    # RA is bit 0 of the second byte (0x80)
    ra = bool(flags[1] & 0x80)
    return {"recursion_available": ra}


def check_dns_recursion(host: str, timeout: int = 3) -> Dict[str, Any]:
    """Check if the DNS server allows recursion (RA flag)."""
    result = {"host": host, "recursion_allowed": False, "error": None}
    try:
        query = dns_query(host)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(query, (host, 53))
            response, _ = sock.recvfrom(512)
            parsed = parse_dns_response(response)
            result["recursion_allowed"] = parsed.get("recursion_available", False)
    except Exception as e:
        result["error"] = str(e)
    return result
