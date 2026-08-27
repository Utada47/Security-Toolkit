"""IPv6 address utilities: validation, expansion, compression."""
import ipaddress
from typing import Dict, Any


def validate_ipv6(address: str) -> bool:
    """Return True if address is a valid IPv6 address."""
    try:
        ipaddress.IPv6Address(address)
        return True
    except Exception:
        return False


def expand_ipv6(address: str) -> str:
    """Return the fully expanded IPv6 address (no :: shorthand)."""
    try:
        return ipaddress.IPv6Address(address).exploded
    except Exception:
        return ""


def compress_ipv6(address: str) -> str:
    """Return the compressed IPv6 address (using :: where possible)."""
    try:
        return str(ipaddress.IPv6Address(address))
    except Exception:
        return ""


def ipv6_info(address: str) -> Dict[str, Any]:
    """Return dict with validation, expanded, compressed forms."""
    valid = validate_ipv6(address)
    return {
        "input": address,
        "valid": valid,
        "expanded": expand_ipv6(address) if valid else None,
        "compressed": compress_ipv6(address) if valid else None,
    }
