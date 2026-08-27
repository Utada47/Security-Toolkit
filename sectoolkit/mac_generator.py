"""Utility to generate random MAC addresses for network testing."""
import random

def random_mac_address(separator: str = ':') -> str:
    """Return a random MAC address (unicast, globally unique)."""
    mac = [random.randint(0x00, 0xff) for _ in range(6)]
    # Ensure unicast and globally unique (least significant bit of first octet = 0)
    mac[0] = mac[0] & 0xfe
    return separator.join(f"{b:02x}" for b in mac)
