"""Tests for network utilities module."""
import pytest
from sectoolkit.network_utils import (
    ip_to_int,
    int_to_ip,
    calculate_cidr_range,
    check_ip_in_range,
    get_private_ip_ranges,
    is_private_ip,
    get_ip_info,
    subnet_split,
    calculate_supernet,
)


def test_ip_to_int():
    """Test IP to integer conversion."""
    assert ip_to_int("192.168.1.1") == 3232235777
    assert ip_to_int("10.0.0.1") == 167772161
    assert ip_to_int("0.0.0.0") == 0


def test_int_to_ip():
    """Test integer to IP conversion."""
    assert int_to_ip(3232235777) == "192.168.1.1"
    assert int_to_ip(167772161) == "10.0.0.1"
    assert int_to_ip(0) == "0.0.0.0"


def test_ip_to_int_and_back():
    """Test round-trip IP conversion."""
    ip = "172.16.254.1"
    assert int_to_ip(ip_to_int(ip)) == ip


def test_calculate_cidr_range():
    """Test CIDR range calculation."""
    result = calculate_cidr_range("192.168.1.0/24")
    
    assert result["network"] == "192.168.1.0"
    assert result["broadcast"] == "192.168.1.255"
    assert result["first_host"] == "192.168.1.1"
    assert result["last_host"] == "192.168.1.254"
    assert result["total_hosts"] == 254
    assert result["prefix_length"] == 24


def test_calculate_cidr_range_slash_32():
    """Test CIDR calculation for single host."""
    result = calculate_cidr_range("192.168.1.1/32")
    
    assert result["network"] == "192.168.1.1"
    assert result["total_hosts"] == 0


def test_check_ip_in_range_true():
    """Test IP in range check (positive)."""
    assert check_ip_in_range("192.168.1.50", "192.168.1.0/24") is True
    assert check_ip_in_range("10.0.0.1", "10.0.0.0/8") is True


def test_check_ip_in_range_false():
    """Test IP in range check (negative)."""
    assert check_ip_in_range("192.168.2.1", "192.168.1.0/24") is False
    assert check_ip_in_range("172.16.0.1", "192.168.0.0/16") is False


def test_get_private_ip_ranges():
    """Test getting private IP ranges."""
    ranges = get_private_ip_ranges()
    
    assert "10.0.0.0/8" in ranges
    assert "172.16.0.0/12" in ranges
    assert "192.168.0.0/16" in ranges
    assert len(ranges) >= 3


def test_is_private_ip_true():
    """Test private IP detection (positive)."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("172.16.0.1") is True
    assert is_private_ip("127.0.0.1") is True


def test_is_private_ip_false():
    """Test private IP detection (negative)."""
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("1.1.1.1") is False


def test_get_ip_info_structure():
    """Test IP info retrieval structure."""
    result = get_ip_info("192.168.1.1")
    
    assert "ip" in result
    assert "is_private" in result
    assert "is_loopback" in result
    assert "is_multicast" in result
    assert "reverse_dns" in result


def test_get_ip_info_private():
    """Test IP info for private address."""
    result = get_ip_info("192.168.1.1")
    
    assert result["is_private"] is True
    assert result["ip"] == "192.168.1.1"


def test_get_ip_info_loopback():
    """Test IP info for loopback address."""
    result = get_ip_info("127.0.0.1")
    
    assert result["is_loopback"] is True


def test_subnet_split():
    """Test subnet splitting."""
    subnets = subnet_split("192.168.1.0/24", 26)
    
    assert len(subnets) == 4
    assert "192.168.1.0/26" in subnets
    assert "192.168.1.64/26" in subnets
    assert "192.168.1.128/26" in subnets
    assert "192.168.1.192/26" in subnets


def test_subnet_split_invalid_prefix():
    """Test subnet split with invalid prefix."""
    subnets = subnet_split("192.168.1.0/24", 20)
    assert len(subnets) == 0


def test_calculate_supernet():
    """Test supernet calculation."""
    cidrs = ["192.168.1.0/24", "192.168.2.0/24"]
    supernet = calculate_supernet(cidrs)
    
    assert supernet != ""
    assert "/" in supernet


def test_calculate_supernet_empty():
    """Test supernet with empty list."""
    supernet = calculate_supernet([])
    assert supernet == ""


def test_calculate_cidr_range_invalid():
    """Test CIDR calculation with invalid input."""
    result = calculate_cidr_range("invalid")
    assert "error" in result
