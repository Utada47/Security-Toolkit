"""Tests for banner grabbing module."""
import pytest
from sectoolkit.banner_grab import (
    grab_banner,
    identify_service_from_banner,
    extract_version_from_banner,
    scan_with_banner_grab,
    identify_service_fingerprint,
)


def test_grab_banner_structure():
    """Test that banner grabbing returns expected structure."""
    result = grab_banner("127.0.0.1", 12345, timeout=0.5)
    
    assert "host" in result
    assert "port" in result
    assert "banner" in result
    assert "service" in result
    assert "version" in result


def test_identify_service_from_banner_http():
    """Test HTTP service identification."""
    banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41"
    service = identify_service_from_banner(banner)
    
    assert service == "http"


def test_identify_service_from_banner_ssh():
    """Test SSH service identification."""
    banner = "SSH-2.0-OpenSSH_7.9"
    service = identify_service_from_banner(banner)
    
    assert service == "ssh"


def test_identify_service_from_banner_unknown():
    """Test unknown service returns None."""
    banner = "UNKNOWN_SERVICE_XYZ_123"
    service = identify_service_from_banner(banner)
    
    assert service is None


def test_extract_version_from_banner_standard():
    """Test version extraction from standard format."""
    banner = "Apache/2.4.41 (Ubuntu)"
    version = extract_version_from_banner(banner)
    
    assert version in ["2.4.41", "2.4"]


def test_extract_version_from_banner_version_keyword():
    """Test version extraction with 'version' keyword."""
    banner = "MyService Version: 1.2.3"
    version = extract_version_from_banner(banner)
    
    assert version == "1.2.3"


def test_extract_version_from_banner_no_version():
    """Test that no version returns None."""
    banner = "MyService"
    version = extract_version_from_banner(banner)
    
    assert version is None


def test_scan_with_banner_grab_structure():
    """Test banner grab scanning returns expected structure."""
    result = scan_with_banner_grab("127.0.0.1", [12345], timeout=0.5)
    
    assert isinstance(result, dict)


def test_identify_service_fingerprint_structure():
    """Test service fingerprinting structure."""
    result = identify_service_fingerprint("127.0.0.1", 80)
    
    assert "host" in result
    assert "port" in result
    assert "likely_service" in result
    assert "confidence" in result
    assert "details" in result


def test_identify_service_fingerprint_common_port():
    """Test fingerprinting falls back to common port mapping."""
    result = identify_service_fingerprint("nonexistent-host.com", 80)
    
    assert result["port"] == 80
    assert result["likely_service"] == "HTTP"


def test_identify_service_from_banner_case_insensitive():
    """Test that service identification is case-insensitive."""
    banner1 = "SSH-2.0-OpenSSH"
    banner2 = "ssh-2.0-openssh"
    
    assert identify_service_from_banner(banner1) == identify_service_from_banner(banner2)


@pytest.mark.skipif(True, reason="Requires live server")
def test_grab_banner_real_service():
    """Test banner grabbing on real service (skipped by default)."""
    result = grab_banner("example.com", 80, timeout=3)
    
    assert result["host"] == "example.com"
    assert result["port"] == 80
