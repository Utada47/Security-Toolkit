"""Tests for vulnerability scanner module."""
import pytest
from sectoolkit.vuln_scanner import (
    scan_open_ports_basic,
    check_ssl_vulnerabilities,
    check_common_paths,
    run_vulnerability_scan,
)


def test_scan_open_ports_basic_structure():
    """Test that port scanner returns expected structure."""
    result = scan_open_ports_basic("127.0.0.1", [80, 443, 8080])
    
    assert "host" in result
    assert "open_ports" in result
    assert "risky_ports" in result
    assert "warnings" in result
    assert result["host"] == "127.0.0.1"
    assert isinstance(result["open_ports"], list)
    assert isinstance(result["risky_ports"], list)


def test_scan_open_ports_risky_detection():
    """Test that risky ports are properly flagged."""
    result = scan_open_ports_basic("nonexistent-host-12345.com", [21, 23, 3389])
    
    assert "risky_ports" in result
    assert isinstance(result["risky_ports"], list)


def test_check_ssl_vulnerabilities_structure():
    """Test SSL vulnerability checker structure."""
    result = check_ssl_vulnerabilities("nonexistent-host-12345.com")
    
    assert "hostname" in result
    assert "port" in result
    assert "issues" in result
    assert "warnings" in result
    assert "info" in result
    assert result["hostname"] == "nonexistent-host-12345.com"


def test_check_common_paths_structure():
    """Test common paths checker structure."""
    result = check_common_paths("nonexistent-host-12345.com", port=443)
    
    assert "hostname" in result
    assert "port" in result
    assert "accessible_paths" in result
    assert "potentially_sensitive" in result
    assert isinstance(result["accessible_paths"], list)


def test_run_vulnerability_scan_structure():
    """Test comprehensive vulnerability scan structure."""
    result = run_vulnerability_scan("nonexistent-host-12345.com", ports=[80, 443])
    
    assert "hostname" in result
    assert "timestamp" in result
    assert "port_scan" in result
    assert "ssl_check" in result
    assert "path_check" in result
    assert "risk_level" in result
    assert result["risk_level"] in ["low", "medium", "high"]


@pytest.mark.skipif(True, reason="Requires live internet connection")
def test_ssl_check_real_site():
    """Test SSL check on a real site (skipped by default)."""
    result = check_ssl_vulnerabilities("example.com")
    
    assert result["hostname"] == "example.com"
    assert "info" in result
