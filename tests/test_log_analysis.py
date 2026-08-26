"""Tests for log analysis module."""
import os
import tempfile
import pytest
from sectoolkit.log_analysis import analyze_log_file, get_default_patterns, detect_brute_force
from collections import Counter


def test_analyze_empty_log():
    """Test analyzing an empty log file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        log_path = f.name
    
    try:
        result = analyze_log_file(log_path)
        assert result["total_lines"] == 0
        assert result["failed_login_count"] == 0
    finally:
        os.unlink(log_path)


def test_analyze_log_with_failed_logins():
    """Test detecting failed login attempts."""
    log_content = """
2024-01-01 10:00:00 192.168.1.100 - Failed login attempt for user admin
2024-01-01 10:00:05 192.168.1.100 - Failed login attempt for user root
2024-01-01 10:00:10 192.168.1.101 - Successful login for user john
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(log_content)
        log_path = f.name
    
    try:
        result = analyze_log_file(log_path)
        assert result["total_lines"] == 4
        assert result["failed_login_count"] == 2
        assert len(result["matches"]["failed_login"]) == 2
    finally:
        os.unlink(log_path)


def test_analyze_log_with_sql_injection():
    """Test detecting SQL injection patterns."""
    log_content = """
2024-01-01 10:00:00 192.168.1.50 GET /search?q=1' UNION SELECT * FROM users--
2024-01-01 10:00:05 192.168.1.50 GET /api/user?id=1 OR 1=1
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(log_content)
        log_path = f.name
    
    try:
        result = analyze_log_file(log_path)
        assert result["sql_injection_count"] >= 1
    finally:
        os.unlink(log_path)


def test_ip_address_counting():
    """Test IP address frequency counting."""
    log_content = """
192.168.1.100 - request 1
192.168.1.100 - request 2
192.168.1.101 - request 1
192.168.1.100 - request 3
"""
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        f.write(log_content)
        log_path = f.name
    
    try:
        result = analyze_log_file(log_path)
        assert result["ip_addresses"]["192.168.1.100"] == 3
        assert result["ip_addresses"]["192.168.1.101"] == 1
        assert len(result["top_ips"]) == 2
    finally:
        os.unlink(log_path)


def test_detect_brute_force():
    """Test brute force detection."""
    ip_counter = Counter({
        "192.168.1.100": 150,
        "192.168.1.101": 50,
        "192.168.1.102": 200,
    })
    
    suspicious = detect_brute_force(ip_counter, threshold=100)
    assert len(suspicious) == 2
    assert "192.168.1.100" in suspicious[0]
    assert "192.168.1.102" in suspicious[1] or "192.168.1.102" in suspicious[0]


def test_default_patterns():
    """Test that default patterns are returned."""
    patterns = get_default_patterns()
    assert "failed_login" in patterns
    assert "sql_injection" in patterns
    assert "xss_attempt" in patterns
    assert isinstance(patterns, dict)
