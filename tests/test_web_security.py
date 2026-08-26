"""Tests for web security headers checker module."""
import pytest
from sectoolkit.web_security import check_security_headers, check_http_redirect


def test_check_security_headers_structure():
    """Test that the function returns expected structure even on error."""
    result = check_security_headers("nonexistent-domain-12345.com", port=443)
    
    assert "hostname" in result
    assert "port" in result
    assert "headers_found" in result
    assert "missing_headers" in result
    assert "security_score" in result
    assert result["hostname"] == "nonexistent-domain-12345.com"
    assert result["port"] == 443


def test_check_http_redirect_structure():
    """Test that HTTP redirect checker returns expected structure."""
    result = check_http_redirect("nonexistent-domain-12345.com", port=80)
    
    assert "hostname" in result
    assert "port" in result
    assert "redirects_to_https" in result
    assert "redirect_url" in result
    assert "status_code" in result
    assert result["hostname"] == "nonexistent-domain-12345.com"


@pytest.mark.skipif(True, reason="Requires live internet connection")
def test_check_security_headers_real_site():
    """Test checking security headers on a real site (skipped by default)."""
    result = check_security_headers("example.com")
    
    assert result["hostname"] == "example.com"
    assert isinstance(result["headers_found"], dict)
    assert isinstance(result["missing_headers"], list)
    assert 0 <= result["security_score"] <= 100
