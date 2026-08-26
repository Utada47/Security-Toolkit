"""Tests for domain information gathering module."""
import pytest
from sectoolkit.domain_info import (
    get_whois_info,
    get_domain_age,
    check_dns_propagation,
    check_subdomain_takeover_risk,
)


def test_get_whois_info_structure():
    """Test that WHOIS info retrieval returns expected structure."""
    result = get_whois_info("example.com")
    
    assert "domain" in result
    assert "registrar" in result
    assert "nameservers" in result
    assert "ip_addresses" in result
    assert "mx_records" in result
    assert result["domain"] == "example.com"


def test_get_whois_info_invalid_domain():
    """Test WHOIS lookup with invalid domain."""
    result = get_whois_info("nonexistent-domain-12345-xyz.com")
    
    assert result["domain"] == "nonexistent-domain-12345-xyz.com"
    assert isinstance(result["ip_addresses"], list)


def test_get_domain_age_structure():
    """Test domain age check structure."""
    result = get_domain_age("example.com")
    
    assert "domain" in result
    assert "serial" in result
    assert "estimated_age" in result


def test_check_dns_propagation_structure():
    """Test DNS propagation check structure."""
    result = check_dns_propagation("example.com")
    
    assert "domain" in result
    assert "propagated" in result
    assert "nameserver_results" in result
    assert "consistent" in result
    assert isinstance(result["nameserver_results"], dict)


def test_check_dns_propagation_custom_nameservers():
    """Test DNS propagation with custom nameservers."""
    result = check_dns_propagation("example.com", nameservers=["8.8.8.8"])
    
    assert "8.8.8.8" in result["nameserver_results"]


def test_check_subdomain_takeover_risk_structure():
    """Test subdomain takeover risk check structure."""
    result = check_subdomain_takeover_risk("example.com", ["www", "api"])
    
    assert "domain" in result
    assert "at_risk" in result
    assert "safe" in result
    assert "unresolvable" in result
    assert isinstance(result["at_risk"], list)
    assert isinstance(result["safe"], list)


def test_check_subdomain_takeover_risk_empty_subdomains():
    """Test with empty subdomain list."""
    result = check_subdomain_takeover_risk("example.com", [])
    
    assert result["domain"] == "example.com"
    assert len(result["at_risk"]) == 0


@pytest.mark.skipif(True, reason="Requires dnspython and live internet")
def test_get_whois_info_real_domain():
    """Test WHOIS lookup on real domain (skipped by default)."""
    result = get_whois_info("google.com")
    
    assert result["domain"] == "google.com"
    assert len(result["ip_addresses"]) > 0
