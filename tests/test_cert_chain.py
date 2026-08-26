"""Tests for certificate chain validation module."""
import pytest
from sectoolkit.cert_chain import (
    get_certificate_chain,
    validate_certificate_dates,
    check_certificate_pinning,
    validate_certificate_chain_integrity,
)


def test_get_certificate_chain_structure():
    """Test that certificate chain retrieval returns expected structure."""
    result = get_certificate_chain("nonexistent-host-12345.com")
    
    assert "hostname" in result
    assert "port" in result
    assert "chain" in result
    assert "chain_length" in result
    assert "root_ca_present" in result


def test_validate_certificate_dates_structure():
    """Test certificate date validation structure."""
    result = validate_certificate_dates("nonexistent-host-12345.com")
    
    assert "hostname" in result
    assert "valid_from" in result
    assert "valid_until" in result
    assert "is_valid_now" in result
    assert "expiry_status" in result


def test_check_certificate_pinning_structure():
    """Test certificate pinning check structure."""
    result = check_certificate_pinning("nonexistent-host-12345.com")
    
    assert "hostname" in result
    assert "public_key_hash" in result
    assert "pinned" in result
    assert "matches" in result


def test_check_certificate_pinning_with_hash():
    """Test pinning check with expected hash."""
    result = check_certificate_pinning(
        "nonexistent-host-12345.com",
        public_key_hash="expected_hash"
    )
    
    assert result["matches"] is not None


def test_validate_certificate_chain_integrity_structure():
    """Test chain integrity validation structure."""
    result = validate_certificate_chain_integrity("nonexistent-host-12345.com")
    
    assert "hostname" in result
    assert "chain_valid" in result
    assert "issues" in result
    assert "warnings" in result
    assert isinstance(result["issues"], list)
    assert isinstance(result["warnings"], list)


@pytest.mark.skipif(True, reason="Requires live internet connection")
def test_get_certificate_chain_real_site():
    """Test certificate chain retrieval on real site (skipped by default)."""
    result = get_certificate_chain("example.com")
    
    assert result["hostname"] == "example.com"
    assert result["chain_length"] >= 1


@pytest.mark.skipif(True, reason="Requires live internet connection")
def test_validate_certificate_dates_real_site():
    """Test date validation on real site (skipped by default)."""
    result = validate_certificate_dates("example.com")
    
    assert result["hostname"] == "example.com"
    assert result["is_valid_now"] in [True, False]
