"""
Tests for sectoolkit.threat_intel

Two tests are intentionally written to FAIL in order to expose known bugs:
  - test_check_ip_reputation_returns_ip_key  (bug: key is 'address', not 'ip')
  - test_lookup_malicious_url_phishing       (bug: sets 'flagged', not 'is_malicious')
"""

import pytest
from sectoolkit.threat_intel import (
    check_ip_reputation,
    lookup_malicious_url,
    match_ioc,
    hash_threat_lookup,
    geoip_lookup,
    bulk_ioc_scan,
    generate_threat_report,
)


# ===========================================================================
# check_ip_reputation
# ===========================================================================

class TestCheckIpReputation:

    def test_check_ip_reputation_returns_ip_key(self):
        """BUG EXPOSURE: result should contain 'ip' key, but the implementation
        uses 'address'. This test will FAIL until the bug is fixed."""
        result = check_ip_reputation("192.168.1.1")
        assert "ip" in result, (
            "Expected key 'ip' in result dict, but got keys: "
            + str(list(result.keys()))
        )
        assert result["ip"] == "192.168.1.1"

    def test_check_ip_reputation_private_ip_is_not_malicious(self):
        """Private (RFC 1918) IPs should never be flagged as malicious."""
        result = check_ip_reputation("10.0.0.1")
        assert result["is_malicious"] is False

    def test_check_ip_reputation_private_ip_reputation(self):
        """Private IPs should have reputation == 'private'."""
        result = check_ip_reputation("10.0.0.1")
        assert result["reputation"] == "private"

    def test_check_ip_reputation_private_ip_tag(self):
        """Private IPs should carry the 'rfc1918' tag."""
        result = check_ip_reputation("172.16.0.5")
        assert "rfc1918" in result["tags"]

    def test_check_ip_reputation_loopback(self):
        """Loopback address (127.0.0.1) should have 'loopback' in tags."""
        result = check_ip_reputation("127.0.0.1")
        assert "loopback" in result["tags"]

    def test_check_ip_reputation_loopback_reputation(self):
        """Loopback address should have reputation == 'loopback'."""
        result = check_ip_reputation("127.0.0.1")
        assert result["reputation"] == "loopback"

    def test_check_ip_reputation_known_malicious_ip(self):
        """185.220.101.1 is in the hardcoded sinklist and should be malicious."""
        result = check_ip_reputation("185.220.101.1")
        assert result["is_malicious"] is True

    def test_check_ip_reputation_known_malicious_ip_tags(self):
        """185.220.101.1 should carry 'tor-exit' and 'botnet' tags."""
        result = check_ip_reputation("185.220.101.1")
        assert "tor-exit" in result["tags"]
        assert "botnet" in result["tags"]

    def test_check_ip_reputation_known_clean_ip(self):
        """8.8.8.8 (Google DNS) should NOT be malicious."""
        result = check_ip_reputation("8.8.8.8")
        assert result["is_malicious"] is False

    def test_check_ip_reputation_known_clean_ip_reputation(self):
        """8.8.8.8 should have reputation == 'dns'."""
        result = check_ip_reputation("8.8.8.8")
        assert result["reputation"] == "dns"

    def test_check_ip_reputation_invalid_ip(self):
        """Non-IP strings should be flagged as 'invalid'."""
        result = check_ip_reputation("not-an-ip")
        assert result["reputation"] == "invalid"
        assert "invalid-ip" in result["tags"]
        assert result["is_malicious"] is False

    def test_check_ip_reputation_public_clean_ip(self):
        """An unknown public IP should have reputation == 'clean'."""
        result = check_ip_reputation("203.0.114.1")  # not in bogon or sinkhole list
        assert result["reputation"] == "clean"

    def test_check_ip_reputation_result_has_required_keys(self):
        """Result dict must contain 'reputation', 'is_malicious', and 'tags' keys."""
        result = check_ip_reputation("192.168.0.1")
        assert "reputation" in result
        assert "is_malicious" in result
        assert "tags" in result


# ===========================================================================
# lookup_malicious_url
# ===========================================================================

class TestLookupMaliciousUrl:

    def test_lookup_malicious_url_phishing(self):
        """BUG EXPOSURE: 'http://phishing-site.com' matches the 'phish' pattern,
        so is_malicious must be True. The bug sets 'flagged' instead, leaving
        is_malicious as False. This test will FAIL until the bug is fixed."""
        result = lookup_malicious_url("http://phishing-site.com")
        assert result["is_malicious"] is True, (
            "Expected is_malicious=True for a phishing URL. "
            "Keys present: " + str(list(result.keys()))
        )

    def test_lookup_malicious_url_clean(self):
        """https://google.com has no malicious keywords; is_malicious must be False."""
        result = lookup_malicious_url("https://google.com")
        assert result["is_malicious"] is False

    def test_lookup_malicious_url_clean_no_patterns(self):
        """Clean URL should have an empty matched_patterns list."""
        result = lookup_malicious_url("https://example.com/home")
        assert result["matched_patterns"] == []

    def test_lookup_malicious_url_malware_keyword(self):
        """URL containing 'malware' should be flagged as malicious."""
        result = lookup_malicious_url("http://evil.example.com/malware-download")
        assert result["is_malicious"] is True

    def test_lookup_malicious_url_returns_url_key(self):
        """Result dict must echo back the original URL under the 'url' key."""
        url = "http://phishing-site.com"
        result = lookup_malicious_url(url)
        assert result["url"] == url

    def test_lookup_malicious_url_matched_patterns_populated(self):
        """When a keyword matches, matched_patterns should be non-empty."""
        result = lookup_malicious_url("http://trojan-dropper.xyz")
        assert len(result["matched_patterns"]) > 0

    def test_lookup_malicious_url_result_has_required_keys(self):
        """Result must contain 'url', 'is_malicious', and 'matched_patterns'."""
        result = lookup_malicious_url("https://benign.com")
        assert "url" in result
        assert "is_malicious" in result
        assert "matched_patterns" in result


# ===========================================================================
# match_ioc
# ===========================================================================

class TestMatchIoc:

    def test_match_ioc_found_exact(self):
        """Exact match against IOC list should set matched=True."""
        result = match_ioc("192.168.1.100", ["192.168.1.100", "10.0.0.1"])
        assert result["matched"] is True

    def test_match_ioc_not_found(self):
        """Value absent from the IOC list should set matched=False."""
        result = match_ioc("8.8.8.8", ["1.2.3.4", "5.6.7.8"])
        assert result["matched"] is False

    def test_match_ioc_case_insensitive(self):
        """Matching should be case-insensitive."""
        result = match_ioc("EVIL.COM", ["evil.com"])
        assert result["matched"] is True

    def test_match_ioc_matched_iocs_populated(self):
        """matched_iocs must list the IOC entries that triggered the match."""
        result = match_ioc("evil.com", ["evil.com", "safe.com"])
        assert "evil.com" in result["matched_iocs"]

    def test_match_ioc_empty_list(self):
        """An empty IOC list should always yield matched=False."""
        result = match_ioc("192.168.1.1", [])
        assert result["matched"] is False
        assert result["matched_iocs"] == []


# ===========================================================================
# hash_threat_lookup
# ===========================================================================

class TestHashThreatLookup:

    def test_hash_threat_lookup_unknown(self):
        """A random well-formed MD5 hash not in the database should return found=False."""
        random_md5 = "a" * 32
        result = hash_threat_lookup(random_md5)
        assert result["found"] is False

    def test_hash_threat_lookup_known_malicious_md5(self):
        """The EICAR MD5 is in the hardcoded list and should be found."""
        eicar_md5 = "44d88612fea8a8f36de82e1278abb02f"
        result = hash_threat_lookup(eicar_md5)
        assert result["found"] is True
        assert result["malware_name"] == "EICAR-Test-File"

    def test_hash_threat_lookup_invalid_length(self):
        """A hash with an invalid length should get threat_level='invalid-hash'."""
        result = hash_threat_lookup("abc123")
        assert result["threat_level"] == "invalid-hash"

    def test_hash_threat_lookup_invalid_chars(self):
        """A 32-char string with non-hex characters should be invalid."""
        result = hash_threat_lookup("g" * 32)
        assert result["threat_level"] == "invalid-hash"

    def test_hash_threat_lookup_result_has_required_keys(self):
        """Result dict must contain 'hash', 'found', 'malware_name', 'threat_level'."""
        result = hash_threat_lookup("a" * 32)
        assert "hash" in result
        assert "found" in result
        assert "malware_name" in result
        assert "threat_level" in result

    def test_hash_threat_lookup_sha1_known(self):
        """The known empty-file SHA-1 hash should be found in the database."""
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = hash_threat_lookup(sha1)
        assert result["found"] is True
        assert result["threat_level"] == "info"



# ===========================================================================
# geoip_lookup
# ===========================================================================

class TestGeoipLookup:

    def test_geoip_lookup_private_192(self):
        """192.168.1.1 is RFC-1918; is_private must be True."""
        result = geoip_lookup("192.168.1.1")
        assert result["is_private"] is True

    def test_geoip_lookup_private_10(self):
        """BUG EXPOSURE: 10.0.0.1 is RFC-1918; is_private must be True.
        The current implementation omits '10.' from its startswith check,
        so this test will FAIL until the bug is fixed."""
        result = geoip_lookup("10.0.0.1")
        assert result["is_private"] is True, (
            "Expected is_private=True for 10.0.0.1 (RFC-1918 10.x.x.x range). "
            f"Got is_private={result['is_private']}"
        )

    def test_geoip_lookup_google_dns(self):
        """8.8.8.8 is in the Google LLC range and should have country == 'US'."""
        result = geoip_lookup("8.8.8.8")
        assert result["country"] == "US"


# ===========================================================================
# bulk_ioc_scan
# ===========================================================================

class TestBulkIocScan:

    def test_bulk_ioc_scan_finds_matches(self):
        """Values that are in the IOC list should appear in matches."""
        ioc_list = ["evil.com", "192.168.1.100", "malware.exe"]
        values = ["evil.com", "safe.org", "192.168.1.100"]
        result = bulk_ioc_scan(values, ioc_list)
        assert result["matched_count"] == 2
        matched_values = [m["value"] for m in result["matches"]]
        assert "evil.com" in matched_values
        assert "192.168.1.100" in matched_values
        assert "safe.org" in result["clean"]

    def test_bulk_ioc_scan_empty(self):
        """An empty values list should return zeros and empty collections."""
        result = bulk_ioc_scan([], ["evil.com"])
        assert result["total"] == 0
        assert result["matched_count"] == 0
        assert result["matches"] == []
        assert result["clean"] == []


# ===========================================================================
# generate_threat_report
# ===========================================================================

class TestGenerateThreatReport:

    def test_generate_threat_report_not_empty(self):
        """generate_threat_report should return a non-empty string."""
        sample_results = [
            check_ip_reputation("8.8.8.8"),
            lookup_malicious_url("http://phishing-site.com"),
            hash_threat_lookup("44d88612fea8a8f36de82e1278abb02f"),
        ]
        report = generate_threat_report(sample_results)
        assert isinstance(report, str)
        assert len(report) > 0
