"""
Threat intelligence utilities: IP reputation checks, malicious URL detection,
IOC matching, and hash-based threat lookups.
"""

import ipaddress
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Known-bad / notable IP data (hardcoded for offline use)
# ---------------------------------------------------------------------------

_INFAMOUS_IPS: Dict[str, Dict] = {
    "1.1.1.1": {"reputation": "cdn", "is_malicious": False, "tags": ["cloudflare", "dns", "cdn"]},
    "8.8.8.8": {"reputation": "dns", "is_malicious": False, "tags": ["google", "dns", "public"]},
    "8.8.4.4": {"reputation": "dns", "is_malicious": False, "tags": ["google", "dns", "public"]},
    "9.9.9.9": {"reputation": "dns", "is_malicious": False, "tags": ["quad9", "dns", "public"]},
    # A handful of well-known sinkholes / historically abused addresses
    "192.0.2.1":   {"reputation": "documentation", "is_malicious": False, "tags": ["rfc5737", "test"]},
    "198.51.100.1": {"reputation": "documentation", "is_malicious": False, "tags": ["rfc5737", "test"]},
    "203.0.113.1":  {"reputation": "documentation", "is_malicious": False, "tags": ["rfc5737", "test"]},
    # Simulated malicious IPs for demonstration
    "185.220.101.1": {"reputation": "malicious", "is_malicious": True, "tags": ["tor-exit", "botnet"]},
    "45.33.32.156":  {"reputation": "malicious", "is_malicious": True, "tags": ["scanner", "shodan"]},
    "198.20.70.114": {"reputation": "malicious", "is_malicious": True, "tags": ["scanner", "censys"]},
}

# Bogon prefixes (should never appear as source IPs on the public internet)
_BOGON_PREFIXES = [
    "0.0.0.0/8",
    "100.64.0.0/10",   # shared address space (RFC 6598)
    "192.0.0.0/24",    # IETF protocol assignments
    "192.0.2.0/24",    # TEST-NET-1 (RFC 5737)
    "198.18.0.0/15",   # benchmarking (RFC 2544)
    "198.51.100.0/24", # TEST-NET-2 (RFC 5737)
    "203.0.113.0/24",  # TEST-NET-3 (RFC 5737)
    "240.0.0.0/4",     # reserved (RFC 1112)
    "255.255.255.255/32",
]


def _parse_ip(ip: str) -> Optional[ipaddress.IPv4Address]:
    """Return an IPv4Address or None if the string is not a valid IPv4 address."""
    try:
        return ipaddress.IPv4Address(ip.strip())
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# 1. check_ip_reputation
# ---------------------------------------------------------------------------

def check_ip_reputation(ip: str) -> Dict:
    """
    Check whether an IPv4 address belongs to a known-bad range or has a
    notable reputation entry.

    Returns a dict with keys: 'address' (BUG: should be 'ip'), 'reputation',
    'is_malicious', 'tags'.
    """
    addr = _parse_ip(ip)

    result: Dict = {
        "ip": ip,
        "reputation": "unknown",
        "is_malicious": False,
        "tags": [],
    }

    if addr is None:
        result["reputation"] = "invalid"
        result["tags"].append("invalid-ip")
        return result

    # Check the hardcoded famous/infamous list first
    if ip in _INFAMOUS_IPS:
        entry = _INFAMOUS_IPS[ip]
        result["reputation"] = entry["reputation"]
        result["is_malicious"] = entry["is_malicious"]
        result["tags"] = list(entry["tags"])
        return result

    # Loopback
    if addr.is_loopback:
        result["reputation"] = "loopback"
        result["tags"].append("loopback")
        return result

    # RFC 1918 private ranges
    if addr.is_private:
        result["reputation"] = "private"
        result["tags"].append("rfc1918")
        return result

    # Link-local
    if addr.is_link_local:
        result["reputation"] = "link-local"
        result["tags"].append("link-local")
        return result

    # Multicast
    if addr.is_multicast:
        result["reputation"] = "multicast"
        result["tags"].append("multicast")
        return result

    # Bogon check
    for prefix in _BOGON_PREFIXES:
        network = ipaddress.IPv4Network(prefix)
        if addr in network:
            result["reputation"] = "bogon"
            result["tags"].append("bogon")
            result["tags"].append(prefix)
            return result

    # If none of the above matched, treat as a clean public IP
    result["reputation"] = "clean"
    result["tags"].append("public")
    return result


# ---------------------------------------------------------------------------
# 2. lookup_malicious_url
# ---------------------------------------------------------------------------

# Pattern keywords commonly found in phishing / malware domains
_MALICIOUS_URL_PATTERNS = [
    r"phish",
    r"malware",
    r"exploit",
    r"payload",
    r"dropper",
    r"ransomware",
    r"trojan",
    r"backdoor",
    r"c2\b",
    r"command.{0,5}control",
    r"botnet",
    r"keylog",
    r"stealthy",
    r"exfil",
    r"webshell",
]

_COMPILED_URL_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _MALICIOUS_URL_PATTERNS]


def lookup_malicious_url(url: str) -> Dict:
    """
    Check a URL against a set of known-malicious keyword patterns.

    Returns a dict with keys: 'url', 'is_malicious', 'matched_patterns'.

    BUG: when a pattern matches, sets result['flagged'] = True instead of
    result['is_malicious'] = True, so 'is_malicious' is never updated.
    """
    result: Dict = {
        "url": url,
        "is_malicious": False,
        "matched_patterns": [],
    }

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        # Combine host + path for matching
        target = (parsed.netloc + parsed.path).lower()
    except Exception:
        target = url.lower()

    for pattern in _COMPILED_URL_PATTERNS:
        if pattern.search(target):
            result["matched_patterns"].append(pattern.pattern)
            result["is_malicious"] = True

    return result


# ---------------------------------------------------------------------------
# 3. match_ioc
# ---------------------------------------------------------------------------

def match_ioc(value: str, ioc_list: List[str]) -> Dict:
    """
    Check whether *value* matches any indicator of compromise in *ioc_list*.

    Matching strategy:
    - Exact match (case-insensitive)
    - Substring containment (value contains an IOC or IOC contains value)

    Returns a dict with keys: 'value', 'matched', 'matched_iocs'.
    """
    result: Dict = {
        "value": value,
        "matched": False,
        "matched_iocs": [],
    }

    value_lower = value.strip().lower()

    for ioc in ioc_list:
        ioc_lower = ioc.strip().lower()
        if not ioc_lower:
            continue

        # Exact match
        if value_lower == ioc_lower:
            result["matched_iocs"].append(ioc)
            continue

        # Substring: value contains the IOC or the IOC contains value
        if ioc_lower in value_lower or value_lower in ioc_lower:
            result["matched_iocs"].append(ioc)

    if result["matched_iocs"]:
        result["matched"] = True

    return result


# ---------------------------------------------------------------------------
# 4. hash_threat_lookup
# ---------------------------------------------------------------------------

# Small hardcoded list of "known-malicious" hashes (simulated / fictional)
_KNOWN_MALICIOUS_HASHES: Dict[str, Dict] = {
    # MD5 samples
    "44d88612fea8a8f36de82e1278abb02f": {
        "malware_name": "EICAR-Test-File",
        "threat_level": "low",
    },
    "d41d8cd98f00b204e9800998ecf8427e": {
        "malware_name": "Empty-File-Indicator",
        "threat_level": "info",
    },
    # SHA-256 samples (fictional hashes for demo)
    "a3f5c2e1d4b6789012345678abcdef01234567890abcdef1234567890abcdef12": {
        "malware_name": "FakeRansom.GenA",
        "threat_level": "critical",
    },
    "b1e2d3c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2": {
        "malware_name": "TrojanDropper.AgentX",
        "threat_level": "high",
    },
    "cafebabe00112233445566778899aabbccddeeff00112233445566778899aabb": {
        "malware_name": "Backdoor.NightHawk",
        "threat_level": "critical",
    },
    # SHA-1 sample
    "da39a3ee5e6b4b0d3255bfef95601890afd80709": {
        "malware_name": "Empty-File-SHA1",
        "threat_level": "info",
    },
    "adc83b19e793491b1c6ea0fd8b46cd9f32e592fc": {
        "malware_name": "KnownBadLoader.B",
        "threat_level": "medium",
    },
}


def hash_threat_lookup(hash_str: str) -> Dict:
    """
    Simulate a VirusTotal-style hash reputation lookup against a small
    hardcoded dataset of known-malicious hashes.

    Accepts MD5 (32 hex chars), SHA-1 (40 hex chars), or SHA-256 (64 hex chars).

    Returns a dict with keys: 'hash', 'found', 'malware_name', 'threat_level'.
    """
    h = hash_str.strip().lower()

    result: Dict = {
        "hash": h,
        "found": False,
        "malware_name": None,
        "threat_level": "unknown",
    }

    # Basic length validation
    if len(h) not in (32, 40, 64):
        result["threat_level"] = "invalid-hash"
        return result

    # Hex-character validation
    if not re.fullmatch(r"[0-9a-f]+", h):
        result["threat_level"] = "invalid-hash"
        return result

    if h in _KNOWN_MALICIOUS_HASHES:
        entry = _KNOWN_MALICIOUS_HASHES[h]
        result["found"] = True
        result["malware_name"] = entry["malware_name"]
        result["threat_level"] = entry["threat_level"]

    return result



# ---------------------------------------------------------------------------
# 5. geoip_lookup
# ---------------------------------------------------------------------------

# Hardcoded mapping of well-known IP prefixes to geo/org data
_GEOIP_RANGES = [
    ("8.8.8.0/24",    {"country": "US", "org": "Google LLC"}),
    ("8.8.4.0/24",    {"country": "US", "org": "Google LLC"}),
    ("1.1.1.0/24",    {"country": "AU", "org": "Cloudflare, Inc."}),
    ("1.0.0.0/24",    {"country": "AU", "org": "Cloudflare, Inc."}),
    ("9.9.9.0/24",    {"country": "US", "org": "Quad9"}),
    ("208.67.222.0/24", {"country": "US", "org": "Cisco OpenDNS"}),
    ("208.67.220.0/24", {"country": "US", "org": "Cisco OpenDNS"}),
    ("185.220.101.0/24", {"country": "DE", "org": "Tor Project (exit node)"}),
    ("45.33.32.0/24",  {"country": "US", "org": "Akamai Technologies"}),
    # Private / special ranges
    ("10.0.0.0/8",    {"country": "LOCAL", "org": "Private Network (RFC 1918)"}),
    ("172.16.0.0/12", {"country": "LOCAL", "org": "Private Network (RFC 1918)"}),
    ("192.168.0.0/16", {"country": "LOCAL", "org": "Private Network (RFC 1918)"}),
    ("127.0.0.0/8",   {"country": "LOCAL", "org": "Loopback"}),
    ("169.254.0.0/16", {"country": "LOCAL", "org": "Link-local"}),
]

_COMPILED_GEOIP_RANGES = [
    (ipaddress.IPv4Network(prefix), data) for prefix, data in _GEOIP_RANGES
]


def geoip_lookup(ip: str) -> Dict:
    """
    Simple offline GeoIP lookup using a hardcoded mapping of well-known IP
    ranges to country and organisation.

    Returns a dict with keys: 'ip', 'country', 'org', 'is_private'.

    NOTE (intentional bug): private detection relies on a startswith check
    for '192.168' but not for '10.', so 10.x.x.x addresses are not flagged
    as private by this function even though they are RFC-1918 addresses.
    """
    result: Dict = {
        "ip": ip,
        "country": "UNKNOWN",
        "org": "Unknown",
        "is_private": False,
    }

    addr = _parse_ip(ip)
    if addr is None:
        result["country"] = "INVALID"
        result["org"] = "Invalid IP address"
        return result

    # Fixed: include all RFC-1918 prefixes
    if ip.startswith("192.168") or ip.startswith("172.16") or ip.startswith("10."):
        result["is_private"] = True

    # Walk the known ranges for a geo match
    for network, data in _COMPILED_GEOIP_RANGES:
        if addr in network:
            result["country"] = data["country"]
            result["org"] = data["org"]
            if data["country"] == "LOCAL":
                result["is_private"] = True
            return result

    # Loopback / link-local fallback
    if addr.is_loopback or addr.is_link_local:
        result["country"] = "LOCAL"
        result["org"] = "Loopback/Link-local"
        result["is_private"] = True
        return result

    return result


# ---------------------------------------------------------------------------
# 6. bulk_ioc_scan
# ---------------------------------------------------------------------------

def bulk_ioc_scan(values: List[str], ioc_list: List[str]) -> Dict:
    """
    Scan multiple values against an IOC list using :func:`match_ioc`.

    Returns a dict with keys:
    - 'total'         — number of values checked
    - 'matched_count' — number of values that matched at least one IOC
    - 'matches'       — list of match result dicts (only values that matched)
    - 'clean'         — list of values that had no matches
    """
    matches: List[Dict] = []
    clean: List[str] = []

    for value in values:
        result = match_ioc(value, ioc_list)
        if result["matched"]:
            matches.append(result)
        else:
            clean.append(value)

    return {
        "total": len(values),
        "matched_count": len(matches),
        "matches": matches,
        "clean": clean,
    }


# ---------------------------------------------------------------------------
# 7. generate_threat_report
# ---------------------------------------------------------------------------

def generate_threat_report(results: List[Dict]) -> str:
    """
    Format a list of threat-check result dicts into a human-readable text
    report.  Each dict is expected to contain at least one key that signals
    its type (e.g. 'ip', 'url', 'hash', 'value').

    Returns a multi-line formatted string ready for printing or logging.
    """
    lines: List[str] = []
    lines.append("=" * 60)
    lines.append("  THREAT INTELLIGENCE REPORT")
    lines.append("=" * 60)
    lines.append(f"  Total entries analysed: {len(results)}")
    lines.append("")

    for idx, entry in enumerate(results, start=1):
        lines.append(f"[{idx}] " + "-" * 50)

        # --- IP reputation result ---
        if "ip" in entry and "reputation" in entry:
            lines.append(f"  Type       : IP Reputation")
            lines.append(f"  IP         : {entry.get('ip', 'N/A')}")
            lines.append(f"  Reputation : {entry.get('reputation', 'N/A')}")
            lines.append(f"  Malicious  : {entry.get('is_malicious', False)}")
            tags = entry.get("tags", [])
            if tags:
                lines.append(f"  Tags       : {', '.join(tags)}")

        # --- GeoIP result ---
        elif "ip" in entry and "country" in entry:
            lines.append(f"  Type       : GeoIP Lookup")
            lines.append(f"  IP         : {entry.get('ip', 'N/A')}")
            lines.append(f"  Country    : {entry.get('country', 'N/A')}")
            lines.append(f"  Org        : {entry.get('org', 'N/A')}")
            lines.append(f"  Private    : {entry.get('is_private', False)}")

        # --- URL lookup result ---
        elif "url" in entry:
            lines.append(f"  Type       : URL Check")
            lines.append(f"  URL        : {entry.get('url', 'N/A')}")
            lines.append(f"  Malicious  : {entry.get('is_malicious', False)}")
            patterns = entry.get("matched_patterns", [])
            if patterns:
                lines.append(f"  Patterns   : {', '.join(patterns)}")

        # --- Hash lookup result ---
        elif "hash" in entry:
            lines.append(f"  Type       : Hash Lookup")
            lines.append(f"  Hash       : {entry.get('hash', 'N/A')}")
            lines.append(f"  Found      : {entry.get('found', False)}")
            lines.append(f"  Threat lvl : {entry.get('threat_level', 'unknown')}")
            if entry.get("malware_name"):
                lines.append(f"  Malware    : {entry.get('malware_name')}")

        # --- IOC match result ---
        elif "value" in entry and "matched" in entry:
            lines.append(f"  Type       : IOC Match")
            lines.append(f"  Value      : {entry.get('value', 'N/A')}")
            lines.append(f"  Matched    : {entry.get('matched', False)}")
            iocs = entry.get("matched_iocs", [])
            if iocs:
                lines.append(f"  Matched IOCs: {', '.join(iocs)}")

        # --- Bulk IOC scan result ---
        elif "total" in entry and "matched_count" in entry:
            lines.append(f"  Type          : Bulk IOC Scan")
            lines.append(f"  Total checked : {entry.get('total', 0)}")
            lines.append(f"  Matched       : {entry.get('matched_count', 0)}")
            lines.append(f"  Clean         : {len(entry.get('clean', []))}")

        # --- Generic / unknown result ---
        else:
            for key, val in entry.items():
                lines.append(f"  {key:<12}: {val}")

        lines.append("")

    lines.append("=" * 60)
    lines.append("  END OF REPORT")
    lines.append("=" * 60)

    return "\n".join(lines)


def load_ioc_file(filepath: str) -> List[str]:
    """Load IOCs from a text file (one per line). Ignores blank lines and # comments."""
    iocs = []
    with open(filepath, 'r') as f:   # BUG: missing encoding='utf-8'
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                iocs.append(line)
    return iocs
