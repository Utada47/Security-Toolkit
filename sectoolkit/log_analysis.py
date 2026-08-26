"""Log analysis module for detecting suspicious patterns in log files."""
import re
from datetime import datetime
from typing import Dict, List, Any
from collections import Counter


def analyze_log_file(filepath: str, patterns: Dict[str, str] = None) -> Dict[str, Any]:
    """Analyze a log file for suspicious patterns.
    
    Args:
        filepath: Path to the log file
        patterns: Optional dict of pattern names to regex patterns
        
    Returns:
        Dict containing analysis results
    """
    if patterns is None:
        patterns = get_default_patterns()
    
    results = {
        "total_lines": 0,
        "matches": {},
        "ip_addresses": Counter(),
        "status_codes": Counter(),
        "suspicious_activity": [],
        "timestamps": [],
    }
    
    for pattern_name in patterns:
        results["matches"][pattern_name] = []
    
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    status_pattern = re.compile(r'\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s')
    timestamp_pattern = re.compile(r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}')
    
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            results["total_lines"] += 1
            
            for pattern_name, pattern_regex in patterns.items():
                if re.search(pattern_regex, line, re.IGNORECASE):
                    results["matches"][pattern_name].append({
                        "line": line_num,
                        "content": line.strip()[:200]
                    })
            
            ip_matches = ip_pattern.findall(line)
            for ip in ip_matches:
                results["ip_addresses"][ip] += 1
            
            status_match = status_pattern.search(line)
            if status_match:
                results["status_codes"][status_match.group(1)] += 1
            
            timestamp_match = timestamp_pattern.search(line)
            if timestamp_match:
                results["timestamps"].append(timestamp_match.group())
    
    results["top_ips"] = results["ip_addresses"].most_common(10)
    results["failed_login_count"] = len(results["matches"].get("failed_login", []))
    results["sql_injection_count"] = len(results["matches"].get("sql_injection", []))
    results["xss_attempt_count"] = len(results["matches"].get("xss_attempt", []))
    
    return results


def get_default_patterns() -> Dict[str, str]:
    """Get default suspicious patterns to search for."""
    return {
        "failed_login": r"(failed|failure|invalid|unauthorized|authentication failed|login failed)",
        "sql_injection": r"(union.*select|concat.*\(|@@version|information_schema)",
        "xss_attempt": r"(<script|javascript:|onerror=|onload=)",
        "directory_traversal": r"(\.\./|\.\.\\|etc/passwd|windows/system32)",
        "error_500": r"(500|internal server error)",
        "brute_force": r"(too many|rate limit|blocked)",
    }


def detect_brute_force(ip_addresses: Counter, threshold: int = 100) -> List[str]:
    """Detect potential brute force attacks based on request frequency."""
    suspicious_ips = []
    for ip, count in ip_addresses.items():
        if count > threshold:
            suspicious_ips.append(f"{ip} ({count} requests)")
    return suspicious_ips
