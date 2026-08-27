"""SQL Injection pattern detector for URL and input validation."""
import re
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs


SQL_INJECTION_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
    r"((\%27)|(\'))union",
    r"exec(\s|\+)+(s|x)p\w+",
    r"union.*select",
    r"insert.*into",
    r"select.*from",
    r"delete.*from",
    r"drop.*table",
    r"update.*set",
    r"concat.*\(",
]


def detect_sqli_in_string(input_string: str) -> Dict[str, Any]:
    """Detect potential SQL injection patterns in a string."""
    result = {
        "input": input_string,
        "is_suspicious": False,
        "matched_patterns": [],
        "risk_level": "low",
    }
    
    input_lower = input_string.lower()
    
    for pattern in SQL_INJECTION_PATTERNS:
        matches = re.findall(pattern, input_lower, re.IGNORECASE)
        if matches:
            result["is_suspicious"] = True
            result["matched_patterns"].append(pattern)
    
    if len(result["matched_patterns"]) >= 3:
        result["risk_level"] = "high"
    elif len(result["matched_patterns"]) >= 1:
        result["risk_level"] = "medium"
    
    return result


def detect_sqli_in_url(url: str) -> Dict[str, Any]:
    """Analyze URL for SQL injection patterns."""
    result = {
        "url": url,
        "suspicious_params": [],
        "is_vulnerable": False,
        "risk_level": "low",
    }
    
    try:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param_name, param_values in params.items():
            for value in param_values:
                detection = detect_sqli_in_string(value)
                if detection["is_suspicious"]:
                    result["suspicious_params"].append({
                        "parameter": param_name,
                        "value": value,
                        "patterns": detection["matched_patterns"],
                        "risk": detection["risk_level"],
                    })
                    result["is_vulnerable"] = True
        
        if result["suspicious_params"]:
            high_risk_count = sum(1 for p in result["suspicious_params"] if p["risk"] == "high")
            if high_risk_count > 0:
                result["risk_level"] = "high"
            else:
                result["risk_level"] = "medium"
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def batch_analyze_urls(urls: List[str]) -> Dict[str, Any]:
    """Analyze multiple URLs for SQL injection patterns."""
    results = {
        "total_urls": len(urls),
        "vulnerable_urls": [],
        "clean_urls": [],
        "summary": {
            "high_risk": 0,
            "medium_risk": 0,
            "low_risk": 0,
        },
    }
    
    for url in urls:
        analysis = detect_sqli_in_url(url)
        if analysis["is_vulnerable"]:
            results["vulnerable_urls"].append(analysis)
            results["summary"][f"{analysis['risk_level']}_risk"] += 1
        else:
            results["clean_urls"].append(url)
            results["summary"]["low_risk"] += 1
    
    return results
