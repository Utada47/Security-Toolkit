"""Cross-Site Scripting (XSS) pattern detector for input validation."""
import re
from typing import Dict, List, Any
from html import unescape


XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>",
    r"<object[^>]*>",
    r"<embed[^>]*>",
    r"<img[^>]*onerror",
    r"<img[^>]*onload",
    r"<body[^>]*onload",
    r"<svg[^>]*onload",
    r"alert\s*\(",
    r"prompt\s*\(",
    r"confirm\s*\(",
    r"eval\s*\(",
    r"expression\s*\(",
    r"<meta[^>]*http-equiv",
]


def detect_xss_in_string(input_string: str) -> Dict[str, Any]:
    """Detect potential XSS patterns in a string."""
    result = {
        "input": input_string,
        "is_suspicious": False,
        "matched_patterns": [],
        "risk_level": "low",
        "decoded_input": None,
    }
    
    decoded = unescape(input_string)
    if decoded != input_string:
        result["decoded_input"] = decoded
    
    test_string = decoded.lower()
    
    for pattern in XSS_PATTERNS:
        if re.search(pattern, test_string, re.IGNORECASE | re.DOTALL):
            result["is_suspicious"] = True
            result["matched_patterns"].append(pattern)
    
    if len(result["matched_patterns"]) >= 3:
        result["risk_level"] = "high"
    elif len(result["matched_patterns"]) >= 1:
        result["risk_level"] = "medium"
    
    return result


def analyze_html_context(html_content: str) -> Dict[str, Any]:
    """Analyze HTML content for XSS vulnerabilities."""
    result = {
        "total_scripts": 0,
        "inline_event_handlers": 0,
        "suspicious_patterns": [],
        "risk_level": "low",
    }
    
    result["total_scripts"] = len(re.findall(r"<script[^>]*>", html_content, re.IGNORECASE))
    
    event_handlers = re.findall(r"on\w+\s*=\s*[\"'][^\"']*[\"']", html_content, re.IGNORECASE)
    result["inline_event_handlers"] = len(event_handlers)
    
    dangerous_tags = ["<iframe", "<object", "<embed", "<applet"]
    for tag in dangerous_tags:
        if tag.lower() in html_content.lower():
            result["suspicious_patterns"].append(f"Found {tag} tag")
    
    if "javascript:" in html_content.lower():
        result["suspicious_patterns"].append("Found javascript: protocol")
    
    if re.search(r"eval\s*\(", html_content, re.IGNORECASE):
        result["suspicious_patterns"].append("Found eval() function")
    
    risk_score = len(result["suspicious_patterns"]) + (result["inline_event_handlers"] // 3)
    
    if risk_score >= 5:
        result["risk_level"] = "high"
    elif risk_score >= 2:
        result["risk_level"] = "medium"
    
    return result


def sanitize_input(input_string: str, aggressive: bool = False) -> str:
    """Basic sanitization of user input to prevent XSS.
    
    Args:
        input_string: The input to sanitize
        aggressive: If True, removes more characters
        
    Returns:
        Sanitized string
    """
    sanitized = input_string
    
    sanitized = sanitized.replace("<", "&lt;")
    sanitized = sanitized.replace(">", "&gt;")
    sanitized = sanitized.replace('"', "&quot;")
    sanitized = sanitized.replace("'", "&#x27;")
    
    if aggressive:
        sanitized = re.sub(r"javascript:", "", sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r"on\w+\s*=", "", sanitized, flags=re.IGNORECASE)
    
    return sanitized


def batch_check_inputs(inputs: List[str]) -> Dict[str, Any]:
    """Check multiple inputs for XSS patterns."""
    results = {
        "total_inputs": len(inputs),
        "suspicious_count": 0,
        "clean_count": 0,
        "high_risk": [],
        "medium_risk": [],
        "low_risk": [],
    }
    
    for inp in inputs:
        analysis = detect_xss_in_string(inp)
        
        if analysis["is_suspicious"]:
            results["suspicious_count"] += 1
            results[f"{analysis['risk_level']}_risk"].append({
                "input": inp,
                "patterns": len(analysis["matched_patterns"]),
            })
        else:
            results["clean_count"] += 1
            results["low_risk"].append(inp)
    
    return results
