"""JWT (JSON Web Token) analysis and security validation."""
import json
import base64
import hmac
import hashlib
from typing import Dict, Any, Optional, List


def decode_jwt_segment(segment: str) -> Dict[str, Any]:
    """Decode a JWT segment (header or payload)."""
    try:
        padding = '=' * (4 - len(segment) % 4)
        decoded = base64.urlsafe_b64decode(segment + padding)
        return json.loads(decoded)
    except Exception as e:
        return {"error": str(e)}


def parse_jwt(token: str) -> Dict[str, Any]:
    """Parse a JWT token into its components."""
    result = {
        "valid_format": False,
        "header": {},
        "payload": {},
        "signature": "",
        "raw_token": token,
    }
    
    parts = token.split('.')
    
    if len(parts) != 3:
        result["error"] = "Invalid JWT format - expected 3 parts separated by dots"
        return result
    
    result["valid_format"] = True
    result["header"] = decode_jwt_segment(parts[0])
    result["payload"] = decode_jwt_segment(parts[1])
    result["signature"] = parts[2]
    
    return result


def analyze_jwt_security(token: str) -> Dict[str, Any]:
    """Analyze JWT token for security issues."""
    result = {
        "token": token,
        "vulnerabilities": [],
        "warnings": [],
        "info": {},
        "risk_level": "low",
    }
    
    parsed = parse_jwt(token)
    
    if not parsed["valid_format"]:
        result["vulnerabilities"].append("Invalid JWT format")
        result["risk_level"] = "high"
        return result
    
    header = parsed["header"]
    payload = parsed["payload"]
    
    if header.get("alg") == "none":
        result["vulnerabilities"].append("Algorithm set to 'none' - token is not signed!")
        result["risk_level"] = "critical"
    
    if header.get("alg") in ["HS256", "HS384", "HS512"]:
        result["warnings"].append(f"Using symmetric algorithm {header['alg']} - secret must be strong")
    
    if "exp" not in payload:
        result["warnings"].append("No expiration time (exp) claim - token never expires")
    else:
        import time
        exp = payload["exp"]
        current_time = int(time.time())
        if exp < current_time:
            result["info"]["expired"] = True
            result["warnings"].append("Token has expired")
        else:
            ttl = exp - current_time
            result["info"]["ttl_seconds"] = ttl
            if ttl > 86400 * 30:
                result["warnings"].append(f"Token expires in {ttl // 86400} days - consider shorter expiration")
    
    if "iat" in payload:
        result["info"]["issued_at"] = payload["iat"]
    
    if "nbf" in payload:
        result["info"]["not_before"] = payload["nbf"]
    
    result["info"]["header"] = header
    result["info"]["payload"] = payload
    
    if len(result["vulnerabilities"]) > 0:
        result["risk_level"] = "high"
    elif len(result["warnings"]) >= 3:
        result["risk_level"] = "medium"
    
    return result


def verify_jwt_signature(token: str, secret: str, algorithm: str = "HS256") -> bool:
    """Verify JWT signature using HMAC."""
    parts = token.split('.')
    
    if len(parts) != 3:
        return False
    
    message = f"{parts[0]}.{parts[1]}"
    signature = parts[2]
    
    if algorithm == "HS256":
        hash_func = hashlib.sha256
    elif algorithm == "HS384":
        hash_func = hashlib.sha384
    elif algorithm == "HS512":
        hash_func = hashlib.sha512
    else:
        return False
    
    expected_sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), message.encode(), hash_func).digest()
    ).decode().rstrip('=')
    
    return hmac.compare_digest(signature, expected_sig)


def brute_force_jwt_secret(token: str, wordlist: List[str], algorithm: str = "HS256") -> Optional[str]:
    """Attempt to brute force JWT secret using a wordlist.
    
    WARNING: Only use on tokens you own or have authorization to test.
    """
    for secret in wordlist:
        if verify_jwt_signature(token, secret.strip(), algorithm):
            return secret.strip()
    return None
