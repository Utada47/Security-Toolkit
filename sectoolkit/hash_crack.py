"""Cryptographic hash cracking and analysis utilities."""
import hashlib
from typing import Dict, List, Any, Optional


def analyze_hash_type(hash_string: str) -> Dict[str, Any]:
    """Analyze a hash to determine its likely algorithm."""
    result = {
        "input": hash_string,
        "length": len(hash_string),
        "likely_algorithms": [],
        "confidence": "low",
    }
    
    hash_len = len(hash_string)
    
    hash_patterns = {
        32: ["MD5", "MD4"],
        40: ["SHA1"],
        56: ["SHA224"],
        64: ["SHA256"],
        96: ["SHA384"],
        128: ["SHA512"],
    }
    
    if hash_len in hash_patterns:
        result["likely_algorithms"] = hash_patterns[hash_len]
        result["confidence"] = "high"
    else:
        if 24 <= hash_len <= 32:
            result["likely_algorithms"] = ["MD5", "MD4", "LM Hash"]
        elif 32 < hash_len <= 50:
            result["likely_algorithms"] = ["SHA1", "NTLM"]
        elif 50 < hash_len <= 70:
            result["likely_algorithms"] = ["SHA224", "SHA256"]
        elif 70 < hash_len <= 100:
            result["likely_algorithms"] = ["SHA384", "SHA512"]
        result["confidence"] = "medium"
    
    return result


def rainbow_table_lookup(hash_string: str, common_values: Optional[List[str]] = None) -> Dict[str, Any]:
    """Attempt to reverse a hash using common values (simplified rainbow table)."""
    if common_values is None:
        common_values = [
            "password", "123456", "admin", "letmein", "welcome",
            "password123", "admin123", "qwerty", "123123", "monkey",
            "1234567890", "iloveyou", "password1", "admin1", "root",
        ]
    
    result = {
        "hash": hash_string,
        "found": False,
        "plaintext": None,
        "algorithm_used": None,
    }
    
    hash_len = len(hash_string)
    hash_patterns = {
        32: "md5",
        40: "sha1",
        56: "sha224",
        64: "sha256",
        96: "sha384",
        128: "sha512",
    }
    
    if hash_len not in hash_patterns:
        result["error"] = f"Unknown hash length: {hash_len}"
        return result
    
    algorithm = hash_patterns[hash_len]
    
    for value in common_values:
        try:
            if algorithm == "md5":
                computed = hashlib.md5(value.encode()).hexdigest()
            elif algorithm == "sha1":
                computed = hashlib.sha1(value.encode()).hexdigest()
            elif algorithm == "sha224":
                computed = hashlib.sha224(value.encode()).hexdigest()
            elif algorithm == "sha256":
                computed = hashlib.sha256(value.encode()).hexdigest()
            elif algorithm == "sha384":
                computed = hashlib.sha384(value.encode()).hexdigest()
            elif algorithm == "sha512":
                computed = hashlib.sha512(value.encode()).hexdigest()
            
            if computed.lower() == hash_string.lower():
                result["found"] = True
                result["plaintext"] = value
                result["algorithm_used"] = algorithm.upper()
                return result
        except:
            continue
    
    return result


def check_hash_weaknesses(hash_string: str) -> Dict[str, Any]:
    """Check for weaknesses in a hash."""
    result = {
        "hash": hash_string,
        "weaknesses": [],
        "recommendations": [],
    }
    
    hash_len = len(hash_string)
    
    if hash_len == 32:
        result["weaknesses"].append("MD5 is cryptographically broken - collisions found")
        result["recommendations"].append("Use SHA256 or stronger algorithm")
    
    if hash_len == 40:
        result["weaknesses"].append("SHA1 is deprecated - should not be used for security")
        result["recommendations"].append("Migrate to SHA256 or SHA512")
    
    if all(c in "0123456789abcdef" for c in hash_string.lower()):
        if hash_len in [32, 40, 56, 64, 96, 128]:
            result["weaknesses"].append("Hash appears to be unsalted")
            result["recommendations"].append("Use a strong salt when hashing passwords")
    
    return result


def estimate_crack_time(hash_algorithm: str, password_length: int, complexity: str = "medium") -> Dict[str, Any]:
    """Estimate time to crack a hash through brute force."""
    result = {
        "algorithm": hash_algorithm,
        "password_length": password_length,
        "complexity": complexity,
        "estimate": {},
    }
    
    charset_sizes = {
        "low": 10,
        "medium": 62,
        "high": 95,
    }
    
    charset_size = charset_sizes.get(complexity, 62)
    possibilities = charset_size ** password_length
    
    hashes_per_second = {
        "md5": 1_000_000_000,
        "sha1": 500_000_000,
        "sha256": 100_000_000,
        "sha512": 50_000_000,
        "bcrypt": 10_000,
        "scrypt": 1_000,
    }
    
    hps = hashes_per_second.get(hash_algorithm.lower(), 100_000_000)
    
    seconds = possibilities / (2 * hps)
    
    result["estimate"]["seconds"] = seconds
    result["estimate"]["minutes"] = seconds / 60
    result["estimate"]["hours"] = seconds / 3600
    result["estimate"]["days"] = seconds / 86400
    result["estimate"]["years"] = seconds / (86400 * 365.25)
    
    if result["estimate"]["years"] > 1000000:
        result["estimate"]["practical"] = "Infeasible (> 1 million years)"
    elif result["estimate"]["days"] > 365:
        result["estimate"]["practical"] = f"{result['estimate']['years']:.2f} years"
    elif result["estimate"]["hours"] > 24:
        result["estimate"]["practical"] = f"{result['estimate']['days']:.2f} days"
    elif result["estimate"]["minutes"] > 60:
        result["estimate"]["practical"] = f"{result['estimate']['hours']:.2f} hours"
    else:
        result["estimate"]["practical"] = f"{result['estimate']['minutes']:.2f} minutes"
    
    return result


def compare_hash_algorithms() -> Dict[str, Any]:
    """Compare security characteristics of different hash algorithms."""
    return {
        "MD5": {
            "hash_length": 32,
            "security": "BROKEN - do not use",
            "speed": "Very Fast",
            "use_case": "Legacy/non-security only",
        },
        "SHA1": {
            "hash_length": 40,
            "security": "DEPRECATED - collisions possible",
            "speed": "Fast",
            "use_case": "Legacy only",
        },
        "SHA256": {
            "hash_length": 64,
            "security": "SECURE",
            "speed": "Fast",
            "use_case": "General purpose hashing",
        },
        "SHA512": {
            "hash_length": 128,
            "security": "SECURE",
            "speed": "Fast",
            "use_case": "High security requirements",
        },
        "bcrypt": {
            "hash_length": 60,
            "security": "SECURE with work factor",
            "speed": "Slow (by design)",
            "use_case": "Password hashing",
        },
        "scrypt": {
            "hash_length": "Variable",
            "security": "VERY SECURE with work factors",
            "speed": "Very Slow (by design)",
            "use_case": "Password hashing, KDF",
        },
        "Argon2": {
            "hash_length": "Variable",
            "security": "VERY SECURE - modern",
            "speed": "Configurable",
            "use_case": "Password hashing (recommended)",
        },
    }
