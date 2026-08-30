"""Password auditing utilities for bulk password policy checks."""
import re
import hashlib
import csv
import json
from typing import Dict, List, Any, Optional, Tuple


# Common weak passwords (small offline list)
_COMMON_PASSWORDS = {
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "1234567890", "qwerty", "abc123",
    "111111", "iloveyou", "sunshine", "princess", "dragon",
    "master", "hello", "login", "shadow", "superman",
}

# Password policy defaults
DEFAULT_POLICY = {
    "min_length": 8,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digits": True,
    "require_symbols": True,
    "max_repeated_chars": 3,
    "disallow_common": True,
}


def check_policy_compliance(password: str, policy: Optional[Dict] = None) -> Dict[str, Any]:
    """Check whether a password meets a given policy.

    Args:
        password: The plaintext password to check.
        policy:   Policy dict. If None, DEFAULT_POLICY is used.

    Returns:
        Dict with keys: 'compliant', 'violations', 'score' (0-100).
    """
    if policy is None:
        policy = DEFAULT_POLICY

    violations: List[str] = []

    # Length check
    if len(password) < policy.get("min_length", 8):
        violations.append(
            f"Too short: {len(password)} chars (min {policy['min_length']})"
        )

    # Character class checks
    if policy.get("require_uppercase") and not re.search(r"[A-Z]", password):
        violations.append("Missing uppercase letter")

    if policy.get("require_lowercase") and not re.search(r"[a-z]", password):
        violations.append("Missing lowercase letter")

    if policy.get("require_digits") and not re.search(r"\d", password):
        violations.append("Missing digit")

    if policy.get("require_symbols") and not re.search(r"[^A-Za-z0-9]", password):
        violations.append("Missing symbol")

    # Repeated characters: flag if any char appears max_rep or more times consecutively
    max_rep = policy.get("max_repeated_chars", 3)
    if re.search(r"(.)\1{" + str(max_rep - 1) + r",}", password):
        violations.append(f"Too many repeated characters (max {max_rep} consecutive)")

    # Common password check
    if policy.get("disallow_common") and password.lower() in _COMMON_PASSWORDS:
        violations.append("Password is in common password list")

    # Score: start at 100, deduct per violation
    score = max(0, 100 - len(violations) * 15)

    return {
        "password_length": len(password),
        "compliant": len(violations) == 0,
        "violations": violations,
        "score": score,
    }


def audit_password_list(passwords: List[str], policy: Optional[Dict] = None) -> Dict[str, Any]:
    """Audit a list of passwords against a policy.

    Returns summary stats and per-password results.
    """
    results = []
    compliant_count = 0
    violation_counts: Dict[str, int] = {}

    for pwd in passwords:
        check = check_policy_compliance(pwd, policy)
        results.append({"password_hint": pwd[:2] + "*" * max(0, len(pwd) - 2), **check})
        if check["compliant"]:
            compliant_count += 1
        for v in check["violations"]:
            # Normalise the violation message for counting
            key = v.split(":")[0]
            violation_counts[key] = violation_counts.get(key, 0) + 1

    total = len(passwords)
    return {
        "total": total,
        "compliant": compliant_count,
        "non_compliant": total - compliant_count,
        "compliance_rate": round(compliant_count / total * 100, 1) if total else 0.0,
        "top_violations": sorted(violation_counts.items(), key=lambda x: x[1], reverse=True),
        "results": results,
    }


def load_passwords_from_file(filepath: str) -> List[str]:
    """Load passwords line-by-line from a plain-text file.

    Blank lines and lines starting with '#' are skipped.
    """
    passwords = []
    # BUG fixed: added encoding='utf-8' to handle non-ASCII passwords on Windows
    with open(filepath, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                passwords.append(line)
    return passwords


def hash_password_sha256(password: str, salt: str = "") -> str:
    """Hash a password with optional salt using SHA-256.

    NOTE: Use bcrypt/argon2 for real password storage — this is for auditing
    hashed dumps, not for storing passwords.
    """
    combined = salt + password
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def detect_password_reuse(hashed_passwords: List[str]) -> Dict[str, Any]:
    """Detect duplicate hashes in a list (indicates password reuse).

    Args:
        hashed_passwords: List of hex hash strings.

    Returns:
        Dict with 'total', 'unique', 'duplicates', 'reuse_rate'.
    """
    from collections import Counter
    counts = Counter(hashed_passwords)
    duplicates = {h: c for h, c in counts.items() if c > 1}

    total = len(hashed_passwords)
    unique = len(counts)

    return {
        "total": total,
        "unique": unique,
        "duplicate_hashes": len(duplicates),
        "reuse_rate": round((total - unique) / total * 100, 1) if total else 0.0,
        "duplicates": duplicates,
    }


def estimate_password_entropy(password: str) -> Dict[str, Any]:
    """Estimate the bit entropy of a password based on character set size."""
    import math

    charset_size = 0
    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"\d", password):
        charset_size += 10
    if re.search(r"[^A-Za-z0-9]", password):
        charset_size += 32  # approximate symbol pool

    if charset_size == 0:
        entropy = 0.0
    else:
        entropy = len(password) * math.log2(charset_size)

    if entropy >= 80:
        strength = "strong"
    elif entropy >= 60:
        strength = "moderate"
    elif entropy >= 40:
        strength = "weak"
    else:
        strength = "very weak"

    return {
        "password_length": len(password),
        "charset_size": charset_size,
        "entropy_bits": round(entropy, 2),
        "strength": strength,
    }


def audit_password_file(filepath: str, file_format: str = "txt", password_column: int = 1,
                        policy: Optional[Dict] = None, check_breaches: bool = False) -> Dict[str, Any]:
    """Audit passwords from a file for policy compliance and breaches.
    
    Args:
        filepath: Path to password file
        file_format: 'txt' (one per line) or 'csv' 
        password_column: Column number for passwords in CSV (1-based)
        policy: Custom password policy dict
        check_breaches: Whether to check against breach databases
        
    Returns:
        Dict with audit results including compliance rates and security scores
    """
    passwords = []
    
    # Read passwords from file
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            if file_format == "csv":
                import csv
                reader = csv.reader(f)
                for row in reader:
                    if len(row) >= password_column:
                        passwords.append(row[password_column - 1].strip())
            else:  # txt format
                passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        return {
            "error": f"Could not read file: {e}",
            "total_passwords": 0,
            "compliant_count": 0,
            "compliance_rate": 0.0,
            "security_score": 0.0,
        }
    
    if not passwords:
        return {
            "total_passwords": 0,
            "compliant_count": 0,
            "compliance_rate": 0.0,
            "security_score": 0.0,
            "common_violations": {},
        }
    
    # Audit each password
    password_results = []
    violation_counts = {}
    breach_count = 0
    total_breach_appearances = 0
    
    for i, password in enumerate(passwords):
        # Check policy compliance
        compliance = check_policy_compliance(password, policy)
        
        result = {
            "index": i + 1,
            "compliant": compliance["compliant"],
            "score": compliance["score"],
            "violations": compliance["violations"],
        }
        
        # Count violations
        for violation in compliance["violations"]:
            violation_counts[violation] = violation_counts.get(violation, 0) + 1
        
        # Check breaches if requested
        if check_breaches:
            try:
                from sectoolkit.breach_check import check_password_breach
                breach_result = check_password_breach(password)
                result["breach_info"] = breach_result
                
                if breach_result["breached"]:
                    breach_count += 1
                    total_breach_appearances += breach_result.get("times_seen", 0)
            except Exception:
                result["breach_info"] = {"breached": False, "error": "Check failed"}
        
        password_results.append(result)
    
    # Calculate summary statistics
    compliant_count = sum(1 for r in password_results if r["compliant"])
    compliance_rate = (compliant_count / len(passwords)) * 100 if passwords else 0.0
    
    avg_score = sum(r["score"] for r in password_results) / len(password_results) if password_results else 0.0
    
    # Calculate security score (weighted combination of compliance and strength)
    security_score = (compliance_rate * 0.7) + (avg_score * 0.3)
    
    # Get most common violations
    common_violations = dict(sorted(violation_counts.items(), key=lambda x: x[1], reverse=True)[:5])
    
    result = {
        "total_passwords": len(passwords),
        "compliant_count": compliant_count,
        "compliance_rate": compliance_rate,
        "security_score": security_score,
        "average_password_score": avg_score,
        "common_violations": common_violations,
        "password_results": password_results,
    }
    
    # Add breach summary if checked
    if check_breaches:
        breach_rate = (breach_count / len(passwords)) * 100 if passwords else 0.0
        most_breached = max(total_breach_appearances, 0) if total_breach_appearances > 0 else 0
        
        result["breach_summary"] = {
            "breached_count": breach_count,
            "breach_rate": breach_rate,
            "total_breach_appearances": total_breach_appearances,
            "most_breached": most_breached,
        }
    
    return result


def export_audit_report(audit_result: Dict[str, Any], filepath: str, fmt: str = "json") -> bool:
    """Export an audit report to JSON or CSV.

    Args:
        audit_result: Output from audit_password_list().
        filepath:     Destination file path.
        fmt:          'json' or 'csv'.

    Returns:
        True on success, False on error.
    """
    try:
        if fmt == "json":
            with open(filepath, "w", encoding="utf-8") as fh:
                json.dump(audit_result, fh, indent=2)
        elif fmt == "csv":
            rows = audit_result.get("results", [])
            if not rows:
                return False
            with open(filepath, "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
                writer.writeheader()
                writer.writerows(rows)
        else:
            return False
        return True
    except Exception:
        return False
