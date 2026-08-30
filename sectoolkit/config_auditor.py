"""Configuration file security auditor.

Scans config files (ini, env, yaml-like, json) for common security
misconfigurations: exposed secrets, weak settings, debug flags, etc.
"""
import re
import os
import json
from typing import Dict, List, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Patterns that suggest a dangerous value is present
# ---------------------------------------------------------------------------

# Key names that likely hold secrets
_SECRET_KEY_PATTERNS = [
    re.compile(r"\b(password|passwd|secret|api[_-]?key|auth[_-]?token"
               r"|access[_-]?key|private[_-]?key|client[_-]?secret"
               r"|db[_-]?pass|database[_-]?password)\b", re.IGNORECASE),
]

# Values that are obviously weak/default
_WEAK_VALUES = {
    "password", "password123", "admin", "root", "123456",
    "changeme", "secret", "test", "default", "example",
    "null", "none", "", "false", "0",
}

# Keys that should never be True/enabled in production
_DANGEROUS_FLAGS = re.compile(
    r"\b(debug|verbose|trace|allow_all|disable_auth|skip_tls"
    r"|insecure|no_verify|unsafe)\b",
    re.IGNORECASE,
)

# Patterns that look like hardcoded IPs / localhost exposed to the world
_INSECURE_BIND = re.compile(r"0\.0\.0\.0")


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------

def parse_env_file(content: str) -> Dict[str, str]:
    """Parse a .env file into a key→value dict.

    Handles:
    - KEY=VALUE
    - KEY="VALUE"  / KEY='VALUE'
    - # comments
    - Blank lines
    """
    result: Dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, raw_val = line.partition("=")
        key = key.strip()
        raw_val = raw_val.strip()
        # Strip surrounding quotes
        if (raw_val.startswith('"') and raw_val.endswith('"')) or \
           (raw_val.startswith("'") and raw_val.endswith("'")):
            raw_val = raw_val[1:-1]
        result[key] = raw_val
    return result


def parse_ini_file(content: str) -> Dict[str, Dict[str, str]]:
    """Minimal INI parser that returns {section: {key: value}}.

    Uses stdlib configparser internally.

    BUG: the function wraps content in a default [DEFAULT] header to handle
    section-less INI files, but this means the 'DEFAULT' section is always
    included even when the file already has explicit sections — causing
    duplicate entries in the output.
    """
    import configparser
    config = configparser.ConfigParser()
    # BUG: unconditionally prepend [DEFAULT] even when sections already exist
    wrapped = "[DEFAULT]\n" + content
    try:
        config.read_string(wrapped)
    except configparser.Error:
        return {}

    result: Dict[str, Dict[str, str]] = {}
    # configparser makes DEFAULT available under every section — we include it raw
    result["DEFAULT"] = dict(config.defaults())
    for section in config.sections():
        result[section] = dict(config[section])
    return result


# ---------------------------------------------------------------------------
# Audit functions
# ---------------------------------------------------------------------------

def scan_for_secrets(pairs: Dict[str, str]) -> List[Dict[str, Any]]:
    """Check key→value pairs for exposed secrets.

    Returns a list of findings, each with 'key', 'severity', 'reason'.
    """
    findings: List[Dict[str, Any]] = []

    for key, value in pairs.items():
        for pattern in _SECRET_KEY_PATTERNS:
            if pattern.search(key):
                severity = "high"
                reason = f"Key '{key}' looks like it holds a secret"

                if value.lower() in _WEAK_VALUES:
                    severity = "critical"
                    reason += f" and the value is a known weak/default: '{value}'"
                elif not value:
                    severity = "medium"
                    reason += " but the value is empty"
                else:
                    # Non-empty, non-weak value — still flag as informational
                    # BUG: should set severity = 'info' for non-weak values,
                    # but sets 'high' for everything — generates too many noisy alerts
                    pass

                findings.append({
                    "key": key,
                    "value_hint": value[:3] + "***" if len(value) > 3 else "***",
                    "severity": severity,
                    "reason": reason,
                })
                break  # don't double-report same key

    return findings


def scan_for_dangerous_flags(pairs: Dict[str, str]) -> List[Dict[str, Any]]:
    """Detect dangerous boolean flags (debug=true, insecure=1, etc.)."""
    findings: List[Dict[str, Any]] = []
    truthy = {"true", "1", "yes", "on", "enabled"}

    for key, value in pairs.items():
        if _DANGEROUS_FLAGS.search(key) and value.lower() in truthy:
            findings.append({
                "key": key,
                "value": value,
                "severity": "high",
                "reason": f"Dangerous flag '{key}' is enabled",
            })

    return findings


def scan_for_insecure_bindings(pairs: Dict[str, str]) -> List[Dict[str, Any]]:
    """Detect services bound to 0.0.0.0 (listens on all interfaces)."""
    findings: List[Dict[str, Any]] = []
    for key, value in pairs.items():
        if _INSECURE_BIND.search(value):
            findings.append({
                "key": key,
                "value": value,
                "severity": "medium",
                "reason": f"'{key}' binds to 0.0.0.0 - exposed on all network interfaces",
            })
    return findings


def audit_env_file(filepath: str) -> Dict[str, Any]:
    """Full audit of a .env file.

    Returns:
        {
          'filepath': str,
          'total_keys': int,
          'findings': [ {key, severity, reason}, ... ],
          'risk_level': 'low' | 'medium' | 'high' | 'critical',
        }
    """
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            content = fh.read()
    except OSError as e:
        return {"filepath": filepath, "error": str(e), "findings": [], "risk_level": "unknown"}

    pairs = parse_env_file(content)
    findings: List[Dict[str, Any]] = []
    findings += scan_for_secrets(pairs)
    findings += scan_for_dangerous_flags(pairs)
    findings += scan_for_insecure_bindings(pairs)

    severities = {f["severity"] for f in findings}
    if "critical" in severities:
        risk = "critical"
    elif "high" in severities:
        risk = "high"
    elif "medium" in severities:
        risk = "medium"
    else:
        risk = "low"

    return {
        "filepath": os.path.abspath(filepath),
        "total_keys": len(pairs),
        "findings": findings,
        "risk_level": risk,
    }


def audit_json_config(filepath: str) -> Dict[str, Any]:
    """Audit a flat JSON config file for security issues."""
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        return {"filepath": filepath, "error": str(e), "findings": [], "risk_level": "unknown"}

    # Flatten nested dicts one level deep for scanning
    pairs: Dict[str, str] = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for sub_key, sub_val in value.items():
                pairs[f"{key}.{sub_key}"] = str(sub_val)
        else:
            pairs[key] = str(value)

    findings: List[Dict[str, Any]] = []
    findings += scan_for_secrets(pairs)
    findings += scan_for_dangerous_flags(pairs)

    severities = {f["severity"] for f in findings}
    risk = "critical" if "critical" in severities else \
           "high"     if "high"     in severities else \
           "medium"   if "medium"   in severities else "low"

    return {
        "filepath": os.path.abspath(filepath),
        "total_keys": len(pairs),
        "findings": findings,
        "risk_level": risk,
    }


def audit_config_file(filepath: str) -> Dict[str, Any]:
    """Audit a configuration file for security issues.
    
    Auto-detects file type and applies appropriate parsing.
    Returns a unified result format.
    """
    filename = os.path.basename(filepath).lower()
    
    # Determine file type and parse accordingly
    if filename.endswith('.env') or 'env' in filename:
        result = audit_env_file(filepath)
        file_type = "env"
    elif filename.endswith(('.ini', '.conf', '.cfg')):
        result = audit_ini_file(filepath)
        file_type = "ini"
    elif filename.endswith('.json'):
        result = audit_json_config(filepath)
        file_type = "json"
    elif filename.endswith(('.yml', '.yaml')):
        # Treat YAML-like files as env for now (basic key=value parsing)
        result = audit_env_file(filepath)
        file_type = "yaml"
    else:
        # Try as env file (most permissive)
        result = audit_env_file(filepath)
        file_type = "unknown"
    
    # Convert to unified format
    findings = result.get("findings", [])
    
    # Calculate risk score (0-100)
    risk_score = 0
    for finding in findings:
        severity = finding.get("severity", "low")
        if severity == "critical":
            risk_score += 25
        elif severity == "high":
            risk_score += 15
        elif severity == "medium":
            risk_score += 10
        elif severity == "low":
            risk_score += 5
    
    risk_score = min(100, risk_score)
    
    # Convert findings to more user-friendly format
    issues = []
    for finding in findings:
        issue = {
            "type": finding.get("type", "security_issue"),
            "key": finding.get("key", ""),
            "severity": finding.get("severity", "low"),
            "description": finding.get("reason", finding.get("description", "")),
        }
        
        # Add value if not sensitive (not from secrets scan)
        if "value_hint" in finding:
            # This is a secret finding, show hint instead
            issue["value"] = finding["value_hint"]
        elif "value" in finding:
            issue["value"] = finding["value"]
        
        # Add recommendation based on the reason/description
        reason = finding.get("reason", "")
        if "secret" in reason.lower():
            issue["type"] = "secret_exposure"
            issue["recommendation"] = "Move this secret to environment variables or a secure vault"
        elif "dangerous flag" in reason.lower():
            issue["type"] = "dangerous_flag"
            issue["recommendation"] = "Disable this flag in production environments"
        elif "0.0.0.0" in reason:
            issue["type"] = "insecure_binding"
            issue["recommendation"] = "Bind to specific interfaces instead of 0.0.0.0"
        elif "weak" in reason.lower() or "default" in reason.lower():
            issue["type"] = "weak_value"
            issue["recommendation"] = "Use a strong, unique value"
        
        issues.append(issue)
    
    return {
        "file": os.path.abspath(filepath),
        "file_type": file_type,
        "total_issues": len(issues),
        "issues": issues,
        "risk_level": result.get("risk_level", "low"),
        "risk_score": risk_score,
    }


def summarise_audit(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate multiple audit results into a summary."""
    total_findings = sum(len(r.get("findings", [])) for r in results)
    by_severity: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for r in results:
        for f in r.get("findings", []):
            sev = f.get("severity", "low")
            by_severity[sev] = by_severity.get(sev, 0) + 1

    overall = "critical" if by_severity["critical"] > 0 else \
              "high"     if by_severity["high"]     > 0 else \
              "medium"   if by_severity["medium"]   > 0 else "low"

    return {
        "files_audited": len(results),
        "total_findings": total_findings,
        "by_severity": by_severity,
        "overall_risk": overall,
    }
