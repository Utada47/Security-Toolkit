"""Simple email validation utility using regex."""
import re
from typing import Dict, Any

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def validate_email(email: str) -> Dict[str, Any]:
    """Validate an email address.
    
    Returns a dict with keys:
      - email: original input
      - is_valid: bool
      - reason: optional explanation when invalid
    """
    result = {"email": email, "is_valid": False}
    
    if not email or "@" not in email:
        result["reason"] = "Missing '@' symbol"
        return result
    
    if EMAIL_REGEX.fullmatch(email):
        result["is_valid"] = True
    else:
        result["reason"] = "Pattern does not match"
    
    return result
