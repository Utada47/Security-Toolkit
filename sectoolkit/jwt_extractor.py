"""Utility for extracting and validating JWT tokens from logs or text."""
import re
from typing import List

JWT_REGEX = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

def extract_jwts(text: str) -> List[str]:
    """Return list of JWT strings found in the input text."""
    return JWT_REGEX.findall(text)
