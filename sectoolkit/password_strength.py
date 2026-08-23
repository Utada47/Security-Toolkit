"""Password strength estimation.

Unlike a naive length-only check, this looks at character-class diversity,
common patterns (sequences, repeated characters, keyboard walks), and
membership in a small list of extremely common passwords — the kinds of
things real attackers try first, long before brute force.
"""
import re
import math

_COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty",
    "abc123", "password1", "111111", "123123", "admin", "letmein",
    "welcome", "monkey", "dragon", "qazwsx", "iloveyou",
}

_KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]


def _has_keyboard_walk(password: str, min_run: int = 4) -> bool:
    lower = password.lower()
    for row in _KEYBOARD_ROWS:
        for i in range(len(row) - min_run + 1):
            if row[i : i + min_run] in lower:
                return True
    return False


def _has_sequential_run(password: str, min_run: int = 4) -> bool:
    """Detects ascending/descending runs like '1234' or 'dcba'."""
    for i in range(len(password) - min_run + 1):
        chunk = password[i : i + min_run]
        ascending = all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(len(chunk) - 1))
        descending = all(ord(chunk[j]) - ord(chunk[j + 1]) == 1 for j in range(len(chunk) - 1))
        if ascending or descending:
            return True
    return False


def _character_pool_size(password: str) -> int:
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32
    return pool


def estimate_entropy_bits(password: str) -> float:
    """A rough entropy estimate: log2(pool_size) * length.

    This deliberately overestimates for patterned passwords (e.g. '1111'
    scores the same pool-based entropy as '8f3k'), which is exactly why
    check_strength() layers pattern detection on top rather than relying
    on this number alone.
    """
    pool = _character_pool_size(password)
    if pool == 0 or len(password) == 0:
        return 0.0
    return len(password) * math.log2(pool)


def check_strength(password: str) -> dict:
    issues = []

    if len(password) < 8:
        issues.append("shorter than 8 characters")
    if password.lower() in _COMMON_PASSWORDS:
        issues.append("matches an extremely common password")
    if not re.search(r"[a-z]", password):
        issues.append("no lowercase letters")
    if not re.search(r"[A-Z]", password):
        issues.append("no uppercase letters")
    if not re.search(r"[0-9]", password):
        issues.append("no digits")
    if not re.search(r"[^a-zA-Z0-9]", password):
        issues.append("no special characters")
    if _has_sequential_run(password):
        issues.append("contains a sequential run (e.g. '1234' or 'abcd')")
    if _has_keyboard_walk(password):
        issues.append("contains a keyboard-adjacent pattern (e.g. 'qwerty')")
    if len(set(password)) <= max(1, len(password) // 4):
        issues.append("very low character variety (lots of repeats)")

    entropy_bits = estimate_entropy_bits(password)

    if entropy_bits < 28 or len(issues) >= 4:
        rating = "very weak"
    elif entropy_bits < 36 or len(issues) >= 3:
        rating = "weak"
    elif entropy_bits < 60 or len(issues) >= 1:
        rating = "moderate"
    else:
        rating = "strong"

    return {
        "rating": rating,
        "entropy_bits": round(entropy_bits, 1),
        "issues": issues,
    }
