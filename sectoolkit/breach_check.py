"""Check whether a password has appeared in known data breaches, using the
Have I Been Pwned "Pwned Passwords" API.

Uses the k-anonymity model: only the first 5 characters of the password's
SHA1 hash are sent to the API. The API returns all hash suffixes matching
that prefix, and the match is found locally — the actual password (and
even its full hash) never leaves your machine.

See: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""
import hashlib
import urllib.request
import urllib.error

_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"


def check_password_breach(password: str, timeout: int = 10) -> dict:
    """Return {'breached': bool, 'times_seen': int} for the given password.

    Raises RuntimeError if the API can't be reached (e.g. no internet
    connection) — callers should handle this distinctly from "not breached".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    url = _API_URL.format(prefix=prefix)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach Have I Been Pwned API: {exc}") from exc

    for line in body.splitlines():
        returned_suffix, count = line.split(":")
        if returned_suffix == suffix:
            return {"breached": True, "times_seen": int(count)}

    return {"breached": False, "times_seen": 0}
