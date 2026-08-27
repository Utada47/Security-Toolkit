"""Utility to generate random HTTP headers for testing purposes."""
import random

COMMON_HEADERS = {
    "User-Agent": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.63 Safari/537.36",
    ],
    "Accept": ["*/*", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"],
    "Accept-Language": ["en-US,en;q=0.5", "es-ES,es;q=0.5"],
    "Connection": ["keep-alive", "close"],
}


def generate_random_headers() -> dict:
    """Return a dict of random HTTP headers for a request."""
    headers = {}
    for name, values in COMMON_HEADERS.items():
        headers[name] = random.choice(values)
    # Add a random X-Forwarded-For IP
    headers["X-Forwarded-For"] = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"
    return headers
