"""Subdomain enumeration using a wordlist and DNS resolution."""
import socket
from typing import List, Dict, Any


def enumerate_subdomains(domain: str, wordlist: List[str]) -> List[str]:
    """Return list of discovered subdomains for given domain.
    
    Simple DNS resolution; ignores failures.
    """
    results = []
    for sub in wordlist:
        host = f"{sub}.{domain}"
        try:
            socket.gethostbyname(host)
            results.append(host)
        except Exception:
            continue
    return results


def load_wordlist(path: str) -> List[str]:
    """Load words from a file, one per line, ignoring blanks and comments (#)."""
    words = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    words.append(line)
    except Exception:
        pass
    return words
