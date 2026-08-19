"""Dictionary (wordlist) based hash cracking.

Given a target hash and a wordlist file, tries each candidate password
against the hash. Wordlists can be huge (millions of lines) — this reads
line-by-line rather than loading the whole file into memory.

This is for auditing your OWN password hashes (e.g. "is this hash trivially
guessable from a common wordlist?") — not for attacking systems you don't
own or don't have authorization to test.
"""
from typing import Optional, Callable
from sectoolkit.hashing import hash_bytes, SUPPORTED_ALGORITHMS


def count_lines(wordlist_path: str) -> int:
    count = 0
    with open(wordlist_path, "rb") as f:
        for _ in f:
            count += 1
    return count


def crack_hash(
    target_hash: str,
    wordlist_path: str,
    algorithm: str = "sha256",
    progress_callback: Optional[Callable[[int, int], None]] = None,
    progress_every: int = 10_000,
) -> Optional[str]:
    """Return the first candidate password whose hash matches, or None."""
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

    target_hash = target_hash.strip().lower()
    total = count_lines(wordlist_path) if progress_callback else 0

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        for i, line in enumerate(f, start=1):
            candidate = line.rstrip("\r\n")
            if not candidate:
                continue

            if hash_bytes(candidate.encode("utf-8"), algorithm) == target_hash:
                return candidate

            if progress_callback and i % progress_every == 0:
                progress_callback(i, total)

    return None
