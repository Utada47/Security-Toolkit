"""Extract human-readable ASCII strings from a (possibly binary) file.

Equivalent in spirit to the Unix `strings` command: scans raw bytes for
runs of printable characters at least `min_length` long. Useful for
spotting embedded URLs, IPs, file paths, or other readable artifacts
inside binaries without needing a disassembler.
"""
import re

_PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % 4)


def extract_strings(path: str, min_length: int = 4, limit: int = 1000) -> list:
    if min_length < 1:
        raise ValueError("min_length must be at least 1")

    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)

    with open(path, "rb") as f:
        data = f.read()

    matches = pattern.findall(data)
    results = [m.decode("ascii") for m in matches[:limit]]
    return results


_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def find_urls_and_ips(strings: list) -> dict:
    """Scan a list of extracted strings for URLs and IPv4 addresses —
    common indicators worth a closer look during file triage.
    """
    urls = set()
    ips = set()
    for s in strings:
        urls.update(_URL_PATTERN.findall(s))
        ips.update(_IP_PATTERN.findall(s))
    return {"urls": sorted(urls), "ips": sorted(ips)}
