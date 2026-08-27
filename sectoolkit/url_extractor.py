"""Utility for extracting URLs from text using regex."""
import re
from typing import List

URL_REGEX = re.compile(
    r"((?:https?://)?(?:[\w-]+\.)+[\w]{2,}(?:/[\w./?%&=-]*)?",
    re.IGNORECASE,
)


def extract_urls(text: str) -> List[str]:
    """Return list of URLs found in the given text."""
    return [match[0] for match in URL_REGEX.findall(text)]
