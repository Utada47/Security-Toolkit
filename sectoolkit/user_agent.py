"""Utility for generating random User-Agent strings."""
import random

COMMON_BROWSERS = ["Chrome", "Firefox", "Safari", "Edge", "Opera"]

OS_TEMPLATES = {
    "Windows": "Windows NT 10.0; Win64; x64",
    "macOS": "Macintosh; Intel Mac OS X 10_15_7",
    "Linux": "X11; Linux x86_64",
    "iOS": "iPhone; CPU iPhone OS 14_0 like Mac OS X",
    "Android": "Linux; Android 11; Pixel 5",
}


def generate_user_agent() -> str:
    """Return a random plausible User-Agent string."""
    browser = random.choice(COMMON_BROWSERS)
    os_name = random.choice(list(OS_TEMPLATES.keys()))
    os_info = OS_TEMPLATES[os_name]
    if browser == "Chrome":
        version = f"{random.randint(80,115)}.0.{random.randint(1000,4000)}.{random.randint(0,200)}"
        return f"Mozilla/5.0 ({os_info}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36"
    if browser == "Firefox":
        version = f"{random.randint(70,115)}.0"
        return f"Mozilla/5.0 ({os_info}; rv:{version}) Gecko/20100101 Firefox/{version}"
    if browser == "Safari":
        version = f"{random.randint(13,16)}.0"
        return f"Mozilla/5.0 ({os_info}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{version} Safari/605.1.15"
    if browser == "Edge":
        version = f"{random.randint(80,115)}.0.{random.randint(1000,4000)}.{random.randint(0,200)}"
        return f"Mozilla/5.0 ({os_info}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 Edg/{version}"
    # Opera
    version = f"{random.randint(70,115)}.0.{random.randint(1000,4000)}.{random.randint(0,200)}"
    return f"Mozilla/5.0 ({os_info}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version} Safari/537.36 OPERA/{version}"