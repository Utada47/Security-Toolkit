"""Utility to generate random usernames for testing purposes."""
import random
import string

def random_username(length: int = 8) -> str:
    """Generate a random alphanumeric username of given length."""
    chars = string.ascii_letters + string.digits + "_-"
    return ''.join(random.choice(chars) for _ in range(length))
