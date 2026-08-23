"""Generate cryptographically secure random passwords.

Uses the `secrets` module (not `random`) — `random` is predictable enough
to be unsuitable for anything security-sensitive, since its output can be
reconstructed from enough samples of its generated values.
"""
import secrets
import string


def generate_password(
    length: int = 16,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    if length < 1:
        raise ValueError("length must be at least 1")

    pool = ""
    required_chars = []

    if use_lowercase:
        pool += string.ascii_lowercase
        required_chars.append(secrets.choice(string.ascii_lowercase))
    if use_uppercase:
        pool += string.ascii_uppercase
        required_chars.append(secrets.choice(string.ascii_uppercase))
    if use_digits:
        pool += string.digits
        required_chars.append(secrets.choice(string.digits))
    if use_symbols:
        pool += "!@#$%^&*()-_=+[]{}"
        required_chars.append(secrets.choice("!@#$%^&*()-_=+[]{}"))

    if not pool:
        raise ValueError("at least one character class must be enabled")

    if length < len(required_chars):
        raise ValueError(
            f"length ({length}) is too short to include one of each enabled "
            f"character class ({len(required_chars)} required)"
        )

    # Guarantee at least one character from each enabled class, then fill
    # the rest randomly, then shuffle so the guaranteed chars aren't
    # predictably placed at the start.
    remaining_length = length - len(required_chars)
    rest = [secrets.choice(pool) for _ in range(remaining_length)]

    all_chars = required_chars + rest
    # Fisher-Yates shuffle using the secrets module's randbelow for each swap
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    return "".join(all_chars)
