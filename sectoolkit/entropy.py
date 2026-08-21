"""Shannon entropy calculation for files.

Entropy ranges from 0 (completely uniform/repetitive data) to 8 (perfectly
random byte distribution, the theoretical max for byte-level data).

High entropy (typically > 7.5) often indicates encrypted, compressed, or
packed data — a common signal analysts use when triaging unknown files,
since legitimate plain-text or simple binary formats rarely reach that
level of randomness.
"""
import math
from collections import Counter


def calculate_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0

    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    return entropy


def calculate_file_entropy(path: str) -> float:
    with open(path, "rb") as f:
        data = f.read()
    return calculate_entropy(data)


def interpret_entropy(entropy: float) -> str:
    if entropy < 1.0:
        return "very low (highly repetitive data, e.g. all-zero or constant bytes)"
    if entropy < 5.0:
        return "low (typical of plain text or structured/sparse data)"
    if entropy < 7.5:
        return "moderate (typical of normal binaries, images, or documents)"
    return "high (typical of encrypted, compressed, or packed data)"


def _entropy_check(path: str) -> dict:
    value = calculate_file_entropy(path)
    return {"value": round(value, 4), "interpretation": interpret_entropy(value)}


def _register():
    from sectoolkit.registry import register_check

    register_check(
        name="entropy",
        description="Shannon entropy (detects encrypted/compressed/packed data)",
        applies_to=lambda path: True,
        run=_entropy_check,
    )


_register()
