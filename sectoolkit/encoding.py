"""Encoding/decoding utilities: base64 and hex."""
import base64


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def from_base64(text: str) -> bytes:
    return base64.b64decode(text)


def to_hex(data: bytes) -> str:
    return data.hex()


def from_hex(text: str) -> bytes:
    return bytes.fromhex(text)
