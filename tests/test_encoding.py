from sectoolkit.encoding import to_base64, from_base64, to_hex, from_hex


def test_base64_roundtrip():
    original = b"The quick brown fox jumps over the lazy dog"
    assert from_base64(to_base64(original)) == original


def test_base64_known_value():
    assert to_base64(b"hello") == "aGVsbG8="


def test_hex_roundtrip():
    original = b"\x00\x01\xff\xfe binary data"
    assert from_hex(to_hex(original)) == original


def test_hex_known_value():
    assert to_hex(b"hello") == "68656c6c6f"


def test_base64_handles_empty_bytes():
    assert from_base64(to_base64(b"")) == b""
