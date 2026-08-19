import hmac
import hashlib
from sectoolkit.hashing import compute_hmac


def test_compute_hmac_matches_stdlib():
    data = b"important message"
    key = b"secret-key"
    expected = hmac.new(key, data, hashlib.sha256).hexdigest()

    assert compute_hmac(data, key, "sha256") == expected


def test_compute_hmac_different_keys_produce_different_output():
    data = b"same message"
    hmac_a = compute_hmac(data, b"key-a")
    hmac_b = compute_hmac(data, b"key-b")

    assert hmac_a != hmac_b
