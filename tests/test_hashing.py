import hashlib
import pytest
from sectoolkit.hashing import hash_bytes, hash_file, hash_file_all, SUPPORTED_ALGORITHMS


def test_hash_bytes_sha256_matches_stdlib_hashlib():
    data = b"hello world"
    assert hash_bytes(data, "sha256") == hashlib.sha256(data).hexdigest()


def test_hash_bytes_md5_matches_stdlib_hashlib():
    data = b"hello world"
    assert hash_bytes(data, "md5") == hashlib.md5(data).hexdigest()


def test_hash_bytes_rejects_unsupported_algorithm():
    with pytest.raises(ValueError):
        hash_bytes(b"data", "not-a-real-algo")


def test_hash_file_matches_hash_bytes(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"hello world")

    assert hash_file(str(file_path), "sha256") == hash_bytes(b"hello world", "sha256")


def test_hash_file_all_returns_every_algorithm(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"test data")

    result = hash_file_all(str(file_path))

    assert set(result.keys()) == set(SUPPORTED_ALGORITHMS)
    assert all(isinstance(v, str) and len(v) > 0 for v in result.values())
