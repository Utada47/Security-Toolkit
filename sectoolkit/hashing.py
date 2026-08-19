"""Hash calculation utilities for files and raw data."""
import hashlib

SUPPORTED_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    hasher = hashlib.new(algorithm)
    hasher.update(data)
    return hasher.hexdigest()


def hash_file(path: str, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def hash_file_all(path: str) -> dict:
    return {algo: hash_file(path, algo) for algo in SUPPORTED_ALGORITHMS}
