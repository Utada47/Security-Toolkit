import pytest
from cryptography.exceptions import InvalidTag
from sectoolkit.crypto import encrypt_bytes, decrypt_bytes, encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip():
    plaintext = b"top secret data"
    password = "correct-horse-battery-staple"

    encrypted = encrypt_bytes(plaintext, password)
    decrypted = decrypt_bytes(encrypted, password)

    assert decrypted == plaintext


def test_encrypted_output_differs_from_plaintext():
    plaintext = b"top secret data"
    encrypted = encrypt_bytes(plaintext, "some-password")

    assert encrypted != plaintext
    assert plaintext not in encrypted


def test_wrong_password_raises_instead_of_returning_garbage():
    plaintext = b"top secret data"
    encrypted = encrypt_bytes(plaintext, "right-password")

    with pytest.raises(InvalidTag):
        decrypt_bytes(encrypted, "wrong-password")


def test_tampered_ciphertext_is_rejected():
    plaintext = b"top secret data"
    encrypted = bytearray(encrypt_bytes(plaintext, "a-password"))
    encrypted[-1] ^= 0xFF  # flip bits in the last byte to simulate tampering

    with pytest.raises(InvalidTag):
        decrypt_bytes(bytes(encrypted), "a-password")


def test_encrypt_decrypt_file_roundtrip(tmp_path):
    original = tmp_path / "secret.txt"
    encrypted = tmp_path / "secret.enc"
    restored = tmp_path / "secret.restored.txt"

    original.write_bytes(b"file contents to protect")

    encrypt_file(str(original), str(encrypted), "file-password")
    decrypt_file(str(encrypted), str(restored), "file-password")

    assert restored.read_bytes() == original.read_bytes()


def test_two_encryptions_of_same_data_produce_different_ciphertext():
    plaintext = b"same data"
    password = "same-password"

    encrypted_1 = encrypt_bytes(plaintext, password)
    encrypted_2 = encrypt_bytes(plaintext, password)

    # Random salt + nonce per encryption means ciphertext should differ
    # even for identical plaintext and password.
    assert encrypted_1 != encrypted_2
