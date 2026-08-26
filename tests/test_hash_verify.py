"""Tests for hash verification utilities."""
import os
import tempfile
import pytest
from sectoolkit.hash_verify import (
    compare_hashes,
    verify_file_hash,
    batch_verify_hashes,
    create_checksum_file,
    parse_checksum_file,
)


def test_compare_hashes_identical():
    """Test comparing identical hashes."""
    hash1 = "5d41402abc4b2a76b9719d911017c592"
    hash2 = "5d41402abc4b2a76b9719d911017c592"
    assert compare_hashes(hash1, hash2) is True


def test_compare_hashes_case_insensitive():
    """Test that hash comparison is case-insensitive."""
    hash1 = "5D41402ABC4B2A76B9719D911017C592"
    hash2 = "5d41402abc4b2a76b9719d911017c592"
    assert compare_hashes(hash1, hash2) is True


def test_compare_hashes_different():
    """Test comparing different hashes."""
    hash1 = "5d41402abc4b2a76b9719d911017c592"
    hash2 = "098f6bcd4621d373cade4e832627b4f6"
    assert compare_hashes(hash1, hash2) is False


def test_verify_file_hash_success():
    """Test verifying a file hash successfully."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("hello")
        filepath = f.name
    
    try:
        expected_hash = "5d41402abc4b2a76b9719d911017c592"
        result = verify_file_hash(filepath, expected_hash, "md5")
        
        assert result["verified"] is True
        assert result["algorithm"] == "md5"
        assert result["expected"] == expected_hash.lower()
        assert result["file"] == filepath
    finally:
        os.unlink(filepath)


def test_verify_file_hash_failure():
    """Test verifying a file hash that doesn't match."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("hello")
        filepath = f.name
    
    try:
        wrong_hash = "0000000000000000000000000000000"
        result = verify_file_hash(filepath, wrong_hash, "md5")
        
        assert result["verified"] is False
    finally:
        os.unlink(filepath)


def test_verify_file_hash_unsupported_algorithm():
    """Test that unsupported algorithm raises ValueError."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        f.write("test")
        filepath = f.name
    
    try:
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            verify_file_hash(filepath, "abc123", "invalid_algo")
    finally:
        os.unlink(filepath)


def test_batch_verify_hashes():
    """Test batch verification of multiple files."""
    file1 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    file1.write("hello")
    file1.close()
    
    file2 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    file2.write("world")
    file2.close()
    
    try:
        files_and_hashes = [
            (file1.name, "5d41402abc4b2a76b9719d911017c592", "md5"),
            (file2.name, "7d793037a0760186574b0282f2f435e7", "md5"),
        ]
        
        result = batch_verify_hashes(files_and_hashes)
        
        assert result["total"] == 2
        assert result["passed"] == 2
        assert result["failed"] == 0
        assert len(result["details"]) == 2
    finally:
        os.unlink(file1.name)
        os.unlink(file2.name)


def test_create_checksum_file():
    """Test creating checksum file content."""
    file1 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    file1.write("hello")
    file1.close()
    
    try:
        content = create_checksum_file([file1.name], algorithm="md5")
        
        assert "5d41402abc4b2a76b9719d911017c592" in content
        assert file1.name in content
    finally:
        os.unlink(file1.name)


def test_parse_checksum_file():
    """Test parsing checksum file content."""
    content = """
5d41402abc4b2a76b9719d911017c592  file1.txt
7d793037a0760186574b0282f2f435e7  file2.txt
# This is a comment
098f6bcd4621d373cade4e832627b4f6  file3.txt
"""
    
    result = parse_checksum_file(content)
    
    assert len(result) == 3
    assert result[0] == ("5d41402abc4b2a76b9719d911017c592", "file1.txt")
    assert result[1] == ("7d793037a0760186574b0282f2f435e7", "file2.txt")
    assert result[2] == ("098f6bcd4621d373cade4e832627b4f6", "file3.txt")


def test_parse_checksum_file_ignores_empty_lines():
    """Test that empty lines are ignored."""
    content = """
5d41402abc4b2a76b9719d911017c592  file1.txt

7d793037a0760186574b0282f2f435e7  file2.txt
"""
    
    result = parse_checksum_file(content)
    assert len(result) == 2
