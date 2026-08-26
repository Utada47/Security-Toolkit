"""Hash comparison and verification utilities."""
from typing import Dict, List, Tuple
from sectoolkit.hashing import hash_file, SUPPORTED_ALGORITHMS


def compare_hashes(hash1: str, hash2: str) -> bool:
    """Compare two hashes for equality (case-insensitive).
    
    Args:
        hash1: First hash string
        hash2: Second hash string
        
    Returns:
        True if hashes match, False otherwise
    """
    return hash1.lower() == hash2.lower()


def verify_file_hash(filepath: str, expected_hash: str, algorithm: str = "sha256") -> Dict[str, any]:
    """Verify a file's hash against an expected value.
    
    Args:
        filepath: Path to the file
        expected_hash: Expected hash value
        algorithm: Hash algorithm to use
        
    Returns:
        Dict with verification results
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    actual_hash = hash_file(filepath, algorithm)
    matches = compare_hashes(actual_hash, expected_hash)
    
    return {
        "file": filepath,
        "algorithm": algorithm,
        "expected": expected_hash.lower(),
        "actual": actual_hash.lower(),
        "verified": matches
    }


def batch_verify_hashes(files_and_hashes: List[Tuple[str, str, str]]) -> Dict[str, any]:
    """Verify multiple files against their expected hashes.
    
    Args:
        files_and_hashes: List of (filepath, expected_hash, algorithm) tuples
        
    Returns:
        Dict with batch verification results
    """
    results = {
        "total": len(files_and_hashes),
        "passed": 0,
        "failed": 0,
        "details": []
    }
    
    for filepath, expected_hash, algorithm in files_and_hashes:
        try:
            verification = verify_file_hash(filepath, expected_hash, algorithm)
            results["details"].append(verification)
            
            if verification["verified"]:
                results["passed"] += 1
            else:
                results["failed"] += 1
        except Exception as e:
            results["details"].append({
                "file": filepath,
                "error": str(e),
                "verified": False
            })
            results["failed"] += 1
    
    return results


def create_checksum_file(filepaths: List[str], algorithm: str = "sha256") -> str:
    """Create a checksum file content for multiple files.
    
    Args:
        filepaths: List of file paths to hash
        algorithm: Hash algorithm to use
        
    Returns:
        String content in format: <hash> <filename>
    """
    lines = []
    for filepath in filepaths:
        try:
            file_hash = hash_file(filepath, algorithm)
            lines.append(f"{file_hash}  {filepath}")
        except Exception as e:
            lines.append(f"# Error hashing {filepath}: {e}")
    
    return "\n".join(lines)


def parse_checksum_file(content: str) -> List[Tuple[str, str]]:
    """Parse a checksum file content.
    
    Args:
        content: Checksum file content
        
    Returns:
        List of (hash, filepath) tuples
    """
    results = []
    for line in content.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        parts = line.split(None, 1)
        if len(parts) == 2:
            hash_value, filepath = parts
            results.append((hash_value, filepath))
    
    return results
