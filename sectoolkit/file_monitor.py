"""File integrity monitoring utilities.

Computes and stores file hashes, then detects changes, additions, and
deletions between snapshots.
"""
import os
import json
import hashlib
import time
from typing import Dict, List, Any, Optional, Tuple


def compute_file_hash(filepath: str, algorithm: str = "sha256") -> Optional[str]:
    """Compute hash of a single file.

    Returns the hex digest, or None if the file cannot be read.
    """
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, ValueError):
        return None


def snapshot_directory(directory: str, algorithm: str = "sha256",
                       recursive: bool = True) -> Dict[str, Any]:
    """Walk a directory and hash every file.

    Returns a snapshot dict:
    {
        'directory': str,
        'algorithm': str,
        'timestamp': float,
        'files': { relative_path: hash_hex, ... }
    }

    BUG: uses os.path.join(directory, f) with os.listdir (non-recursive)
    even when recursive=True because the recursive branch accidentally
    calls os.listdir instead of os.walk.
    """
    snapshot: Dict[str, Any] = {
        "directory": os.path.abspath(directory),
        "algorithm": algorithm,
        "timestamp": time.time(),
        "files": {},
    }

    if recursive:
        # BUG: should use os.walk but accidentally uses os.listdir
        for f in os.listdir(directory):
            full = os.path.join(directory, f)
            if os.path.isfile(full):
                rel = os.path.relpath(full, directory)
                h = compute_file_hash(full, algorithm)
                if h is not None:
                    snapshot["files"][rel] = h
    else:
        for f in os.listdir(directory):
            full = os.path.join(directory, f)
            if os.path.isfile(full):
                rel = os.path.relpath(full, directory)
                h = compute_file_hash(full, algorithm)
                if h is not None:
                    snapshot["files"][rel] = h

    return snapshot


def save_snapshot(snapshot: Dict[str, Any], filepath: str) -> bool:
    """Persist a snapshot to a JSON file."""
    try:
        with open(filepath, "w", encoding="utf-8") as fh:
            json.dump(snapshot, fh, indent=2)
        return True
    except OSError:
        return False


def load_snapshot(filepath: str) -> Optional[Dict[str, Any]]:
    """Load a previously saved snapshot from a JSON file."""
    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def compare_snapshots(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two directory snapshots and report changes.

    Returns:
        {
          'added':    [paths added in new],
          'removed':  [paths in old but not new],
          'modified': [paths whose hash changed],
          'unchanged': int,
          'summary':  str,
        }
    """
    old_files: Dict[str, str] = old.get("files", {})
    new_files: Dict[str, str] = new.get("files", {})

    added = [p for p in new_files if p not in old_files]
    removed = [p for p in old_files if p not in new_files]
    modified = [
        p for p in old_files
        if p in new_files and old_files[p] != new_files[p]
    ]
    unchanged = len(old_files) - len(modified) - len(removed)

    total_changes = len(added) + len(removed) + len(modified)
    summary = (
        f"{total_changes} change(s): "
        f"{len(added)} added, {len(removed)} removed, {len(modified)} modified"
    )

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "modified": sorted(modified),
        "unchanged": max(0, unchanged),
        "summary": summary,
    }


def monitor_file(filepath: str, interval: int = 5,
                 max_checks: int = 3) -> List[Dict[str, Any]]:
    """Poll a single file for changes over time.

    Args:
        filepath:   Path to monitor.
        interval:   Seconds between checks (default 5).
        max_checks: Maximum number of polls before returning.

    Returns:
        List of change events (dicts with 'timestamp', 'event', 'filepath').

    NOTE: This is a simplified polling implementation — production monitoring
    should use OS-level hooks (inotify / FSEvents / ReadDirectoryChangesW).
    """
    events: List[Dict[str, Any]] = []

    if not os.path.exists(filepath):
        return [{"timestamp": time.time(), "event": "not_found", "filepath": filepath}]

    prev_hash = compute_file_hash(filepath)
    prev_mtime = os.path.getmtime(filepath)

    for _ in range(max_checks - 1):
        time.sleep(interval)
        if not os.path.exists(filepath):
            events.append({"timestamp": time.time(), "event": "deleted", "filepath": filepath})
            break
        curr_hash = compute_file_hash(filepath)
        curr_mtime = os.path.getmtime(filepath)
        if curr_hash != prev_hash:
            events.append({
                "timestamp": curr_mtime,
                "event": "modified",
                "filepath": filepath,
                "old_hash": prev_hash,
                "new_hash": curr_hash,
            })
            prev_hash = curr_hash
            prev_mtime = curr_mtime

    return events


def find_large_files(directory: str, threshold_mb: float = 100.0) -> List[Dict[str, Any]]:
    """Find files larger than a threshold in a directory tree."""
    results = []
    threshold_bytes = threshold_mb * 1024 * 1024
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                size = os.path.getsize(full)
                if size > threshold_bytes:
                    results.append({
                        "filepath": full,
                        "size_bytes": size,
                        "size_mb": round(size / (1024 * 1024), 2),
                    })
            except OSError:
                continue
    return sorted(results, key=lambda x: x["size_bytes"], reverse=True)


def find_recently_modified(directory: str, within_seconds: int = 3600) -> List[Dict[str, Any]]:
    """Find files modified within the last N seconds."""
    results = []
    cutoff = time.time() - within_seconds
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            full = os.path.join(root, fname)
            try:
                mtime = os.path.getmtime(full)
                if mtime >= cutoff:
                    results.append({
                        "filepath": full,
                        "modified_at": mtime,
                        "seconds_ago": round(time.time() - mtime, 1),
                    })
            except OSError:
                continue
    return sorted(results, key=lambda x: x["modified_at"], reverse=True)
