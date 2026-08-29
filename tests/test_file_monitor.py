"""Tests for file_monitor module."""
import os
import json
import tempfile
import time
import pytest
from sectoolkit.file_monitor import (
    compute_file_hash,
    snapshot_directory,
    save_snapshot,
    load_snapshot,
    compare_snapshots,
    find_large_files,
    find_recently_modified,
)


class TestComputeFileHash:

    def test_returns_hex_string(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world", encoding="utf-8")
        h = compute_file_hash(str(f))
        assert h is not None
        assert len(h) == 64  # sha256

    def test_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("same content", encoding="utf-8")
        assert compute_file_hash(str(f)) == compute_file_hash(str(f))

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("content A", encoding="utf-8")
        f2.write_text("content B", encoding="utf-8")
        assert compute_file_hash(str(f1)) != compute_file_hash(str(f2))

    def test_nonexistent_file_returns_none(self):
        result = compute_file_hash("/does/not/exist.txt")
        assert result is None

    def test_md5_algorithm(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("test", encoding="utf-8")
        h = compute_file_hash(str(f), algorithm="md5")
        assert h is not None
        assert len(h) == 32


class TestSnapshotDirectory:

    def test_snapshot_contains_expected_keys(self, tmp_path):
        (tmp_path / "file.txt").write_text("hi", encoding="utf-8")
        snap = snapshot_directory(str(tmp_path))
        assert "directory" in snap
        assert "algorithm" in snap
        assert "timestamp" in snap
        assert "files" in snap

    def test_snapshot_lists_top_level_files(self, tmp_path):
        (tmp_path / "a.txt").write_text("aaa", encoding="utf-8")
        (tmp_path / "b.txt").write_text("bbb", encoding="utf-8")
        snap = snapshot_directory(str(tmp_path))
        assert len(snap["files"]) == 2

    def test_snapshot_recursive_finds_nested_files(self, tmp_path):
        """BUG EXPOSURE: recursive=True should include files in subdirectories.
        
        The current implementation calls os.listdir even in the recursive branch,
        so nested files are NOT included. This test should FAIL.
        """
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "top.txt").write_text("top", encoding="utf-8")
        (sub / "nested.txt").write_text("nested", encoding="utf-8")
        snap = snapshot_directory(str(tmp_path), recursive=True)
        # Should find both top.txt and subdir/nested.txt
        paths = list(snap["files"].keys())
        assert any("nested.txt" in p for p in paths), (
            f"Expected nested.txt in recursive snapshot, got: {paths}"
        )

    def test_snapshot_non_recursive_skips_subdirs(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "top.txt").write_text("top", encoding="utf-8")
        (sub / "nested.txt").write_text("nested", encoding="utf-8")
        snap = snapshot_directory(str(tmp_path), recursive=False)
        paths = list(snap["files"].keys())
        assert all("nested.txt" not in p for p in paths)

    def test_empty_directory(self, tmp_path):
        snap = snapshot_directory(str(tmp_path))
        assert snap["files"] == {}


class TestSaveAndLoadSnapshot:

    def test_save_and_reload(self, tmp_path):
        snap = {"directory": "/tmp", "algorithm": "sha256",
                "timestamp": 1234.0, "files": {"a.txt": "abc123"}}
        path = str(tmp_path / "snap.json")
        assert save_snapshot(snap, path) is True
        loaded = load_snapshot(path)
        assert loaded == snap

    def test_load_missing_file_returns_none(self):
        result = load_snapshot("/does/not/exist.json")
        assert result is None

    def test_save_returns_false_on_bad_path(self):
        result = save_snapshot({}, "/nonexistent_dir/snap.json")
        assert result is False


class TestCompareSnapshots:

    def test_no_changes(self):
        snap = {"files": {"a.txt": "hash1", "b.txt": "hash2"}}
        diff = compare_snapshots(snap, snap)
        assert diff["added"] == []
        assert diff["removed"] == []
        assert diff["modified"] == []
        assert diff["unchanged"] == 2

    def test_detect_added_file(self):
        old = {"files": {"a.txt": "h1"}}
        new = {"files": {"a.txt": "h1", "b.txt": "h2"}}
        diff = compare_snapshots(old, new)
        assert "b.txt" in diff["added"]

    def test_detect_removed_file(self):
        old = {"files": {"a.txt": "h1", "b.txt": "h2"}}
        new = {"files": {"a.txt": "h1"}}
        diff = compare_snapshots(old, new)
        assert "b.txt" in diff["removed"]

    def test_detect_modified_file(self):
        old = {"files": {"a.txt": "old_hash"}}
        new = {"files": {"a.txt": "new_hash"}}
        diff = compare_snapshots(old, new)
        assert "a.txt" in diff["modified"]

    def test_summary_string(self):
        old = {"files": {"a.txt": "h1"}}
        new = {"files": {"b.txt": "h2"}}
        diff = compare_snapshots(old, new)
        assert "change" in diff["summary"].lower()


class TestFindLargeFiles:

    def test_no_large_files(self, tmp_path):
        (tmp_path / "small.txt").write_text("tiny", encoding="utf-8")
        result = find_large_files(str(tmp_path), threshold_mb=1.0)
        assert result == []

    def test_finds_large_file(self, tmp_path):
        large = tmp_path / "big.bin"
        large.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MB
        result = find_large_files(str(tmp_path), threshold_mb=1.0)
        assert len(result) == 1
        assert result[0]["size_mb"] > 1.0


class TestFindRecentlyModified:

    def test_finds_new_file(self, tmp_path):
        f = tmp_path / "new.txt"
        f.write_text("fresh", encoding="utf-8")
        result = find_recently_modified(str(tmp_path), within_seconds=60)
        assert any("new.txt" in r["filepath"] for r in result)

    def test_empty_directory(self, tmp_path):
        result = find_recently_modified(str(tmp_path), within_seconds=60)
        assert result == []
