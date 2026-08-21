from sectoolkit.strings_extract import extract_strings, find_urls_and_ips


def test_extracts_readable_strings_from_binary_data(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00\x01\x02hello world\x00\x00\x03testing123\x00")

    result = extract_strings(str(f), min_length=4)

    assert "hello world" in result
    assert "testing123" in result


def test_ignores_runs_shorter_than_min_length(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x00ab\x00cd\x00longenoughstring\x00")

    result = extract_strings(str(f), min_length=5)

    assert "ab" not in result
    assert "cd" not in result
    assert "longenoughstring" in result


def test_extract_strings_rejects_invalid_min_length(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"data")

    try:
        extract_strings(str(f), min_length=0)
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_extract_strings_respects_limit(tmp_path):
    f = tmp_path / "sample.bin"
    content = b"\x00".join([f"string{i}".encode() for i in range(20)])
    f.write_bytes(content)

    result = extract_strings(str(f), min_length=4, limit=5)

    assert len(result) == 5


def test_find_urls_and_ips_detects_both():
    strings = [
        "connecting to http://evil.example.com/payload",
        "backup server at 10.0.0.5",
        "just a normal string with no indicators",
    ]

    result = find_urls_and_ips(strings)

    assert "http://evil.example.com/payload" in result["urls"]
    assert "10.0.0.5" in result["ips"]


def test_find_urls_and_ips_deduplicates():
    strings = [
        "http://example.com and http://example.com again",
    ]

    result = find_urls_and_ips(strings)

    assert result["urls"] == ["http://example.com"]


def test_find_urls_and_ips_returns_empty_lists_when_nothing_found():
    result = find_urls_and_ips(["nothing interesting here", "just plain text"])

    assert result["urls"] == []
    assert result["ips"] == []
