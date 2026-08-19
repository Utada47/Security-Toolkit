from sectoolkit.crack import crack_hash, count_lines
from sectoolkit.hashing import hash_bytes


def test_crack_finds_password_present_in_wordlist(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\npassword\nqwerty\nmysecretpass\nletmein\n")

    target = hash_bytes(b"mysecretpass", "sha256")
    result = crack_hash(target, str(wordlist), "sha256")

    assert result == "mysecretpass"


def test_crack_returns_none_when_password_not_in_wordlist(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\npassword\nqwerty\n")

    target = hash_bytes(b"not-in-the-list-at-all", "sha256")
    result = crack_hash(target, str(wordlist), "sha256")

    assert result is None


def test_crack_handles_windows_style_crlf_wordlist(tmp_path):
    # Wordlists downloaded on/for Windows often use \r\n line endings.
    # If those aren't stripped, every hash comparison silently fails even
    # when the correct password IS in the list.
    wordlist = tmp_path / "words_crlf.txt"
    wordlist.write_bytes(b"123456\r\npassword\r\nmysecretpass\r\nqwerty\r\n")

    target = hash_bytes(b"mysecretpass", "sha256")
    result = crack_hash(target, str(wordlist), "sha256")

    assert result == "mysecretpass"


def test_crack_skips_blank_lines(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\n\n\npassword\n\nmysecretpass\n")

    target = hash_bytes(b"mysecretpass", "sha256")
    result = crack_hash(target, str(wordlist), "sha256")

    assert result == "mysecretpass"


def test_crack_is_case_sensitive_by_design(tmp_path):
    # Cracking should try exact candidates as given — case-folding a
    # candidate would silently "find" a different password than the
    # wordlist actually contains.
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("MySecretPass\n")

    target = hash_bytes(b"mysecretpass", "sha256")  # lowercase target
    result = crack_hash(target, str(wordlist), "sha256")

    assert result is None


def test_count_lines(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("a\nb\nc\n")

    assert count_lines(str(wordlist)) == 3


def test_crack_matches_target_hash_case_insensitively(tmp_path):
    # Hashes are often pasted/copied in uppercase (e.g. from some tools).
    # The target hash string itself should match regardless of its case.
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("mysecretpass\n")

    target = hash_bytes(b"mysecretpass", "sha256").upper()
    result = crack_hash(target, str(wordlist), "sha256")

    assert result == "mysecretpass"
