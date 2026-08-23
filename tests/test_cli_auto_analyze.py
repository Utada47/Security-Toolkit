from click.testing import CliRunner
from sectoolkit.cli import cli


def test_auto_analyze_runs_when_no_subcommand_matches(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello")

    runner = CliRunner()
    result = runner.invoke(cli, [str(sample)])

    assert result.exit_code == 0
    assert "Analyzing:" in result.output
    assert "hashes" in result.output


def test_explicit_hash_subcommand_still_works(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello")

    runner = CliRunner()
    result = runner.invoke(cli, ["hash", str(sample), "--algorithm", "md5"])

    assert result.exit_code == 0
    assert "md5:" in result.output


def test_nonexistent_path_gives_normal_command_error():
    runner = CliRunner()
    result = runner.invoke(cli, ["this-file-does-not-exist.xyz"])

    assert result.exit_code != 0
    assert "No such command" in result.output


def test_analyze_subcommand_works_explicitly(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(sample)])

    assert result.exit_code == 0
    assert "Analyzing:" in result.output


def test_crack_command_finds_password(tmp_path):
    from sectoolkit.hashing import hash_bytes

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\npassword\nmysecretpass\n")
    target = hash_bytes(b"mysecretpass", "sha256")

    runner = CliRunner()
    result = runner.invoke(cli, ["crack", target, str(wordlist)])

    assert result.exit_code == 0
    assert "MATCH FOUND" in result.output
    assert "mysecretpass" in result.output


def test_crack_command_reports_no_match(tmp_path):
    from sectoolkit.hashing import hash_bytes

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("123456\npassword\n")
    target = hash_bytes(b"not-in-wordlist", "sha256")

    runner = CliRunner()
    result = runner.invoke(cli, ["crack", target, str(wordlist)])

    assert result.exit_code == 0
    assert "No match found" in result.output


def test_analyze_json_output_is_valid_json(tmp_path):
    import json

    sample = tmp_path / "sample.txt"
    sample.write_text("hello world")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(sample), "--json"])

    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["file"] == str(sample)
    assert "hashes" in parsed["results"]


def test_analyze_json_output_omits_plain_text_report_lines(tmp_path):
    sample = tmp_path / "sample.txt"
    sample.write_text("hello world")

    runner = CliRunner()
    result = runner.invoke(cli, ["analyze", str(sample), "--json"])

    assert "Analyzing:" not in result.output
    assert "Applicable checks:" not in result.output


def test_metadata_command_shows_pdf_metadata(tmp_path):
    from pypdf import PdfWriter

    pdf_path = tmp_path / "doc.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.add_metadata({"/Author": "Test Author"})
    with open(pdf_path, "wb") as f:
        writer.write(f)

    runner = CliRunner()
    result = runner.invoke(cli, ["metadata", str(pdf_path)])

    assert result.exit_code == 0
    assert "Test Author" in result.output


def test_metadata_command_rejects_unsupported_file(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("plain text, not image or pdf")

    runner = CliRunner()
    result = runner.invoke(cli, ["metadata", str(text_file)])

    assert result.exit_code != 0
    assert "not a recognized image or PDF" in result.output


def test_check_password_command_reports_weak_password():
    runner = CliRunner()
    result = runner.invoke(cli, ["check-password", "--password", "123456"])

    assert result.exit_code == 0
    assert "very weak" in result.output


def test_check_password_command_reports_strong_password():
    runner = CliRunner()
    result = runner.invoke(cli, ["check-password", "--password", "kR9$mZ2p!vB7xL"])

    assert result.exit_code == 0
    assert "strong" in result.output
    assert "No issues found" in result.output


def test_generate_password_command_respects_length():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-password", "--length", "24"])

    assert result.exit_code == 0
    assert len(result.output.strip()) == 24


def test_generate_password_command_respects_count():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-password", "--count", "5"])

    lines = result.output.strip().split("\n")
    assert len(lines) == 5
    assert len(set(lines)) == 5  # all distinct


def test_generate_password_command_errors_on_too_short_length():
    runner = CliRunner()
    result = runner.invoke(cli, ["generate-password", "--length", "2"])

    assert result.exit_code != 0
    assert "too short" in result.output


def test_strings_command_prints_extracted_strings(tmp_path):
    binfile = tmp_path / "sample.bin"
    binfile.write_bytes(b"\x00\x01hello world\x00\x02testing123\x00")

    runner = CliRunner()
    result = runner.invoke(cli, ["strings", str(binfile), "--min-length", "4"])

    assert result.exit_code == 0
    assert "hello world" in result.output
    assert "testing123" in result.output


def test_strings_command_urls_only_flag(tmp_path):
    binfile = tmp_path / "sample.bin"
    binfile.write_bytes(b"\x00connecting to http://evil.example.com and 10.0.0.5\x00")

    runner = CliRunner()
    result = runner.invoke(cli, ["strings", str(binfile), "--urls-only"])

    assert result.exit_code == 0
    assert "URL: http://evil.example.com" in result.output
    assert "IP:  10.0.0.5" in result.output


def test_subcommand_name_takes_priority_over_same_named_file(tmp_path, monkeypatch):
    # If a file literally named 'hash' exists in the CWD, the 'hash' SUBCOMMAND
    # wins over auto-analyzing a file called 'hash' — matches how git/npm/etc.
    # resolve ambiguity between a command name and a same-named file.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hash").write_text("not actually meant as a subcommand")

    runner = CliRunner()
    result = runner.invoke(cli, ["hash"])

    assert "Missing argument" in result.output or "FILEPATH" in result.output
