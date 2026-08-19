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


def test_subcommand_name_takes_priority_over_same_named_file(tmp_path, monkeypatch):
    # If a file literally named 'hash' exists in the CWD, the 'hash' SUBCOMMAND
    # wins over auto-analyzing a file called 'hash' — matches how git/npm/etc.
    # resolve ambiguity between a command name and a same-named file.
    monkeypatch.chdir(tmp_path)
    (tmp_path / "hash").write_text("not actually meant as a subcommand")

    runner = CliRunner()
    result = runner.invoke(cli, ["hash"])

    assert "Missing argument" in result.output or "FILEPATH" in result.output
