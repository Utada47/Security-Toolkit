"""CLI integration tests for threat intelligence commands."""

from click.testing import CliRunner
from sectoolkit.cli import cli


def test_threat_ip_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['threat-ip', '8.8.8.8'])
    assert result.exit_code == 0
    assert '8.8.8.8' in result.output


def test_threat_url_command():
    runner = CliRunner()
    result = runner.invoke(cli, ['threat-url', 'http://phishing-site.com'])
    assert result.exit_code == 0


def test_threat_hash_command_unknown():
    runner = CliRunner()
    result = runner.invoke(cli, ['threat-hash', 'a' * 32])
    assert result.exit_code == 0


def test_threat_ioc_command_match():
    runner = CliRunner()
    result = runner.invoke(cli, ['threat-ioc', 'evil-domain.com', '--ioc-file', 'wordlists/sample_iocs.txt'])
    assert result.exit_code == 0
