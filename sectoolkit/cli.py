"""Command-line interface for the security toolkit."""
import os
import click
from sectoolkit import __version__
from sectoolkit import hashing  # noqa: F401 - triggers check registration
from sectoolkit import entropy  # noqa: F401 - triggers check registration
from sectoolkit import filetype  # noqa: F401 - triggers check registration
from sectoolkit import strings_extract  # noqa: F401 - triggers check registration
from sectoolkit import metadata_pdf  # noqa: F401 - triggers check registration
from sectoolkit import metadata_image  # noqa: F401 - triggers check registration
from sectoolkit import macros  # noqa: F401 - triggers check registration
from sectoolkit.hashing import hash_file_all, SUPPORTED_ALGORITHMS, hash_file
from sectoolkit.crypto import encrypt_file, decrypt_file
from sectoolkit.crack import crack_hash, count_lines
from sectoolkit.strings_extract import extract_strings, find_urls_and_ips
from sectoolkit.analyze import analyze_file, suggest_commands


class AutoAnalyzeGroup(click.Group):
    """A click Group that falls back to 'analyze <file>' when the first
    argument isn't a known subcommand but IS an existing file path.

    This is what makes 'sectoolkit myfile.txt' work directly, without
    typing 'sectoolkit analyze myfile.txt' or any other subcommand name.
    """

    def resolve_command(self, ctx, args):
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            candidate = args[0]
            if os.path.exists(candidate):
                return "analyze", self.commands["analyze"], args
            raise


@click.group(cls=AutoAnalyzeGroup)
@click.version_option(version=__version__, prog_name="sectoolkit")
def cli():
    """Security Toolkit — an all-in-one defensive cybersecurity CLI.

    \b
    Modules:
      hash        Compute file hashes (md5/sha1/sha256/sha512)
      encrypt     Encrypt a file (AES-256-GCM)
      decrypt     Decrypt a file encrypted with this tool
      analyze     Run every applicable check against a file (also runs
                  automatically if you just type: sectoolkit <file>)

    Run 'sectoolkit COMMAND --help' for details on any command.
    """
    pass


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(SUPPORTED_ALGORITHMS),
    default=None,
    help="Specific algorithm to use. If omitted, all algorithms are shown.",
)
def hash(filepath, algorithm):
    """Compute hash(es) of a file."""
    if algorithm:
        click.echo(f"{algorithm}: {hash_file(filepath, algorithm)}")
    else:
        for algo, digest in hash_file_all(filepath).items():
            click.echo(f"{algo}: {digest}")


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.argument("output", type=click.Path())
@click.password_option(confirmation_prompt=True)
def encrypt(filepath, output, password):
    """Encrypt a file with a password (AES-256-GCM)."""
    encrypt_file(filepath, output, password)
    click.echo(f"Encrypted -> {output}")


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.argument("output", type=click.Path())
@click.password_option(confirmation_prompt=False)
def decrypt(filepath, output, password):
    """Decrypt a file that was encrypted with 'sectoolkit encrypt'."""
    try:
        decrypt_file(filepath, output, password)
    except Exception:
        raise click.ClickException("Decryption failed: wrong password or corrupted file")
    click.echo(f"Decrypted -> {output}")


@cli.command()
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output the report as JSON instead of plain text.")
def analyze(filepath, as_json):
    """Run every applicable check against a file and print a report.

    This also runs automatically when you type 'sectoolkit <file>'
    without any subcommand.
    """
    results = analyze_file(filepath)

    if as_json:
        import json

        click.echo(json.dumps({"file": filepath, "results": results}, indent=2, default=str))
        return

    applicable = suggest_commands(filepath)
    click.echo(f"Analyzing: {filepath}")
    click.echo(f"Applicable checks: {', '.join(applicable)}\n")

    for check_name, result in results.items():
        click.echo(f"[{check_name}]")
        if isinstance(result, dict):
            for key, value in result.items():
                click.echo(f"  {key}: {value}")
        else:
            click.echo(f"  {result}")
        click.echo("")


@cli.command()
@click.argument("target_hash")
@click.argument("wordlist", type=click.Path(exists=True))
@click.option(
    "--algorithm",
    "-a",
    type=click.Choice(SUPPORTED_ALGORITHMS),
    default="sha256",
    help="Hash algorithm the target hash was generated with.",
)
def crack(target_hash, wordlist, algorithm):
    """Try to find a password matching TARGET_HASH using a WORDLIST file.

    Use this to audit hashes you own (e.g. "is this password hash trivially
    guessable from a common wordlist?"). Reads the wordlist line-by-line, so
    very large wordlists (millions of entries) are fine.
    """
    click.echo(f"Counting wordlist entries...")
    total = count_lines(wordlist)
    click.echo(f"Trying {total:,} candidates against the {algorithm} hash...")

    def report_progress(current, total):
        click.echo(f"  ...{current:,} / {total:,} tried", err=True)

    result = crack_hash(
        target_hash, wordlist, algorithm, progress_callback=report_progress
    )

    if result is not None:
        click.echo(f"MATCH FOUND: {result!r}")
    else:
        click.echo("No match found in this wordlist.")


@cli.command(name="strings")
@click.argument("filepath", type=click.Path(exists=True))
@click.option("--min-length", "-n", default=6, help="Minimum length of a string to report.")
@click.option("--limit", "-l", default=1000, help="Maximum number of strings to print.")
@click.option("--urls-only", is_flag=True, help="Only print detected URLs and IPs, not every string.")
def strings_cmd(filepath, min_length, limit, urls_only):
    """Extract the full list of readable strings from a file.

    Unlike the 'strings' entry shown in 'sectoolkit <file>' auto-analyze
    (which only summarizes counts + detected URLs/IPs), this prints every
    matching string, similar to the Unix 'strings' command.
    """
    extracted = extract_strings(filepath, min_length=min_length, limit=limit)

    if urls_only:
        indicators = find_urls_and_ips(extracted)
        for url in indicators["urls"]:
            click.echo(f"URL: {url}")
        for ip in indicators["ips"]:
            click.echo(f"IP:  {ip}")
        return

    for s in extracted:
        click.echo(s)


if __name__ == "__main__":
    cli()
