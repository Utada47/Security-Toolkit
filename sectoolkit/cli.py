"""Command-line interface for the security toolkit."""
import click
from sectoolkit.hashing import hash_file_all, SUPPORTED_ALGORITHMS, hash_file
from sectoolkit.crypto import encrypt_file, decrypt_file


@click.group()
def cli():
    """Security Toolkit — defensive file & system analysis utilities."""
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


if __name__ == "__main__":
    cli()
