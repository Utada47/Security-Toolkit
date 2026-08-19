"""Command-line interface for the security toolkit."""
import click
from sectoolkit.hashing import hash_file_all, SUPPORTED_ALGORITHMS, hash_file


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


if __name__ == "__main__":
    cli()
