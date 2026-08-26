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
from sectoolkit.password_strength import check_strength
from sectoolkit.password_generator import generate_password
from sectoolkit.breach_check import check_password_breach
from sectoolkit.dns_lookup import resolve_hostname, reverse_lookup
from sectoolkit.tls_check import get_certificate_info
from sectoolkit.port_scanner import scan_ports, scan_common_ports, COMMON_PORTS
from sectoolkit.strings_extract import extract_strings, find_urls_and_ips
from sectoolkit.analyze import analyze_file, suggest_commands
from sectoolkit.log_analysis import analyze_log_file, detect_brute_force, get_default_patterns
from sectoolkit.web_security import check_security_headers, check_http_redirect
from sectoolkit.vuln_scanner import run_vulnerability_scan
from sectoolkit.hash_verify import verify_file_hash, batch_verify_hashes, parse_checksum_file


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


@cli.command(name="metadata")
@click.argument("filepath", type=click.Path(exists=True))
def metadata_cmd(filepath):
    """Show full metadata for an image or PDF file.

    Shows the complete metadata dict (EXIF for images, document info for
    PDFs) — the auto-analyze summary in 'sectoolkit <file>' shows the same
    data, so this command is mainly useful when you want metadata output
    in isolation without the other checks running alongside it.
    """
    from sectoolkit.metadata_image import extract_exif, _is_image
    from sectoolkit.metadata_pdf import extract_pdf_metadata, _is_pdf

    if _is_image(filepath):
        data = extract_exif(filepath)
    elif _is_pdf(filepath):
        data = extract_pdf_metadata(filepath)
    else:
        raise click.ClickException("File is not a recognized image or PDF")

    if not data:
        click.echo("No metadata found.")
        return

    for key, value in data.items():
        click.echo(f"{key}: {value}")


@cli.command(name="check-password")
@click.option("--password", prompt=True, hide_input=True, help="Password to check (prompted securely if omitted).")
@click.option("--breach-check", is_flag=True, help="Also check this password against Have I Been Pwned (requires internet).")
def check_password(password, breach_check):
    """Check a password's strength (pattern analysis + entropy estimate).

    Prompts for the password with hidden input if not piped/scripted, so
    it doesn't end up in your shell history.
    """
    result = check_strength(password)

    click.echo(f"Rating: {result['rating']}")
    click.echo(f"Estimated entropy: {result['entropy_bits']} bits")

    if result["issues"]:
        click.echo("Issues found:")
        for issue in result["issues"]:
            click.echo(f"  - {issue}")
    else:
        click.echo("No issues found.")

    if breach_check:
        click.echo("")
        try:
            breach_result = check_password_breach(password)
        except RuntimeError as exc:
            click.echo(f"Breach check failed: {exc}")
            return

        if breach_result["breached"]:
            click.echo(
                f"⚠ This password has appeared in {breach_result['times_seen']:,} known breaches. "
                "Do not use it."
            )
        else:
            click.echo("✓ This password was not found in any known breach.")


@cli.command(name="generate-password")
@click.option("--length", "-l", default=16, show_default=True, help="Password length.")
@click.option("--no-lowercase", is_flag=True, help="Exclude lowercase letters.")
@click.option("--no-uppercase", is_flag=True, help="Exclude uppercase letters.")
@click.option("--no-digits", is_flag=True, help="Exclude digits.")
@click.option("--no-symbols", is_flag=True, help="Exclude symbols.")
@click.option("--count", "-c", default=1, show_default=True, help="Number of passwords to generate.")
def generate_password_cmd(length, no_lowercase, no_uppercase, no_digits, no_symbols, count):
    """Generate one or more cryptographically secure random passwords."""
    try:
        for _ in range(count):
            pw = generate_password(
                length=length,
                use_lowercase=not no_lowercase,
                use_uppercase=not no_uppercase,
                use_digits=not no_digits,
                use_symbols=not no_symbols,
            )
            click.echo(pw)
    except ValueError as exc:
        raise click.ClickException(str(exc))


@cli.command(name="dns")
@click.argument("target")
def dns_command(target):
    """Look up DNS records for a hostname, or reverse-lookup an IP address.

    Automatically detects whether TARGET looks like an IP address or a
    hostname and does the right kind of lookup.
    """
    import ipaddress

    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        result = reverse_lookup(target)
        if result.get("hostname"):
            click.echo(f"{target} -> {result['hostname']}")
        else:
            click.echo(f"No PTR record found for {target} ({result.get('error', 'unknown')})")
    else:
        result = resolve_hostname(target)
        if result["addresses"]:
            click.echo(f"{target} resolves to:")
            for addr in result["addresses"]:
                click.echo(f"  {addr}")
        else:
            click.echo(f"Could not resolve {target}: {result.get('error', 'unknown error')}")


@cli.command(name="cert-check")
@click.argument("hostname")
@click.option("--port", default=443, show_default=True, help="Port to connect to.")
def cert_check(hostname, port):
    """Inspect a host's SSL/TLS certificate (issuer, expiry, alt names)."""
    result = get_certificate_info(hostname, port=port)

    if "error" in result:
        raise click.ClickException(f"Could not retrieve certificate: {result['error']}")

    click.echo(f"Host: {result['hostname']}")
    click.echo(f"Subject CN: {result['subject_common_name']}")
    click.echo(f"Issuer: {result['issuer']}")
    click.echo(f"Valid from: {result['not_before']}")
    click.echo(f"Valid until: {result['not_after']}")

    if result["is_expired"]:
        click.echo("⚠ Certificate has EXPIRED.")
    elif result["days_until_expiry"] < 14:
        click.echo(f"⚠ Certificate expires soon: {result['days_until_expiry']} days remaining.")
    else:
        click.echo(f"Days until expiry: {result['days_until_expiry']}")

    if result["subject_alt_names"]:
        click.echo(f"Covers hostnames: {', '.join(result['subject_alt_names'])}")


@cli.command(name="port-scan")
@click.argument("host")
@click.option("--ports", help="Comma-separated ports or ranges, e.g. '22,80,443' or '1-1024'. Defaults to common ports.")
@click.option("--timeout", default=1.0, show_default=True, help="Connection timeout per port, in seconds.")
def port_scan(host, ports, timeout):
    """Scan a host's TCP ports to see which are open.

    \b
    Only scan hosts you own or are explicitly authorized to test.
    """
    if ports:
        port_list = []
        for chunk in ports.split(","):
            chunk = chunk.strip()
            if "-" in chunk:
                start, end = chunk.split("-")
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(chunk))

        click.echo(f"Scanning {len(port_list)} port(s) on {host}...")
        results = scan_ports(host, port_list, timeout=timeout)
        open_ports = {p: COMMON_PORTS.get(p, "unknown") for p, is_open in sorted(results.items()) if is_open}
    else:
        click.echo(f"Scanning common ports on {host}...")
        open_ports = scan_common_ports(host, timeout=timeout)

    if not open_ports:
        click.echo("No open ports found.")
        return

    click.echo(f"\nOpen ports on {host}:")
    for port, service in open_ports.items():
        click.echo(f"  {port}/tcp  {service}")


@cli.command(name="log-analyze")
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output the report as JSON instead of plain text.")
@click.option("--brute-force-threshold", default=100, show_default=True, help="Threshold for detecting brute force attempts.")
def log_analyze(logfile, as_json, brute_force_threshold):
    """Analyze a log file for suspicious patterns and activity.

    Detects failed logins, SQL injection attempts, XSS patterns, directory
    traversal, and potential brute force attacks.
    """
    result = analyze_log_file(logfile)
    
    if as_json:
        import json
        result["top_ips"] = [{"ip": ip, "count": count} for ip, count in result["top_ips"]]
        click.echo(json.dumps(result, indent=2, default=str))
        return
    
    click.echo(f"Analyzing: {logfile}\n")
    click.echo(f"Total lines: {result['total_lines']}")
    click.echo(f"Unique IP addresses: {len(result['ip_addresses'])}\n")
    
    click.echo("[Failed Login Attempts]")
    click.echo(f"  Count: {result['failed_login_count']}")
    if result['failed_login_count'] > 0 and result['failed_login_count'] <= 5:
        for match in result['matches']['failed_login'][:5]:
            click.echo(f"    Line {match['line']}: {match['content']}")
    
    click.echo("\n[SQL Injection Attempts]")
    click.echo(f"  Count: {result['sql_injection_count']}")
    if result['sql_injection_count'] > 0 and result['sql_injection_count'] <= 3:
        for match in result['matches']['sql_injection'][:3]:
            click.echo(f"    Line {match['line']}: {match['content']}")
    
    click.echo("\n[XSS Attempts]")
    click.echo(f"  Count: {result['xss_attempt_count']}")
    if result['xss_attempt_count'] > 0 and result['xss_attempt_count'] <= 3:
        for match in result['matches']['xss_attempt'][:3]:
            click.echo(f"    Line {match['line']}: {match['content']}")
    
    click.echo("\n[Top IP Addresses]")
    for ip, count in result['top_ips'][:5]:
        click.echo(f"  {ip}: {count} requests")
    
    suspicious_ips = detect_brute_force(result['ip_addresses'], threshold=brute_force_threshold)
    if suspicious_ips:
        click.echo("\n[Potential Brute Force Attacks]")
        for ip_info in suspicious_ips:
            click.echo(f"  ⚠ {ip_info}")


@cli.command(name="web-security")
@click.argument("hostname")
@click.option("--port", default=443, show_default=True, help="Port to connect to.")
@click.option("--check-http", is_flag=True, help="Also check if HTTP (port 80) redirects to HTTPS.")
def web_security(hostname, port, check_http):
    """Check web server security headers and configurations.
    
    Analyzes HTTP security headers like HSTS, CSP, X-Frame-Options, and more.
    """
    click.echo(f"Checking security headers for {hostname}:{port}...\n")
    
    result = check_security_headers(hostname, port=port)
    
    if "error" in result:
        raise click.ClickException(f"Could not connect: {result['error']}")
    
    click.echo(f"Security Score: {result['security_score']:.1f}%\n")
    
    if result["headers_found"]:
        click.echo("[Security Headers Found]")
        for header, value in result["headers_found"].items():
            click.echo(f"  ✓ {header}: {value}")
    
    if result["missing_headers"]:
        click.echo("\n[Missing Security Headers]")
        for header in result["missing_headers"]:
            click.echo(f"  ✗ {header}")
    
    if check_http:
        click.echo("\n[HTTP to HTTPS Redirect Check]")
        redirect_result = check_http_redirect(hostname, port=80)
        
        if "error" in redirect_result:
            click.echo(f"  Could not check HTTP redirect: {redirect_result['error']}")
        elif redirect_result["redirects_to_https"]:
            click.echo(f"  ✓ HTTP redirects to HTTPS (status: {redirect_result['status_code']})")
        else:
            click.echo(f"  ✗ HTTP does not redirect to HTTPS")


@cli.command(name="vuln-scan")
@click.argument("hostname")
@click.option("--ports", help="Comma-separated ports to scan, e.g. '21,22,80,443'. Defaults to common ports.")
@click.option("--json", "as_json", is_flag=True, help="Output the report as JSON.")
def vuln_scan(hostname, ports, as_json):
    """Run a basic vulnerability scan on a target host.
    
    \b
    IMPORTANT: Only scan hosts you own or have explicit authorization to test.
    Unauthorized scanning may be illegal.
    
    Checks for:
    - Open ports and risky services
    - SSL/TLS vulnerabilities
    - Common sensitive paths
    """
    if ports:
        port_list = [int(p.strip()) for p in ports.split(",")]
    else:
        port_list = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
    
    click.echo(f"Scanning {hostname}...\n")
    result = run_vulnerability_scan(hostname, ports=port_list)
    
    if as_json:
        import json
        click.echo(json.dumps(result, indent=2, default=str))
        return
    
    click.echo(f"[Scan Summary]")
    click.echo(f"Target: {result['hostname']}")
    click.echo(f"Timestamp: {result['timestamp']}")
    click.echo(f"Risk Level: {result['risk_level'].upper()}\n")
    
    click.echo(f"[Port Scan Results]")
    if result["port_scan"]["open_ports"]:
        click.echo(f"Open ports: {', '.join(map(str, result['port_scan']['open_ports']))}")
    else:
        click.echo("No open ports found")
    
    if result["port_scan"]["risky_ports"]:
        click.echo("\n[Risky Services Detected]")
        for risky in result["port_scan"]["risky_ports"]:
            click.echo(f"  ⚠ Port {risky['port']}: {risky['risk']}")
    
    if result.get("ssl_check") and result["ssl_check"].get("issues"):
        click.echo("\n[SSL/TLS Issues]")
        for issue in result["ssl_check"]["issues"]:
            click.echo(f"  ⚠ {issue}")
        if result["ssl_check"].get("info"):
            click.echo(f"\n  Protocol: {result['ssl_check']['info'].get('protocol', 'unknown')}")
            click.echo(f"  Cipher: {result['ssl_check']['info'].get('cipher', 'unknown')}")
    
    if result.get("path_check") and result["path_check"].get("potentially_sensitive"):
        click.echo("\n[Potentially Sensitive Paths]")
        for path in result["path_check"]["potentially_sensitive"]:
            click.echo(f"  ⚠ {path}")


@cli.command(name="verify-hash")
@click.argument("filepath", type=click.Path(exists=True))
@click.argument("expected_hash")
@click.option("--algorithm", "-a", default="sha256", show_default=True, help="Hash algorithm to use.")
def verify_hash(filepath, expected_hash, algorithm):
    """Verify a file's hash against an expected value.
    
    Useful for checking file integrity after download or transfer.
    """
    result = verify_file_hash(filepath, expected_hash, algorithm)
    
    click.echo(f"File: {result['file']}")
    click.echo(f"Algorithm: {result['algorithm'].upper()}")
    click.echo(f"Expected: {result['expected']}")
    click.echo(f"Actual:   {result['actual']}")
    click.echo("")
    
    if result["verified"]:
        click.echo("✓ VERIFIED - Hash matches!")
    else:
        click.echo("✗ MISMATCH - Hash does not match!")
        raise click.Exit(1)


@cli.command(name="verify-checksums")
@click.argument("checksum_file", type=click.Path(exists=True))
@click.option("--algorithm", "-a", default="sha256", show_default=True, help="Hash algorithm to use.")
def verify_checksums(checksum_file, algorithm):
    """Verify multiple files using a checksum file.
    
    Checksum file format: <hash>  <filepath>
    Lines starting with # are treated as comments.
    """
    try:
        with open(checksum_file, 'r') as f:
            content = f.read()
    except Exception as e:
        raise click.ClickException(f"Could not read checksum file: {e}")
    
    checksums = parse_checksum_file(content)
    
    if not checksums:
        click.echo("No checksums found in file.")
        return
    
    click.echo(f"Verifying {len(checksums)} file(s)...\n")
    
    files_and_hashes = [(filepath, hash_val, algorithm) for hash_val, filepath in checksums]
    result = batch_verify_hashes(files_and_hashes)
    
    click.echo(f"Results: {result['passed']} passed, {result['failed']} failed\n")
    
    if result["failed"] == 0:
        click.echo("✓ All files verified successfully!")
    else:
        click.echo("✗ Some files failed verification:")
        for detail in result["details"]:
            if not detail.get("verified"):
                click.echo(f"  {detail.get('file', 'unknown')}: MISMATCH")
        raise click.Exit(1)


if __name__ == "__main__":
    cli()
