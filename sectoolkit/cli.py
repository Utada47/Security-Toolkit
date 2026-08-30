"""Command-line interface for the security toolkit."""
import os
import json
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
from sectoolkit.sqli_detector import detect_sqli_in_url, detect_sqli_in_string, batch_analyze_urls
from sectoolkit.xss_detector import detect_xss_in_string, analyze_html_context
from sectoolkit.jwt_analyzer import parse_jwt, analyze_jwt_security, verify_jwt_signature
from sectoolkit.file_monitor import snapshot_directory, save_snapshot, load_snapshot, compare_snapshots
from sectoolkit.config_auditor import audit_config_file
from sectoolkit.password_audit import audit_password_file
from sectoolkit.api_security import test_http_methods, check_rate_limiting, check_cors_policy
from sectoolkit.hash_crack import analyze_hash_type, rainbow_table_lookup, estimate_crack_time, compare_hash_algorithms
from sectoolkit.threat_intel import check_ip_reputation, geoip_lookup, lookup_malicious_url, hash_threat_lookup, match_ioc
from sectoolkit.reporter import export_json, export_csv, export_html, create_summary_report


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
@click.option("--export", "export_path", default=None, help="Export report to a file.")
@click.option("--export-format", "export_format", type=click.Choice(["json", "csv", "html"]), default="json", show_default=True, help="Export file format.")
def log_analyze(logfile, as_json, brute_force_threshold, export_path, export_format):
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

    if export_path:
        export_data = {k: v for k, v in result.items() if k != "top_ips"}
        export_data["top_ips"] = [{"ip": ip, "count": count} for ip, count in result["top_ips"]]
        if export_format == "json":
            export_json(export_data, export_path)
        elif export_format == "csv":
            rows = [{"key": k, "value": str(v)} for k, v in export_data.items()]
            export_csv(rows, export_path)
        elif export_format == "html":
            export_html(export_data, title="Log Analysis Report", filepath=export_path)
        click.echo(f"Report saved to {export_path}")


@cli.command(name="web-security")
@click.argument("hostname")
@click.option("--port", default=443, show_default=True, help="Port to connect to.")
@click.option("--check-http", is_flag=True, help="Also check if HTTP (port 80) redirects to HTTPS.")
@click.option("--export", "export_path", default=None, help="Export report to a file.")
@click.option("--export-format", "export_format", type=click.Choice(["json", "csv", "html"]), default="json", show_default=True, help="Export file format.")
def web_security(hostname, port, check_http, export_path, export_format):
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

    if export_path:
        export_data = {
            "hostname": hostname,
            "security_score": result.get("security_score"),
            "headers_found": str(result.get("headers_found", {})),
            "missing_headers": str(result.get("missing_headers", [])),
        }
        if export_format == "json":
            export_json(export_data, export_path)
        elif export_format == "csv":
            rows = [{"key": k, "value": str(v)} for k, v in export_data.items()]
            export_csv(rows, export_path)
        elif export_format == "html":
            export_html(export_data, title="Web Security Report", filepath=export_path)
        click.echo(f"Report saved to {export_path}")


@cli.command(name="vuln-scan")
@click.argument("hostname")
@click.option("--ports", help="Comma-separated ports to scan, e.g. '21,22,80,443'. Defaults to common ports.")
@click.option("--json", "as_json", is_flag=True, help="Output the report as JSON.")
@click.option("--export", "export_path", default=None, help="Export report to a file.")
@click.option("--export-format", "export_format", type=click.Choice(["json", "csv", "html"]), default="json", show_default=True, help="Export file format.")
def vuln_scan(hostname, ports, as_json, export_path, export_format):
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

    if export_path:
        export_data = {
            "hostname": result.get("hostname"),
            "timestamp": str(result.get("timestamp")),
            "risk_level": result.get("risk_level"),
            "open_ports": str(result["port_scan"].get("open_ports", [])),
            "risky_ports": str(result["port_scan"].get("risky_ports", [])),
        }
        if export_format == "json":
            export_json(export_data, export_path)
        elif export_format == "csv":
            rows = [{"key": k, "value": str(v)} for k, v in export_data.items()]
            export_csv(rows, export_path)
        elif export_format == "html":
            export_html(export_data, title="Vulnerability Scan Report", filepath=export_path)
        click.echo(f"Report saved to {export_path}")


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


@cli.command(name="sqli-check")
@click.argument("target")
@click.option("--type", "-t", type=click.Choice(["url", "string"]), default="url", show_default=True, help="Type of input to check.")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def sqli_check(target, type, output_json):
    """Check URL or string for SQL injection patterns.
    
    Examples:
      sectoolkit sqli-check "http://example.com/search?q=test' OR 1=1--"
      sectoolkit sqli-check "admin' OR '1'='1" --type string
    """
    import json
    
    if type == "url":
        result = detect_sqli_in_url(target)
    else:
        result = detect_sqli_in_string(target)
    
    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        if type == "url":
            click.echo(f"URL: {result['url']}")
            click.echo(f"Vulnerable: {result['is_vulnerable']}")
            click.echo(f"Risk Level: {result['risk_level'].upper()}")
            
            if result["suspicious_params"]:
                click.echo("\n[Suspicious Parameters]")
                for param in result["suspicious_params"]:
                    click.echo(f"  Parameter: {param['parameter']}")
                    click.echo(f"  Value: {param['value']}")
                    click.echo(f"  Risk: {param['risk'].upper()}")
                    click.echo(f"  Patterns matched: {len(param['patterns'])}\n")
            else:
                click.echo("\nNo suspicious patterns detected.")
        else:
            click.echo(f"Input: {result['input']}")
            click.echo(f"Suspicious: {result['is_suspicious']}")
            click.echo(f"Risk Level: {result['risk_level'].upper()}")
            click.echo(f"Patterns matched: {len(result['matched_patterns'])}")


@cli.command(name="xss-check")
@click.argument("input_string")
@click.option("--type", "-t", type=click.Choice(["string", "html"]), default="string", show_default=True, help="Type of analysis.")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def xss_check(input_string, type, output_json):
    """Check string or HTML content for XSS patterns.
    
    Examples:
      sectoolkit xss-check "<script>alert('XSS')</script>"
      sectoolkit xss-check "<img src=x onerror=alert(1)>"
    """
    import json
    
    if type == "html":
        result = analyze_html_context(input_string)
    else:
        result = detect_xss_in_string(input_string)
    
    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        if type == "string":
            click.echo(f"Input: {result['input'][:100]}...")
            click.echo(f"Suspicious: {result['is_suspicious']}")
            click.echo(f"Risk Level: {result['risk_level'].upper()}")
            click.echo(f"Patterns matched: {len(result['matched_patterns'])}")
            
            if result.get("decoded_input"):
                click.echo(f"\nDecoded input detected: {result['decoded_input'][:100]}...")
        else:
            click.echo(f"Total <script> tags: {result['total_scripts']}")
            click.echo(f"Inline event handlers: {result['inline_event_handlers']}")
            click.echo(f"Risk Level: {result['risk_level'].upper()}")
            
            if result["suspicious_patterns"]:
                click.echo("\n[Suspicious Patterns]")
                for pattern in result["suspicious_patterns"]:
                    click.echo(f"  ⚠ {pattern}")


@cli.command(name="jwt-analyze")
@click.argument("token")
@click.option("--verify", is_flag=True, help="Verify signature (requires --secret).")
@click.option("--secret", help="Secret key for signature verification.")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def jwt_analyze(token, verify, secret, output_json):
    """Analyze JWT token for security issues.
    
    Example:
      sectoolkit jwt-analyze "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    """
    import json
    
    result = analyze_jwt_security(token)
    
    if verify and secret:
        verified = verify_jwt_signature(token, secret)
        result["signature_valid"] = verified
    
    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"[JWT Analysis]")
        click.echo(f"Risk Level: {result['risk_level'].upper()}\n")
        
        if result.get("vulnerabilities"):
            click.echo("[Vulnerabilities]")
            for vuln in result["vulnerabilities"]:
                click.echo(f"  ⚠ {vuln}")
            click.echo("")
        
        if result.get("warnings"):
            click.echo("[Warnings]")
            for warn in result["warnings"]:
                click.echo(f"  • {warn}")
            click.echo("")
        
        if result.get("info"):
            info = result["info"]
            if info.get("header"):
                click.echo(f"Algorithm: {info['header'].get('alg', 'unknown')}")
            if info.get("ttl_seconds"):
                click.echo(f"Time to expiration: {info['ttl_seconds']} seconds")
            if info.get("expired"):
                click.echo("Status: EXPIRED")
        
        if verify and secret:
            if result.get("signature_valid"):
                click.echo("\n✓ Signature is valid")
            else:
                click.echo("\n✗ Signature is invalid")


@cli.command(name="api-methods")
@click.argument("url")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def api_methods(url, output_json):
    """Test which HTTP methods are allowed on an API endpoint.
    
    Example:
      sectoolkit api-methods "https://api.example.com/users"
    """
    import json
    
    result = test_http_methods(url)
    
    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"URL: {result['url']}\n")
        
        if result["allowed_methods"]:
            click.echo(f"Allowed methods: {', '.join(result['allowed_methods'])}")
        
        if result["unsafe_methods"]:
            click.echo(f"\n⚠ Unsafe methods enabled: {', '.join(result['unsafe_methods'])}")
        
        if result["forbidden_methods"]:
            click.echo(f"Forbidden methods: {', '.join(result['forbidden_methods'])}")


@cli.command(name="hash-analyze")
@click.argument("hash_string")
@click.option("--crack", is_flag=True, help="Attempt to crack using common values.")
@click.option("--estimate-time", is_flag=True, help="Estimate brute force crack time.")
@click.option("--length", default=8, help="Password length for time estimate.")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def hash_analyze(hash_string, crack, estimate_time, length, output_json):
    """Analyze a hash to determine algorithm and check for weaknesses.
    
    Example:
      sectoolkit hash-analyze "5d41402abc4b2a76b9719d911017c592" --crack
    """
    import json
    
    analysis = analyze_hash_type(hash_string)
    
    if crack:
        crack_result = rainbow_table_lookup(hash_string)
        analysis["crack_attempt"] = crack_result
    
    if estimate_time and analysis.get("likely_algorithms"):
        if analysis["likely_algorithms"]:
            algo = analysis["likely_algorithms"][0].lower()
            analysis["crack_time"] = estimate_crack_time(algo, length)
        else:
            analysis["crack_time"] = {"error": "Algorithm unknown"}
    
    if output_json:
        click.echo(json.dumps(analysis, indent=2))
    else:
        click.echo(f"Hash: {hash_string}")
        click.echo(f"Length: {analysis['length']}")
        click.echo(f"Likely algorithm(s): {', '.join(analysis['likely_algorithms'])}")
        click.echo(f"Confidence: {analysis['confidence']}\n")
        
        if crack and analysis.get("crack_attempt"):
            result = analysis["crack_attempt"]
            if result["found"]:
                click.echo(f"✓ CRACKED! Plaintext: {result['plaintext']}")
                click.echo(f"Algorithm: {result['algorithm_used']}")
            else:
                click.echo("✗ Could not crack using common values")
        
        if estimate_time and analysis.get("crack_time"):
            time_est = analysis["crack_time"]
            click.echo(f"\nBrute force estimate ({length} char password, {time_est['complexity']} complexity):")
            click.echo(f"Practical time: {time_est['estimate']['practical']}")


@cli.command(name="cors-check")
@click.argument("url")
@click.option("--origin", default="https://evil.com", help="Origin to test.")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def cors_check(url, origin, output_json):
    """Check CORS policy configuration on an endpoint.
    
    Example:
      sectoolkit cors-check "https://api.example.com"
    """
    import json
    
    result = check_cors_policy(url, origin)
    
    if output_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"URL: {result['url']}")
        click.echo(f"Testing origin: {result['test_origin']}\n")
        
        if result["cors_enabled"]:
            click.echo("✓ CORS is enabled")
            click.echo(f"Allowed origins: {', '.join(result['allowed_origins'])}")
            if result["allowed_methods"]:
                click.echo(f"Allowed methods: {', '.join(result['allowed_methods'])}")
            click.echo(f"Credentials allowed: {result['allows_credentials']}")
            
            if result["security_issues"]:
                click.echo("\n⚠ Security Issues:")
                for issue in result["security_issues"]:
                    click.echo(f"  {issue}")
        else:
            click.echo("✓ CORS is not enabled or not detected")


@cli.command(name="threat-ip")
@click.argument("ip")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def threat_ip(ip, output_json):
    """Check an IP address against threat intelligence data.

    Looks up IP reputation and geolocation information.

    \b
    Example:
      sectoolkit threat-ip 185.220.101.1
    """
    import json

    reputation = check_ip_reputation(ip)
    geo = geoip_lookup(ip)

    result = {"ip": ip, "reputation": reputation, "geolocation": geo}

    if output_json:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        click.echo(f"[IP Reputation: {ip}]")
        click.echo(f"  Is malicious: {reputation.get('is_malicious', 'unknown')}")
        click.echo(f"  Reputation:   {reputation.get('reputation', 'unknown')}")
        if reputation.get("tags"):
            click.echo(f"  Tags:         {', '.join(reputation['tags'])}")
        if reputation.get("is_bogon"):
            click.echo("  \u26a0 Bogon / reserved address space")
        click.echo("")
        click.echo("[Geolocation]")
        for key, value in geo.items():
            if key != "ip":
                click.echo(f"  {key}: {value}")


@cli.command(name="threat-url")
@click.argument("url")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def threat_url(url, output_json):
    """Check a URL against threat intelligence data.

    Looks up whether the URL matches known malicious patterns or domains.

    \b
    Example:
      sectoolkit threat-url "http://malware-domain.example.com/payload"
    """
    import json

    result = lookup_malicious_url(url)

    if output_json:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        click.echo(f"[URL Threat Check]")
        click.echo(f"  URL:         {result.get('url', url)}")
        click.echo(f"  Is malicious:{result.get('is_malicious', 'unknown')}")
        click.echo(f"  Risk level:  {result.get('risk_level', 'unknown')}")
        if result.get("reasons"):
            click.echo("  Reasons:")
            for reason in result["reasons"]:
                click.echo(f"    - {reason}")
        if result.get("domain_info"):
            click.echo(f"  Domain info: {result['domain_info']}")


@cli.command(name="threat-hash")
@click.argument("hash_value")
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def threat_hash(hash_value, output_json):
    """Check a file hash against threat intelligence data.

    Looks up whether the hash matches known malware or threat samples.

    \b
    Example:
      sectoolkit threat-hash d41d8cd98f00b204e9800998ecf8427e
    """
    import json

    result = hash_threat_lookup(hash_value)

    if output_json:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        click.echo(f"[Hash Threat Lookup]")
        click.echo(f"  Hash:        {result.get('hash', hash_value)}")
        click.echo(f"  Is malicious:{result.get('is_malicious', 'unknown')}")
        click.echo(f"  Algorithm:   {result.get('algorithm', 'unknown')}")
        if result.get("malware_name"):
            click.echo(f"  Malware:     {result['malware_name']}")
        if result.get("tags"):
            click.echo(f"  Tags:        {', '.join(result['tags'])}")


@cli.command(name="threat-ioc")
@click.argument("value")
@click.option(
    "--ioc-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to a file containing one IOC per line to match against.",
)
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
def threat_ioc(value, ioc_file, output_json):
    """Match a value against a list of Indicators of Compromise (IOCs).

    Provide --ioc-file (one IOC per line) or checks against the built-in
    IOC list.

    \b
    Example:
      sectoolkit threat-ioc 185.220.101.1
      sectoolkit threat-ioc suspicious.domain.com --ioc-file my-iocs.txt
    """
    import json

    ioc_list = None
    if ioc_file:
        try:
            with open(ioc_file, "r", encoding="utf-8") as f:
                ioc_list = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except Exception as exc:
            raise click.ClickException(f"Could not read IOC file: {exc}")

    if ioc_list is not None:
        result = match_ioc(value, ioc_list)
    else:
        result = match_ioc(value)

    if output_json:
        click.echo(json.dumps(result, indent=2, default=str))
    else:
        click.echo(f"[IOC Match: {value}]")
        click.echo(f"  Matched: {result.get('matched', False)}")
        if result.get("matched"):
            click.echo(f"  IOC type:      {result.get('ioc_type', 'unknown')}")
            click.echo(f"  Matched value: {result.get('matched_ioc', 'unknown')}")
        else:
            click.echo("  No match found in IOC list.")


@cli.command(name="report")
@click.option("--input", "input_file", default=None, help="Path to a JSON file containing previous scan results.")
@click.option("--output", "output_file", required=True, help="Output file path.")
@click.option(
    "--format", "report_format",
    type=click.Choice(["json", "csv", "html"]),
    default="html",
    show_default=True,
    help="Output format.",
)
@click.option("--title", default="Security Report", show_default=True, help="Report title.")
def report(input_file, output_file, report_format, title):
    """Export scan results to a file (JSON, CSV, or HTML).

    Reads results from --input (a JSON file produced by a previous scan)
    and writes a formatted report to --output.

    \b
    Example:
      sectoolkit report --input results.json --output report.html --format html
    """
    data = {}
    if input_file:
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as exc:
            raise click.ClickException(f"Could not read input file: {exc}")

    if report_format == "json":
        export_json(data, output_file)
    elif report_format == "csv":
        if isinstance(data, list):
            rows = data
        elif isinstance(data, dict):
            rows = [{"key": k, "value": str(v)} for k, v in data.items()]
        else:
            rows = [{"data": str(data)}]
        export_csv(rows, output_file)
    elif report_format == "html":
        if isinstance(data, dict):
            export_html(data, title=title, filepath=output_file)
        else:
            export_html({"data": str(data)}, title=title, filepath=output_file)

    click.echo(f"Report saved to {output_file}")


@cli.command(name="file-monitor")
@click.argument("directory", type=click.Path(exists=True))
@click.option("--snapshot-file", default="snapshot.json", help="File to save/load snapshots.")
@click.option("--algorithm", "-a", default="sha256", help="Hash algorithm to use.")
@click.option("--recursive", "-r", is_flag=True, default=True, help="Recursively scan subdirectories.")
@click.option("--compare", is_flag=True, help="Compare with existing snapshot instead of creating new one.")
def file_monitor(directory, snapshot_file, algorithm, recursive, compare):
    """Monitor directory for file changes using hash snapshots.
    
    Creates a snapshot of all files in the directory with their hashes.
    Use --compare to detect changes since the last snapshot.
    """
    from sectoolkit.file_monitor import (
        snapshot_directory, save_snapshot, load_snapshot, compare_snapshots
    )
    
    if compare:
        # Load existing snapshot and compare
        old_snapshot = load_snapshot(snapshot_file)
        if old_snapshot is None:
            raise click.ClickException(f"Could not load snapshot from {snapshot_file}")
        
        click.echo("Creating current snapshot...")
        new_snapshot = snapshot_directory(directory, algorithm=algorithm, recursive=recursive)
        
        click.echo("Comparing snapshots...")
        changes = compare_snapshots(old_snapshot, new_snapshot)
        
        click.echo(f"\n{changes['summary']}")
        
        if changes["added"]:
            click.echo(f"\nAdded files ({len(changes['added'])}):")
            for path in changes["added"]:
                click.echo(f"  + {path}")
        
        if changes["removed"]:
            click.echo(f"\nRemoved files ({len(changes['removed'])}):")
            for path in changes["removed"]:
                click.echo(f"  - {path}")
        
        if changes["modified"]:
            click.echo(f"\nModified files ({len(changes['modified'])}):")
            for path in changes["modified"]:
                click.echo(f"  * {path}")
        
        if changes["unchanged"] > 0:
            click.echo(f"\nUnchanged files: {changes['unchanged']}")
        
        # Save new snapshot for next comparison
        if save_snapshot(new_snapshot, snapshot_file):
            click.echo(f"\nSnapshot updated: {snapshot_file}")
        else:
            click.echo(f"\nWarning: Could not save snapshot to {snapshot_file}")
    else:
        # Create new snapshot
        click.echo(f"Creating snapshot of {directory}...")
        snapshot = snapshot_directory(directory, algorithm=algorithm, recursive=recursive)
        
        if save_snapshot(snapshot, snapshot_file):
            click.echo(f"Snapshot saved: {snapshot_file}")
            click.echo(f"Files scanned: {len(snapshot['files'])}")
            click.echo(f"Algorithm: {snapshot['algorithm']}")
        else:
            raise click.ClickException(f"Could not save snapshot to {snapshot_file}")


@cli.command(name="config-audit")
@click.argument("config_file", type=click.Path(exists=True))
@click.option("--json", "output_json", is_flag=True, help="Output in JSON format.")
@click.option("--severity", type=click.Choice(["low", "medium", "high"]), help="Only show issues of specified severity or higher.")
def config_audit(config_file, output_json, severity):
    """Audit configuration files for security issues.
    
    Supports .env, .ini, .json, and YAML-like config files.
    Detects exposed secrets, weak settings, debug flags, etc.
    """
    from sectoolkit.config_auditor import audit_config_file
    
    result = audit_config_file(config_file)
    
    if output_json:
        import json
        click.echo(json.dumps(result, indent=2))
        return
    
    click.echo(f"Auditing: {config_file}")
    click.echo(f"File type: {result['file_type']}")
    click.echo(f"Total issues: {result['total_issues']}")
    
    if result['risk_score'] > 0:
        click.echo(f"Risk score: {result['risk_score']}/100\n")
    
    # Filter by severity if specified
    issues_to_show = result['issues']
    if severity:
        severity_levels = {"low": 1, "medium": 2, "high": 3}
        min_level = severity_levels[severity]
        issues_to_show = [
            issue for issue in issues_to_show 
            if severity_levels.get(issue.get('severity', 'low'), 1) >= min_level
        ]
    
    if issues_to_show:
        for issue in issues_to_show:
            severity_indicator = {
                'low': 'INFO',
                'medium': 'WARN',
                'high': 'CRITICAL'
            }.get(issue.get('severity', 'low'), 'INFO')
            
            click.echo(f"{severity_indicator} {issue['type'].upper()}")
            click.echo(f"  Key: {issue['key']}")
            if 'value' in issue and issue['value']:
                value_preview = str(issue['value'])[:50]
                if len(str(issue['value'])) > 50:
                    value_preview += "..."
                click.echo(f"  Value: {value_preview}")
            click.echo(f"  Issue: {issue['description']}")
            if 'recommendation' in issue and issue['recommendation']:
                click.echo(f"  Fix: {issue['recommendation']}")
            click.echo("")
    else:
        if severity:
            click.echo(f"No {severity}+ severity issues found.")
        else:
            click.echo("No security issues found.")


@cli.command(name="password-audit")
@click.argument("password_file", type=click.Path(exists=True))
@click.option("--format", "file_format", type=click.Choice(["txt", "csv"]), default="txt", help="Input file format.")
@click.option("--column", default=1, help="Column number for passwords in CSV (1-based).")
@click.option("--policy-file", type=click.Path(exists=True), help="JSON file with custom password policy.")
@click.option("--export", "export_path", help="Export results to file.")
@click.option("--export-format", type=click.Choice(["json", "csv", "html"]), default="json", help="Export format.")
@click.option("--breach-check", is_flag=True, help="Check passwords against breach database (requires internet).")
def password_audit(password_file, file_format, column, policy_file, export_path, export_format, breach_check):
    """Audit a list of passwords for policy compliance and breaches.
    
    Supports text files (one password per line) or CSV files.
    Checks against password policies and optionally breach databases.
    """
    from sectoolkit.password_audit import audit_password_file
    from sectoolkit.reporter import export_json, export_csv, export_html
    
    # Load custom policy if provided
    policy = None
    if policy_file:
        import json
        try:
            with open(policy_file, 'r') as f:
                policy = json.load(f)
        except Exception as e:
            raise click.ClickException(f"Could not load policy file: {e}")
    
    click.echo(f"Auditing passwords from {password_file}...")
    if breach_check:
        click.echo("Breach checking enabled (this may take some time)...")
    
    result = audit_password_file(
        password_file, 
        file_format=file_format,
        password_column=column,
        policy=policy,
        check_breaches=breach_check
    )
    
    # Display summary
    click.echo(f"\n[Audit Summary]")
    click.echo(f"Total passwords: {result['total_passwords']}")
    click.echo(f"Policy compliant: {result['compliant_count']} ({result['compliance_rate']:.1f}%)")
    
    if result['common_violations']:
        click.echo(f"\n[Most Common Violations]")
        for violation, count in result['common_violations'].items():
            click.echo(f"  {violation}: {count}")
    
    if breach_check and result.get('breach_summary'):
        breach = result['breach_summary']
        click.echo(f"\n[Breach Check Results]")
        click.echo(f"Breached passwords: {breach['breached_count']} ({breach['breach_rate']:.1f}%)")
        if breach['most_breached']:
            click.echo(f"Most breached password appeared in: {breach['most_breached']} breaches")
    
    click.echo(f"\n[Security Score]")
    click.echo(f"Overall score: {result['security_score']:.1f}/100")
    
    # Export if requested
    if export_path:
        if export_format == "json":
            export_json(result, export_path)
        elif export_format == "csv":
            # Convert to CSV-friendly format
            csv_data = []
            for i, pwd_result in enumerate(result.get('password_results', [])):
                csv_data.append({
                    'password_index': i + 1,
                    'compliant': pwd_result.get('compliant', False),
                    'score': pwd_result.get('score', 0),
                    'violations': '; '.join(pwd_result.get('violations', [])),
                    'breached': pwd_result.get('breach_info', {}).get('breached', False) if breach_check else 'N/A'
                })
            export_csv(csv_data, export_path)
        elif export_format == "html":
            export_html(result, title="Password Audit Report", filepath=export_path)
        
        click.echo(f"Results exported to {export_path}")


if __name__ == "__main__":
    cli()
