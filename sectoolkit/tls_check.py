"""Inspect a host's SSL/TLS certificate: issuer, validity dates, SANs, etc.

Useful for verifying a certificate hasn't expired, checking who issued it,
and confirming which hostnames it actually covers — all things worth
double-checking on any server you manage.
"""
import ssl
import socket
from datetime import datetime, timezone


def get_certificate_info(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """Connect to hostname:port and return details about its TLS certificate.

    Returns a dict with an 'error' key instead of raising, on any
    connection or TLS failure (host down, wrong port, self-signed cert
    rejected by default verification, etc.) — the point of this tool is to
    report findings, not crash on the first unusual certificate.
    """
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return {"hostname": hostname, "error": str(exc)}

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    san_entries = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]

    return {
        "hostname": hostname,
        "subject_common_name": subject.get("commonName"),
        "issuer": issuer.get("organizationName") or issuer.get("commonName"),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_expired": now > not_after,
        "days_until_expiry": (not_after - now).days,
        "subject_alt_names": san_entries,
    }
