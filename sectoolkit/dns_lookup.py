"""DNS lookup utilities: forward (hostname -> IP) and reverse (IP -> hostname)."""
import socket


def resolve_hostname(hostname: str) -> dict:
    """Resolve a hostname to its IPv4/IPv6 addresses.

    Returns {'hostname': ..., 'addresses': [...]} or {'hostname': ...,
    'error': ...} if resolution fails (e.g. NXDOMAIN, no network).
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return {"hostname": hostname, "addresses": [], "error": str(exc)}

    addresses = sorted({r[4][0] for r in results})
    return {"hostname": hostname, "addresses": addresses}


def reverse_lookup(ip_address: str) -> dict:
    """Resolve an IP address back to a hostname, if it has a PTR record."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except (socket.herror, socket.gaierror) as exc:
        return {"ip": ip_address, "hostname": None, "error": str(exc)}

    return {"ip": ip_address, "hostname": hostname}
