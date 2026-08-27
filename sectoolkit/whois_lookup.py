"""Simple WHOIS lookup using socket (rudimentary)."""
import socket
from typing import Dict, Any

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
}


def whois_lookup(domain: str) -> Dict[str, Any]:
    """Perform a simple WHOIS query for the domain.
    
    Returns raw WHOIS response text.
    """
    result = {"domain": domain, "response": None, "error": None}
    try:
        tld = domain.split('.')[-1]
        server = WHOIS_SERVERS.get(tld, "whois.iana.org")
        with socket.create_connection((server, 43), timeout=5) as sock:
            sock.sendall((domain + "\r\n").encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
        result["response"] = response.decode(errors='ignore')
    except Exception as e:
        result["error"] = str(e)
    return result
