"""SSL/TLS certificate chain validator and analyzer."""
from typing import Dict, List, Any
import socket
import ssl
from datetime import datetime


def get_certificate_chain(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Retrieve the full certificate chain from a server.
    
    Args:
        hostname: Target hostname
        port: Port to connect to
        
    Returns:
        Dict containing certificate chain information
    """
    result = {
        "hostname": hostname,
        "port": port,
        "chain": [],
        "chain_length": 0,
        "root_ca_present": False,
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert_bin()
                
                if cert_der:
                    cert_dict = ssock.getpeercert()
                    result["chain"].append({
                        "subject": dict(x[0] for x in cert_dict.get("subject", [])),
                        "issuer": dict(x[0] for x in cert_dict.get("issuer", [])),
                        "notBefore": cert_dict.get("notBefore"),
                        "notAfter": cert_dict.get("notAfter"),
                        "version": cert_dict.get("version"),
                    })
                    
                    result["chain_length"] = 1
                    
                    issuer = dict(x[0] for x in cert_dict.get("issuer", []))
                    subject = dict(x[0] for x in cert_dict.get("subject", []))
                    
                    if issuer.get("commonName") == subject.get("commonName"):
                        result["root_ca_present"] = True
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def validate_certificate_dates(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Validate certificate dates and expiry status.
    
    Args:
        hostname: Target hostname
        port: Port to connect to
        
    Returns:
        Dict containing date validation information
    """
    result = {
        "hostname": hostname,
        "valid_from": None,
        "valid_until": None,
        "days_valid": None,
        "is_valid_now": False,
        "expiry_status": "unknown",
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()
                
                if cert_dict:
                    not_before = cert_dict.get("notBefore")
                    not_after = cert_dict.get("notAfter")
                    
                    result["valid_from"] = not_before
                    result["valid_until"] = not_after
                    
                    if not_before and not_after:
                        try:
                            from_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                            to_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            
                            now = datetime.utcnow()
                            result["is_valid_now"] = from_date <= now <= to_date
                            result["days_valid"] = (to_date - from_date).days
                            
                            if now > to_date:
                                result["expiry_status"] = "expired"
                            elif now < from_date:
                                result["expiry_status"] = "not_yet_valid"
                            else:
                                days_until = (to_date - now).days
                                result["expiry_status"] = f"valid ({days_until} days remaining)"
                        except ValueError:
                            result["expiry_status"] = "unable_to_parse_dates"
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_certificate_pinning(hostname: str, port: int = 443, public_key_hash: str = None) -> Dict[str, Any]:
    """Check if a certificate matches an expected public key hash.
    
    Args:
        hostname: Target hostname
        port: Port to connect to
        public_key_hash: Expected public key hash (optional)
        
    Returns:
        Dict containing pinning validation information
    """
    result = {
        "hostname": hostname,
        "public_key_hash": None,
        "pinned": False,
        "matches": False if public_key_hash else None,
    }
    
    try:
        import hashlib
        import base64
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_der = ssock.getpeercert_bin()
                
                if cert_der:
                    cert_hash = hashlib.sha256(cert_der).digest()
                    cert_hash_b64 = base64.b64encode(cert_hash).decode('ascii')
                    result["public_key_hash"] = cert_hash_b64
                    result["pinned"] = True
                    
                    if public_key_hash:
                        result["matches"] = cert_hash_b64 == public_key_hash
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def validate_certificate_chain_integrity(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Validate that the certificate chain is properly formed.
    
    Args:
        hostname: Target hostname
        port: Port to connect to
        
    Returns:
        Dict containing chain integrity validation
    """
    result = {
        "hostname": hostname,
        "chain_valid": False,
        "issues": [],
        "warnings": [],
    }
    
    try:
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_dict = ssock.getpeercert()
                    
                    result["chain_valid"] = True
                    
                    subject = dict(x[0] for x in cert_dict.get("subject", []))
                    san = cert_dict.get("subjectAltName", [])
                    
                    if not subject.get("commonName") and not san:
                        result["issues"].append("No CN or SAN found")
                    
                    if subject.get("commonName", "").startswith("*."):
                        result["warnings"].append("Wildcard certificate detected")
                    
        except ssl.SSLError as e:
            result["chain_valid"] = False
            result["issues"].append(f"SSL verification failed: {str(e)}")
    
    except Exception as e:
        result["error"] = str(e)
    
    return result
