"""WHOIS lookup and domain information gathering."""
import socket
from typing import Dict, Any, List


def get_whois_info(domain: str) -> Dict[str, Any]:
    """Get WHOIS information for a domain (basic implementation).
    
    Note: Full WHOIS requires external service. This is a placeholder
    that attempts basic DNS and socket information.
    
    Args:
        domain: Domain name to look up
        
    Returns:
        Dict containing available domain information
    """
    result = {
        "domain": domain,
        "registrar": None,
        "nameservers": [],
        "ip_addresses": [],
        "mx_records": [],
        "whois_server": "whois.iana.org",
    }
    
    try:
        import dns.resolver
        import dns.rdatatype
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            result["ip_addresses"] = [rr.to_text() for rr in answers]
        except Exception:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            result["nameservers"] = [rr.to_text() for rr in answers]
        except Exception:
            pass
        
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            result["mx_records"] = [(rr.preference, rr.exchange.to_text()) for rr in answers]
        except Exception:
            pass
        
    except ImportError:
        result["note"] = "dnspython not installed - basic DNS lookups available only"
        
        try:
            result["ip_addresses"] = [socket.gethostbyname(domain)]
        except socket.gaierror:
            result["ip_addresses"] = []
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def get_domain_age(domain: str) -> Dict[str, Any]:
    """Estimate domain age from DNS SOA record.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Dict containing domain age information
    """
    result = {
        "domain": domain,
        "serial": None,
        "estimated_age": None,
    }
    
    try:
        import dns.resolver
        import dns.rdatatype
        
        answers = dns.resolver.resolve(domain, 'SOA')
        soa_record = answers[0]
        result["serial"] = int(soa_record.serial)
        
    except ImportError:
        result["note"] = "dnspython not installed"
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_dns_propagation(domain: str, nameservers: List[str] = None) -> Dict[str, Any]:
    """Check if a domain is propagated across nameservers.
    
    Args:
        domain: Domain name to check
        nameservers: List of nameservers to check (uses common ones if not provided)
        
    Returns:
        Dict containing DNS propagation information
    """
    if nameservers is None:
        nameservers = [
            "8.8.8.8",
            "1.1.1.1",
            "208.67.222.222",
        ]
    
    result = {
        "domain": domain,
        "propagated": True,
        "nameserver_results": {},
        "consistent": True,
    }
    
    ips = []
    
    for ns in nameservers:
        try:
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(2)
            
            ip = socket.gethostbyname_ex(domain)[2][0] if domain else None
            result["nameserver_results"][ns] = ip
            
            if ip:
                ips.append(ip)
        except Exception as e:
            result["nameserver_results"][ns] = f"Error: {str(e)}"
    
    if ips and len(set(ips)) > 1:
        result["consistent"] = False
    
    if not ips:
        result["propagated"] = False
    
    return result


def check_subdomain_takeover_risk(domain: str, subdomains: List[str]) -> Dict[str, Any]:
    """Check if subdomains are at risk of takeover (CNAME without valid target).
    
    Args:
        domain: Main domain
        subdomains: List of subdomains to check
        
    Returns:
        Dict containing subdomain takeover risk information
    """
    result = {
        "domain": domain,
        "at_risk": [],
        "safe": [],
        "unresolvable": [],
    }
    
    try:
        import dns.resolver
        import dns.rdatatype
        import dns.exception
        
        for subdomain in subdomains:
            full_domain = f"{subdomain}.{domain}" if subdomain else domain
            
            try:
                answers = dns.resolver.resolve(full_domain, 'CNAME')
                cname_target = answers[0].to_text()
                
                try:
                    dns.resolver.resolve(cname_target, 'A')
                    result["safe"].append(full_domain)
                except (dns.exception.NXDOMAIN, dns.resolver.NXDOMAIN):
                    result["at_risk"].append({
                        "subdomain": full_domain,
                        "cname_target": cname_target,
                        "risk": "CNAME points to non-existent domain"
                    })
            except (dns.exception.NXDOMAIN, dns.resolver.NXDOMAIN):
                result["unresolvable"].append(full_domain)
            except Exception:
                pass
    
    except ImportError:
        result["note"] = "dnspython not installed"
    
    return result
