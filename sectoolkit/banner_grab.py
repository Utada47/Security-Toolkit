"""Service banner grabbing for port identification."""
import socket
from typing import Dict, Any, Optional


def grab_banner(host: str, port: int, timeout: float = 2.0) -> Dict[str, Any]:
    """Attempt to grab service banner from a port.
    
    Args:
        host: Target hostname or IP
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        Dict containing banner information
    """
    result = {
        "host": host,
        "port": port,
        "banner": None,
        "service": None,
        "version": None,
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        except:
            pass
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        if banner:
            result["banner"] = banner[:200]
            result["service"] = identify_service_from_banner(banner)
            result["version"] = extract_version_from_banner(banner)
    
    except Exception as e:
        result["error"] = str(e)
    
    return result


def identify_service_from_banner(banner: str) -> Optional[str]:
    """Identify service type from banner string.
    
    Args:
        banner: Banner string received from service
        
    Returns:
        Service name or None
    """
    banner_lower = banner.lower()
    
    service_patterns = {
        "ssh": ["ssh", "openssh"],
        "ftp": ["ftp", "filezilla"],
        "http": ["http", "apache", "nginx", "iis"],
        "smtp": ["smtp", "postfix", "sendmail", "exim"],
        "mysql": ["mysql"],
        "postgresql": ["postgresql"],
        "redis": ["redis"],
        "mongodb": ["mongodb"],
        "elasticsearch": ["elasticsearch"],
        "rabbitmq": ["rabbitmq"],
    }
    
    for service, patterns in service_patterns.items():
        for pattern in patterns:
            if pattern in banner_lower:
                return service
    
    return None


def extract_version_from_banner(banner: str) -> Optional[str]:
    """Extract version information from banner.
    
    Args:
        banner: Banner string
        
    Returns:
        Version string or None
    """
    import re
    
    version_patterns = [
        r'(\d+\.\d+\.\d+)',
        r'(\d+\.\d+)',
        r'[vV]ersion[\s:]+([\d\.]+)',
    ]
    
    for pattern in version_patterns:
        match = re.search(pattern, banner)
        if match:
            return match.group(1)
    
    return None


def scan_with_banner_grab(host: str, ports: list, timeout: float = 2.0) -> Dict[int, Dict[str, Any]]:
    """Scan ports and grab banners from open ones.
    
    Args:
        host: Target hostname or IP
        ports: List of ports to scan
        timeout: Connection timeout
        
    Returns:
        Dict mapping port numbers to banner information
    """
    results = {}
    
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                banner_info = grab_banner(host, port, timeout)
                results[port] = banner_info
        except:
            pass
    
    return results


def identify_service_fingerprint(host: str, port: int) -> Dict[str, Any]:
    """Perform deeper service fingerprinting.
    
    Args:
        host: Target hostname or IP
        port: Port number
        
    Returns:
        Dict containing fingerprint information
    """
    result = {
        "host": host,
        "port": port,
        "likely_service": None,
        "confidence": "low",
        "details": {},
    }
    
    banner_info = grab_banner(host, port, timeout=3.0)
    
    if banner_info.get("service"):
        result["likely_service"] = banner_info["service"]
        result["confidence"] = "high" if banner_info.get("version") else "medium"
        result["details"] = {
            "banner": banner_info.get("banner"),
            "version": banner_info.get("version"),
        }
    else:
        common_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            27017: "MongoDB",
        }
        
        if port in common_services:
            result["likely_service"] = common_services[port]
            result["confidence"] = "medium"
    
    return result
