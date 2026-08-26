"""Basic vulnerability scanner for common web vulnerabilities."""
import socket
import ssl
from typing import Dict, List, Any
from urllib.parse import urlparse


def scan_open_ports_basic(host: str, ports: List[int]) -> Dict[str, Any]:
    """Scan for open ports and identify potential security issues."""
    results = {
        "host": host,
        "open_ports": [],
        "risky_ports": [],
        "warnings": [],
    }
    
    risky_port_info = {
        21: "FTP - Unencrypted file transfer",
        23: "Telnet - Unencrypted remote access",
        25: "SMTP - Potential mail relay",
        3389: "RDP - Remote Desktop (brute force target)",
        5900: "VNC - Remote access",
        1433: "MSSQL - Database exposed",
        3306: "MySQL - Database exposed",
        5432: "PostgreSQL - Database exposed",
        27017: "MongoDB - Database exposed",
        6379: "Redis - Database exposed",
    }
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                results["open_ports"].append(port)
                
                if port in risky_port_info:
                    results["risky_ports"].append({
                        "port": port,
                        "risk": risky_port_info[port]
                    })
        except:
            pass
    
    return results


def check_ssl_vulnerabilities(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Check for SSL/TLS vulnerabilities and weak configurations."""
    results = {
        "hostname": hostname,
        "port": port,
        "issues": [],
        "warnings": [],
        "info": {},
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                results["info"]["cipher"] = cipher[0] if cipher else None
                results["info"]["protocol"] = ssock.version()
                
                if cipher:
                    cipher_name = cipher[0].lower()
                    if "rc4" in cipher_name:
                        results["issues"].append("Weak cipher RC4 detected")
                    if "des" in cipher_name and "3des" not in cipher_name:
                        results["issues"].append("Weak cipher DES detected")
                    if "md5" in cipher_name:
                        results["issues"].append("Weak hash MD5 in cipher")
                
                protocol = ssock.version()
                if protocol in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
                    results["issues"].append(f"Outdated protocol: {protocol}")
                
    except ssl.SSLError as e:
        results["issues"].append(f"SSL Error: {str(e)}")
    except Exception as e:
        results["error"] = str(e)
    
    return results


def check_common_paths(hostname: str, port: int = 443, use_https: bool = True) -> Dict[str, Any]:
    """Check for common sensitive paths and files."""
    results = {
        "hostname": hostname,
        "port": port,
        "accessible_paths": [],
        "potentially_sensitive": [],
    }
    
    sensitive_paths = [
        "/.git/config",
        "/.env",
        "/admin",
        "/phpinfo.php",
        "/server-status",
        "/wp-admin",
        "/.htaccess",
        "/config.php",
        "/backup.zip",
        "/database.sql",
    ]
    
    protocol = "https" if use_https else "http"
    
    for path in sensitive_paths:
        try:
            if use_https:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        request = f"HEAD {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        response = ssock.recv(1024).decode('utf-8', errors='ignore')
                        
                        if "200 OK" in response:
                            results["accessible_paths"].append(path)
                            results["potentially_sensitive"].append(path)
                        elif "403 Forbidden" in response:
                            results["accessible_paths"].append(f"{path} (403 - exists but forbidden)")
            else:
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    request = f"HEAD {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    response = sock.recv(1024).decode('utf-8', errors='ignore')
                    
                    if "200 OK" in response:
                        results["accessible_paths"].append(path)
                        results["potentially_sensitive"].append(path)
                    elif "403 Forbidden" in response:
                        results["accessible_paths"].append(f"{path} (403 - exists but forbidden)")
        except:
            pass
    
    return results


def run_vulnerability_scan(hostname: str, ports: List[int] = None) -> Dict[str, Any]:
    """Run a comprehensive vulnerability scan."""
    if ports is None:
        ports = [21, 22, 23, 25, 80, 443, 3306, 3389, 5432, 8080]
    
    results = {
        "hostname": hostname,
        "timestamp": None,
        "port_scan": {},
        "ssl_check": {},
        "path_check": {},
        "risk_level": "low",
    }
    
    from datetime import datetime
    results["timestamp"] = datetime.now().isoformat()
    
    results["port_scan"] = scan_open_ports_basic(hostname, ports)
    
    if 443 in results["port_scan"]["open_ports"]:
        results["ssl_check"] = check_ssl_vulnerabilities(hostname, 443)
        results["path_check"] = check_common_paths(hostname, 443, use_https=True)
    elif 80 in results["port_scan"]["open_ports"]:
        results["path_check"] = check_common_paths(hostname, 80, use_https=False)
    
    risk_count = 0
    if results["port_scan"]["risky_ports"]:
        risk_count += len(results["port_scan"]["risky_ports"])
    if results["ssl_check"].get("issues"):
        risk_count += len(results["ssl_check"]["issues"])
    if results["path_check"].get("potentially_sensitive"):
        risk_count += len(results["path_check"]["potentially_sensitive"])
    
    if risk_count >= 5:
        results["risk_level"] = "high"
    elif risk_count >= 2:
        results["risk_level"] = "medium"
    
    return results
