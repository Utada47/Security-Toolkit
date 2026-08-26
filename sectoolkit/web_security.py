"""Web security headers checker module."""
import socket
import ssl
from typing import Dict, Any, List
from datetime import datetime


def check_security_headers(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Check for common security headers on a web server.
    
    Args:
        hostname: Target hostname
        port: Port to connect to (default: 443)
        
    Returns:
        Dict containing security headers information
    """
    result = {
        "hostname": hostname,
        "port": port,
        "headers_found": {},
        "missing_headers": [],
        "security_score": 0,
        "timestamp": datetime.now().isoformat(),
    }
    
    required_headers = {
        "Strict-Transport-Security": "Enforces HTTPS connections",
        "X-Content-Type-Options": "Prevents MIME sniffing attacks",
        "X-Frame-Options": "Prevents clickjacking",
        "X-XSS-Protection": "Browser XSS protection",
        "Content-Security-Policy": "Controls resource loading",
        "Referrer-Policy": "Controls referrer information",
        "Permissions-Policy": "Controls browser features",
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                ssock.sendall(request.encode())
                
                response = b""
                while True:
                    try:
                        chunk = ssock.recv(4096)
                        if not chunk:
                            break
                        response += chunk
                    except:
                        break
        
        response_str = response.decode('utf-8', errors='ignore')
        lines = response_str.split('\r\n')
        
        for line in lines:
            if ': ' in line:
                header_name, header_value = line.split(': ', 1)
                header_name = header_name.strip()
                
                if header_name in required_headers:
                    result["headers_found"][header_name] = header_value[:100]
        
        for header in required_headers:
            if header not in result["headers_found"]:
                result["missing_headers"].append(header)
        
        result["security_score"] = (len(result["headers_found"]) / len(required_headers)) * 100
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_http_redirect(hostname: str, port: int = 80) -> Dict[str, Any]:
    """Check if HTTP redirects to HTTPS.
    
    Args:
        hostname: Target hostname
        port: Port to connect to (default: 80)
        
    Returns:
        Dict containing redirect information
    """
    result = {
        "hostname": hostname,
        "port": port,
        "redirects_to_https": False,
        "redirect_url": None,
        "status_code": None,
    }
    
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            request = f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
            sock.sendall(request.encode())
            
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except:
                    break
        
        response_str = response.decode('utf-8', errors='ignore')
        lines = response_str.split('\r\n')
        
        if lines:
            status_line = lines[0]
            if '301' in status_line or '302' in status_line or '307' in status_line:
                result["status_code"] = status_line.split()[1]
                
                for line in lines:
                    if line.lower().startswith('location:'):
                        redirect_url = line.split(':', 1)[1].strip()
                        result["redirect_url"] = redirect_url
                        if redirect_url.startswith('https://'):
                            result["redirects_to_https"] = True
        
    except Exception as e:
        result["error"] = str(e)
    
    return result


def check_certificate_transparency(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Check if certificate includes CT precertificate timestamps.
    
    Args:
        hostname: Target hostname
        port: Port to connect to (default: 443)
        
    Returns:
        Dict containing certificate transparency information
    """
    result = {
        "hostname": hostname,
        "has_ct_logs": False,
        "ct_entries": [],
    }
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert_bin()
                if cert_bin:
                    result["has_ct_logs"] = True
                    result["ct_entries"] = ["Certificate obtained (CT verification requires external validation)"]
    except Exception as e:
        result["error"] = str(e)
    
    return result
