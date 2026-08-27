"""API security testing utilities for REST endpoints."""
import socket
import ssl
import json
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse


def test_http_methods(url: str, methods: Optional[List[str]] = None) -> Dict[str, Any]:
    """Test which HTTP methods are allowed on an endpoint."""
    if methods is None:
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"]
    
    result = {
        "url": url,
        "allowed_methods": [],
        "forbidden_methods": [],
        "unsafe_methods": [],
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    
    for method in methods:
        try:
            if use_ssl:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        request = f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        response = ssock.recv(2048).decode('utf-8', errors='ignore')
            else:
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    request = f"{method} {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    response = sock.recv(2048).decode('utf-8', errors='ignore')
            
            if "405 Method Not Allowed" in response or "405" in response.split('\n')[0]:
                result["forbidden_methods"].append(method)
            elif "403" in response.split('\n')[0]:
                result["forbidden_methods"].append(method)
            else:
                result["allowed_methods"].append(method)
                if method in ["PUT", "DELETE", "TRACE", "CONNECT"]:
                    result["unsafe_methods"].append(method)
        except:
            pass
    
    return result


def check_rate_limiting(url: str, requests_count: int = 20) -> Dict[str, Any]:
    """Test if rate limiting is implemented on an endpoint."""
    result = {
        "url": url,
        "total_requests": requests_count,
        "successful_requests": 0,
        "rate_limited": False,
        "rate_limit_detected_at": None,
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    
    for i in range(requests_count):
        try:
            if use_ssl:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        response = ssock.recv(2048).decode('utf-8', errors='ignore')
            else:
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    response = sock.recv(2048).decode('utf-8', errors='ignore')
            
            if "429" in response.split('\n')[0] or "Too Many Requests" in response:
                result["rate_limited"] = True
                result["rate_limit_detected_at"] = i + 1
                break
            else:
                result["successful_requests"] += 1
        except:
            pass
    
    return result


def check_cors_policy(url: str, origin: str = "https://evil.com") -> Dict[str, Any]:
    """Check CORS policy configuration."""
    result = {
        "url": url,
        "test_origin": origin,
        "cors_enabled": False,
        "allows_credentials": False,
        "allowed_origins": [],
        "allowed_methods": [],
        "security_issues": [],
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    
    try:
        if use_ssl:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    request = f"OPTIONS {path} HTTP/1.1\r\nHost: {hostname}\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
                    ssock.sendall(request.encode())
                    response = ssock.recv(2048).decode('utf-8', errors='ignore')
        else:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                request = f"OPTIONS {path} HTTP/1.1\r\nHost: {hostname}\r\nOrigin: {origin}\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())
                response = sock.recv(2048).decode('utf-8', errors='ignore')
        
        if "Access-Control-Allow-Origin" in response:
            result["cors_enabled"] = True
            
            for line in response.split('\n'):
                if "Access-Control-Allow-Origin:" in line:
                    allowed_origin = line.split(':', 1)[1].strip()
                    result["allowed_origins"].append(allowed_origin)
                    if allowed_origin == "*":
                        result["security_issues"].append("CORS allows all origins (*)")
                
                if "Access-Control-Allow-Credentials:" in line:
                    if "true" in line.lower():
                        result["allows_credentials"] = True
                        if "*" in result["allowed_origins"]:
                            result["security_issues"].append("Credentials allowed with wildcard origin - CRITICAL")
                
                if "Access-Control-Allow-Methods:" in line:
                    methods = line.split(':', 1)[1].strip()
                    result["allowed_methods"] = [m.strip() for m in methods.split(',')]
    except:
        pass
    
    return result


def test_authentication_bypass(url: str) -> Dict[str, Any]:
    """Test for common authentication bypass techniques."""
    result = {
        "url": url,
        "tests_performed": [],
        "potential_bypasses": [],
    }
    
    parsed = urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"
    
    test_headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
    ]
    
    for headers in test_headers:
        test_name = list(headers.keys())[0]
        result["tests_performed"].append(test_name)
        
        try:
            if use_ssl:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\n"
                        for key, value in headers.items():
                            request += f"{key}: {value}\r\n"
                        request += "Connection: close\r\n\r\n"
                        ssock.sendall(request.encode())
                        response = ssock.recv(2048).decode('utf-8', errors='ignore')
            else:
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\n"
                    for key, value in headers.items():
                        request += f"{key}: {value}\r\n"
                    request += "Connection: close\r\n\r\n"
                    sock.sendall(request.encode())
                    response = sock.recv(2048).decode('utf-8', errors='ignore')
            
            if "200 OK" in response and "401" not in response and "403" not in response:
                result["potential_bypasses"].append({
                    "method": test_name,
                    "headers": headers,
                })
        except:
            pass
    
    return result
