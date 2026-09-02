"""Advanced network scanning with OS detection and service fingerprinting.

Extends basic port scanning with OS detection, service version detection,
and advanced network reconnaissance techniques.
"""
import socket
import struct
import random
import time
import subprocess
import threading
from typing import Dict, List, Any, Optional, Tuple
import re


class AdvancedNetworkScanner:
    """Advanced network scanner with OS detection capabilities."""
    
    def __init__(self, timeout: float = 2.0, max_threads: int = 50):
        """Initialize scanner with configuration.
        
        Args:
            timeout: Socket timeout in seconds
            max_threads: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_threads = max_threads
        self.results = {}
    
    def scan_target(self, target: str, ports: List[int] = None) -> Dict[str, Any]:
        """Perform comprehensive scan of target.
        
        Args:
            target: Target IP or hostname
            ports: List of ports to scan (default: common ports)
            
        Returns:
            Dict containing scan results
        """
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]
        
        result = {
            'target': target,
            'timestamp': time.time(),
            'port_scan': {},
            'os_detection': {},
            'service_detection': {},
            'ttl_analysis': {},
            'timing_analysis': {}
        }
        
        try:
            # Basic port scan with timing analysis
            result['port_scan'] = self._advanced_port_scan(target, ports)
            
            # OS detection based on TCP/IP stack fingerprinting
            result['os_detection'] = self._detect_os(target, result['port_scan'].get('open_ports', []))
            
            # Service version detection
            result['service_detection'] = self._detect_services(target, result['port_scan'].get('open_ports', []))
            
            # TTL analysis for OS hints
            result['ttl_analysis'] = self._analyze_ttl(target)
            
            # Timing analysis for firewall/IDS detection
            result['timing_analysis'] = self._analyze_timing(target)
            
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _advanced_port_scan(self, target: str, ports: List[int]) -> Dict[str, Any]:
        """Advanced port scanning with SYN scan simulation."""
        open_ports = []
        closed_ports = []
        filtered_ports = []
        port_timings = {}
        
        def scan_port(port: int) -> Tuple[int, str, float]:
            start_time = time.time()
            
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                
                result = sock.connect_ex((target, port))
                response_time = time.time() - start_time
                
                sock.close()
                
                if result == 0:
                    return port, 'open', response_time
                else:
                    return port, 'closed', response_time
                    
            except socket.timeout:
                return port, 'filtered', time.time() - start_time
            except Exception:
                return port, 'closed', time.time() - start_time
        
        # Threaded scanning
        threads = []
        results_queue = []
        
        def worker(port_list):
            for port in port_list:
                port_result = scan_port(port)
                results_queue.append(port_result)
        
        # Split ports among threads
        chunk_size = max(1, len(ports) // self.max_threads)
        for i in range(0, len(ports), chunk_size):
            chunk = ports[i:i + chunk_size]
            thread = threading.Thread(target=worker, args=(chunk,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Process results
        for port, status, timing in results_queue:
            port_timings[port] = timing
            
            if status == 'open':
                open_ports.append(port)
            elif status == 'closed':
                closed_ports.append(port)
            else:
                filtered_ports.append(port)
        
        return {
            'open_ports': sorted(open_ports),
            'closed_ports': sorted(closed_ports),
            'filtered_ports': sorted(filtered_ports),
            'port_timings': port_timings,
            'scan_technique': 'TCP Connect'
        }
    
    def _detect_os(self, target: str, open_ports: List[int]) -> Dict[str, Any]:
        """Detect operating system using various fingerprinting techniques."""
        os_hints = []
        confidence = 0
        
        # TTL-based detection
        ttl_info = self._get_ttl_signature(target)
        if ttl_info:
            os_hints.append(ttl_info)
        
        # Port pattern analysis
        port_patterns = self._analyze_port_patterns(open_ports)
        os_hints.extend(port_patterns)
        
        # TCP window size analysis (if we can get it)
        window_info = self._analyze_tcp_window(target, open_ports)
        if window_info:
            os_hints.append(window_info)
        
        # Service banner analysis
        banner_info = self._analyze_service_banners(target, open_ports)
        os_hints.extend(banner_info)
        
        # Determine most likely OS
        os_votes = {}
        for hint in os_hints:
            os_name = hint.get('os', 'Unknown')
            weight = hint.get('confidence', 1)
            os_votes[os_name] = os_votes.get(os_name, 0) + weight
        
        if os_votes:
            likely_os = max(os_votes.items(), key=lambda x: x[1])
            confidence = min(100, (likely_os[1] / len(os_hints)) * 100)
        else:
            likely_os = ('Unknown', 0)
        
        return {
            'detected_os': likely_os[0],
            'confidence': confidence,
            'os_hints': os_hints,
            'all_candidates': dict(sorted(os_votes.items(), key=lambda x: x[1], reverse=True))
        }
    
    def _get_ttl_signature(self, target: str) -> Optional[Dict[str, Any]]:
        """Get TTL signature for OS detection."""
        try:
            # Try to ping and extract TTL
            if hasattr(subprocess, 'run'):
                # Windows ping
                result = subprocess.run(['ping', '-n', '1', target], 
                                      capture_output=True, text=True, timeout=5)
                output = result.stdout
                
                # Extract TTL from ping output
                ttl_match = re.search(r'TTL=(\d+)', output, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # Common TTL values and their OS associations
                    ttl_signatures = {
                        64: ('Linux/Unix', 80),
                        128: ('Windows', 75),
                        255: ('Cisco/Network Device', 70),
                        60: ('MacOS', 65),
                        32: ('Windows 95/98', 60)
                    }
                    
                    # Find closest TTL match
                    closest_ttl = min(ttl_signatures.keys(), key=lambda x: abs(x - ttl))
                    if abs(closest_ttl - ttl) <= 10:  # Allow some variation
                        os_name, confidence = ttl_signatures[closest_ttl]
                        return {
                            'method': 'TTL Analysis',
                            'ttl_value': ttl,
                            'os': os_name,
                            'confidence': confidence
                        }
        except Exception:
            pass
        
        return None
    
    def _analyze_port_patterns(self, open_ports: List[int]) -> List[Dict[str, Any]]:
        """Analyze port patterns for OS hints."""
        hints = []
        
        # Windows-specific ports
        windows_ports = {135, 139, 445, 1433, 3389}
        if windows_ports.intersection(set(open_ports)):
            hints.append({
                'method': 'Port Pattern',
                'os': 'Windows',
                'confidence': 60,
                'evidence': f"Windows-specific ports found: {windows_ports.intersection(set(open_ports))}"
            })
        
        # Linux/Unix-specific ports
        unix_ports = {22, 25, 80, 443}
        if unix_ports.intersection(set(open_ports)) and 135 not in open_ports:
            hints.append({
                'method': 'Port Pattern',
                'os': 'Linux/Unix',
                'confidence': 50,
                'evidence': f"Unix-like service ports found: {unix_ports.intersection(set(open_ports))}"
            })
        
        # Database servers
        db_ports = {1433: 'Windows/SQL Server', 3306: 'MySQL', 5432: 'PostgreSQL'}
        for port in open_ports:
            if port in db_ports:
                hints.append({
                    'method': 'Database Detection',
                    'os': f'Database Server ({db_ports[port]})',
                    'confidence': 40,
                    'evidence': f"Database port {port} open"
                })
        
        return hints
    
    def _analyze_tcp_window(self, target: str, open_ports: List[int]) -> Optional[Dict[str, Any]]:
        """Analyze TCP window size for OS detection."""
        # This would require raw socket access which might be limited
        # For now, return a placeholder implementation
        return None
    
    def _analyze_service_banners(self, target: str, open_ports: List[int]) -> List[Dict[str, Any]]:
        """Analyze service banners for OS information."""
        hints = []
        
        for port in open_ports[:5]:  # Limit to first 5 ports for performance
            try:
                banner = self._grab_banner(target, port)
                if banner:
                    os_info = self._extract_os_from_banner(banner, port)
                    if os_info:
                        hints.append(os_info)
            except Exception:
                continue
        
        return hints
    
    def _grab_banner(self, target: str, port: int, timeout: float = 3.0) -> Optional[str]:
        """Grab service banner from a port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send appropriate probe based on port
            if port == 80 or port == 8080:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                pass  # SMTP sends banner automatically
            else:
                sock.send(b'\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
            
        except Exception:
            return None
    
    def _extract_os_from_banner(self, banner: str, port: int) -> Optional[Dict[str, Any]]:
        """Extract OS information from service banner."""
        banner_lower = banner.lower()
        
        # Common OS indicators in banners
        os_indicators = {
            'ubuntu': ('Ubuntu Linux', 70),
            'debian': ('Debian Linux', 70),
            'centos': ('CentOS Linux', 70),
            'red hat': ('Red Hat Linux', 70),
            'windows': ('Windows', 65),
            'microsoft': ('Windows', 60),
            'iis': ('Windows/IIS', 75),
            'apache': ('Linux/Apache', 50),
            'nginx': ('Linux/Nginx', 50),
            'openssh': ('Linux/Unix', 60),
            'freebsd': ('FreeBSD', 80),
            'openbsd': ('OpenBSD', 80)
        }
        
        for indicator, (os_name, confidence) in os_indicators.items():
            if indicator in banner_lower:
                return {
                    'method': 'Banner Analysis',
                    'os': os_name,
                    'confidence': confidence,
                    'evidence': f"Banner on port {port}: {banner[:100]}"
                }
        
        return None
    
    def _detect_services(self, target: str, open_ports: List[int]) -> Dict[str, Any]:
        """Detect service versions on open ports."""
        services = {}
        
        for port in open_ports:
            try:
                service_info = self._identify_service(target, port)
                if service_info:
                    services[port] = service_info
            except Exception:
                continue
        
        return services
    
    def _identify_service(self, target: str, port: int) -> Optional[Dict[str, Any]]:
        """Identify service running on a specific port."""
        banner = self._grab_banner(target, port)
        
        service_info = {
            'port': port,
            'service': self._get_common_service_name(port),
            'banner': banner,
            'version': None,
            'cpe': None  # Common Platform Enumeration
        }
        
        if banner:
            # Extract version information
            version_info = self._extract_version_from_banner(banner, port)
            if version_info:
                service_info.update(version_info)
        
        return service_info
    
    def _get_common_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC',
            139: 'NetBIOS', 143: 'IMAP', 443: 'HTTPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'SQL Server',
            3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
            8080: 'HTTP-Alt'
        }
        return common_services.get(port, f'Unknown-{port}')
    
    def _extract_version_from_banner(self, banner: str, port: int) -> Dict[str, Any]:
        """Extract version information from service banner."""
        version_info = {}
        
        # Common version patterns
        patterns = [
            r'apache/(\d+\.\d+\.\d+)',
            r'nginx/(\d+\.\d+\.\d+)',
            r'openssh[_\s](\d+\.\d+)',
            r'microsoft-iis/(\d+\.\d+)',
            r'postfix\s+(\d+\.\d+\.\d+)',
            r'dovecot\s+(\d+\.\d+\.\d+)',
            r'vsftpd\s+(\d+\.\d+\.\d+)',
            r'(\d+\.\d+\.\d+)',  # Generic version pattern
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version_info['version'] = match.group(1)
                break
        
        # Extract product name
        if 'apache' in banner.lower():
            version_info['product'] = 'Apache HTTP Server'
        elif 'nginx' in banner.lower():
            version_info['product'] = 'Nginx'
        elif 'openssh' in banner.lower():
            version_info['product'] = 'OpenSSH'
        elif 'iis' in banner.lower():
            version_info['product'] = 'Microsoft IIS'
        
        return version_info
    
    def _analyze_ttl(self, target: str) -> Dict[str, Any]:
        """Analyze TTL values for additional OS hints."""
        return {'ttl_analysis': 'implemented in _get_ttl_signature'}
    
    def _analyze_timing(self, target: str) -> Dict[str, Any]:
        """Analyze response timing patterns."""
        try:
            timings = []
            for _ in range(5):
                start_time = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                try:
                    sock.connect((target, 80))  # Try common port
                    sock.close()
                    response_time = time.time() - start_time
                    timings.append(response_time)
                except:
                    sock.close()
                    timings.append(1.0)  # Timeout value
            
            avg_timing = sum(timings) / len(timings)
            timing_variance = sum((t - avg_timing) ** 2 for t in timings) / len(timings)
            
            # High variance might indicate rate limiting or firewall
            firewall_suspected = timing_variance > 0.1 or avg_timing > 0.5
            
            return {
                'average_response_time': avg_timing,
                'timing_variance': timing_variance,
                'firewall_suspected': firewall_suspected,
                'raw_timings': timings
            }
            
        except Exception as e:
            return {'error': str(e)}


def ping_sweep(network: str, timeout: float = 1.0) -> List[str]:
    """Perform ping sweep to discover live hosts.
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        timeout: Ping timeout in seconds
        
    Returns:
        List of responding IP addresses
    """
    import ipaddress
    
    live_hosts = []
    
    try:
        network_obj = ipaddress.ip_network(network, strict=False)
        
        def ping_host(ip_str: str) -> Optional[str]:
            try:
                # Use subprocess to ping
                result = subprocess.run(
                    ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip_str],
                    capture_output=True, text=True, timeout=timeout + 1
                )
                if result.returncode == 0:
                    return ip_str
            except:
                pass
            return None
        
        # Threaded ping sweep
        threads = []
        results_queue = []
        
        def worker(ip_list):
            for ip in ip_list:
                result = ping_host(str(ip))
                if result:
                    results_queue.append(result)
        
        # Convert to list of IPs
        all_ips = list(network_obj.hosts())
        
        # Split among threads
        chunk_size = max(1, len(all_ips) // 20)  # Max 20 threads
        for i in range(0, len(all_ips), chunk_size):
            chunk = all_ips[i:i + chunk_size]
            thread = threading.Thread(target=worker, args=(chunk,))
            threads.append(thread)
            thread.start()
        
        # Wait for completion
        for thread in threads:
            thread.join()
        
        live_hosts = sorted(results_queue)
        
    except Exception as e:
        print(f"Error in ping sweep: {e}")
    
    return live_hosts


def scan_network_range(network: str, ports: List[int] = None) -> Dict[str, Any]:
    """Scan an entire network range for open ports and services.
    
    Args:
        network: Network in CIDR notation
        ports: List of ports to scan
        
    Returns:
        Dict containing scan results for all discovered hosts
    """
    if ports is None:
        ports = [22, 80, 443, 21, 25, 53, 135, 139, 445, 3389]
    
    # First, discover live hosts
    live_hosts = ping_sweep(network)
    
    if not live_hosts:
        return {'error': 'No live hosts discovered', 'network': network}
    
    # Scan each live host
    scanner = AdvancedNetworkScanner()
    results = {
        'network': network,
        'live_hosts': live_hosts,
        'host_results': {},
        'summary': {}
    }
    
    for host in live_hosts:
        try:
            host_result = scanner.scan_target(host, ports)
            results['host_results'][host] = host_result
        except Exception as e:
            results['host_results'][host] = {'error': str(e)}
    
    # Generate summary
    total_open_ports = sum(
        len(result.get('port_scan', {}).get('open_ports', []))
        for result in results['host_results'].values()
        if 'error' not in result
    )
    
    detected_os = {}
    for result in results['host_results'].values():
        if 'os_detection' in result:
            os_name = result['os_detection'].get('detected_os', 'Unknown')
            detected_os[os_name] = detected_os.get(os_name, 0) + 1
    
    results['summary'] = {
        'total_hosts_scanned': len(live_hosts),
        'total_open_ports': total_open_ports,
        'detected_operating_systems': detected_os
    }
    
    return results