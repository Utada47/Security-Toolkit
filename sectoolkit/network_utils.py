"""Network utilities for IP geolocation and CIDR calculations."""
import socket
import struct
from typing import Dict, List, Any, Tuple


def ip_to_int(ip: str) -> int:
    """Convert IP address to integer.
    
    Args:
        ip: IP address string (e.g., "192.168.1.1")
        
    Returns:
        Integer representation of IP
    """
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def int_to_ip(num: int) -> str:
    """Convert integer to IP address.
    
    Args:
        num: Integer representation of IP
        
    Returns:
        IP address string
    """
    return socket.inet_ntoa(struct.pack("!I", num))


def calculate_cidr_range(cidr: str) -> Dict[str, Any]:
    """Calculate IP range from CIDR notation.
    
    Args:
        cidr: CIDR notation (e.g., "192.168.1.0/24")
        
    Returns:
        Dict containing network information
    """
    try:
        ip, prefix = cidr.split('/')
        prefix = int(prefix)
        
        ip_int = ip_to_int(ip)
        mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
        
        network = ip_int & mask
        broadcast = network | (~mask & 0xffffffff)
        
        first_host = network + 1
        last_host = broadcast - 1
        total_hosts = (broadcast - network) - 1
        
        return {
            "cidr": cidr,
            "network": int_to_ip(network),
            "broadcast": int_to_ip(broadcast),
            "netmask": int_to_ip(mask),
            "first_host": int_to_ip(first_host),
            "last_host": int_to_ip(last_host),
            "total_hosts": max(0, total_hosts),
            "prefix_length": prefix,
        }
    except Exception as e:
        return {"error": str(e)}


def check_ip_in_range(ip: str, cidr: str) -> bool:
    """Check if an IP address is within a CIDR range.
    
    Args:
        ip: IP address to check
        cidr: CIDR notation
        
    Returns:
        True if IP is in range, False otherwise
    """
    try:
        network_info = calculate_cidr_range(cidr)
        if "error" in network_info:
            return False
        
        ip_int = ip_to_int(ip)
        network_int = ip_to_int(network_info["network"])
        broadcast_int = ip_to_int(network_info["broadcast"])
        
        return network_int <= ip_int <= broadcast_int
    except:
        return False


def get_private_ip_ranges() -> List[str]:
    """Get list of private IP ranges (RFC 1918).
    
    Returns:
        List of private IP CIDR ranges
    """
    return [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ]


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private, False otherwise
    """
    for cidr in get_private_ip_ranges():
        if check_ip_in_range(ip, cidr):
            return True
    return False


def get_ip_info(ip: str) -> Dict[str, Any]:
    """Get information about an IP address.
    
    Args:
        ip: IP address
        
    Returns:
        Dict containing IP information
    """
    result = {
        "ip": ip,
        "is_private": is_private_ip(ip),
        "is_loopback": ip.startswith("127."),
        "is_multicast": False,
        "reverse_dns": None,
    }
    
    try:
        ip_int = ip_to_int(ip)
        if 224 <= (ip_int >> 24) <= 239:
            result["is_multicast"] = True
    except:
        pass
    
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = hostname
    except:
        pass
    
    return result


def subnet_split(cidr: str, new_prefix: int) -> List[str]:
    """Split a subnet into smaller subnets.
    
    Args:
        cidr: Original CIDR notation
        new_prefix: New prefix length (must be larger than original)
        
    Returns:
        List of subnet CIDR notations
    """
    try:
        ip, prefix = cidr.split('/')
        prefix = int(prefix)
        
        if new_prefix <= prefix:
            return []
        
        num_subnets = 2 ** (new_prefix - prefix)
        network_info = calculate_cidr_range(cidr)
        
        if "error" in network_info:
            return []
        
        base_ip = ip_to_int(network_info["network"])
        subnet_size = 2 ** (32 - new_prefix)
        
        subnets = []
        for i in range(num_subnets):
            subnet_ip = int_to_ip(base_ip + (i * subnet_size))
            subnets.append(f"{subnet_ip}/{new_prefix}")
        
        return subnets
    except:
        return []


def calculate_supernet(cidrs: List[str]) -> str:
    """Calculate the smallest supernet containing all given subnets.
    
    Args:
        cidrs: List of CIDR notations
        
    Returns:
        Supernet CIDR notation
    """
    if not cidrs:
        return ""
    
    try:
        ips = [ip_to_int(cidr.split('/')[0]) for cidr in cidrs]
        min_ip = min(ips)
        max_ip = max(ips)
        
        for prefix in range(0, 33):
            mask = (0xffffffff >> (32 - prefix)) << (32 - prefix)
            network = min_ip & mask
            broadcast = network | (~mask & 0xffffffff)
            
            if network <= min_ip and max_ip <= broadcast:
                return f"{int_to_ip(network)}/{prefix}"
        
        return "0.0.0.0/0"
    except:
        return ""
