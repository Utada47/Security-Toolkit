"""Network packet analysis and monitoring utilities."""
import socket
import struct
import textwrap
from typing import Dict, List, Any


def format_ipv4(bytes_ip: bytes) -> str:
    """Format IPv4 address from bytes."""
    return ".".join(map(str, bytes_ip))


def format_ipv6(bytes_ip: bytes) -> str:
    """Format IPv6 address from bytes."""
    return ":".join(format(int(bytes_ip[i:i+2].hex(), 16), 'x') for i in range(0, 16, 2))


def parse_icmp_packet(data: bytes) -> Dict[str, Any]:
    """Parse ICMP packet data."""
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return {
        "type": icmp_type,
        "code": code,
        "checksum": checksum,
        "data": data[4:]
    }


def parse_tcp_segment(data: bytes) -> Dict[str, Any]:
    """Parse TCP segment data."""
    (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "sequence": sequence,
        "acknowledgment": acknowledgment,
        "flags": {
            "URG": flag_urg,
            "ACK": flag_ack,
            "PSH": flag_psh,
            "RST": flag_rst,
            "SYN": flag_syn,
            "FIN": flag_fin
        },
        "payload": data[offset:]
    }


def parse_udp_segment(data: bytes) -> Dict[str, Any]:
    """Parse UDP segment data."""
    src_port, dest_port, length = struct.unpack('! H H 2x H', data[:8])
    return {
        "src_port": src_port,
        "dest_port": dest_port,
        "length": length,
        "payload": data[8:]
    }


def parse_ipv4_packet(data: bytes) -> Dict[str, Any]:
    """Parse IPv4 packet."""
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    
    return {
        "version": version,
        "header_length": header_length,
        "ttl": ttl,
        "protocol": proto,
        "src": format_ipv4(src),
        "dest": format_ipv4(dest),
        "payload": data[header_length:]
    }


def analyze_packet_stream(packets: List[bytes]) -> Dict[str, Any]:
    """Analyze a stream of network packets."""
    analysis = {
        "total_packets": len(packets),
        "protocols": {},
        "top_src_ips": {},
        "top_dst_ips": {},
        "port_activity": {},
        "suspicious_flags": [],
        "protocol_distribution": {}
    }
    
    for packet in packets:
        if len(packet) < 20:
            continue
            
        try:
            ipv4_packet = parse_ipv4_packet(packet)
            src_ip = ipv4_packet["src"]
            dst_ip = ipv4_packet["dest"]
            proto = ipv4_packet["protocol"]
            
            analysis["top_src_ips"][src_ip] = analysis["top_src_ips"].get(src_ip, 0) + 1
            analysis["top_dst_ips"][dst_ip] = analysis["top_dst_ips"].get(dst_ip, 0) + 1
            
            proto_name = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }.get(proto, f"Other({proto})")
            
            analysis["protocol_distribution"][proto_name] = analysis["protocol_distribution"].get(proto_name, 0) + 1
            
            if proto == 6:
                tcp_seg = parse_tcp_segment(ipv4_packet["payload"])
                port = tcp_seg["dest_port"]
                analysis["port_activity"][port] = analysis["port_activity"].get(port, 0) + 1
                
                if tcp_seg["flags"]["RST"] and tcp_seg["flags"]["SYN"]:
                    analysis["suspicious_flags"].append(f"SYN+RST from {src_ip}:{tcp_seg['src_port']} to {dst_ip}:{port}")
                    
        except Exception:
            pass
    
    analysis["top_src_ips"] = sorted(analysis["top_src_ips"].items(), key=lambda x: x[1], reverse=True)[:5]
    analysis["top_dst_ips"] = sorted(analysis["top_dst_ips"].items(), key=lambda x: x[1], reverse=True)[:5]
    analysis["port_activity"] = sorted(analysis["port_activity"].items(), key=lambda x: x[1], reverse=True)[:10]
    
    return analysis


def detect_port_scan_pattern(packets: List[bytes]) -> Dict[str, Any]:
    """Detect port scan patterns in packet stream."""
    results = {
        "potential_scans": [],
        "scan_sources": {},
    }
    
    port_connections = {}
    
    for packet in packets:
        if len(packet) < 20:
            continue
            
        try:
            ipv4_packet = parse_ipv4_packet(packet)
            if ipv4_packet["protocol"] == 6:
                tcp_seg = parse_tcp_segment(ipv4_packet["payload"])
                src_ip = ipv4_packet["src"]
                dst_port = tcp_seg["dest_port"]
                
                key = src_ip
                if key not in port_connections:
                    port_connections[key] = set()
                port_connections[key].add(dst_port)
        except Exception:
            pass
    
    for src_ip, ports in port_connections.items():
        if len(ports) > 10:
            results["potential_scans"].append(f"Source {src_ip} scanned {len(ports)} different ports")
            results["scan_sources"][src_ip] = len(ports)
    
    return results
