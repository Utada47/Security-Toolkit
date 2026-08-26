"""Tests for packet analysis module."""
import struct
import pytest
from sectoolkit.packet_analysis import (
    format_ipv4,
    format_ipv6,
    parse_icmp_packet,
    parse_tcp_segment,
    parse_udp_segment,
    parse_ipv4_packet,
    analyze_packet_stream,
    detect_port_scan_pattern,
)


def test_format_ipv4():
    """Test IPv4 formatting."""
    ip_bytes = struct.pack('! 4s', b'\xc0\xa8\x01\x01')
    result = format_ipv4(ip_bytes)
    assert result == "192.168.1.1"


def test_format_ipv6():
    """Test IPv6 formatting."""
    ip_bytes = b'\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
    result = format_ipv6(ip_bytes)
    assert isinstance(result, str)
    assert ":" in result


def test_parse_icmp_packet():
    """Test ICMP packet parsing."""
    icmp_data = struct.pack('! B B H', 8, 0, 0x1234) + b'test data'
    result = parse_icmp_packet(icmp_data)
    
    assert result["type"] == 8
    assert result["code"] == 0
    assert result["checksum"] == 0x1234


def test_parse_tcp_segment():
    """Test TCP segment parsing."""
    src_port = 12345
    dst_port = 80
    sequence = 1000
    ack = 2000
    flags = (5 << 12) | 0x0002
    
    tcp_data = struct.pack('! H H L L H', src_port, dst_port, sequence, ack, flags) + b'payload'
    result = parse_tcp_segment(tcp_data)
    
    assert result["src_port"] == src_port
    assert result["dest_port"] == dst_port
    assert result["sequence"] == sequence
    assert result["acknowledgment"] == ack
    assert result["flags"]["SYN"] == 1


def test_parse_udp_segment():
    """Test UDP segment parsing."""
    src_port = 53
    dst_port = 12345
    length = 20
    
    udp_data = struct.pack('! H H 2x H', src_port, dst_port, length) + b'payload'
    result = parse_udp_segment(udp_data)
    
    assert result["src_port"] == src_port
    assert result["dest_port"] == dst_port
    assert result["length"] == length


def test_parse_ipv4_packet():
    """Test IPv4 packet parsing."""
    version_header = (4 << 4) | 5
    ttl = 64
    proto = 6
    
    ipv4_header = struct.pack(
        '! B B H H H B B H 4s 4s',
        version_header,
        0,
        40,
        0,
        0,
        ttl,
        proto,
        0,
        b'\xc0\xa8\x01\x01',
        b'\xc0\xa8\x01\x02'
    )
    
    result = parse_ipv4_packet(ipv4_header + b'payload')
    
    assert result["version"] == 4
    assert result["ttl"] == ttl
    assert result["protocol"] == proto
    assert result["src"] == "192.168.1.1"
    assert result["dest"] == "192.168.1.2"


def test_analyze_packet_stream_empty():
    """Test analyzing empty packet stream."""
    result = analyze_packet_stream([])
    
    assert result["total_packets"] == 0
    assert result["protocols"] == {}
    assert result["top_src_ips"] == []


def test_analyze_packet_stream_structure():
    """Test packet stream analysis returns expected structure."""
    result = analyze_packet_stream([])
    
    assert "total_packets" in result
    assert "protocols" in result
    assert "top_src_ips" in result
    assert "top_dst_ips" in result
    assert "port_activity" in result
    assert "suspicious_flags" in result
    assert "protocol_distribution" in result


def test_detect_port_scan_pattern_empty():
    """Test port scan detection with empty stream."""
    result = detect_port_scan_pattern([])
    
    assert "potential_scans" in result
    assert "scan_sources" in result
    assert result["potential_scans"] == []
