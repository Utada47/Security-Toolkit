"""Steganography detection utilities.

Detects potential hidden data in images and other file formats using
various statistical and structural analysis techniques.
"""
import os
import struct
from typing import Dict, List, Any, Optional, Tuple
import re


def detect_image_steganography(file_path: str) -> Dict[str, Any]:
    """Detect potential steganography in image files.
    
    Args:
        file_path: Path to image file
        
    Returns:
        Dict containing analysis results and suspicion indicators
    """
    result = {
        'file_path': file_path,
        'file_type': _detect_image_type(file_path),
        'suspicious_indicators': [],
        'analysis': {},
        'risk_level': 'low'
    }
    
    if not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    
    try:
        # Check file size vs. expected size
        size_analysis = _analyze_file_size(file_path)
        result['analysis']['size_analysis'] = size_analysis
        
        if size_analysis.get('suspicious', False):
            result['suspicious_indicators'].append('Unusual file size for image type')
        
        # Analyze LSB patterns (Least Significant Bit steganography)
        if result['file_type'] in ['PNG', 'BMP']:
            lsb_analysis = _analyze_lsb_patterns(file_path)
            result['analysis']['lsb_analysis'] = lsb_analysis
            
            if lsb_analysis.get('suspicious', False):
                result['suspicious_indicators'].append('Suspicious LSB patterns detected')
        
        # Check for hidden metadata/comments
        metadata_analysis = _analyze_metadata_anomalies(file_path)
        result['analysis']['metadata'] = metadata_analysis
        
        if metadata_analysis.get('suspicious', False):
            result['suspicious_indicators'].append('Unusual metadata patterns')
        
        # Entropy analysis on pixel data
        entropy_analysis = _analyze_pixel_entropy(file_path)
        result['analysis']['entropy'] = entropy_analysis
        
        if entropy_analysis.get('high_entropy_regions', 0) > 0:
            result['suspicious_indicators'].append('High entropy regions in pixel data')
        
        # Calculate overall risk level
        if len(result['suspicious_indicators']) >= 3:
            result['risk_level'] = 'high'
        elif len(result['suspicious_indicators']) >= 2:
            result['risk_level'] = 'medium'
        elif len(result['suspicious_indicators']) >= 1:
            result['risk_level'] = 'low'
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def detect_file_steganography(file_path: str) -> Dict[str, Any]:
    """Detect steganography in various file types.
    
    Args:
        file_path: Path to file to analyze
        
    Returns:
        Dict containing analysis results
    """
    result = {
        'file_path': file_path,
        'suspicious_indicators': [],
        'analysis': {},
        'risk_level': 'low'
    }
    
    if not os.path.exists(file_path):
        result['error'] = 'File not found'
        return result
    
    try:
        # Check for appended data (common in executable steganography)
        append_analysis = _detect_appended_data(file_path)
        result['analysis']['appended_data'] = append_analysis
        
        if append_analysis.get('suspicious', False):
            result['suspicious_indicators'].append('Suspicious appended data detected')
        
        # Check for unusual string patterns
        string_analysis = _analyze_string_patterns(file_path)
        result['analysis']['strings'] = string_analysis
        
        if string_analysis.get('encoded_strings', 0) > 10:
            result['suspicious_indicators'].append('High number of encoded strings')
        
        # Analyze file structure anomalies
        structure_analysis = _analyze_file_structure(file_path)
        result['analysis']['structure'] = structure_analysis
        
        if structure_analysis.get('anomalies', 0) > 0:
            result['suspicious_indicators'].append('File structure anomalies detected')
        
        # Calculate risk level
        if len(result['suspicious_indicators']) >= 2:
            result['risk_level'] = 'high'
        elif len(result['suspicious_indicators']) >= 1:
            result['risk_level'] = 'medium'
        
    except Exception as e:
        result['error'] = str(e)
    
    return result


def _detect_image_type(file_path: str) -> Optional[str]:
    """Detect image file type from magic bytes."""
    try:
        with open(file_path, 'rb') as f:
            header = f.read(16)
        
        if header.startswith(b'\x89PNG\r\n\x1a\n'):
            return 'PNG'
        elif header.startswith(b'\xFF\xD8\xFF'):
            return 'JPEG'
        elif header.startswith(b'BM'):
            return 'BMP'
        elif header.startswith(b'GIF87a') or header.startswith(b'GIF89a'):
            return 'GIF'
        elif header.startswith(b'RIFF') and header[8:12] == b'WEBP':
            return 'WEBP'
        
    except Exception:
        pass
    
    return None


def _analyze_file_size(file_path: str) -> Dict[str, Any]:
    """Analyze if file size is suspicious for its type."""
    try:
        file_size = os.path.getsize(file_path)
        
        # Read some file content to estimate expected size
        with open(file_path, 'rb') as f:
            header = f.read(1024)
        
        # Basic heuristics for size analysis
        expected_ratio = 1.0
        
        # For images, check if size seems disproportionate
        image_type = _detect_image_type(file_path)
        if image_type:
            # Very basic estimation - real implementation would be more sophisticated
            if file_size > 10 * 1024 * 1024:  # > 10MB
                expected_ratio = 0.8  # Might be suspicious for typical images
        
        return {
            'file_size': file_size,
            'suspicious': file_size > expected_ratio * 5 * 1024 * 1024,
            'size_category': 'large' if file_size > 1024 * 1024 else 'normal'
        }
        
    except Exception as e:
        return {'error': str(e), 'suspicious': False}


def _analyze_lsb_patterns(file_path: str) -> Dict[str, Any]:
    """Analyze Least Significant Bit patterns in image data."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple LSB analysis - look for non-random patterns in LSBs
        lsb_bytes = []
        
        # Extract LSBs from what might be pixel data (skip headers)
        start_offset = min(1024, len(data) // 4)  # Skip likely header data
        
        for i in range(start_offset, min(start_offset + 10000, len(data))):
            lsb_bytes.append(data[i] & 1)
        
        if len(lsb_bytes) < 100:
            return {'suspicious': False, 'reason': 'Insufficient data'}
        
        # Calculate chi-square test for randomness
        ones = sum(lsb_bytes)
        zeros = len(lsb_bytes) - ones
        
        expected = len(lsb_bytes) / 2
        if expected > 0:
            chi_square = ((ones - expected) ** 2 + (zeros - expected) ** 2) / expected
        else:
            chi_square = 0
        
        # Simple threshold for suspicion
        suspicious = chi_square > 10.0
        
        return {
            'lsb_ones': ones,
            'lsb_zeros': zeros,
            'chi_square': chi_square,
            'suspicious': suspicious,
            'randomness_score': min(1.0, chi_square / 20.0)
        }
        
    except Exception as e:
        return {'error': str(e), 'suspicious': False}


def _analyze_metadata_anomalies(file_path: str) -> Dict[str, Any]:
    """Check for suspicious metadata patterns."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Look for suspicious patterns in metadata
        suspicious_patterns = [
            b'steghide',
            b'outguess',
            b'jsteg',
            b'f5stego',
            b'openstego'
        ]
        
        found_patterns = []
        for pattern in suspicious_patterns:
            if pattern in data:
                found_patterns.append(pattern.decode('ascii', errors='ignore'))
        
        # Look for unusual comment fields or metadata
        long_comments = []
        comment_patterns = [
            rb'comment[^\x00]{100,}',
            rb'description[^\x00]{100,}',
            rb'software[^\x00]{50,}'
        ]
        
        for pattern in comment_patterns:
            matches = re.findall(pattern, data, re.IGNORECASE)
            long_comments.extend(matches)
        
        return {
            'suspicious_tools': found_patterns,
            'long_comments': len(long_comments),
            'suspicious': len(found_patterns) > 0 or len(long_comments) > 2
        }
        
    except Exception as e:
        return {'error': str(e), 'suspicious': False}


def _analyze_pixel_entropy(file_path: str) -> Dict[str, Any]:
    """Analyze entropy in different regions of image data."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Simple entropy analysis on chunks of data
        chunk_size = 1024
        high_entropy_regions = 0
        total_chunks = 0
        
        for i in range(0, len(data) - chunk_size, chunk_size):
            chunk = data[i:i + chunk_size]
            entropy = _calculate_chunk_entropy(chunk)
            
            if entropy > 7.5:  # High entropy threshold
                high_entropy_regions += 1
            
            total_chunks += 1
        
        entropy_ratio = high_entropy_regions / total_chunks if total_chunks > 0 else 0
        
        return {
            'high_entropy_regions': high_entropy_regions,
            'total_regions': total_chunks,
            'entropy_ratio': entropy_ratio,
            'suspicious': entropy_ratio > 0.3  # >30% high entropy regions
        }
        
    except Exception as e:
        return {'error': str(e), 'high_entropy_regions': 0}


def _calculate_chunk_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a data chunk."""
    if not data:
        return 0.0
    
    # Count byte frequencies
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(data)
    
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * (p.bit_length() - 1)  # Approximation of log2
    
    return entropy


def _detect_appended_data(file_path: str) -> Dict[str, Any]:
    """Detect data appended to end of files."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check for known file format endings
        suspicious = False
        extra_data_size = 0
        
        # PNG files should end with IEND chunk
        if data.startswith(b'\x89PNG'):
            iend_pos = data.rfind(b'IEND')
            if iend_pos > 0 and iend_pos + 12 < len(data):
                extra_data_size = len(data) - (iend_pos + 12)
                suspicious = extra_data_size > 100
        
        # JPEG files should end with FFD9
        elif data.startswith(b'\xFF\xD8'):
            if not data.endswith(b'\xFF\xD9'):
                # Look for last FFD9 marker
                ffd9_pos = data.rfind(b'\xFF\xD9')
                if ffd9_pos > 0 and ffd9_pos + 2 < len(data):
                    extra_data_size = len(data) - (ffd9_pos + 2)
                    suspicious = extra_data_size > 10
        
        return {
            'extra_data_size': extra_data_size,
            'suspicious': suspicious,
            'format_compliant': not suspicious
        }
        
    except Exception as e:
        return {'error': str(e), 'suspicious': False}


def _analyze_string_patterns(file_path: str) -> Dict[str, Any]:
    """Analyze string patterns that might indicate hidden data."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Look for base64-like strings
        base64_pattern = rb'[A-Za-z0-9+/]{20,}={0,2}'
        base64_matches = re.findall(base64_pattern, data)
        
        # Look for hex-encoded strings
        hex_pattern = rb'[0-9A-Fa-f]{40,}'
        hex_matches = re.findall(hex_pattern, data)
        
        # Look for suspicious URLs or paths
        url_pattern = rb'https?://[^\s]{20,}'
        url_matches = re.findall(url_pattern, data)
        
        return {
            'base64_strings': len(base64_matches),
            'hex_strings': len(hex_matches),
            'urls': len(url_matches),
            'encoded_strings': len(base64_matches) + len(hex_matches)
        }
        
    except Exception as e:
        return {'error': str(e), 'encoded_strings': 0}


def _analyze_file_structure(file_path: str) -> Dict[str, Any]:
    """Analyze file structure for anomalies."""
    try:
        file_size = os.path.getsize(file_path)
        
        with open(file_path, 'rb') as f:
            header = f.read(1024)
            
            # Seek to middle and end to check structure
            f.seek(file_size // 2)
            middle = f.read(1024)
            
            f.seek(max(0, file_size - 1024))
            tail = f.read(1024)
        
        anomalies = 0
        
        # Check for null byte patterns (might indicate padding or hidden data)
        null_runs_header = _count_null_runs(header)
        null_runs_middle = _count_null_runs(middle)
        null_runs_tail = _count_null_runs(tail)
        
        if null_runs_tail > null_runs_header * 3:
            anomalies += 1  # Unusual null pattern at end
        
        # Check entropy differences between sections
        header_entropy = _calculate_chunk_entropy(header)
        tail_entropy = _calculate_chunk_entropy(tail)
        
        if abs(header_entropy - tail_entropy) > 3.0:
            anomalies += 1  # Significant entropy difference
        
        return {
            'anomalies': anomalies,
            'null_runs': {
                'header': null_runs_header,
                'middle': null_runs_middle,
                'tail': null_runs_tail
            },
            'entropy_difference': abs(header_entropy - tail_entropy)
        }
        
    except Exception as e:
        return {'error': str(e), 'anomalies': 0}


def _count_null_runs(data: bytes) -> int:
    """Count runs of null bytes in data."""
    null_runs = 0
    in_run = False
    
    for byte in data:
        if byte == 0:
            if not in_run:
                null_runs += 1
                in_run = True
        else:
            in_run = False
    
    return null_runs