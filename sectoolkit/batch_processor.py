"""Batch processing utilities for multiple file operations.

Processes multiple files in parallel for various security analysis tasks.
"""
import os
import json
import asyncio
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import time


class BatchProcessor:
    """Handle batch processing of multiple files for security analysis."""
    
    def __init__(self, max_workers: int = 10):
        """Initialize batch processor.
        
        Args:
            max_workers: Maximum number of concurrent workers
        """
        self.max_workers = max_workers
        self.results = []
        
    def process_files(self, file_paths: List[str], 
                     operation: Callable[[str], Dict[str, Any]],
                     progress_callback: Optional[Callable] = None) -> List[Dict[str, Any]]:
        """Process multiple files with the given operation.
        
        Args:
            file_paths: List of file paths to process
            operation: Function to apply to each file
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of results from processing each file
        """
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(self._safe_operation, file_path, operation): file_path
                for file_path in file_paths
            }
            
            # Collect results as they complete
            for i, future in enumerate(concurrent.futures.as_completed(future_to_file)):
                file_path = future_to_file[future]
                try:
                    result = future.result()
                    result['file_path'] = file_path
                    results.append(result)
                    
                    if progress_callback:
                        progress_callback(i + 1, len(file_paths), file_path)
                        
                except Exception as exc:
                    error_result = {
                        'file_path': file_path,
                        'error': str(exc),
                        'success': False
                    }
                    results.append(error_result)
                    
        return results
    
    def _safe_operation(self, file_path: str, operation: Callable) -> Dict[str, Any]:
        """Safely execute operation on file with error handling."""
        try:
            result = operation(file_path)
            result['success'] = True
            result['timestamp'] = time.time()
            return result
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def scan_directory(self, directory: str, pattern: str = "*", 
                      recursive: bool = True) -> List[str]:
        """Scan directory for files matching pattern.
        
        Args:
            directory: Directory to scan
            pattern: File pattern (glob style)
            recursive: Whether to scan subdirectories
            
        Returns:
            List of matching file paths
        """
        path = Path(directory)
        
        if recursive:
            files = list(path.rglob(pattern))
        else:
            files = list(path.glob(pattern))
            
        return [str(f) for f in files if f.is_file()]
    
    def export_results(self, results: List[Dict[str, Any]], 
                      output_path: str, format: str = "json") -> bool:
        """Export batch processing results to file.
        
        Args:
            results: Results to export
            output_path: Output file path
            format: Export format (json, csv)
            
        Returns:
            True if export successful, False otherwise
        """
        try:
            if format.lower() == "json":
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, default=str)
            elif format.lower() == "csv":
                import csv
                if results:
                    fieldnames = set()
                    for result in results:
                        fieldnames.update(result.keys())
                    
                    with open(output_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=list(fieldnames))
                        writer.writeheader()
                        for result in results:
                            # Flatten nested dicts for CSV
                            flat_result = self._flatten_dict(result)
                            writer.writerow(flat_result)
            else:
                return False
                
            return True
        except Exception:
            return False
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', 
                     sep: str = '_') -> Dict[str, Any]:
        """Flatten nested dictionary for CSV export."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                items.append((new_key, str(v)))
            else:
                items.append((new_key, v))
        return dict(items)


def hash_batch_operation(file_path: str) -> Dict[str, Any]:
    """Batch operation: compute hashes for a file."""
    from sectoolkit.hashing import hash_file_all
    
    try:
        hashes = hash_file_all(file_path)
        return {
            'operation': 'hash',
            'hashes': hashes,
            'file_size': os.path.getsize(file_path)
        }
    except Exception as e:
        raise Exception(f"Hash computation failed: {e}")


def analyze_batch_operation(file_path: str) -> Dict[str, Any]:
    """Batch operation: full analysis for a file."""
    from sectoolkit.analyze import analyze_file
    
    try:
        results = analyze_file(file_path)
        return {
            'operation': 'analyze',
            'analysis_results': results,
            'file_size': os.path.getsize(file_path)
        }
    except Exception as e:
        raise Exception(f"Analysis failed: {e}")


def entropy_batch_operation(file_path: str) -> Dict[str, Any]:
    """Batch operation: entropy calculation for a file."""
    from sectoolkit.entropy import calculate_file_entropy, interpret_entropy
    
    try:
        entropy = calculate_file_entropy(file_path)
        interpretation = interpret_entropy(entropy)
        
        return {
            'operation': 'entropy',
            'entropy': entropy,
            'interpretation': interpretation,
            'file_size': os.path.getsize(file_path)
        }
    except Exception as e:
        raise Exception(f"Entropy calculation failed: {e}")


def create_batch_report(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Create summary report from batch processing results."""
    total_files = len(results)
    successful = len([r for r in results if r.get('success', False)])
    failed = total_files - successful
    
    # Collect statistics
    operations = {}
    total_size = 0
    
    for result in results:
        if result.get('success', False):
            op = result.get('operation', 'unknown')
            operations[op] = operations.get(op, 0) + 1
            total_size += result.get('file_size', 0)
    
    return {
        'summary': {
            'total_files': total_files,
            'successful': successful,
            'failed': failed,
            'success_rate': (successful / total_files * 100) if total_files > 0 else 0,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
        },
        'operations': operations,
        'timestamp': time.time()
    }