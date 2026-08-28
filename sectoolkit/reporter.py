"""Reporting and export utilities for security scan results.

Supports exporting results to JSON, CSV, and HTML formats, as well as
formatting individual scan results for display.
"""

import csv
import json
import io
from datetime import datetime, timezone
from typing import Dict, List


def export_json(data: Dict, filepath: str) -> bool:
    """Export a data dict to a JSON file.

    Args:
        data: Dictionary of scan results to export.
        filepath: Path to the output JSON file.

    Returns:
        True on success, False on failure.

    Note:
        BUG: File is opened without explicit encoding, which can cause
        UnicodeEncodeError on Windows when data contains non-ASCII characters.
        Should use open(filepath, 'w', encoding='utf-8').
    """
    try:
        content = json.dumps(data, indent=2, default=str)
        with open(filepath, 'w') as f:  # BUG: missing encoding='utf-8'
            f.write(content)
        return True
    except Exception:
        return False


def export_csv(rows: List[Dict], filepath: str) -> bool:
    """Export a list of dicts as a CSV file.

    Args:
        rows: List of dictionaries representing rows.
        filepath: Path to the output CSV file.

    Returns:
        True on success, False on failure.

    Note:
        BUG: Uses csv.writer instead of csv.DictWriter, so header row and
        data rows may not align if keys appear in different orders.
        Should use csv.DictWriter with fieldnames=rows[0].keys().
    """
    if not rows:
        return False
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)  # BUG: should be csv.DictWriter
            # Write header from first row's keys
            headers = list(rows[0].keys())
            writer.writerow(headers)
            # Write data rows — values may not match header order for all dicts
            for row in rows:
                writer.writerow(list(row.values()))
        return True
    except Exception:
        return False


def export_html(
    data: Dict,
    title: str = 'Security Report',
    filepath: str = 'report.html',
) -> bool:
    """Generate a simple HTML report file from a data dict.

    Args:
        data: Dictionary of scan results to render as a table.
        title: Title shown in the HTML page heading.
        filepath: Path to the output HTML file.

    Returns:
        True on success, False on failure.
    """
    try:
        rows_html = ''
        for key, value in data.items():
            safe_key = str(key).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            safe_val = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            rows_html += f'        <tr><td>{safe_key}</td><td>{safe_val}</td></tr>\n'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2em; background: #f9f9f9; color: #222; }}
    h1 {{ color: #333; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 900px; background: #fff; }}
    th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
    th {{ background: #333; color: #fff; }}
    tr:nth-child(even) {{ background: #f2f2f2; }}
    .timestamp {{ color: #666; font-size: 0.9em; margin-bottom: 1em; }}
  </style>
</head>
<body>
  <h1>{title}</h1>
  <p class="timestamp">Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
  <table>
    <thead>
      <tr><th>Field</th><th>Value</th></tr>
    </thead>
    <tbody>
{rows_html}    </tbody>
  </table>
</body>
</html>
"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        return True
    except Exception:
        return False


def format_scan_result(result: Dict, format_type: str = 'text') -> str:
    """Format a single scan result dict for display.

    Args:
        result: Dictionary containing scan result data.
        format_type: Output format — 'text', 'json', or 'minimal'.

    Returns:
        Formatted string representation of the result.
    """
    if format_type == 'json':
        return json.dumps(result, indent=2, default=str)

    if format_type == 'minimal':
        # One-liner: key=value pairs separated by spaces
        parts = []
        for key, value in result.items():
            parts.append(f'{key}={value}')
        return ' '.join(parts)

    # Default: 'text' — human-readable multi-line
    lines = []
    for key, value in result.items():
        if isinstance(value, list):
            lines.append(f'{key}:')
            for item in value:
                lines.append(f'  - {item}')
        elif isinstance(value, dict):
            lines.append(f'{key}:')
            for k, v in value.items():
                lines.append(f'  {k}: {v}')
        else:
            lines.append(f'{key}: {value}')
    return '\n'.join(lines)


def create_summary_report(results: List[Dict], scan_type: str = 'general') -> Dict:
    """Create a summary dictionary from a list of scan results.

    Each result dict is expected to optionally contain a 'risk_level' key
    with values 'high', 'medium', or 'low'.

    Args:
        results: List of scan result dicts.
        scan_type: Label describing the type of scan performed.

    Returns:
        Summary dict with keys:
          scan_type, total, high_risk, medium_risk, low_risk, timestamp.
    """
    high_risk = 0
    medium_risk = 0
    low_risk = 0

    for result in results:
        level = str(result.get('risk_level', '')).lower()
        if level == 'high':
            high_risk += 1
        elif level == 'medium':
            medium_risk += 1
        elif level == 'low':
            low_risk += 1

    return {
        'scan_type': scan_type,
        'total': len(results),
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
