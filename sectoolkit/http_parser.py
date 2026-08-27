"""Utility to parse and analyze HTTP responses from raw socket data."""
import re
from typing import Dict, Any

STATUS_LINE_RE = re.compile(r"^(HTTP/\d\.\d) (\d{3}) (.*)$", re.MULTILINE)
HEADER_RE = re.compile(r"^(.*?):\s*(.*)$", re.MULTILINE)


def parse_http_response(raw: str) -> Dict[str, Any]:
    """Parse raw HTTP response string into status line, headers, body."""
    parts = raw.split('\r\n\r\n', 1)
    header_part = parts[0]
    body = parts[1] if len(parts) > 1 else ""
    lines = header_part.split('\r\n')
    status_match = STATUS_LINE_RE.match(lines[0])
    result = {"status": None, "code": None, "reason": None, "headers": {}, "body": body}
    if status_match:
        result["status"] = status_match.group(1)
        result["code"] = int(status_match.group(2))
        result["reason"] = status_match.group(3)
    for line in lines[1:]:
        m = HEADER_RE.match(line)
        if m:
            result["headers"][m.group(1).strip()] = m.group(2).strip()
    return result
