"""Tests for sectoolkit.reporter module — JSON/CSV/HTML export and formatting."""

import csv
import json
import os
import tempfile

import pytest

from sectoolkit.reporter import (
    create_summary_report,
    export_csv,
    export_html,
    export_json,
    format_scan_result,
)


# ---------------------------------------------------------------------------
# export_json
# ---------------------------------------------------------------------------

def test_export_json_creates_file():
    """export_json writes a file that exists and contains valid JSON."""
    data = {"hostname": "example.com", "risk_level": "low", "open_ports": [80, 443]}

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        result = export_json(data, path)
        assert result is True
        assert os.path.exists(path)

        with open(path, "r", encoding="utf-8") as f:
            loaded = json.load(f)

        assert loaded == data
    finally:
        os.remove(path)


def test_export_json_utf8_content():
    """export_json handles unicode characters and round-trips correctly."""
    data = {
        "message": "Ünïcödé tëxt — café résumé naïve",
        "cjk": "中文字符",
        "emoji": "🔒🛡️",
    }

    fd, path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        result = export_json(data, path)
        assert result is True

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        loaded = json.loads(content)
        assert loaded["message"] == data["message"]
        assert loaded["cjk"] == data["cjk"]
        assert loaded["emoji"] == data["emoji"]
    finally:
        os.remove(path)


# ---------------------------------------------------------------------------
# export_csv
# ---------------------------------------------------------------------------

def test_export_csv_creates_file():
    """export_csv writes a CSV file whose headers match the dict keys."""
    rows = [
        {"ip": "192.168.1.1", "port": 22, "status": "open"},
        {"ip": "192.168.1.2", "port": 80, "status": "open"},
        {"ip": "192.168.1.3", "port": 443, "status": "closed"},
    ]

    fd, path = tempfile.mkstemp(suffix=".csv")
    os.close(fd)
    try:
        result = export_csv(rows, path)
        assert result is True
        assert os.path.exists(path)

        with open(path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            read_rows = list(reader)

        assert set(headers) == {"ip", "port", "status"}
        assert len(read_rows) == 3
        assert read_rows[0]["ip"] == "192.168.1.1"
    finally:
        os.remove(path)


# ---------------------------------------------------------------------------
# export_html
# ---------------------------------------------------------------------------

def test_export_html_creates_file():
    """export_html writes a file that contains <html> markup."""
    data = {"target": "example.com", "score": "85%", "issues": "none"}

    fd, path = tempfile.mkstemp(suffix=".html")
    os.close(fd)
    try:
        result = export_html(data, title="Security Report", filepath=path)
        assert result is True
        assert os.path.exists(path)

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        assert "<html" in content.lower()
        assert "Security Report" in content
    finally:
        os.remove(path)


# ---------------------------------------------------------------------------
# format_scan_result
# ---------------------------------------------------------------------------

def test_format_scan_result_text():
    """format_scan_result with default format_type='text' returns a string."""
    result = {"hostname": "example.com", "risk_level": "medium", "open_ports": [22, 80]}
    output = format_scan_result(result)
    assert isinstance(output, str)
    assert len(output) > 0


def test_format_scan_result_json():
    """format_scan_result with format_type='json' returns a valid JSON string."""
    result = {"hostname": "example.com", "risk_level": "high", "issues": ["no HTTPS"]}
    output = format_scan_result(result, format_type="json")
    assert isinstance(output, str)

    # Must be parseable JSON
    parsed = json.loads(output)
    assert parsed["hostname"] == "example.com"
    assert parsed["risk_level"] == "high"


# ---------------------------------------------------------------------------
# create_summary_report
# ---------------------------------------------------------------------------

def test_create_summary_report_structure():
    """create_summary_report returns a dict with the expected top-level keys."""
    results = [
        {"host": "a.com", "risk_level": "low"},
        {"host": "b.com", "risk_level": "medium"},
    ]
    report = create_summary_report(results, scan_type="vuln")

    expected_keys = {"scan_type", "total", "high_risk", "medium_risk", "low_risk", "timestamp"}
    assert expected_keys.issubset(set(report.keys()))
    assert report["scan_type"] == "vuln"
    assert report["total"] == 2


def test_create_summary_report_counts_high_risk():
    """create_summary_report correctly counts results with risk_level='high'."""
    results = [
        {"host": "a.com", "risk_level": "high"},
        {"host": "b.com", "risk_level": "high"},
        {"host": "c.com", "risk_level": "medium"},
        {"host": "d.com", "risk_level": "low"},
        {"host": "e.com"},  # no risk_level key
    ]
    report = create_summary_report(results, scan_type="port_scan")

    assert report["high_risk"] == 2
    assert report["medium_risk"] == 1
    assert report["low_risk"] == 1
    assert report["total"] == 5
