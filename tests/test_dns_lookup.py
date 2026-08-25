import socket
from unittest.mock import patch
from sectoolkit.dns_lookup import resolve_hostname, reverse_lookup


def test_resolve_hostname_returns_addresses_on_success():
    fake_result = [(socket.AF_INET, None, None, "", ("93.184.216.34", 0))]

    with patch("socket.getaddrinfo", return_value=fake_result):
        result = resolve_hostname("example.com")

    assert result["hostname"] == "example.com"
    assert "93.184.216.34" in result["addresses"]
    assert "error" not in result


def test_resolve_hostname_deduplicates_addresses():
    fake_result = [
        (socket.AF_INET, None, None, "", ("93.184.216.34", 0)),
        (socket.AF_INET, None, None, "", ("93.184.216.34", 0)),  # duplicate, e.g. TCP + UDP entries
    ]

    with patch("socket.getaddrinfo", return_value=fake_result):
        result = resolve_hostname("example.com")

    assert result["addresses"] == ["93.184.216.34"]


def test_resolve_hostname_handles_nxdomain_gracefully():
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        result = resolve_hostname("does-not-exist.invalid")

    assert result["addresses"] == []
    assert "error" in result


def test_reverse_lookup_returns_hostname_on_success():
    with patch("socket.gethostbyaddr", return_value=("example.com", [], ["93.184.216.34"])):
        result = reverse_lookup("93.184.216.34")

    assert result["hostname"] == "example.com"


def test_reverse_lookup_handles_no_ptr_record_gracefully():
    with patch("socket.gethostbyaddr", side_effect=socket.herror("host not found")):
        result = reverse_lookup("192.0.2.1")

    assert result["hostname"] is None
    assert "error" in result
