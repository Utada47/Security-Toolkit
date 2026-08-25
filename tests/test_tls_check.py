import ssl
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from sectoolkit.tls_check import get_certificate_info


def _make_fake_cert(days_until_expiry=30):
    not_after = datetime.now(timezone.utc) + timedelta(days=days_until_expiry)
    not_before = datetime.now(timezone.utc) - timedelta(days=30)

    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": ((("organizationName", "Test CA"),),),
        "notBefore": not_before.strftime("%b %d %H:%M:%S %Y GMT"),
        "notAfter": not_after.strftime("%b %d %H:%M:%S %Y GMT"),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }


def _mock_connection(cert):
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = cert
    mock_ssock.__enter__.return_value = mock_ssock
    mock_ssock.__exit__.return_value = False

    mock_context = MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock

    mock_sock = MagicMock()
    mock_sock.__enter__.return_value = mock_sock
    mock_sock.__exit__.return_value = False

    return mock_context, mock_sock


def test_extracts_certificate_details():
    cert = _make_fake_cert(days_until_expiry=60)
    mock_context, mock_sock = _mock_connection(cert)

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = get_certificate_info("example.com")

    assert result["subject_common_name"] == "example.com"
    assert result["issuer"] == "Test CA"
    assert "www.example.com" in result["subject_alt_names"]


def test_detects_non_expired_certificate():
    cert = _make_fake_cert(days_until_expiry=60)
    mock_context, mock_sock = _mock_connection(cert)

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = get_certificate_info("example.com")

    assert result["is_expired"] is False
    assert result["days_until_expiry"] > 0


def test_detects_expired_certificate():
    cert = _make_fake_cert(days_until_expiry=-10)  # expired 10 days ago
    mock_context, mock_sock = _mock_connection(cert)

    with patch("ssl.create_default_context", return_value=mock_context), \
         patch("socket.create_connection", return_value=mock_sock):
        result = get_certificate_info("example.com")

    assert result["is_expired"] is True


def test_connection_failure_returns_error_instead_of_raising():
    with patch("socket.create_connection", side_effect=OSError("Connection refused")):
        result = get_certificate_info("unreachable.invalid")

    assert "error" in result
    assert result["hostname"] == "unreachable.invalid"


def test_ssl_error_returns_error_instead_of_raising():
    with patch("socket.create_connection", side_effect=ssl.SSLError("certificate verify failed")):
        result = get_certificate_info("badcert.invalid")

    assert "error" in result
