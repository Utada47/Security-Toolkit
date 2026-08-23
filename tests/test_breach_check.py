import hashlib
from io import BytesIO
from unittest.mock import patch, MagicMock
from sectoolkit.breach_check import check_password_breach


def _fake_response(body: str):
    """Build a mock object that behaves like the context manager returned
    by urllib.request.urlopen(), so we never make a real network call.
    """
    mock_resp = MagicMock()
    mock_resp.read.return_value = body.encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    return mock_resp


def test_detects_breached_password():
    password = "password"
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    suffix = sha1[5:]

    # Simulate the API returning our suffix (with a plausible seen-count)
    # alongside some unrelated suffixes, exactly like the real API would.
    fake_body = f"AAAA1111AAAA1111AAAA1111AAAA1111AAAA:5\n{suffix}:9999999\nBBBB2222BBBB2222BBBB2222BBBB2222BBBB:2"

    with patch("urllib.request.urlopen", return_value=_fake_response(fake_body)):
        result = check_password_breach(password)

    assert result["breached"] is True
    assert result["times_seen"] == 9999999


def test_reports_not_breached_when_suffix_absent():
    fake_body = "AAAA1111AAAA1111AAAA1111AAAA1111AAAA:5\nBBBB2222BBBB2222BBBB2222BBBB2222BBBB:2"

    with patch("urllib.request.urlopen", return_value=_fake_response(fake_body)):
        result = check_password_breach("some-unique-password-not-in-list")

    assert result["breached"] is False
    assert result["times_seen"] == 0


def test_sends_only_hash_prefix_never_the_full_password():
    """The whole point of k-anonymity: verify the request URL only ever
    contains a 5-character hash prefix, never the password or full hash.
    """
    captured_urls = []

    def fake_urlopen(url, timeout=None):
        captured_urls.append(url)
        return _fake_response("AAAA:1")

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        check_password_breach("my-actual-real-password")

    assert len(captured_urls) == 1
    assert "my-actual-real-password" not in captured_urls[0]
    # URL should end in exactly a 5-char hex prefix
    prefix = captured_urls[0].rsplit("/", 1)[-1]
    assert len(prefix) == 5


def test_network_error_raises_runtime_error_not_silent_failure():
    import urllib.error

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("no connection")):
        try:
            check_password_breach("anything")
            assert False, "should have raised RuntimeError"
        except RuntimeError as exc:
            assert "Have I Been Pwned" in str(exc)
