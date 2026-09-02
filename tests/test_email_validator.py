from sectoolkit.email_validator import validate_email


def test_valid_email_passes():
    result = validate_email("user@example.com")
    assert result["is_valid"] is True


def test_missing_at_symbol_is_invalid():
    result = validate_email("userexample.com")
    assert result["is_valid"] is False
    assert "@" in result["reason"]


def test_missing_domain_extension_is_invalid():
    result = validate_email("user@example")
    assert result["is_valid"] is False


def test_empty_string_is_invalid():
    result = validate_email("")
    assert result["is_valid"] is False
