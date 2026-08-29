"""Tests for the password_audit module."""
import pytest
from sectoolkit.password_audit import (
    check_policy_compliance,
    audit_password_list,
    hash_password_sha256,
    detect_password_reuse,
    estimate_password_entropy,
    export_audit_report,
)
import tempfile
import os
import json
import csv


class TestCheckPolicyCompliance:

    def test_strong_password_compliant(self):
        """A strong password should pass all default policy checks."""
        result = check_policy_compliance("Tr0ub4dor&3")
        assert result["compliant"] is True
        assert result["violations"] == []

    def test_too_short_fails(self):
        """Password shorter than min_length should be non-compliant."""
        result = check_policy_compliance("Ab1!")
        assert result["compliant"] is False
        assert any("Too short" in v for v in result["violations"])

    def test_missing_uppercase_fails(self):
        result = check_policy_compliance("password1!")
        assert any("uppercase" in v for v in result["violations"])

    def test_missing_lowercase_fails(self):
        result = check_policy_compliance("PASSWORD1!")
        assert any("lowercase" in v for v in result["violations"])

    def test_missing_digit_fails(self):
        result = check_policy_compliance("Password!!")
        assert any("digit" in v for v in result["violations"])

    def test_missing_symbol_fails(self):
        result = check_policy_compliance("Password123")
        assert any("symbol" in v for v in result["violations"])

    def test_common_password_fails(self):
        """'password' is in the common list and should be flagged."""
        result = check_policy_compliance("password")
        assert any("common" in v.lower() for v in result["violations"])

    def test_repeated_chars_detected(self):
        """'aaaa' has 4 consecutive identical chars; default max is 3, so it should fail.
        
        BUG EXPOSURE: the regex uses > instead of >=, so 'aaaa' (4 repeats) triggers
        only when there are MORE THAN max_rep repetitions, meaning exactly 3 consecutive
        passes when it shouldn't.
        """
        # 'aaaa' = 4 identical chars in a row — should violate max_repeated_chars=3
        result = check_policy_compliance("Aaaa1!LongEnough")
        assert any("repeated" in v.lower() for v in result["violations"]), (
            "Expected repeated-char violation for 'aaaa' with max=3"
        )

    def test_score_is_100_for_compliant(self):
        result = check_policy_compliance("Tr0ub4dor&3")
        assert result["score"] == 100

    def test_score_decreases_with_violations(self):
        result = check_policy_compliance("password")  # multiple violations
        assert result["score"] < 100

    def test_custom_policy_no_symbols(self):
        """Custom policy with require_symbols=False should accept symbol-free passwords."""
        policy = {**{"min_length": 8, "require_uppercase": True,
                     "require_lowercase": True, "require_digits": True,
                     "require_symbols": False, "disallow_common": True}}
        result = check_policy_compliance("SecurePass1", policy)
        assert result["compliant"] is True

    def test_password_hint_not_in_result(self):
        """check_policy_compliance does not expose the full password."""
        result = check_policy_compliance("supersecret1A!")
        assert "supersecret1A!" not in str(result)


class TestAuditPasswordList:

    def test_empty_list(self):
        result = audit_password_list([])
        assert result["total"] == 0
        assert result["compliance_rate"] == 0.0

    def test_all_compliant(self):
        passwords = ["Tr0ub4dor&3", "C0mpl3x!Pass", "Str0ng@Word1"]
        result = audit_password_list(passwords)
        assert result["compliant"] == 3
        assert result["compliance_rate"] == 100.0

    def test_all_non_compliant(self):
        passwords = ["password", "123456", "abc"]
        result = audit_password_list(passwords)
        assert result["non_compliant"] == 3

    def test_mixed_list(self):
        passwords = ["Tr0ub4dor&3", "password"]
        result = audit_password_list(passwords)
        assert result["compliant"] == 1
        assert result["non_compliant"] == 1
        assert result["compliance_rate"] == 50.0

    def test_password_hint_masks_password(self):
        result = audit_password_list(["SecretPass1!"])
        hint = result["results"][0]["password_hint"]
        assert "SecretPass1!" not in hint
        assert hint.startswith("Se")


class TestHashPasswordSha256:

    def test_deterministic(self):
        h1 = hash_password_sha256("hello")
        h2 = hash_password_sha256("hello")
        assert h1 == h2

    def test_salt_changes_hash(self):
        h1 = hash_password_sha256("hello", salt="abc")
        h2 = hash_password_sha256("hello", salt="xyz")
        assert h1 != h2

    def test_returns_64_hex_chars(self):
        h = hash_password_sha256("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


class TestDetectPasswordReuse:

    def test_no_duplicates(self):
        hashes = ["aaa", "bbb", "ccc"]
        result = detect_password_reuse(hashes)
        assert result["duplicate_hashes"] == 0
        assert result["reuse_rate"] == 0.0

    def test_with_duplicates(self):
        hashes = ["aaa", "aaa", "bbb"]
        result = detect_password_reuse(hashes)
        assert result["duplicate_hashes"] == 1
        assert result["reuse_rate"] > 0

    def test_empty_list(self):
        result = detect_password_reuse([])
        assert result["total"] == 0
        assert result["reuse_rate"] == 0.0


class TestEstimatePasswordEntropy:

    def test_all_lowercase_entropy(self):
        result = estimate_password_entropy("abcdefgh")
        assert result["charset_size"] == 26
        assert result["entropy_bits"] > 0

    def test_mixed_charset_higher_entropy(self):
        r1 = estimate_password_entropy("abcdefgh")
        r2 = estimate_password_entropy("Abcdef1!")
        assert r2["entropy_bits"] > r1["entropy_bits"]

    def test_strength_labels(self):
        result = estimate_password_entropy("Tr0ub4dor&3Secure!")
        assert result["strength"] in ("strong", "moderate", "weak", "very weak")

    def test_empty_password(self):
        result = estimate_password_entropy("")
        assert result["entropy_bits"] == 0.0


class TestExportAuditReport:

    def test_export_json(self):
        data = {"total": 1, "compliant": 1, "results": [{"password_hint": "ab***"}]}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            path = f.name
        try:
            ok = export_audit_report(data, path, fmt="json")
            assert ok is True
            with open(path, encoding="utf-8") as fh:
                loaded = json.load(fh)
            assert loaded["total"] == 1
        finally:
            os.unlink(path)

    def test_export_csv(self):
        data = {"results": [{"password_hint": "ab***", "compliant": True, "score": 100}]}
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv", mode="w") as f:
            path = f.name
        try:
            ok = export_audit_report(data, path, fmt="csv")
            assert ok is True
            with open(path, encoding="utf-8") as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
            assert rows[0]["password_hint"] == "ab***"
        finally:
            os.unlink(path)

    def test_unknown_format_returns_false(self):
        ok = export_audit_report({}, "irrelevant.xyz", fmt="xml")
        assert ok is False
