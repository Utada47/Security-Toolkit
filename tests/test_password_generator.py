import string
from sectoolkit.password_generator import generate_password


def test_generated_password_has_requested_length():
    pw = generate_password(20)
    assert len(pw) == 20


def test_generated_password_includes_all_enabled_classes_by_default():
    pw = generate_password(16)
    assert any(c in string.ascii_lowercase for c in pw)
    assert any(c in string.ascii_uppercase for c in pw)
    assert any(c in string.digits for c in pw)
    assert any(c in "!@#$%^&*()-_=+[]{}" for c in pw)


def test_disabling_a_class_excludes_it():
    pw = generate_password(20, use_symbols=False, use_digits=False)
    assert not any(c in "!@#$%^&*()-_=+[]{}" for c in pw)
    assert not any(c in string.digits for c in pw)


def test_two_generated_passwords_are_different():
    # Astronomically unlikely to collide if randomness is working correctly.
    pw1 = generate_password(16)
    pw2 = generate_password(16)
    assert pw1 != pw2


def test_rejects_zero_or_negative_length():
    for bad_length in (0, -5):
        try:
            generate_password(bad_length)
            assert False, f"should have raised ValueError for length={bad_length}"
        except ValueError:
            pass


def test_rejects_when_all_classes_disabled():
    try:
        generate_password(10, use_lowercase=False, use_uppercase=False, use_digits=False, use_symbols=False)
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_rejects_length_too_short_for_required_classes():
    # All 4 classes enabled needs at least 4 characters to guarantee one of each.
    try:
        generate_password(2, use_lowercase=True, use_uppercase=True, use_digits=True, use_symbols=True)
        assert False, "should have raised ValueError"
    except ValueError:
        pass


def test_single_class_password_only_uses_that_class():
    pw = generate_password(20, use_uppercase=False, use_digits=False, use_symbols=False)
    assert all(c in string.ascii_lowercase for c in pw)


def test_generated_passwords_score_strong_against_our_own_checker():
    from sectoolkit.password_strength import check_strength

    for _ in range(10):
        pw = generate_password(16)
        result = check_strength(pw)
        assert result["rating"] == "strong"
