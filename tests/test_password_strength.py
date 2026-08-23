from sectoolkit.password_strength import check_strength, estimate_entropy_bits


def test_common_password_is_rated_very_weak():
    result = check_strength("123456")
    assert result["rating"] == "very weak"
    assert "matches an extremely common password" in result["issues"]


def test_short_password_flagged():
    result = check_strength("aB1!")
    assert "shorter than 8 characters" in result["issues"]


def test_strong_random_password_has_no_issues():
    result = check_strength("kR9$mZ2p!vB7xL")
    assert result["rating"] == "strong"
    assert result["issues"] == []


def test_detects_sequential_run():
    result = check_strength("abcd5678")
    assert any("sequential run" in issue for issue in result["issues"])


def test_detects_keyboard_walk():
    result = check_strength("qwertyui")
    assert any("keyboard-adjacent" in issue for issue in result["issues"])


def test_detects_low_character_variety():
    result = check_strength("aaaaaaaa")
    assert any("low character variety" in issue for issue in result["issues"])


def test_missing_character_classes_are_each_flagged():
    result = check_strength("alllowercase")
    assert "no uppercase letters" in result["issues"]
    assert "no digits" in result["issues"]
    assert "no special characters" in result["issues"]


def test_entropy_increases_with_character_pool_diversity():
    lowercase_only = estimate_entropy_bits("abcdefgh")
    mixed_pool = estimate_entropy_bits("aB3!fG7@")

    assert mixed_pool > lowercase_only


def test_entropy_of_empty_password_is_zero():
    assert estimate_entropy_bits("") == 0.0


def test_rating_is_always_one_of_the_defined_levels():
    for pw in ["", "a", "password", "Str0ng3r!Pass", "kR9$mZ2p!vB7xL9#qT"]:
        result = check_strength(pw)
        assert result["rating"] in ("very weak", "weak", "moderate", "strong")
