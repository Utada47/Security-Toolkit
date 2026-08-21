import os
from sectoolkit.entropy import calculate_entropy, calculate_file_entropy, interpret_entropy


def test_entropy_of_uniform_data_is_zero():
    assert calculate_entropy(b"\x00" * 1000) == 0.0


def test_entropy_of_uniform_nonzero_byte_is_zero():
    assert calculate_entropy(b"A" * 500) == 0.0


def test_entropy_of_empty_data_is_zero():
    assert calculate_entropy(b"") == 0.0


def test_entropy_of_random_data_is_high():
    random_data = os.urandom(50_000)
    entropy = calculate_entropy(random_data)
    assert entropy > 7.9  # true random byte data should be very close to 8.0


def test_entropy_of_two_alternating_bytes_is_exactly_one():
    # Exactly two equally-likely symbols -> entropy of exactly 1.0 bit
    data = (b"\x00\x01") * 1000
    assert abs(calculate_entropy(data) - 1.0) < 1e-9


def test_entropy_is_between_zero_and_eight_for_arbitrary_data():
    data = b"the quick brown fox jumps over the lazy dog" * 50
    entropy = calculate_entropy(data)
    assert 0.0 <= entropy <= 8.0


def test_calculate_file_entropy_matches_calculate_entropy(tmp_path):
    data = os.urandom(1000)
    file_path = tmp_path / "random.bin"
    file_path.write_bytes(data)

    assert calculate_file_entropy(str(file_path)) == calculate_entropy(data)


def test_interpret_entropy_labels():
    assert "repetitive" in interpret_entropy(0.0)
    assert "high" in interpret_entropy(7.9)
    assert "moderate" in interpret_entropy(6.0)
