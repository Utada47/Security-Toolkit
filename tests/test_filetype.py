from sectoolkit.filetype import detect_file_type, extension_mismatch


def test_detects_pe_executable_by_magic_bytes(tmp_path):
    fake = tmp_path / "fake.jpg"
    fake.write_bytes(b"MZ" + b"\x00" * 100)

    assert "PE executable" in detect_file_type(str(fake))


def test_detects_real_png(tmp_path):
    real = tmp_path / "real.png"
    real.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

    assert detect_file_type(str(real)) == "PNG image"


def test_detects_real_pdf(tmp_path):
    real = tmp_path / "real.pdf"
    real.write_bytes(b"%PDF-1.7\n" + b"\x00" * 20)

    assert detect_file_type(str(real)) == "PDF document"


def test_detects_zip_based_formats(tmp_path):
    docx = tmp_path / "document.docx"
    docx.write_bytes(b"PK\x03\x04" + b"\x00" * 20)

    assert "ZIP" in detect_file_type(str(docx))


def test_plain_text_detection(tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("just some plain ascii text")

    assert detect_file_type(str(text_file)) == "Plain text (or empty file)"


def test_extension_mismatch_flags_disguised_executable(tmp_path):
    fake = tmp_path / "photo.jpg"
    fake.write_bytes(b"MZ" + b"\x00" * 100)

    result = extension_mismatch(str(fake))

    assert result["suspicious"] is True
    assert result["extension"] == ".jpg"


def test_extension_mismatch_passes_for_genuine_file(tmp_path):
    real = tmp_path / "photo.png"
    real.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

    result = extension_mismatch(str(real))

    assert result["suspicious"] is False


def test_extension_mismatch_with_no_extension_is_not_flagged(tmp_path):
    real = tmp_path / "README"
    real.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 50)

    result = extension_mismatch(str(real))

    assert result["suspicious"] is False
    assert result["extension"] == "(none)"
