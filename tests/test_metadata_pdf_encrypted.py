from pypdf import PdfWriter
from sectoolkit.metadata_pdf import extract_pdf_metadata


def test_encrypted_pdf_does_not_crash(tmp_path):
    encrypted_path = tmp_path / "encrypted.pdf"
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.encrypt("some-password")
    with open(encrypted_path, "wb") as f:
        writer.write(f)

    # Should not raise — should report something sensible instead.
    result = extract_pdf_metadata(str(encrypted_path))

    assert result.get("is_encrypted") is True
