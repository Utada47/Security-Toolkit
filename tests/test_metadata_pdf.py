from pypdf import PdfWriter
from sectoolkit.metadata_pdf import extract_pdf_metadata


def _make_test_pdf(path, metadata=None, pages=1):
    writer = PdfWriter()
    for _ in range(pages):
        writer.add_blank_page(width=200, height=200)
    if metadata:
        writer.add_metadata(metadata)
    with open(path, "wb") as f:
        writer.write(f)


def test_extracts_author_and_producer(tmp_path):
    pdf_path = tmp_path / "doc.pdf"
    _make_test_pdf(str(pdf_path), metadata={"/Author": "Jane Doe", "/Producer": "Microsoft Word"})

    result = extract_pdf_metadata(str(pdf_path))

    assert result["Author"] == "Jane Doe"
    assert result["Producer"] == "Microsoft Word"


def test_reports_correct_page_count(tmp_path):
    pdf_path = tmp_path / "doc.pdf"
    _make_test_pdf(str(pdf_path), pages=3)

    result = extract_pdf_metadata(str(pdf_path))

    assert result["page_count"] == 3


def test_unencrypted_pdf_reports_is_encrypted_false(tmp_path):
    pdf_path = tmp_path / "doc.pdf"
    _make_test_pdf(str(pdf_path))

    result = extract_pdf_metadata(str(pdf_path))

    assert result["is_encrypted"] is False


def test_non_pdf_file_returns_empty_dict_instead_of_crashing(tmp_path):
    fake_pdf = tmp_path / "notreally.pdf"
    fake_pdf.write_text("this is not a pdf at all")

    result = extract_pdf_metadata(str(fake_pdf))

    assert result == {}
