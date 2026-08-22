import zipfile
from unittest.mock import patch, MagicMock
from sectoolkit.macros import detect_macros


def _make_plain_docx(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", "<xml>no macros here</xml>")
        z.writestr("[Content_Types].xml", "<Types/>")


def test_detects_no_macros_in_plain_document(tmp_path):
    docx_path = tmp_path / "plain.docx"
    _make_plain_docx(str(docx_path))

    result = detect_macros(str(docx_path))

    assert result["has_macros"] is False
    assert result["macro_count"] == 0


def test_non_office_file_reports_error_instead_of_crashing(tmp_path):
    not_office = tmp_path / "notes.txt"
    not_office.write_text("just plain text, not an office document")

    result = detect_macros(str(not_office))

    assert result["has_macros"] is False
    assert "error" in result


def test_detects_macros_when_present(tmp_path):
    # Building a real macro-laden Office file is impractical (and some
    # environments/AV tools flag such samples even when harmless test
    # fixtures). We mock VBA_Parser here to verify OUR aggregation logic
    # (counting macros, collecting names) is correct, given a parser that
    # reports macros were found. The file just needs a valid zip signature
    # to pass our own pre-check before VBA_Parser is (mock-)invoked.
    docx_path = tmp_path / "placeholder.docm"
    docx_path.write_bytes(b"PK\x03\x04" + b"\x00" * 20)

    mock_parser = MagicMock()
    mock_parser.detect_vba_macros.return_value = True
    mock_parser.extract_macros.return_value = [
        (None, None, "ThisDocument", "Sub AutoOpen()\nEnd Sub"),
        (None, None, "Module1", "Sub Foo()\nEnd Sub"),
    ]

    with patch("sectoolkit.macros.VBA_Parser", return_value=mock_parser):
        result = detect_macros(str(docx_path))

    assert result["has_macros"] is True
    assert result["macro_count"] == 2
    assert "ThisDocument" in result["macro_names"]
    assert "Module1" in result["macro_names"]


def test_parser_is_always_closed_even_on_error(tmp_path):
    docx_path = tmp_path / "placeholder.docm"
    docx_path.write_bytes(b"PK\x03\x04" + b"\x00" * 20)

    mock_parser = MagicMock()
    mock_parser.detect_vba_macros.side_effect = RuntimeError("simulated parser failure")

    with patch("sectoolkit.macros.VBA_Parser", return_value=mock_parser):
        try:
            detect_macros(str(docx_path))
        except RuntimeError:
            pass

    mock_parser.close.assert_called_once()


def test_plain_text_file_is_never_treated_as_containing_macros(tmp_path):
    # Regression test: VBA_Parser has a fallback mode that treats
    # unrecognized files as raw VBA source text, which previously caused
    # plain .txt files to be misreported as having macros. Our own
    # signature pre-check must prevent that.
    not_office = tmp_path / "notes.txt"
    not_office.write_text("Sub AutoOpen()\nEnd Sub\n")  # even VBA-looking text!

    result = detect_macros(str(not_office))

    assert result["has_macros"] is False
