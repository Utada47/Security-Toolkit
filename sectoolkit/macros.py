"""Detect VBA macros in Microsoft Office documents.

Macro-enabled Office documents are one of the most common phishing/malware
delivery mechanisms ("enable content to view this invoice"). This module
flags whether a document contains macros at all — a strong signal to treat
the file with extra caution, especially if it arrived unexpectedly.
"""
from oletools.olevba import VBA_Parser


def _is_office_file(path: str) -> bool:
    """Check the file's signature before handing it to VBA_Parser.

    VBA_Parser falls back to treating unrecognized files as raw VBA source
    text if it doesn't recognize an OLE2/OOXML container — which means a
    plain .txt file can be misreported as "containing macros". Gating on a
    real container signature avoids that false positive entirely.
    """
    try:
        with open(path, "rb") as f:
            header = f.read(8)
    except Exception:
        return False

    is_ole2 = header == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    is_zip_based = header[:4] == b"PK\x03\x04"  # OOXML formats are zip archives
    return is_ole2 or is_zip_based


def detect_macros(path: str) -> dict:
    """Return whether the file contains VBA macros, and their raw source if so.

    Works for both legacy OLE formats (.doc/.xls/.ppt) and modern OOXML
    macro-enabled formats (.docm/.xlsm/.pptm) — oletools handles both.
    """
    if not _is_office_file(path):
        return {"has_macros": False, "error": "not a supported Office file"}

    try:
        parser = VBA_Parser(path)
    except Exception:
        return {"has_macros": False, "error": "not a supported Office file"}

    try:
        has_macros = parser.detect_vba_macros()
        macro_count = 0
        macro_names = []

        if has_macros:
            for (_, _, vba_filename, _) in parser.extract_macros():
                macro_count += 1
                macro_names.append(vba_filename)

        return {
            "has_macros": has_macros,
            "macro_count": macro_count,
            "macro_names": macro_names,
        }
    finally:
        parser.close()


def _register():
    from sectoolkit.registry import register_check

    register_check(
        name="macros",
        description="Detect VBA macros in Office documents (common phishing vector)",
        applies_to=_is_office_file,
        run=detect_macros,
    )


_register()
