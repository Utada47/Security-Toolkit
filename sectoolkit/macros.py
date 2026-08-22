"""Detect VBA macros in Microsoft Office documents.

Macro-enabled Office documents are one of the most common phishing/malware
delivery mechanisms ("enable content to view this invoice"). This module
flags whether a document contains macros at all — a strong signal to treat
the file with extra caution, especially if it arrived unexpectedly.
"""
from oletools.olevba import VBA_Parser


def detect_macros(path: str) -> dict:
    """Return whether the file contains VBA macros, and their raw source if so.

    Works for both legacy OLE formats (.doc/.xls/.ppt) and modern OOXML
    macro-enabled formats (.docm/.xlsm/.pptm) — oletools handles both.
    """
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
