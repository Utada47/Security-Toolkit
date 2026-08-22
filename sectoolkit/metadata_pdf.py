"""Extract metadata from PDF files.

PDF metadata often reveals more than intended: the real author's name
(even after "anonymizing" a document's visible content), the software
used to create/edit it, and sometimes internal file paths.
"""
from pypdf import PdfReader


def extract_pdf_metadata(path: str) -> dict:
    """Return PDF document metadata, or {} if the file can't be read as a PDF."""
    try:
        reader = PdfReader(path)
    except Exception:
        return {}

    result = {"is_encrypted": reader.is_encrypted, "page_count": None}

    if reader.is_encrypted:
        # Metadata (and page count) are inaccessible without the password —
        # report what we safely know rather than crashing on locked content.
        return result

    if reader.metadata is not None:
        for key, value in reader.metadata.items():
            clean_key = key.lstrip("/")
            result[clean_key] = str(value) if value is not None else None

    result["page_count"] = len(reader.pages)

    return result
