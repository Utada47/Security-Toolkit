"""Detect a file's real type by inspecting its magic bytes (file signature),
independent of its extension.

This catches the classic disguise trick: renaming malware.exe to photo.jpg.
The extension says one thing; the actual byte signature says another.
"""

# (signature bytes, offset, description)
_SIGNATURES = [
    (b"\x4d\x5a", 0, "Windows PE executable (.exe/.dll)"),
    (b"\x7fELF", 0, "Linux ELF executable"),
    (b"%PDF-", 0, "PDF document"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"GIF87a", 0, "GIF image"),
    (b"GIF89a", 0, "GIF image"),
    (b"PK\x03\x04", 0, "ZIP archive (also: docx/xlsx/pptx/jar/apk)"),
    (b"\x1f\x8b", 0, "GZIP archive"),
    (b"Rar!\x1a\x07\x00", 0, "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Legacy MS Office document (.doc/.xls/.ppt)"),
    (b"#!", 0, "Script with shebang (e.g. bash, python)"),
]


def detect_file_type(path: str) -> str:
    with open(path, "rb") as f:
        header = f.read(16)

    for signature, offset, description in _SIGNATURES:
        end = offset + len(signature)
        if header[offset:end] == signature:
            return description

    if all(byte == 0x00 or 32 <= byte <= 126 or byte in (9, 10, 13) for byte in header):
        return "Plain text (or empty file)"

    return "Unknown binary format"


def extension_mismatch(path: str) -> dict:
    """Compare the file's extension against its detected real type.

    Returns a dict noting whether they appear consistent — a useful signal
    when a file's extension has been deliberately changed to disguise it.
    """
    import os

    ext = os.path.splitext(path)[1].lower()
    detected = detect_file_type(path)

    ext_expectations = {
        ".exe": "Windows PE executable",
        ".dll": "Windows PE executable",
        ".jpg": "JPEG image",
        ".jpeg": "JPEG image",
        ".png": "PNG image",
        ".pdf": "PDF document",
        ".zip": "ZIP archive",
        ".gz": "GZIP archive",
        ".rar": "RAR archive",
    }

    expected_substring = ext_expectations.get(ext)
    suspicious = expected_substring is not None and expected_substring not in detected

    return {"extension": ext or "(none)", "detected_type": detected, "suspicious": suspicious}


def _filetype_check(path: str) -> dict:
    return extension_mismatch(path)


def _register():
    from sectoolkit.registry import register_check

    register_check(
        name="filetype",
        description="Detect real file type via magic bytes; flag extension mismatches",
        applies_to=lambda path: True,
        run=_filetype_check,
    )


_register()
