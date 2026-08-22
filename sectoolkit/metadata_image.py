"""Extract EXIF metadata from image files.

EXIF data can leak more than people expect: GPS coordinates of where a
photo was taken, the exact camera/phone model, and the original timestamp
— all still embedded even after the photo has been shared or reposted.
This module surfaces that data so it can be reviewed (and stripped) before
sharing sensitive images.
"""
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS


def _convert_to_degrees(value):
    d, m, s = value
    return float(d) + float(m) / 60.0 + float(s) / 3600.0


def _extract_gps(gps_info: dict) -> dict:
    gps_data = {}
    for key, value in gps_info.items():
        tag_name = GPSTAGS.get(key, key)
        gps_data[tag_name] = value

    if "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
        lat = _convert_to_degrees(gps_data["GPSLatitude"])
        if gps_data.get("GPSLatitudeRef") == "S":
            lat = -lat
        lon = _convert_to_degrees(gps_data["GPSLongitude"])
        if gps_data.get("GPSLongitudeRef") == "W":
            lon = -lon
        gps_data["decimal_coordinates"] = (round(lat, 6), round(lon, 6))

    return gps_data


def extract_exif(path: str) -> dict:
    """Return a dict of EXIF tags, or {} if the file has none / isn't an image."""
    try:
        image = Image.open(path)
        exif_raw = image.getexif()
    except Exception:
        return {}

    if not exif_raw:
        return {}

    result = {}
    for tag_id, value in exif_raw.items():
        tag_name = TAGS.get(tag_id, tag_id)

        if tag_name == "GPSInfo":
            try:
                gps_ifd = exif_raw.get_ifd(tag_id)
                result["GPS"] = _extract_gps(gps_ifd)
            except Exception:
                pass
        else:
            # Some EXIF values are bytes and not JSON/print friendly — decode
            # what we safely can, otherwise fall back to a string repr.
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="replace")
                except Exception:
                    value = repr(value)
            result[str(tag_name)] = value

    return result


def has_gps_location(exif_data: dict) -> bool:
    return "GPS" in exif_data and "decimal_coordinates" in exif_data.get("GPS", {})


def _is_image(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(12)
    except Exception:
        return False

    return (
        header[:3] == b"\xff\xd8\xff"  # JPEG
        or header[:8] == b"\x89PNG\r\n\x1a\n"  # PNG
        or header[:6] in (b"GIF87a", b"GIF89a")  # GIF
    )


def _register():
    from sectoolkit.registry import register_check

    register_check(
        name="image_metadata",
        description="Extract EXIF metadata from images (flags GPS location leaks)",
        applies_to=_is_image,
        run=extract_exif,
    )


_register()
