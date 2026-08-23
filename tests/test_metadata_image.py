from PIL import Image
import piexif
from sectoolkit.metadata_image import extract_exif, has_gps_location


def _make_test_image_with_gps(path):
    img = Image.new("RGB", (10, 10), color="blue")
    gps_ifd = {
        piexif.GPSIFD.GPSLatitudeRef: "S",
        piexif.GPSIFD.GPSLatitude: ((6, 1), (12, 1), (0, 1)),
        piexif.GPSIFD.GPSLongitudeRef: "E",
        piexif.GPSIFD.GPSLongitude: ((106, 1), (49, 1), (0, 1)),
    }
    exif_dict = {"GPS": gps_ifd, "0th": {piexif.ImageIFD.Make: b"TestCamera"}}
    exif_bytes = piexif.dump(exif_dict)
    img.save(path, exif=exif_bytes)


def test_extracts_gps_coordinates_from_image_with_exif(tmp_path):
    image_path = tmp_path / "photo.jpg"
    _make_test_image_with_gps(str(image_path))

    exif = extract_exif(str(image_path))

    assert has_gps_location(exif) is True
    lat, lon = exif["GPS"]["decimal_coordinates"]
    assert -6.3 < lat < -6.1  # roughly matches the southern-hemisphere coords we set
    assert 106.7 < lon < 106.9


def test_extracts_camera_make_from_exif(tmp_path):
    image_path = tmp_path / "photo.jpg"
    _make_test_image_with_gps(str(image_path))

    exif = extract_exif(str(image_path))

    assert exif.get("Make") == "TestCamera"


def test_image_without_exif_returns_empty_dict(tmp_path):
    image_path = tmp_path / "plain.png"
    Image.new("RGB", (5, 5), color="white").save(image_path)

    exif = extract_exif(str(image_path))

    assert exif == {}


def test_has_gps_location_false_when_no_gps():
    assert has_gps_location({}) is False
    assert has_gps_location({"Make": "SomeCamera"}) is False


def test_non_image_file_returns_empty_dict_instead_of_crashing(tmp_path):
    not_an_image = tmp_path / "notes.txt"
    not_an_image.write_text("just some text, not an image at all")

    exif = extract_exif(str(not_an_image))

    assert exif == {}
