"""Metadata extraction.

EXIF is read with ExifRead because it exposes camera metadata in a convenient
and predictable tag-oriented structure. IPTC is extracted via Pillow's
IptcImagePlugin and mapped to standard human-readable IIM field names.
"""

from pathlib import Path
from typing import Any

import exifread
from PIL import Image, IptcImagePlugin

# Common IPTC-IIM Application Record (Dataset 2) tag names
IPTC_TAGS: dict[tuple[int, int], str] = {
    (2, 5): "Object Name (Title)",
    (2, 15): "Category",
    (2, 20): "Supplemental Categories",
    (2, 25): "Keywords",
    (2, 40): "Special Instructions",
    (2, 55): "Date Created",
    (2, 60): "Time Created",
    (2, 80): "By-line (Creator)",
    (2, 85): "By-line Title",
    (2, 90): "City",
    (2, 95): "Province/State",
    (2, 100): "Country Code",
    (2, 101): "Country Name",
    (2, 103): "Transmission Reference",
    (2, 105): "Headline",
    (2, 110): "Credit",
    (2, 115): "Source",
    (2, 116): "Copyright Notice",
    (2, 120): "Caption/Abstract",
    (2, 122): "Writer/Editor",
}


def _clean_value(value: Any) -> str:
    """Convert metadata values (including byte strings and lists) into readable strings."""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace").strip()
    if isinstance(value, (list, tuple)):
        return ", ".join(_clean_value(item) for item in value)
    return str(value)


def extract_exif(path: Path) -> dict[str, str]:
    """Read EXIF tags without changing the evidence file."""
    tags_out: dict[str, str] = {}

    try:
        with path.open("rb") as image_file:
            tags = exifread.process_file(
                image_file,
                details=False,
                stop_tag="UNDEF",
            )

        for tag, value in tags.items():
            # Thumbnail binary data is not useful in the text report and can
            # make JSON enormous, so it is intentionally excluded.
            if tag.lower() == "thumbnail" or tag == "JPEGThumbnail":
                continue
            tags_out[tag] = _clean_value(value)

    except Exception:
        # Metadata absence or an unsupported metadata structure should not
        # prevent the rest of the forensic analysis.
        pass

    return tags_out


def extract_iptc(path: Path) -> dict[str, str]:
    """Extract and decode IPTC-IIM metadata blocks using Pillow's IptcImagePlugin."""
    iptc_out: dict[str, str] = {}

    try:
        with Image.open(path) as image:
            raw_iptc = IptcImagePlugin.getiptcinfo(image)

            if isinstance(raw_iptc, dict):
                for key, value in raw_iptc.items():
                    label = IPTC_TAGS.get(key, f"IPTC {key}")
                    iptc_out[label] = _clean_value(value)
    except Exception:
        pass

    return iptc_out


def extract_metadata(path: Path) -> dict[str, dict[str, str]]:
    """Return all metadata groups used by the prototype."""
    return {
        "exif": extract_exif(path),
        "iptc": extract_iptc(path),
    }
