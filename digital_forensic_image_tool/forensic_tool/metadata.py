"""Metadata extraction.

EXIF is read with ExifRead because it exposes camera metadata in a convenient
and predictable tag-oriented structure. IPTC support varies by image format;
Pillow may expose raw IPTC information for JPEG/TIFF files, so this module
makes a best-effort extraction without claiming that absent metadata means
the image has never contained it.
"""

from pathlib import Path
from typing import Any

import exifread
from PIL import Image


def _clean_value(value: Any) -> str:
    """Convert metadata values into JSON/report-friendly strings."""
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
            if tag.lower() == "thumbnail":
                continue
            tags_out[tag] = _clean_value(value)

    except Exception:
        # Metadata absence or an unsupported metadata structure should not
        # prevent the rest of the forensic analysis.
        pass

    return tags_out


def extract_iptc(path: Path) -> dict[str, str]:
    """Attempt to extract IPTC information exposed through Pillow.

    IPTC is commonly stored in JPEG APP13 data. Pillow's info dictionary may
    expose this under an 'iptc' key depending on the image and Pillow version.
    Since support is format-dependent, an empty result is considered normal.
    """
    iptc_out: dict[str, str] = {}

    try:
        with Image.open(path) as image:
            raw_iptc = image.info.get("iptc")

            if isinstance(raw_iptc, dict):
                for key, value in raw_iptc.items():
                    iptc_out[str(key)] = _clean_value(value)
            elif raw_iptc is not None:
                iptc_out["raw"] = _clean_value(raw_iptc)
    except Exception:
        pass

    return iptc_out


def extract_metadata(path: Path) -> dict[str, dict[str, str]]:
    """Return all metadata groups used by the prototype."""
    return {
        "exif": extract_exif(path),
        "iptc": extract_iptc(path),
    }
