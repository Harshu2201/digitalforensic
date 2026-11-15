"""Image validation and technical property extraction.

This module is deliberately small. Its job is to answer questions such as:
- Is the supplied file actually an image?
- What image format does the decoder identify?
- Can the image be decoded?
- What are its dimensions, color mode and channel count?

The original file is only read; this module does not save or modify it.
"""

from pathlib import Path
from typing import Any

import cv2
import numpy as np
from PIL import Image

from .config import SUPPORTED_EXTENSIONS, SUPPORTED_PIL_FORMATS


def detect_format(path: Path) -> dict[str, Any]:
    """Detect an image's real format using Pillow.

    File extensions are useful hints, but forensic analysis should not rely
    on an extension alone. Pillow examines the file signature/structure
    through its decoder and reports the format it recognizes.
    """
    result: dict[str, Any] = {
        "extension": path.suffix.lower(),
        "extension_claim": SUPPORTED_EXTENSIONS.get(path.suffix.lower(), "Unknown"),
        "detected_format": None,
        "valid": False,
        "error": None,
    }

    try:
        # Image.open() identifies the format without necessarily decoding all
        # pixel data. The context manager ensures the file is closed.
        with Image.open(path) as image:
            result["detected_format"] = image.format
            result["valid"] = image.format in SUPPORTED_PIL_FORMATS
    except Exception as exc:
        result["error"] = str(exc)

    return result


def get_image_properties(path: Path) -> dict[str, Any]:
    """Extract basic technical properties and perform a decode check.

    A successful Image.open() proves the container is recognized. Calling
    load() goes one step further: it forces Pillow to decode the pixel data,
    which catches many forms of truncation/corruption.

    OpenCV is also used as a second decoder. Two independent decoders are a
    useful basic cross-check for a student prototype, although this is not a
    substitute for a full forensic validation process.
    """
    result: dict[str, Any] = {
        "width": None,
        "height": None,
        "mode": None,
        "channels": None,
        "pil_format": None,
        "pil_decode": False,
        "opencv_decode": False,
        "opencv_shape": None,
        "error": None,
    }

    try:
        with Image.open(path) as image:
            result["width"], result["height"] = image.size
            result["mode"] = image.mode
            result["channels"] = len(image.getbands())
            result["pil_format"] = image.format

            # Force actual pixel decoding rather than only reading headers.
            image.load()
            result["pil_decode"] = True
    except Exception as exc:
        result["error"] = str(exc)

    # OpenCV provides an independent decoder. np.fromfile() handles paths
    # containing non-ASCII characters more reliably on some Windows setups.
    try:
        raw = np.fromfile(str(path), dtype=np.uint8)
        decoded = cv2.imdecode(raw, cv2.IMREAD_UNCHANGED)
        if decoded is not None:
            result["opencv_decode"] = True
            result["opencv_shape"] = list(decoded.shape)
    except Exception:
        # This is intentionally minimal: the main result already records
        # Pillow errors, and the CLI should remain readable.
        pass

    return result


def verify_image(path: Path) -> dict[str, Any]:
    """Perform Pillow's structural verification.

    Image.verify() checks the file for problems detectable by Pillow without
    decoding the image for normal use. Because verify() can invalidate the
    image object, this function opens a fresh object and performs verification
    independently from get_image_properties().
    """
    result = {"pil_verify": False, "error": None}

    try:
        with Image.open(path) as image:
            image.verify()
        result["pil_verify"] = True
    except Exception as exc:
        result["error"] = str(exc)

    return result
