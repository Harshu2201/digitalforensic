"""Forensic file analysis.

This module focuses on evidence-oriented properties rather than visual
editing. It records hashes, filesystem timestamps and a simple integrity
assessment.

Important limitation: filesystem timestamps are metadata maintained by the
operating system/filesystem. They are not automatically proof of acquisition,
creation, or capture time.
"""

from datetime import datetime
from pathlib import Path
from typing import Any
import hashlib

from .config import HASH_ALGORITHMS, HASH_CHUNK_SIZE


def _timestamp(timestamp: float) -> str:
    """Convert a filesystem timestamp into a readable local-time string."""
    return datetime.fromtimestamp(timestamp).astimezone().strftime(
        "%Y-%m-%d %H:%M:%S %z"
    )


def collect_file_properties(path: Path) -> dict[str, Any]:
    """Collect size and filesystem timestamps."""
    stat = path.stat()

    return {
        "path": str(path.resolve()),
        "file_name": path.name,
        "size_bytes": stat.st_size,
        "created": _timestamp(stat.st_ctime),
        "modified": _timestamp(stat.st_mtime),
        "accessed": _timestamp(stat.st_atime),
    }


def calculate_hashes(path: Path) -> dict[str, str]:
    """Calculate MD5 and SHA-256 over the complete original byte stream.

    Cryptographic hashes are useful for identifying a file and demonstrating
    that the bytes analyzed later are the same bytes that were hashed earlier.
    The file is read in chunks to avoid unnecessary memory consumption.
    """
    hashers = {name: hashlib.new(name) for name in HASH_ALGORITHMS}

    with path.open("rb") as file:
        while chunk := file.read(HASH_CHUNK_SIZE):
            for hasher in hashers.values():
                hasher.update(chunk)

    return {name: hasher.hexdigest() for name, hasher in hashers.items()}


def integrity_status(image_properties: dict, verification: dict) -> dict[str, Any]:
    """Create a simple PASS/FAIL/UNKNOWN integrity assessment.

    This is deliberately conservative. A PASS means the file could be
    recognized, verified and decoded by the implemented libraries. It does
    NOT mean the evidence is authentic or untampered historically.
    """
    pil_decode = image_properties.get("pil_decode", False)
    opencv_decode = image_properties.get("opencv_decode", False)
    pil_verify = verification.get("pil_verify", False)

    passed = pil_decode and opencv_decode and pil_verify

    return {
        "decode_check": "PASS" if pil_decode else "FAIL",
        "opencv_check": "PASS" if opencv_decode else "FAIL",
        "pil_verify": "PASS" if pil_verify else "FAIL",
        "overall": "PASS" if passed else "FAIL",
        "interpretation": (
            "Image was successfully recognized and decoded by the implemented checks."
            if passed
            else "One or more image validation checks failed."
        ),
    }
