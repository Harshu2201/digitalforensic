"""Human-readable and JSON reporting."""

import json
from pathlib import Path
from typing import Any


def build_report(
    file_properties: dict[str, Any],
    format_info: dict[str, Any],
    image_properties: dict[str, Any],
    hashes: dict[str, str],
    metadata: dict[str, dict[str, str]],
    verification: dict[str, Any],
    integrity: dict[str, Any],
) -> dict[str, Any]:
    """Combine results from independent modules into one report object."""
    return {
        "file": file_properties,
        "format": format_info,
        "image_properties": image_properties,
        "hashes": hashes,
        "metadata": metadata,
        "verification": verification,
        "integrity": integrity,
    }


def _print_metadata(title: str, data: dict[str, str]) -> None:
    print(f"\n[{title}]")
    if not data:
        print("No metadata found.")
        return

    print(f"Tags found       : {len(data)}")
    for key, value in data.items():
        print(f"{key:<24}: {value}")


def print_report(report: dict[str, Any], summary: bool = False) -> None:
    """Print the forensic results in a simple examiner-friendly format."""
    print("=" * 60)
    print("DIGITAL FORENSIC IMAGE ANALYSIS REPORT")
    print("=" * 60)

    file_info = report["file"]
    fmt = report["format"]
    props = report["image_properties"]
    integrity = report["integrity"]

    print("\n[FILE]")
    print(f"Path             : {file_info['path']}")
    print(f"File Name        : {file_info['file_name']}")
    print(f"Size             : {file_info['size_bytes']} bytes")
    print(f"Detected Format  : {fmt['detected_format'] or 'Unknown'}")
    print(f"Extension Claim  : {fmt['extension_claim']}")
    print(f"Format Valid     : {'YES' if fmt['valid'] else 'NO'}")

    print("\n[HASHES]")
    print(f"MD5              : {report['hashes']['md5']}")
    print(f"SHA-256          : {report['hashes']['sha256']}")

    print("\n[IMAGE PROPERTIES]")
    print(f"Dimensions       : {props['width']} x {props['height']}")
    print(f"Mode             : {props['mode']}")
    print(f"Channels         : {props['channels']}")
    print(f"PIL Format       : {props['pil_format']}")
    print(f"OpenCV Read      : {integrity['opencv_check']}")

    print("\n[INTEGRITY]")
    print(f"PIL Verify       : {integrity['pil_verify']}")
    print(f"Decode Check     : {integrity['decode_check']}")
    print(f"Overall Status   : {integrity['overall']}")
    print(f"Interpretation   : {integrity['interpretation']}")

    print("\n[FILE TIMESTAMPS]")
    print(f"Created          : {file_info['created']}")
    print(f"Modified         : {file_info['modified']}")
    print(f"Accessed         : {file_info['accessed']}")

    if not summary:
        _print_metadata("EXIF", report["metadata"]["exif"])
        _print_metadata("IPTC", report["metadata"]["iptc"])

    print("\n" + "=" * 60)
    print("Analysis complete.")
    print("=" * 60)


def save_json(report: dict[str, Any], output_path: Path) -> None:
    """Write the complete structured report for later examination."""
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2, ensure_ascii=False)
