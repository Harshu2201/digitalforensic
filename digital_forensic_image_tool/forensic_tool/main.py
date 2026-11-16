"""Command-line entry point for the Digital Forensic Image Analysis Tool."""

import argparse
from pathlib import Path
import sys

from .analysis import (
    calculate_hashes,
    collect_file_properties,
    integrity_status,
    perform_ela,
)
from .image_processor import detect_format, get_image_properties, verify_image
from .metadata import extract_metadata
from .report import build_report, print_report, save_json


def parse_arguments() -> argparse.Namespace:
    """Define the CLI interface.

    The CLI intentionally has only a few options so that a final-year project
    remains easy to understand and demonstrate during a viva.
    """
    parser = argparse.ArgumentParser(
        description="Basic Digital Forensic Image Analysis Tool"
    )
    parser.add_argument("image", help="Path to the image evidence file")
    parser.add_argument(
        "--json",
        dest="json_path",
        help="Optional path for saving the complete JSON report",
    )
    parser.add_argument(
        "--summary",
        action="store_true",
        help="Hide detailed EXIF/IPTC entries",
    )
    return parser.parse_args()


def analyze_image(path: Path) -> dict:
    """Run the complete analysis pipeline in a predictable order."""
    file_properties = collect_file_properties(path)

    # First identify the real image format before extracting deeper details.
    format_info = detect_format(path)

    # These operations are intentionally separated so each module has one
    # clear responsibility and can be tested independently.
    image_properties = get_image_properties(path)
    verification = verify_image(path)

    # Hashing is performed on the original bytes, not on decoded pixels.
    hashes = calculate_hashes(path)

    metadata = extract_metadata(path)

    integrity = integrity_status(image_properties, verification)

    # Error Level Analysis saves a visual heatmap alongside the input file.
    ela = perform_ela(path, format_info)

    return build_report(
        file_properties,
        format_info,
        image_properties,
        hashes,
        metadata,
        verification,
        integrity,
        ela,
    )


def main() -> int:
    """Validate arguments, execute analysis, and return a shell exit code."""
    args = parse_arguments()
    path = Path(args.image)

    if not path.exists():
        print(f"Error: file does not exist: {path}")
        return 1

    if not path.is_file():
        print(f"Error: path is not a file: {path}")
        return 1

    try:
        report = analyze_image(path)
        print_report(report, summary=args.summary)

        if args.json_path:
            save_json(report, Path(args.json_path))
            print(f"\nJSON report saved to: {args.json_path}")

        # A failed integrity check gives automation a useful non-zero result.
        return 0 if report["integrity"]["overall"] == "PASS" else 2

    except PermissionError:
        print("Error: permission denied while reading the evidence file.")
        return 1
    except OSError as exc:
        print(f"Error reading evidence file: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
