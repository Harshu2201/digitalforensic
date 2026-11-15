# Digital Forensic Image Analysis Tool

A command-line prototype for final-year Computer Engineering students to perform basic digital forensic analysis on image files. The tool validates an image, calculates cryptographic hashes, extracts EXIF/IPTC/file metadata, checks basic file integrity, and produces a readable forensic report.

## Features

- Image format detection and validation
- SHA-256 and MD5 hash generation
- File size and filesystem timestamp collection
- EXIF metadata extraction using ExifRead
- Basic IPTC extraction when available through Pillow
- Image properties: dimensions, mode, format, channels
- Basic OpenCV decode/read check
- PIL integrity verification
- Optional JSON report export
- Simple command-line interface

## Project structure

```text
digital_forensic_image_tool/
├── forensic_tool/
│   ├── __init__.py
│   ├── config.py
│   ├── image_processor.py
│   ├── metadata.py
│   ├── analysis.py
│   ├── report.py
│   └── main.py
├── tests/
│   └── test_basic.py
├── requirements.txt
└── README.md
```

## Requirements

- Python 3.10+ recommended
- Pillow
- OpenCV
- NumPy
- ExifRead

Install:

```bash
python -m venv .venv
```

Windows:

```bash
.venv\Scripts\activate
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Then:

```bash
pip install -r requirements.txt
```

## Usage

Analyze an image:

```bash
python -m forensic_tool.main sample.jpg
```

Save a JSON report:

```bash
python -m forensic_tool.main sample.jpg --json report.json
```

Show only a compact summary:

```bash
python -m forensic_tool.main sample.jpg --summary
```

Get help:

```bash
python -m forensic_tool.main --help
```

## Example output

```text
============================================================
DIGITAL FORENSIC IMAGE ANALYSIS REPORT
============================================================

[FILE]
Path             : sample.jpg
File Name        : sample.jpg
Size             : 184532 bytes
Detected Format  : JPEG
MIME Type        : image/jpeg

[HASHES]
MD5              : 6e3f...b18a
SHA-256          : 9d6a...f721

[IMAGE PROPERTIES]
Dimensions       : 1920 x 1080
Mode             : RGB
Channels         : 3
PIL Format       : JPEG
OpenCV Read      : PASS

[INTEGRITY]
PIL Verify       : PASS
Decode Check     : PASS
Overall Status   : PASS

[FILE TIMESTAMPS]
Created          : 2026-10-07 20:10:32
Modified         : 2026-10-07 20:11:05
Accessed         : 2026-10-07 20:11:05

[EXIF]
EXIF tags found  : 8
Make             : Example Camera
Model            : Example X1
DateTimeOriginal : 2026:10:07 20:08:12

[IPTC]
IPTC tags found  : 0

============================================================
Analysis complete.
============================================================
```

Actual metadata and hashes will depend on the input image.

## Forensic design notes

The prototype treats the input image as evidence and avoids modifying it. Hashes are calculated from the original bytes, while image decoding is performed separately for analysis. SHA-256 is included as the primary integrity identifier; MD5 is provided mainly for compatibility with older forensic workflows.

Filesystem timestamps describe the current filesystem's record of the file and should **not** automatically be interpreted as proof of when the photograph was taken. EXIF timestamps, when present, are a separate source of evidence and can also be missing or modified.

This is an educational prototype, not a replacement for a validated forensic suite. It does not perform deleted-file recovery, filesystem timeline reconstruction, steganography detection, JPEG quantization analysis, chain-of-custody management, or court-grade evidence preservation.
