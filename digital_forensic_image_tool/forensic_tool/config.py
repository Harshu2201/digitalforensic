"""Central configuration for the prototype."""

# Formats supported by Pillow/OpenCV for this educational image-analysis tool.
SUPPORTED_EXTENSIONS = {
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".bmp": "BMP",
    ".tif": "TIFF",
    ".tiff": "TIFF",
    ".webp": "WEBP",
}

# Pillow's detected format names that we accept.
SUPPORTED_PIL_FORMATS = {
    "JPEG", "PNG", "BMP", "TIFF", "WEBP"
}

HASH_ALGORITHMS = ("md5", "sha256")

# Read files in chunks instead of loading the complete evidence file into RAM.
HASH_CHUNK_SIZE = 1024 * 1024  # 1 MiB
