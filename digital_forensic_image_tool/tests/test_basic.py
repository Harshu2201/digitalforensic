"""Small smoke test for the capstone prototype."""

from pathlib import Path
from tempfile import NamedTemporaryFile

from PIL import Image

from forensic_tool.analysis import calculate_hashes, collect_file_properties
from forensic_tool.image_processor import detect_format, get_image_properties


def test_basic_image_analysis():
    """Create a temporary PNG and verify the core pipeline works."""
    with NamedTemporaryFile(suffix=".png", delete=False) as temp:
        path = Path(temp.name)

    try:
        image = Image.new("RGB", (100, 50), (255, 255, 255))
        image.save(path)

        fmt = detect_format(path)
        props = get_image_properties(path)
        hashes = calculate_hashes(path)
        file_info = collect_file_properties(path)

        assert fmt["detected_format"] == "PNG"
        assert fmt["valid"] is True
        assert props["width"] == 100
        assert props["height"] == 50
        assert props["pil_decode"] is True
        assert props["opencv_decode"] is True
        assert len(hashes["sha256"]) == 64
        assert file_info["size_bytes"] > 0
    finally:
        path.unlink(missing_ok=True)
