"""Zero-dependency Web Interface for the Digital Forensic Image Analysis Tool.

Run directly with:
    python app.py
Then click http://127.0.0.1:5000 in the terminal to open in Chrome.
"""

import base64
import html
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import re
import tempfile

from forensic_tool.main import analyze_image

HOST = "127.0.0.1"
PORT = 5000


def _image_to_data_uri(path: Path) -> str:
    """Convert an image file into a base64 data URI for inline browser display."""
    mime = "image/png" if path.suffix.lower() == ".png" else "image/jpeg"
    encoded = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime};base64,{encoded}"


def _render_rows(data: dict) -> str:
    if not data:
        return "<tr><td colspan='2' class='muted'>No entries found.</td></tr>"
    return "".join(
        f"<tr><th>{html.escape(str(k))}</th><td>{html.escape(str(v))}</td></tr>"
        for k, v in data.items()
    )


def _render_page(
    report: dict | None = None,
    orig_uri: str = "",
    ela_uri: str = "",
    error: str = "",
) -> str:
    results_html = ""

    if error:
        results_html = f"<div class='alert'>{html.escape(error)}</div>"
    elif report:
        f_info = report["file"]
        fmt = report["format"]
        props = report["image_properties"]
        integ = report["integrity"]
        ela = report.get("ela", {})
        hashes = report["hashes"]

        ela_panel = (
            f"<img src='{ela_uri}' alt='ELA Heatmap'>"
            f"<p class='caption'>Quality Baseline: {ela.get('quality_level')}% | "
            f"Max Pixel Diff: {ela.get('max_difference')}</p>"
            if ela_uri
            else f"<p class='muted'>{html.escape(ela.get('reason', 'ELA not generated.'))}</p>"
        )

        json_pretty = html.escape(json.dumps(report, indent=2, ensure_ascii=False))

        results_html = f"""
        <div class="metrics">
            <div class="card"><span>Integrity</span><strong>{html.escape(integ['overall'])}</strong></div>
            <div class="card"><span>Format</span><strong>{html.escape(str(fmt['detected_format'] or 'Unknown'))}</strong></div>
            <div class="card"><span>Dimensions</span><strong>{props['width']} x {props['height']}</strong></div>
            <div class="card"><span>File Size</span><strong>{f_info['size_bytes']:,} bytes</strong></div>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h3>Original Evidence Image</h3>
                <img src="{orig_uri}" alt="Original Image">
                <p class="caption">{html.escape(f_info['file_name'])}</p>
            </div>
            <div class="panel">
                <h3>Error Level Analysis (ELA)</h3>
                {ela_panel}
            </div>
        </div>

        <div class="panel">
            <h3>Cryptographic Hashes &amp; Integrity</h3>
            <table>
                <tr><th>MD5</th><td><code>{html.escape(hashes['md5'])}</code></td></tr>
                <tr><th>SHA-256</th><td><code>{html.escape(hashes['sha256'])}</code></td></tr>
                <tr><th>Format Valid</th><td>{'YES' if fmt['valid'] else 'NO'}</td></tr>
                <tr><th>PIL Verify / OpenCV / Decode</th><td>{integ['pil_verify']} / {integ['opencv_check']} / {integ['decode_check']}</td></tr>
                <tr><th>Interpretation</th><td>{html.escape(integ['interpretation'])}</td></tr>
            </table>
        </div>

        <div class="grid-2">
            <div class="panel">
                <h3>EXIF Metadata ({len(report['metadata']['exif'])} tags)</h3>
                <div class="scroll-box"><table>{_render_rows(report['metadata']['exif'])}</table></div>
            </div>
            <div class="panel">
                <h3>IPTC Metadata ({len(report['metadata']['iptc'])} tags)</h3>
                <div class="scroll-box"><table>{_render_rows(report['metadata']['iptc'])}</table></div>
            </div>
        </div>

        <div class="panel">
            <h3>File Timestamps</h3>
            <table>
                <tr><th>Created</th><td>{html.escape(f_info['created'])}</td></tr>
                <tr><th>Modified</th><td>{html.escape(f_info['modified'])}</td></tr>
                <tr><th>Accessed</th><td>{html.escape(f_info['accessed'])}</td></tr>
            </table>
        </div>

        <details class="panel">
            <summary><strong>View Raw JSON Report</strong></summary>
            <pre>{json_pretty}</pre>
        </details>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Digital Forensic Image Analysis Tool</title>
<style>
    body {{ font-family: Segoe UI, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
    .container {{ max-width: 1200px; margin: auto; }}
    h1 {{ margin-top: 0; color: #38bdf8; }}
    .upload-box {{ background: #1e293b; padding: 20px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 24px; }}
    button {{ background: #0284c7; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }}
    button:hover {{ background: #0369a1; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 20px; }}
    .card {{ background: #1e293b; padding: 16px; border-radius: 10px; border: 1px solid #334155; }}
    .card span {{ display: block; font-size: 13px; color: #94a3b8; }}
    .card strong {{ font-size: 20px; color: #4ade80; }}
    .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }}
    .panel {{ background: #1e293b; padding: 18px; border-radius: 10px; border: 1px solid #334155; margin-bottom: 20px; }}
    .panel h3 {{ margin-top: 0; color: #7dd3fc; }}
    img {{ max-width: 100%; max-height: 380px; border-radius: 6px; border: 1px solid #475569; display: block; margin: auto; }}
    .caption {{ text-align: center; font-size: 13px; color: #94a3b8; margin-top: 8px; }}
    .scroll-box {{ max-height: 360px; overflow-y: auto; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #334155; vertical-align: top; word-break: break-word; }}
    th {{ width: 36%; color: #cbd5e1; }}
    code {{ color: #fbbf24; font-size: 12px; }}
    pre {{ background: #020617; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; }}
    .alert {{ background: #7f1d1d; color: #fecaca; padding: 14px; border-radius: 8px; margin-bottom: 20px; }}
    .muted {{ color: #94a3b8; }}
</style>
</head>
<body>
<div class="container">
    <h1>Digital Forensic Image Analysis Tool</h1>
    <form class="upload-box" method="POST" enctype="multipart/form-data">
        <input type="file" name="image" accept="image/*" required>
        <button type="submit">Analyze Evidence Image</button>
    </form>
    {results_html}
</div>
</body>
</html>"""


class ForensicWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(_render_page().encode("utf-8"))

    def do_POST(self):
        content_type = self.headers.get("Content-Type", "")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        match = re.search(r"boundary=(.+)", content_type)
        if not match:
            self._respond(_render_page(error="Invalid form submission."))
            return

        boundary = match.group(1).strip('"').encode("utf-8")
        parts = body.split(b"--" + boundary)

        filename = "uploaded_evidence.jpg"
        file_bytes = b""

        for part in parts:
            if b"Content-Disposition" in part and b'name="image"' in part:
                header, _, data = part.partition(b"\r\n\r\n")
                fn_match = re.search(rb'filename="([^"]+)"', header)
                if fn_match:
                    filename = Path(fn_match.group(1).decode("utf-8", errors="replace")).name
                file_bytes = data.rstrip(b"\r\n")
                break

        if not file_bytes:
            self._respond(_render_page(error="Please select an image file first."))
            return

        with tempfile.TemporaryDirectory() as tmp_dir:
            evidence_path = Path(tmp_dir) / filename
            evidence_path.write_bytes(file_bytes)

            report = analyze_image(evidence_path)
            orig_uri = _image_to_data_uri(evidence_path)

            ela_uri = ""
            ela_path_str = report.get("ela", {}).get("output_image", "")
            if ela_path_str and Path(ela_path_str).exists():
                ela_uri = _image_to_data_uri(Path(ela_path_str))

            self._respond(_render_page(report=report, orig_uri=orig_uri, ela_uri=ela_uri))

    def _respond(self, html_content: str):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html_content.encode("utf-8"))

    def log_message(self, format, *args):
        # Keep terminal clean while serving requests
        pass


if __name__ == "__main__":
    server = HTTPServer((HOST, PORT), ForensicWebHandler)
    print("=" * 60)
    print("Digital Forensic Image Analysis Web Server Running!")
    print(f"Open in Chrome: http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the server.")
    print("=" * 60)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")
        server.server_close()
