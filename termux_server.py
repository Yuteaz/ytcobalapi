"""Zero-dependency HTTP server for Termux / Android (only requires `yt-dlp` + `ffmpeg`)."""

import json
import os
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

import yt_dlp

from yt_core import (
    BackendError,
    get_video_info,
    prepare_download,
    verify_internal_secret,
)

PORT = int(os.getenv("PORT", "7860"))


class TermuxHandler(BaseHTTPRequestHandler):
    def _send_cors(self):
        origin = self.headers.get("Origin", "")
        if origin in ("https://yutohub.site", "https://www.yutohub.site") or origin.endswith(".yutohub.pages.dev"):
            self.send_header("Access-Control-Allow-Origin", origin)
        else:
            self.send_header("Access-Control-Allow-Origin", "https://yutohub.site")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _send_json(self, status: int, data: dict):
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self._send_cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self._send_cors()
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/health":
            return self._send_json(200, {"ok": True, "yt_dlp_version": yt_dlp.version.__version__, "runtime": "termux"})

        if parsed.path == "/info":
            url = (qs.get("url") or [""])[0]
            secret = self.headers.get("X-Internal-Secret")
            try:
                verify_internal_secret(secret)
                if len(url) < 8:
                    raise BackendError(400, "Missing url parameter.")
                return self._send_json(200, get_video_info(url))
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})

        if parsed.path == "/download":
            url = (qs.get("url") or [""])[0]
            quality = (qs.get("quality") or ["1080"])[0]
            fmt = (qs.get("format") or ["mp4"])[0]
            try:
                exp = int((qs.get("exp") or ["0"])[0])
            except ValueError:
                exp = 0
            sig = (qs.get("sig") or [""])[0]

            tmpdir = None
            try:
                tmpdir, output_path, filename, media_type = prepare_download(url, quality, fmt, exp, sig)
                size = os.path.getsize(output_path)
                ascii_name = filename.encode("ascii", "ignore").decode("ascii") or "video"

                self.send_response(200)
                self._send_cors()
                self.send_header("Content-Type", media_type)
                self.send_header("Content-Length", str(size))
                self.send_header(
                    "Content-Disposition",
                    f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}",
                )
                self.end_headers()

                with open(output_path, "rb") as f:
                    shutil.copyfileobj(f, self.wfile, length=256 * 1024)
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})
            except BrokenPipeError:
                pass
            finally:
                if tmpdir:
                    shutil.rmtree(tmpdir, ignore_errors=True)
            return

        self._send_json(404, {"detail": "Not found"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), TermuxHandler)
    print(f"YutoHub Termux YouTube backend listening on http://127.0.0.1:{PORT}")
    server.serve_forever()
