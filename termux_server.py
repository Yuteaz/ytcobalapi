"""Zero-dependency HTTP server for Termux / Android (only requires `yt-dlp` + `ffmpeg`)."""

import json
import os
import shutil
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse

import yt_dlp

from yt_core import (
    BackendError,
    get_job_status,
    get_video_info,
    pop_job_file,
    prepare_download,
    start_download_job,
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

    def _stream_file(self, tmpdir: str, output_path: str, filename: str, media_type: str):
        try:
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
        except BrokenPipeError:
            pass
        finally:
            if tmpdir:
                shutil.rmtree(tmpdir, ignore_errors=True)

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

        if parsed.path == "/start":
            url = (qs.get("url") or [""])[0]
            quality = (qs.get("quality") or ["1080"])[0]
            fmt = (qs.get("format") or ["mp4"])[0]
            try:
                exp = int((qs.get("exp") or ["0"])[0])
            except ValueError:
                exp = 0
            sig = (qs.get("sig") or [""])[0]

            try:
                job = start_download_job(url, quality, fmt, exp, sig)
                return self._send_json(200, job)
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})

        if parsed.path == "/status":
            job_id = (qs.get("job") or [""])[0]
            token = (qs.get("token") or [""])[0]
            try:
                return self._send_json(200, get_job_status(job_id, token))
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})

        if parsed.path == "/file":
            job_id = (qs.get("job") or [""])[0]
            token = (qs.get("token") or [""])[0]
            try:
                tmpdir, output_path, filename, media_type = pop_job_file(job_id, token)
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})
            self._stream_file(tmpdir, output_path, filename, media_type)
            return

        if parsed.path == "/download":
            url = (qs.get("url") or [""])[0]
            quality = (qs.get("quality") or ["1080"])[0]
            fmt = (qs.get("format") or ["mp4"])[0]
            try:
                exp = int((qs.get("exp") or ["0"])[0])
            except ValueError:
                exp = 0
            sig = (qs.get("sig") or [""])[0]

            try:
                tmpdir, output_path, filename, media_type = prepare_download(url, quality, fmt, exp, sig)
            except BackendError as err:
                return self._send_json(err.status_code, {"detail": err.detail})
            self._stream_file(tmpdir, output_path, filename, media_type)
            return

        self._send_json(404, {"detail": "Not found"})


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), TermuxHandler)
    print(f"YutoHub Termux YouTube backend listening on http://127.0.0.1:{PORT}")
    server.serve_forever()
