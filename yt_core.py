import base64
import hashlib
import hmac
import os
import re
import shutil
import tempfile
import time
from typing import Any, Dict, Optional, Tuple

import yt_dlp

BACKEND_SECRET = os.getenv("BACKEND_SECRET", "").strip()
MAX_DURATION_SECONDS = int(os.getenv("MAX_DURATION_SECONDS", "3600"))
YT_ID_PATTERN = re.compile(
    r"(?:v=|youtu\.be/|youtube\.com/(?:shorts|embed|live)/)([a-zA-Z0-9_-]{11})"
)
COOKIES_PATH = os.path.join(tempfile.gettempdir(), "yt_cookies.txt")


class BackendError(Exception):
    def __init__(self, status_code: int, detail: str):
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


def init_cookies_file() -> Optional[str]:
    raw_b64 = os.getenv("YT_COOKIES_B64", "").strip()
    raw_txt = os.getenv("YT_COOKIES_TXT", "").strip()
    if raw_b64:
        try:
            decoded = base64.b64decode(raw_b64).decode("utf-8")
            with open(COOKIES_PATH, "w", encoding="utf-8") as f:
                f.write(decoded)
            return COOKIES_PATH
        except Exception:
            pass
    if raw_txt:
        with open(COOKIES_PATH, "w", encoding="utf-8") as f:
            f.write(raw_txt)
        return COOKIES_PATH
    return COOKIES_PATH if os.path.exists(COOKIES_PATH) else None


def extract_video_id(url: str) -> str:
    m = YT_ID_PATTERN.search(url or "")
    if not m:
        raise BackendError(400, "Invalid YouTube URL.")
    return m.group(1)


def verify_internal_secret(header_secret: Optional[str]) -> None:
    if not BACKEND_SECRET:
        return
    if not header_secret or not hmac.compare_digest(header_secret, BACKEND_SECRET):
        raise BackendError(401, "Unauthorized.")


def verify_download_sig(url: str, quality: str, fmt: str, exp: int, sig: str) -> None:
    if not BACKEND_SECRET:
        return
    if exp < int(time.time()):
        raise BackendError(403, "Download link expired. Request a new one.")
    payload = f"{url}|{quality}|{fmt}|{exp}".encode("utf-8")
    expected = hmac.new(BACKEND_SECRET.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not sig or not hmac.compare_digest(sig, expected):
        raise BackendError(403, "Invalid download signature.")


def sanitize_filename(name: str) -> str:
    cleaned = re.sub(r'[\\/:*?"<>|\r\n]+', "", name or "video").strip()
    return cleaned[:90] or "video"


def get_video_info(url: str) -> Dict[str, Any]:
    video_id = extract_video_id(url)
    clean_url = f"https://www.youtube.com/watch?v={video_id}"

    ydl_opts: Dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "skip_download": True,
    }
    cookiefile = init_cookies_file()
    if cookiefile:
        ydl_opts["cookiefile"] = cookiefile

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(clean_url, download=False)
    except Exception as exc:
        raise BackendError(422, f"Failed to extract video info: {exc}")

    duration = int(info.get("duration") or 0)
    if duration > MAX_DURATION_SECONDS:
        raise BackendError(
            413,
            f"Video exceeds free limit of {MAX_DURATION_SECONDS // 60} minutes.",
        )

    available_heights = set()
    for f in info.get("formats") or []:
        h = f.get("height")
        if isinstance(h, int) and f.get("vcodec") not in (None, "none"):
            available_heights.add(h)

    formats = []
    for q, label, badge in [
        ("2160", "2160p 4K", "4K"),
        ("1440", "1440p 2K", "2K"),
        ("1080", "1080p Full HD", "HD"),
        ("720", "720p HD", "HD"),
        ("480", "480p SD", ""),
        ("360", "360p Fast", ""),
    ]:
        if int(q) in available_heights or int(q) <= 720:
            formats.append({"quality": q, "label": label, "format": "mp4", "badge": badge})

    formats.append({"quality": "1080", "label": "Audio MP3", "format": "mp3", "badge": "320k"})

    return {
        "videoId": video_id,
        "url": clean_url,
        "title": info.get("title") or "YouTube Video",
        "author": info.get("uploader") or info.get("channel") or "YouTube Creator",
        "duration": duration,
        "thumbnail": info.get("thumbnail") or f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg",
        "maxResThumbnail": f"https://i.ytimg.com/vi/{video_id}/maxresdefault.jpg",
        "formats": formats,
    }


def prepare_download(
    url: str, quality: str, fmt: str, exp: int, sig: str
) -> Tuple[str, str, str, str]:
    fmt = (fmt or "mp4").lower()
    if fmt not in ("mp4", "mp3", "m4a"):
        raise BackendError(400, "Unsupported format.")
    if quality not in ("2160", "1440", "1080", "720", "480", "360"):
        quality = "1080"

    verify_download_sig(url, quality, fmt, exp, sig)
    video_id = extract_video_id(url)
    clean_url = f"https://www.youtube.com/watch?v={video_id}"

    tmpdir = tempfile.mkdtemp(prefix="yt_")

    def cleanup() -> None:
        shutil.rmtree(tmpdir, ignore_errors=True)

    ydl_opts: Dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "outtmpl": os.path.join(tmpdir, "%(title)s.%(ext)s"),
        "max_filesize": 1500 * 1024 * 1024,
    }

    cookiefile = init_cookies_file()
    if cookiefile:
        ydl_opts["cookiefile"] = cookiefile

    if fmt in ("mp3", "m4a"):
        ydl_opts["format"] = "bestaudio/best"
        ydl_opts["postprocessors"] = [
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": fmt,
                "preferredquality": "320" if fmt == "mp3" else "192",
            }
        ]
    else:
        max_h = int(quality)
        ydl_opts["format"] = (
            f"bestvideo[height<={max_h}][ext=mp4]+bestaudio[ext=m4a]/"
            f"bestvideo[height<={max_h}]+bestaudio/best[height<={max_h}]/best"
        )
        ydl_opts["merge_output_format"] = "mp4"

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(clean_url, download=False)
            duration = int(info.get("duration") or 0)
            if duration > MAX_DURATION_SECONDS:
                cleanup()
                raise BackendError(413, "Video exceeds maximum allowed duration.")
            ydl.download([clean_url])
    except BackendError:
        raise
    except Exception as exc:
        cleanup()
        raise BackendError(500, f"Download failed: {exc}")

    files = [
        os.path.join(tmpdir, f)
        for f in os.listdir(tmpdir)
        if os.path.isfile(os.path.join(tmpdir, f))
    ]
    if not files:
        cleanup()
        raise BackendError(500, "No output file produced.")

    output_path = files[0]
    safe_title = sanitize_filename(info.get("title") or video_id)
    ext = os.path.splitext(output_path)[1].lstrip(".") or fmt
    media_type = "audio/mpeg" if ext == "mp3" else ("audio/mp4" if ext == "m4a" else "video/mp4")

    return tmpdir, output_path, f"{safe_title}.{ext}", media_type
