import base64
import hashlib
import hmac
import os
import re
import secrets
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Dict, Optional, Tuple

import yt_dlp

BACKEND_SECRET = os.getenv("BACKEND_SECRET", "").strip()
MAX_DURATION_SECONDS = int(os.getenv("MAX_DURATION_SECONDS", "3600"))
YT_ID_PATTERN = re.compile(
    r"(?:v=|youtu\.be/|youtube\.com/(?:shorts|embed|live)/)([a-zA-Z0-9_-]{11})"
)
COOKIES_PATH = os.path.join(tempfile.gettempdir(), "yt_cookies.txt")

_INFO_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_JOBS: Dict[str, Dict[str, Any]] = {}
_JOBS_LOCK = threading.Lock()
JOB_TTL_SECONDS = 600


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
    now = time.time()
    cached = _INFO_CACHE.get(video_id)
    if cached and cached[0] > now:
        return cached[1]

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

    formats.append({"quality": "1080", "label": "Audio M4A (Fast)", "format": "m4a", "badge": "INSTANT"})
    formats.append({"quality": "1080", "label": "Audio MP3", "format": "mp3", "badge": "192k"})

    payload = {
        "videoId": video_id,
        "url": clean_url,
        "title": info.get("title") or "YouTube Video",
        "author": info.get("uploader") or info.get("channel") or "YouTube Creator",
        "duration": duration,
        "thumbnail": info.get("thumbnail") or f"https://i.ytimg.com/vi/{video_id}/hqdefault.jpg",
        "maxResThumbnail": f"https://i.ytimg.com/vi/{video_id}/maxresdefault.jpg",
        "formats": formats,
    }
    _INFO_CACHE[video_id] = (now + 600, payload)
    return payload


def _duration_filter(info: Dict[str, Any], *, incomplete: bool = False) -> Optional[str]:
    duration = info.get("duration")
    if duration and int(duration) > MAX_DURATION_SECONDS:
        return f"Video exceeds maximum allowed duration of {MAX_DURATION_SECONDS // 60} minutes."
    return None


def prepare_download(
    url: str,
    quality: str,
    fmt: str,
    exp: int,
    sig: str,
    progress_cb: Optional[Callable[[Dict[str, Any]], None]] = None,
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

    def on_progress(d: Dict[str, Any]) -> None:
        if not progress_cb:
            return
        status = d.get("status")
        if status == "downloading":
            total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
            downloaded = d.get("downloaded_bytes") or 0
            pct = round((downloaded / total) * 100, 1) if total > 0 else None
            spd = d.get("speed") or 0
            speed_str = f"{spd / (1024 * 1024):.1f} MB/s" if spd >= 1024 * 1024 else (
                f"{spd / 1024:.0f} KB/s" if spd > 0 else ""
            )
            progress_cb({"state": "downloading", "percent": pct, "speed": speed_str})
        elif status == "finished":
            progress_cb({"state": "merging", "percent": 100, "speed": ""})

    def on_postprocess(d: Dict[str, Any]) -> None:
        if progress_cb and d.get("status") == "started":
            progress_cb({"state": "merging", "percent": 100, "speed": ""})

    ydl_opts: Dict[str, Any] = {
        "quiet": True,
        "no_warnings": True,
        "noplaylist": True,
        "outtmpl": os.path.join(tmpdir, "%(title)s.%(ext)s"),
        "max_filesize": 1500 * 1024 * 1024,
        "concurrent_fragment_downloads": 6,
        "http_chunk_size": 10 * 1024 * 1024,
        "retries": 3,
        "fragment_retries": 3,
        "match_filter": _duration_filter,
        "progress_hooks": [on_progress],
        "postprocessor_hooks": [on_postprocess],
    }

    cookiefile = init_cookies_file()
    if cookiefile:
        ydl_opts["cookiefile"] = cookiefile

    if fmt == "m4a":
        # Direct M4A copy: zero transcoding overhead on mobile CPUs
        ydl_opts["format"] = "bestaudio[ext=m4a]/bestaudio/best"
    elif fmt == "mp3":
        ydl_opts["format"] = "bestaudio/best"
        ydl_opts["postprocessors"] = [
            {
                "key": "FFmpegExtractAudio",
                "preferredcodec": "mp3",
                "preferredquality": "192",
            }
        ]
        ydl_opts["postprocessor_args"] = {"ffmpeg": ["-threads", "0"]}
    else:
        max_h = int(quality)
        if max_h <= 360:
            ydl_opts["format"] = f"best[height<={max_h}][ext=mp4]/bestvideo[height<={max_h}]+bestaudio/best"
        else:
            ydl_opts["format"] = (
                f"bestvideo[height<={max_h}][vcodec^=avc1][ext=mp4]+bestaudio[ext=m4a]/"
                f"bestvideo[height<={max_h}][ext=mp4]+bestaudio[ext=m4a]/"
                f"bestvideo[height<={max_h}]+bestaudio/best[height<={max_h}]/best"
            )
        ydl_opts["merge_output_format"] = "mp4"

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(clean_url, download=True)
    except BackendError:
        cleanup()
        raise
    except Exception as exc:
        cleanup()
        raise BackendError(500, f"Download failed: {exc}")

    if not info:
        cleanup()
        raise BackendError(413, "Video skipped (exceeds duration or unavailable).")

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


def _cleanup_expired_jobs() -> None:
    now = time.time()
    with _JOBS_LOCK:
        expired = [jid for jid, job in _JOBS.items() if job.get("expires", 0) < now]
        for jid in expired:
            job = _JOBS.pop(jid, None)
            if job and job.get("tmpdir"):
                shutil.rmtree(job["tmpdir"], ignore_errors=True)


def start_download_job(url: str, quality: str, fmt: str, exp: int, sig: str) -> Dict[str, str]:
    _cleanup_expired_jobs()
    fmt_clean = (fmt or "mp4").lower()
    if fmt_clean not in ("mp4", "mp3", "m4a"):
        raise BackendError(400, "Unsupported format.")
    if quality not in ("2160", "1440", "1080", "720", "480", "360"):
        quality = "1080"

    verify_download_sig(url, quality, fmt_clean, exp, sig)
    extract_video_id(url)

    job_id = secrets.token_hex(8)
    token = secrets.token_urlsafe(16)

    with _JOBS_LOCK:
        _JOBS[job_id] = {
            "token": token,
            "state": "starting",
            "percent": 0,
            "speed": "",
            "error": None,
            "tmpdir": None,
            "output_path": None,
            "filename": None,
            "media_type": None,
            "expires": time.time() + JOB_TTL_SECONDS,
        }

    def update_progress(info: Dict[str, Any]) -> None:
        with _JOBS_LOCK:
            job = _JOBS.get(job_id)
            if job and job["state"] not in ("ready", "error"):
                job["state"] = info.get("state", job["state"])
                if info.get("percent") is not None:
                    job["percent"] = info["percent"]
                if "speed" in info:
                    job["speed"] = info["speed"]

    def worker() -> None:
        try:
            tmpdir, output_path, filename, media_type = prepare_download(
                url, quality, fmt_clean, exp, sig, progress_cb=update_progress
            )
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["state"] = "ready"
                    job["percent"] = 100
                    job["speed"] = ""
                    job["tmpdir"] = tmpdir
                    job["output_path"] = output_path
                    job["filename"] = filename
                    job["media_type"] = media_type
                    job["expires"] = time.time() + JOB_TTL_SECONDS
                else:
                    shutil.rmtree(tmpdir, ignore_errors=True)
        except BackendError as err:
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["state"] = "error"
                    job["error"] = err.detail
        except Exception as exc:
            with _JOBS_LOCK:
                job = _JOBS.get(job_id)
                if job:
                    job["state"] = "error"
                    job["error"] = str(exc)

    threading.Thread(target=worker, daemon=True).start()
    return {"jobId": job_id, "token": token}


def get_job_status(job_id: str, token: str) -> Dict[str, Any]:
    _cleanup_expired_jobs()
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job or not hmac.compare_digest(job["token"], token or ""):
            raise BackendError(404, "Job not found or expired.")
        return {
            "state": job["state"],
            "percent": job["percent"],
            "speed": job["speed"],
            "error": job["error"],
            "filename": job["filename"],
        }


def pop_job_file(job_id: str, token: str) -> Tuple[str, str, str, str]:
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job or not hmac.compare_digest(job["token"], token or ""):
            raise BackendError(404, "File not found or expired.")
        if job["state"] != "ready" or not job["output_path"] or not os.path.exists(job["output_path"]):
            raise BackendError(409, "File is not ready yet.")
        _JOBS.pop(job_id, None)
        return job["tmpdir"], job["output_path"], job["filename"], job["media_type"]
