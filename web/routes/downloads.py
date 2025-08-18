# web/routes/downloads.py
from flask import Blueprint, Response, stream_with_context, redirect, jsonify, request
import requests
from urllib.parse import urlparse
import os

downloads_bp = Blueprint("downloads", __name__)

# Upstream sources (update if vendors change paths)
UPSTREAMS = {
    "windows": "https://download.wireguard.com/windows-client/wireguard-installer.exe",
    "macos":   "https://download.wireguard.com/macos/WireGuard.dmg",
    "linux":   "https://www.wireguard.com/install/",  # docs (varies by distro)
    "android": "https://play.google.com/store/apps/details?id=com.wireguard.android",
    "ios":     "https://apps.apple.com/app/wireguard/id1441195209",
}

TIMEOUT = (10, 60)  # (connect, read) seconds
CHUNK = 8192


def _filename_from_upstream(url: str, upstream_headers: dict) -> str:
    # Prefer upstream Content-Disposition filename if present
    cd = upstream_headers.get("Content-Disposition")
    if cd and "filename=" in cd:
        return cd.split("filename=")[-1].strip('"; ')
    # Fallback to URL path
    path = urlparse(url).path
    base = os.path.basename(path)
    return base or "download.bin"


@downloads_bp.route("/download/wireguard/<platform>")
def download_wireguard(platform: str):
    """Stream/proxy official downloads through your domain.
       For mobile and Linux, we redirect (stores/docs)."""
    platform = platform.lower()

    if platform not in UPSTREAMS:
        return ("Not found", 404)

    upstream = UPSTREAMS[platform]

    # Stores/docs must open externally (cannot be proxied as binaries)
    if platform in ("android", "ios", "linux"):
        # You can swap to a lightweight info page if you prefer not to 302.
        return redirect(upstream, code=302)

    # Proxy the binary (Windows/macOS)
    try:
        r = requests.get(upstream, stream=True, timeout=TIMEOUT, allow_redirects=True)
    except requests.RequestException:
        return ("Upstream unavailable. Please try again later.", 502)

    if r.status_code >= 400:
        return (f"Upstream error ({r.status_code}).", 502)

    filename = _filename_from_upstream(r.url, r.headers)
    content_type = r.headers.get("Content-Type", "application/octet-stream")
    content_length = r.headers.get("Content-Length")

    headers = {
        "Content-Type": content_type,
        "Content-Disposition": f'attachment; filename="{filename}"',
    }
    if content_length:
        headers["Content-Length"] = content_length

    return Response(stream_with_context(r.iter_content(CHUNK)), headers=headers)


@downloads_bp.route("/download/wireguard/meta/<platform>")
def download_meta(platform: str):
    """Optional: expose size/last-modified so the UI can show file size."""
    platform = platform.lower()
    url = UPSTREAMS.get(platform)
    if not url:
        return jsonify({"ok": False, "error": "unknown platform"}), 404

    # For store/docs, just redirect info
    if platform in ("android", "ios", "linux"):
        return jsonify({
            "ok": True,
            "type": "redirect",
            "url": url
        })

    try:
        r = requests.head(url, allow_redirects=True, timeout=TIMEOUT)
    except requests.RequestException:
        return jsonify({"ok": False, "error": "upstream unavailable"}), 502

    size = r.headers.get("Content-Length")
    lm = r.headers.get("Last-Modified")
    ct = r.headers.get("Content-Type")
    filename = _filename_from_upstream(r.url, r.headers)

    return jsonify({
        "ok": True,
        "type": "binary",
        "filename": filename,
        "content_type": ct,
        "size_bytes": int(size) if size and size.isdigit() else None,
        "last_modified": lm
    })
