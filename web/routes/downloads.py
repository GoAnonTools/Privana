# web/routes/downloads.py
from __future__ import annotations

import os
import io
import sqlite3
import secrets
import base64
import ipaddress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
from flask import (
    Blueprint, request, jsonify, session, send_file,
    redirect, Response, stream_with_context, url_for, abort, flash, current_app
)
from web.utils.guards import require_passkey_for_sensitive_action
from rate_limit import limiter
from web.crypto import encrypt_text
from web.db import get_db as central_get_db


def public_app_url() -> str:
    """
    Return the trusted public app URL.

    Security: never build bootstrap URLs from request.host_url, because Host
    can be attacker-controlled and those URLs are interpolated into scripts.
    """
    base = (os.getenv("PUBLIC_APP_URL") or "").strip().rstrip("/")
    if not base:
        # Local-dev fallback only. Production must set PUBLIC_APP_URL.
        if os.getenv("ENVIRONMENT", "development").lower() == "production":
            raise RuntimeError("PUBLIC_APP_URL must be set in production.")
        base = "http://127.0.0.1:5000"
    if not (base.startswith("https://") or base.startswith("http://127.0.0.1") or base.startswith("http://localhost")):
        raise RuntimeError("PUBLIC_APP_URL must be https:// in production-like environments.")
    return base

# Local or remote depending on your API_MODE wiring
# sg_issue_config removed - use manual registration flow if not in stub mode

# -----------------------------------------------------------------------------
# Blueprint
# -----------------------------------------------------------------------------
downloads_bp = Blueprint("downloads", __name__)

# -----------------------------------------------------------------------------
# Constants (vendor links, timeouts)
# -----------------------------------------------------------------------------
UPSTREAMS = {
    "windows": "https://download.wireguard.com/windows-client/wireguard-installer.exe",
    "macos":   "https://download.wireguard.com/macos/WireGuard.dmg",
    "linux":   "https://www.wireguard.com/install/",  # docs per distro
    "android": "https://play.google.com/store/apps/details?id=com.wireguard.android",
    "ios":     "https://apps.apple.com/app/wireguard/id1441195209",
}
TIMEOUT = (10, 60)  # (connect, read)
CHUNK = 8192

# Stub mode: generate a dummy-looking config so the UI flow works before the core is deployed
ISSUE_CONFIG_STUB = os.getenv("ISSUE_CONFIG_STUB", "0") == "1"
# Values used to shape the stub config (purely cosmetic)
WG_HOST    = os.getenv("WG_HOST", "127.0.0.1")
WG_PORT    = int(os.getenv("WG_PORT", "51820"))
WG_CIDR    = os.getenv("WG_CIDR", "10.7.0.0/24")
WG_DNS     = os.getenv("WG_DNS", "1.1.1.1")
WG_ALLOWED = os.getenv("WG_ALLOWED_IPS", "0.0.0.0/0,::/0")

# -----------------------------------------------------------------------------
# DB helpers
# -----------------------------------------------------------------------------
TRIAL_DAYS = 7



def _client_ip() -> str:
    forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return forwarded or request.remote_addr or "unknown"


def _db():    return central_get_db()



def _get_user(user_id: int):
    with _db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def _device_belongs(user_id: int, device_id: int) -> bool:
    with _db() as conn:
        row = conn.execute(
            "SELECT id FROM devices WHERE id = ? AND user_id = ?",
            (device_id, user_id)
        ).fetchone()
        return row is not None


def _is_subscription_ok(u: sqlite3.Row) -> bool:
    """
    Allow if user has an active subscription OR is within a trial window.
    """
    status = (u["subscription_status"] or "").lower()
    if status == "active":
        return True

    plan = (u["subscription_plan"] or "").lower()
    if plan != "trial":
        return False

    raw = u["created_at"]  # "YYYY-MM-DD HH:MM:SS"
    try:
        created = datetime.fromisoformat(raw)
    except Exception:
        created = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    return datetime.now(timezone.utc) < created + timedelta(days=TRIAL_DAYS)

# -----------------------------------------------------------------------------
# Utility for upstream filename detection
# -----------------------------------------------------------------------------
def _filename_from_upstream(url: str, upstream_headers: dict) -> str:
    cd = upstream_headers.get("Content-Disposition")
    if cd and "filename=" in cd:
        return cd.split("filename=")[-1].strip('"; ')
    path = urlparse(url).path
    base = os.path.basename(path)
    return base or "download.bin"

# -----------------------------------------------------------------------------
# Stub config generator (DEV ONLY)
# -----------------------------------------------------------------------------
def _stub_issue_config(user_id: int, device_id: int) -> dict:
    """
    Generate a placeholder client config. This will NOT connect anywhere,
    it’s only for exercising the UI before the real server exists.
    """
    # Obvious placeholder: never generate realistic-looking private keys in stub mode.
    private_key_placeholder = "PLACEHOLDER_CLIENT_PRIVATE_KEY"

    # pick a stable-ish IP from WG_CIDR based on device_id
    try:
        net = ipaddress.ip_network(WG_CIDR, strict=False)
        hosts = list(net.hosts())
        # reserve first host for server → start from index 1 with an offset
        idx = min(len(hosts) - 1, max(1, device_id % max(2, len(hosts))))
        ip = str(hosts[idx])
    except Exception:
        ip = "10.7.0.42"  # fallback

    conf = f"""# STUB CONFIG — for UI testing only. Will not connect until server is deployed.
[Interface]
PrivateKey = {private_key_placeholder}
Address = {ip}/32
DNS = {WG_DNS}

[Peer]
PublicKey = PLACEHOLDER_SERVER_PUBLIC_KEY
Endpoint = {WG_HOST}:{WG_PORT}
AllowedIPs = {WG_ALLOWED}
PersistentKeepalive = 25
"""
    return {
        "success": True,
        "public_key": "PLACEHOLDER_CLIENT_PUBLIC_KEY",
        "config": conf,
    }

# -----------------------------------------------------------------------------
# 1) One-click config (generates + downloads client .conf)
# -----------------------------------------------------------------------------
@downloads_bp.get("/download/config/<int:device_id>")
def download_config(device_id: int):
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = int(session["user_id"])

    # Verify device belongs to user and grab its name for filename
    with _db() as conn:
        d = conn.execute(
            "SELECT id, user_id, name FROM devices WHERE id = ?",
            (device_id,)
        ).fetchone()
        if not d or d["user_id"] != user_id:
            flash("Device not found.", "error")
            return redirect(url_for("dashboard.dashboard"))
        device_name = d["name"] or "device"

    # Issue config via stub (dev) or fail (real flow moved to register_key)
    try:
        if ISSUE_CONFIG_STUB:
            payload = _stub_issue_config(user_id=user_id, device_id=device_id)
        else:
            flash("Automated config generation is currently unavailable. Please use the 'Add Device' button on the dashboard for manual setup.", "error")
            return redirect(url_for("dashboard.dashboard"))
    except Exception:
        current_app.logger.exception("Config generation failed")
        flash("Server error while issuing config.", "error")
        return redirect(url_for("dashboard.dashboard"))

    if not payload.get("success"):
        flash(payload.get("message", "Failed to issue config."), "error")
        return redirect(url_for("dashboard.dashboard"))

    cfg_text = payload.get("config") or ""
    pub_key  = payload.get("public_key")
    if not cfg_text:
        current_app.logger.error("Empty config returned for device %s", device_id)
        flash("Empty config from server.", "error")
        return redirect(url_for("dashboard.dashboard"))

    # Upsert into device_configs for UI
    with _db() as conn:
        existing = conn.execute(
            "SELECT id FROM device_configs WHERE device_id = ?",
            (device_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE device_configs SET public_key = ?, config = ?, created_at = CURRENT_TIMESTAMP WHERE device_id = ?",
                (pub_key, encrypt_text(cfg_text), device_id)
            )
        else:
            conn.execute(
                "INSERT INTO device_configs (device_id, public_key, config) VALUES (?, ?, ?)",
                (device_id, pub_key, encrypt_text(cfg_text))
            )
        conn.commit()

    fname = f"Privana-{device_name}-{device_id}.conf"
    return send_file(
        io.BytesIO(cfg_text.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=fname,
        max_age=0
    )

# -----------------------------------------------------------------------------
# 2) Vendor installers (proxy/redirect)
# -----------------------------------------------------------------------------
@downloads_bp.get("/download/wireguard/<platform>")
def download_wireguard(platform: str):
    platform = platform.lower()
    if platform not in UPSTREAMS:
        return "Not found", 404

    upstream = UPSTREAMS[platform]

    # Stores/docs must open externally
    if platform in ("android", "ios", "linux"):
        return redirect(upstream, code=302)

    # Proxy the binary (Windows/macOS)
    try:
        r = requests.get(upstream, stream=True, timeout=TIMEOUT, allow_redirects=False)
        if 300 <= r.status_code < 400:
            return jsonify({"ok": False, "error": "upstream redirect blocked"}), 502
    except requests.RequestException:
        return "Upstream unavailable. Please try again later.", 502

    if r.status_code >= 400:
        return f"Upstream error ({r.status_code}).", 502

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


@downloads_bp.get("/download/wireguard/meta/<platform>")
def download_meta(platform: str):
    platform = platform.lower()
    url = UPSTREAMS.get(platform)
    if not url:
        return jsonify({"ok": False, "error": "unknown platform"}), 404

    # For store/docs, just say it's a redirect target
    if platform in ("android", "ios", "linux"):
        return jsonify({"ok": True, "type": "redirect", "url": url})

    # HEAD first; fall back to GET if needed
    try:
        r = requests.head(url, allow_redirects=False, timeout=TIMEOUT)
        if 300 <= r.status_code < 400:
            return jsonify({"ok": True, "type": "redirect_blocked", "url": url})
        if r.status_code >= 400:
            r = requests.get(url, allow_redirects=False, timeout=TIMEOUT, stream=False)
            if 300 <= r.status_code < 400:
                return jsonify({"ok": True, "type": "redirect_blocked", "url": url})
    except requests.RequestException:
        filename = _filename_from_upstream(url, {})
        return jsonify({
            "ok": True,
            "type": "binary",
            "filename": filename,
            "content_type": None,
            "size_bytes": None,
            "last_modified": None,
        })

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
        "last_modified": lm,
    })

# -----------------------------------------------------------------------------
# 3) Optional tokenized bootstrap (Windows/Linux)
# -----------------------------------------------------------------------------
def _mint_config_token(user_id: int, device_id: int, minutes: int = 10) -> str:
    token = secrets.token_urlsafe(32)
    exp = (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()
    requester_ip = _client_ip()
    with _db() as conn:
        conn.execute(
            """
            INSERT INTO config_download_tokens (
                user_id,
                device_id,
                token,
                requester_ip,
                expires_at
            )
            VALUES (?,?,?,?,?)
            """,
            (user_id, device_id, token, requester_ip, exp),
        )
        conn.commit()
    return token


@downloads_bp.get("/download/config/by-token/<token>")
@limiter.limit("10 per minute")
def download_config_by_token(token: str):
    # Validate token & get user/device
    with _db() as conn:
        row = conn.execute(
            "SELECT * FROM config_download_tokens WHERE token = ? AND used = 0",
            (token,),
        ).fetchone()
        if not row:
            return jsonify({"success": False, "message": "invalid or used token"}), 400

        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except Exception:
            current_app.logger.exception("Invalid config download token expiry")
            exp = datetime.now(timezone.utc)
        if datetime.now(timezone.utc) > exp:
            return jsonify({"success": False, "message": "token expired"}), 400

        requester_ip = row["requester_ip"]
        current_ip = _client_ip()
        if requester_ip and requester_ip != current_ip:
            conn.execute("UPDATE config_download_tokens SET used = 1 WHERE id = ?", (row["id"],))
            conn.commit()
            return jsonify({"success": False, "message": "invalid or used token"}), 400

        user_id = int(row["user_id"])
        device_id = int(row["device_id"])

    # Issue config via stub (dev) or fail (real)
    if ISSUE_CONFIG_STUB:
        payload = _stub_issue_config(user_id=user_id, device_id=device_id)
    else:
        return jsonify({"success": False, "message": "Automated config generation unavailable. Use manual registration."}), 502

    if not payload.get("success"):
        return jsonify({"success": False, "message": payload.get("message", "failed to issue config")}), 502

    cfg_text = payload.get("config") or ""
    if not cfg_text:
        return jsonify({"success": False, "message": "empty config"}), 502

    # Upsert locally and mark token used
    with _db() as conn:
        existing = conn.execute(
            "SELECT id FROM device_configs WHERE device_id = ?",
            (device_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE device_configs SET public_key = ?, config = ?, created_at = CURRENT_TIMESTAMP WHERE device_id = ?",
                (payload.get("public_key"), encrypt_text(cfg_text), device_id)
            )
        else:
            conn.execute(
                "INSERT INTO device_configs (device_id, public_key, config) VALUES (?, ?, ?)",
                (device_id, payload.get("public_key"), encrypt_text(cfg_text))
            )
        conn.execute("UPDATE config_download_tokens SET used = 1 WHERE id = ?", (row["id"],))
        conn.commit()

    fname = f"Privana-{device_id}.conf"
    return send_file(
        io.BytesIO(cfg_text.encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name=fname,
        max_age=0
    )


@downloads_bp.get("/download/bootstrap/windows/<int:device_id>")
def bootstrap_windows(device_id: int):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = int(session["user_id"])

    u = _get_user(user_id)
    if not u or not _is_subscription_ok(u):
        abort(403)
    if not _device_belongs(user_id, device_id):
        abort(404)

    token = _mint_config_token(user_id, device_id, minutes=10)
    cfg_url = public_app_url() + url_for("downloads.download_config_by_token", token=token)
    tunnel_name = f"Privana-{device_id}"

    ps = f"""#Requires -Version 5
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
  Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList "-ExecutionPolicy RemoteSigned -File `"$PSCommandPath`""
  exit
}}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tunnelName = "{tunnel_name}"
$tmp = Join-Path $env:TEMP "$tunnelName.conf"
$wgExe = Join-Path $env:ProgramFiles "WireGuard\\wireguard.exe"
Write-Host "Downloading Privana settings..." -ForegroundColor Cyan
Invoke-WebRequest -Uri "{cfg_url}" -OutFile $tmp

$configText = Get-Content -Raw -Path $tmp
if ($configText -notmatch '\\[Interface\\]' -or $configText -notmatch '\\[Peer\\]') {{
  Remove-Item -Force $tmp -ErrorAction SilentlyContinue
  throw "Downloaded Privana config is invalid."
}}
$blockedDirectives = @('PostUp', 'PostDown', 'PreUp', 'PreDown', 'Table')
foreach ($directive in $blockedDirectives) {{
  if ($configText -match "(?im)^\\s*$directive\\s*=") {{
    Remove-Item -Force $tmp -ErrorAction SilentlyContinue
    throw "Downloaded Privana config contains unsupported WireGuard directives."
  }}
}}

if (!(Test-Path $wgExe)) {{
  Start-Process "https://download.wireguard.com/windows-client/wireguard-installer.exe"
  Write-Host "Install WireGuard, then re-run this script."
  exit 1
}}
& $wgExe /installtunnelservice $tmp
Start-Sleep -Seconds 2
Write-Host "Installed. The tunnel will run in the background and auto-start on boot." -ForegroundColor Green
"""
    return Response(
        ps,
        mimetype="text/plain",
        headers={"Content-Disposition": f'attachment; filename="Privana-Setup-Windows-{device_id}.ps1"'}
    )


@downloads_bp.get("/download/bootstrap/linux/<int:device_id>")
def bootstrap_linux(device_id: int):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = int(session["user_id"])

    u = _get_user(user_id)
    if not u or not _is_subscription_ok(u):
        abort(403)
    if not _device_belongs(user_id, device_id):
        abort(404)

    token = _mint_config_token(user_id, device_id, minutes=10)
    cfg_url = public_app_url() + url_for("downloads.download_config_by_token", token=token)
    name = f"privana-{device_id}"

    sh = f"""#!/usr/bin/env bash
set -euo pipefail
NAME="{name}"
URL="{cfg_url}"
echo "[Privana] Downloading settings..."
TMP="$(mktemp)"
cleanup() {{
  rm -f "$TMP"
}}
trap cleanup EXIT

curl -fsSL "$URL" -o "$TMP"

if ! grep -q '^\\[Interface\\]' "$TMP" || ! grep -q '^\\[Peer\\]' "$TMP"; then
  echo "[Privana] Downloaded config is invalid." >&2
  exit 1
fi

if grep -Eiq '^\\s*(PostUp|PostDown|PreUp|PreDown|Table)\\s*=' "$TMP"; then
  echo "[Privana] Downloaded config contains unsupported WireGuard directives." >&2
  exit 1
fi

if ! command -v wg-quick >/dev/null 2>&1; then
  echo "[Privana] Installing wireguard-tools..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update && sudo apt install -y wireguard wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y epel-release || true
    sudo yum install -y wireguard-tools
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm wireguard-tools
  else
    echo "[Privana] Please install wireguard-tools manually." >&2
    exit 1
  fi
fi
echo "[Privana] Installing to /etc/wireguard/$NAME.conf"
sudo mkdir -p /etc/wireguard
sudo mv "$TMP" "/etc/wireguard/$NAME.conf"
TMP=""
sudo chmod 600 "/etc/wireguard/$NAME.conf"
echo "[Privana] Enabling & starting..."
if command -v systemctl >/dev/null 2>&1; then
  sudo systemctl enable --now "wg-quick@${{NAME}}"
else
  sudo wg-quick up "$NAME"
  echo "[Privana] Note: will not auto-start on boot (no systemd)."
fi
echo "[Privana] Done."
"""
    return Response(
        sh,
        mimetype="text/x-shellscript",
        headers={"Content-Disposition": f'attachment; filename="privana-setup-linux-{device_id}.sh"'}
    )
