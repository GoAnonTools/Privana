from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3
import os
import stat
import re
from markupsafe import escape
from datetime import datetime, timezone
from web.utils.wireguard import (
    check_wireguard_status,
    toggle_wireguard_protection,
)
import qrcode
import io
import base64
from web.routes.auth import consume_trial_if_expired, get_db as auth_get_db, TRIAL_DAYS
from itsdangerous import URLSafeSerializer, BadSignature, SignatureExpired
from urllib.parse import urljoin
from flask import request, jsonify, session
from web.utils.api_client import (
    sg_status,
    sg_add_peer,
    sg_get_peer_config,
    sg_remove_peer,
    sg_update_peer_last_connected,
    sg_stats,
)
from web.db import get_db
from web.utils.guards import (
    user_has_passkey,
    require_passkey_for_sensitive_action,
    require_passkey_for_sensitive_action_json
)




def public_app_url() -> str:
    """
    Return trusted public app URL for QR/config links.

    Security: do not rely on request.host_url or url_for(..., _external=True)
    because Host can be attacker-controlled.
    """
    base = (os.getenv("PUBLIC_APP_URL") or "").strip().rstrip("/")
    if not base:
        if os.getenv("ENVIRONMENT", "development").lower() == "production":
            raise RuntimeError("PUBLIC_APP_URL must be set in production.")
        base = "http://127.0.0.1:5000"
    if not (base.startswith("https://") or base.startswith("http://127.0.0.1") or base.startswith("http://localhost")):
        raise RuntimeError("PUBLIC_APP_URL must be https:// in production-like environments.")
    return base


# Blueprint
dashboard_bp = Blueprint("dashboard", __name__)

ALLOWED_PLATFORMS = {"windows", "macos", "mac", "linux", "android", "ios"}

def validate_device_name(value: str) -> str:
    """Allow simple human device names only."""
    value = (value or "").strip()

    if not 1 <= len(value) <= 40:
        raise ValueError("Device name must be between 1 and 40 characters.")

    if not re.fullmatch(r"[A-Za-z0-9 _.\-]+", value):
        raise ValueError("Device name can only contain letters, numbers, spaces, dots, dashes, and underscores.")

    return value


def validate_platform(value: str) -> str:
    value = (value or "").strip().lower()

    if value not in ALLOWED_PLATFORMS:
        raise ValueError("Unsupported platform.")

    return "macos" if value == "mac" else value

# ---- User token helper ----

import secrets

def ensure_user_token(user_id: int) -> str:
    conn = get_db()
    row = conn.execute("SELECT token FROM users WHERE id = ?", (user_id,)).fetchone()
    if row and row["token"]:
        conn.close()
        return row["token"]
    new_token = secrets.token_urlsafe(32)
    conn.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, user_id))
    conn.commit()
    conn.close()
    return new_token


def _qr_serializer() -> URLSafeSerializer:
    # Uses your Flask SECRET_KEY
    from flask import current_app
    return URLSafeSerializer(current_app.config["SECRET_KEY"], salt="qr-config")


# ---- Trial helper for banner/CTA ----
def _trial_context(user_id: int):
    """
    Return trial state from users table.
    Source of truth:
      - users.trial_started_at
      - users.trial_expires_at
      - users.trial_consumed_at
    """
    consume_trial_if_expired(user_id)

    conn = get_db()
    row = conn.execute(
        """
        SELECT trial_started_at, trial_expires_at, trial_consumed_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    conn.close()

    trial = {
        "status": "not_started",
        "days_left": None,
        "trial_started_at": None,
        "trial_expires_at": None,
        "trial_consumed_at": None,
    }

    if not row:
        return trial

    trial["trial_started_at"] = row["trial_started_at"]
    trial["trial_expires_at"] = row["trial_expires_at"]
    trial["trial_consumed_at"] = row["trial_consumed_at"]

    if row["trial_consumed_at"]:
        trial["status"] = "ended"
        trial["days_left"] = 0
        return trial

    if not row["trial_started_at"] or not row["trial_expires_at"]:
        trial["status"] = "not_started"
        trial["days_left"] = TRIAL_DAYS
        return trial

    try:
        expires = datetime.fromisoformat(row["trial_expires_at"])
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        seconds_left = max(0, int((expires - now).total_seconds()))
        days_left = (seconds_left + 86399) // 86400

        if seconds_left <= 0:
            trial["status"] = "ended"
            trial["days_left"] = 0
        else:
            trial["status"] = "active"
            trial["days_left"] = days_left

    except Exception:
        trial["status"] = "active"
        trial["days_left"] = TRIAL_DAYS

    return trial

# ---- Plan limit helper (unchanged) ----
def get_device_limit_for_plan(plan):
    limits = {
        "trial": 1,
        "individual": 3,
        "family": 6,
        "small team": 10,
    }
    return limits.get((plan or "").lower(), 1)

def check_device_limit(user_id):
    """Check if user has reached their device limit"""
    conn = get_db()
    user_data = conn.execute(
        """
        SELECT u.subscription_plan, u.device_limit, COUNT(d.id) as device_count
        FROM users u
        LEFT JOIN devices d ON u.id = d.user_id
        WHERE u.id = ?
        GROUP BY u.id
        """,
        (user_id,),
    ).fetchone()
    conn.close()

    if not user_data:
        return False, "User not found"

    subscription_plan = user_data["subscription_plan"]
    device_limit = user_data["device_limit"] or get_device_limit_for_plan(subscription_plan)
    device_count = user_data["device_count"] or 0

    if device_count >= device_limit:
        return False, f"You've reached your device limit ({device_limit}) for your {subscription_plan} plan"

    return True, f"You can add {device_limit - device_count} more device(s)"

def is_trial_expired_for_user(user_id: int) -> bool:
    """Return True when a trial user has consumed/expired their trial."""
    consume_trial_if_expired(user_id)

    conn = get_db()
    row = conn.execute(
        "SELECT subscription_plan, trial_consumed_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    conn.close()

    if not row:
        return True

    plan = (row["subscription_plan"] or "trial").lower()
    return plan == "trial" and bool(row["trial_consumed_at"])


def require_active_dashboard():
    """Guard for normal page routes."""
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    if is_trial_expired_for_user(int(session["user_id"])):
        return redirect(url_for("auth.trial_ended"))

    return None


def require_active_dashboard_json():
    """Guard for JSON/browser action routes."""
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    if is_trial_expired_for_user(int(session["user_id"])):
        return jsonify({
            "success": False,
            "message": "Trial expired",
            "redirect": url_for("auth.trial_ended"),
        }), 403

    return None

# ----------------------------
# Routes
# ----------------------------

@dashboard_bp.route("/")
def root_to_dashboard():
    # single source of truth: /dashboard
    return redirect(url_for("dashboard.dashboard"))

@dashboard_bp.route("/dashboard")
def dashboard():
    guard = require_active_dashboard()
    if guard:
        return guard

    user_id = session["user_id"]
    TRIAL_DAYS = 7  # adjust if your free-trial length changes

    conn = get_db()

    # Load user (dict so we can fill defaults easily)
    user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        conn.close()
        flash("User not found. Please log in again.", "error")
        return redirect(url_for("auth.logout"))
    user = dict(user_row)

    # Do not render the account token into dashboard HTML. It can be revealed
    # through a protected POST endpoint only when explicitly requested.

    # Ensure device_limit exists (fallback from plan)
    if user.get("device_limit") is None:
        plan = (user.get("subscription_plan") or "trial")
        limit = get_device_limit_for_plan(plan)
        user["device_limit"] = limit
        try:
            conn.execute("UPDATE users SET device_limit = ? WHERE id = ?", (limit, user_id))
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # Devices (with config presence)
    devices = conn.execute(
        """
        SELECT d.*,
               dc.config IS NOT NULL AS has_config,
               dc.created_at AS config_created_at
        FROM devices d
        LEFT JOIN device_configs dc ON d.id = dc.device_id
        WHERE d.user_id = ?
        ORDER BY d.created_at DESC
        """,
        (user_id,),
    ).fetchall()

    # Passkey presence
    has_passkey = bool(
        conn.execute("SELECT 1 FROM authenticators WHERE user_id = ? LIMIT 1", (user_id,)).fetchone()
    )

    # Real protection status (your helper)
    protection_status = check_wireguard_status()

    # Compute usage summary for the bar
    device_count = len(devices)
    device_limit = user.get("device_limit") or 1
    percent = int(round((device_count / device_limit) * 100)) if device_limit else 0
    usage_percent_str = f"{max(0, min(100, percent))}%"
    usage_summary = f"{device_count} / {device_limit}"

    # Trial banner context (status + days_left)
    trial = _trial_context(user_id)

    # WireGuard download links (you also have the local /download routes elsewhere)
    wireguard_downloads = {
        "windows": "https://www.wireguard.com/install/",
        "macos": "https://www.wireguard.com/install/",
        "linux": "https://www.wireguard.com/install/",
        "android": "https://www.wireguard.com/install/",
        "ios": "https://www.wireguard.com/install/",
    }

    conn.close()

    return render_template(
        "dashboard.html",
        user=user,
        devices=devices,
        protection_status=protection_status,
        usage_percent_str=usage_percent_str,
        usage_summary=usage_summary,
        trial=trial,
        TRIAL_DAYS=TRIAL_DAYS,
        has_passkey=has_passkey,
        wireguard_downloads=wireguard_downloads,
    )

# ---- Protection toggle (support both old and new URLs) ----
@dashboard_bp.route("/dashboard/toggle-protection", methods=["POST"])
@dashboard_bp.route("/toggle-protection", methods=["POST"])
def toggle_protection():
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard

    is_connected = check_wireguard_status()
    try:
        if is_connected:
            # Bring down interface
            success, message = toggle_wireguard_protection(None, enable=False)
            status = "unprotected"
        else:
            # Bring up interface using first available config
            conn = get_db()
            cfg = conn.execute(
                """
                SELECT dc.config
                FROM device_configs dc
                JOIN devices d ON dc.device_id = d.id
                WHERE d.user_id = ?
                LIMIT 1
                """,
                (session["user_id"],),
            ).fetchone()
            conn.close()

            if not cfg:
                return jsonify({"success": False, "message": "No device configuration found"}), 400

            # Save config temporarily (same behavior as your code)
            config_path = os.path.join(os.path.expanduser("~"), ".privana", "privana.conf")
            fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
            try:
                os.write(fd, config.encode("utf-8"))
            finally:
                os.close(fd)

            try:
                os.chmod(config_path, 0o600)
            except Exception:
                pass

            success, message = toggle_wireguard_protection(config_path, enable=True)
            status = "protected"

        if success:
            return jsonify({"success": True, "message": message, "status": status})
        else:
            return jsonify({"success": False, "message": message})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

# ---- Device polling (support both old and new URLs) ----
@dashboard_bp.route("/dashboard/check-devices-status")
@dashboard_bp.route("/check-devices-status")
def check_devices_status():
    guard = require_active_dashboard_json()
    if guard:
        return guard

    user_id = session["user_id"]
    conn = get_db()
    rows = conn.execute(
        "SELECT id, name, platform, is_connected, last_connected FROM devices WHERE user_id = ?",
        (user_id,),
    ).fetchall()
    conn.close()

    devices = [
        {
            "id": r["id"],
            "name": r["name"],
            "platform": r["platform"],
            "is_connected": bool(r["is_connected"]),
            "last_connected": r["last_connected"],
        }
        for r in rows
    ]
    return jsonify({"success": True, "devices": devices})


@dashboard_bp.route("/account/token/reveal", methods=["POST"])
def reveal_token():
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard

    token = ensure_user_token(int(session["user_id"]))
    return jsonify({"success": True, "token": token})


@dashboard_bp.route("/account/token/regenerate", methods=["POST"])
def regenerate_token():
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard
    import secrets
    new_token = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, session["user_id"]))
    conn.commit()
    conn.close()
    flash("New token generated.", "success")
    return redirect(url_for("dashboard.dashboard"))


# ---- CRUD/Actions (unchanged behavior, cleaned a bit) ----
@dashboard_bp.route("/add-device", methods=["POST"])
def add_device():
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = session["user_id"]
    try:
        name = validate_device_name(request.form.get("name"))
        platform = validate_platform(request.form.get("platform"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("dashboard.dashboard"))

    can_add, message = check_device_limit(user_id)
    if not can_add:
        flash(message or f"You’ve hit the maximum number of devices for your plan.", "error")
        return redirect(url_for("dashboard.dashboard", limit="reached"))

    conn = get_db()
    conn.execute(
        "INSERT INTO devices (user_id, name, platform) VALUES (?, ?, ?)",
        (user_id, name, platform),
    )
    conn.commit()
    conn.close()

    flash("Device added successfully!", "success")
    return redirect(url_for("dashboard.dashboard"))


@dashboard_bp.route("/remove-device/<int:device_id>", methods=["POST"])
def remove_device(device_id):
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = session["user_id"]
    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if device:
        conn.execute("DELETE FROM device_configs WHERE device_id = ?", (device_id,))
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
        flash("Device removed successfully!", "success")
    else:
        flash("Device not found.", "error")

    conn.close()
    return redirect(url_for("dashboard.dashboard"))

@dashboard_bp.post("/register-key/<int:device_id>")
def register_key(device_id):
    """
    Browser-facing endpoint for the proper client-side key generation flow.

    The browser generates a WireGuard keypair using WebCrypto, sends ONLY the
    public key here, and receives back a config template with
    PrivateKey = PLACEHOLDER. The browser substitutes PLACEHOLDER with the real
    private key before triggering the download — the private key never touches
    the server.

    Body JSON: { "public_key": "<base64 WireGuard public key>" }
    Returns JSON: { "success": true, "config": "<.conf text with PLACEHOLDER>" }
    """
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard

    user_id = int(session["user_id"])
    data = request.get_json(silent=True) or {}
    public_key = (data.get("public_key") or "").strip()

    if not public_key:
        return jsonify({"success": False, "message": "public_key is required"}), 400

    # Basic sanity check: WireGuard public keys are 44-char base64
    import re
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', public_key):
        return jsonify({"success": False, "message": "invalid public_key format"}), 400

    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        return jsonify({"success": False, "message": "device not found"}), 404

    # Call the VPN server to register the public key and get an assigned IP
    try:
        r = sg_add_peer(public_key=public_key, user_id=user_id, device_id=device_id)
        payload = r.json()
    except Exception as e:
        conn.close()
        return jsonify({"success": False, "message": f"VPN server error: {e}"}), 502

    if not payload.get("success"):
        conn.close()
        return jsonify({"success": False, "message": payload.get("message", "peer registration failed")}), 400

    assigned_ip = payload.get("assigned_ip", "")
    server_public_key = os.getenv("WG_SERVER_PUBLIC_KEY", "")
    server_endpoint   = os.getenv("WG_SERVER_ENDPOINT", "vpn.privana.pro:51820")
    dns               = os.getenv("WG_DNS", "1.1.1.1, 1.0.0.1")

    # Config template — private key is a placeholder, filled in by the browser
    config_template = f"""[Interface]
PrivateKey = PLACEHOLDER
Address = {assigned_ip}
DNS = {dns}

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
PersistentKeepalive = 25
"""

    # Upsert into device_configs — no private key stored
    existing = conn.execute(
        "SELECT id FROM device_configs WHERE device_id = ?", (device_id,)
    ).fetchone()
    if existing:
        conn.execute(
            "UPDATE device_configs SET public_key=?, assigned_ip=?, config=?, created_at=datetime('now') WHERE device_id=?",
            (public_key, assigned_ip, config_template, device_id),
        )
    else:
        conn.execute(
            "INSERT INTO device_configs (device_id, public_key, assigned_ip, config) VALUES (?,?,?,?)",
            (device_id, public_key, assigned_ip, config_template),
        )
    conn.execute(
        "UPDATE devices SET has_config=1, config_created_at=datetime('now') WHERE id=?",
        (device_id,),
    )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "config": config_template})

@dashboard_bp.route('/show-qr/<int:device_id>')
def show_qr(device_id):
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = session['user_id']
    conn = get_db()

    # Verify ownership
    device = conn.execute(
        'SELECT * FROM devices WHERE id = ? AND user_id = ?',
        (device_id, user_id)
    ).fetchone()
    if not device:
        conn.close()
        flash('Device not found.', 'error')
        return redirect(url_for('dashboard.dashboard'))

    # Ensure a config exists for this device
    row = conn.execute(
        'SELECT config FROM device_configs WHERE device_id = ?',
        (device_id,)
    ).fetchone()

    if not row or not row['config']:
        conn.close()
        # generate then come back to QR
        return redirect(url_for('dashboard.generate_config',
                                device_id=device_id,
                                next=url_for('dashboard.show_qr', device_id=device_id)))
    conn.close()

    # Create a short-lived, signed token that encodes (user_id, device_id)
    s = _qr_serializer()
    token = s.dumps({"u": user_id, "d": device_id})

    # Absolute URL the phone will open to fetch the config
    cfg_url = public_app_url() + url_for('dashboard.qr_token_config', token=token)

    # Make a compact QR for that URL
    import qrcode, io, base64
    qr = qrcode.QRCode(
        version=None,  # auto
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=6,
        border=1,
    )
    qr.add_data(cfg_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf)
    img_b64 = base64.b64encode(buf.getvalue()).decode('ascii')

    # Simple, fixed-width page with the QR
    safe_device_name = escape(device["name"])
    safe_platform = escape((device["platform"] or "").capitalize())

    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Privana QR – {safe_device_name}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    :root {{
      --border:#e5e7eb; --text:#0f172a; --muted:#64748b; --brand1:#0ea5e9; --brand2:#2563eb;
    }}
    html,body{{margin:0;padding:0;background:#fff;color:var(--text);font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;}}
    .wrap{{max-width:420px;margin:32px auto;padding:0 16px;}}
    .card{{border:1px solid var(--border);border-radius:14px;padding:16px;box-shadow:0 10px 24px rgba(2,6,23,.06)}}
    h1{{margin:0 0 8px;font-size:18px}}
    .muted{{color:var(--muted);font-size:13px;margin-bottom:12px}}
    .qr{{display:grid;place-items:center;min-height:320px}}
    .qr img{{width:300px;height:300px;image-rendering:pixelated}}
    .row{{display:flex;justify-content:space-between;align-items:center;margin-top:12px;gap:8px;flex-wrap:wrap}}
    .btn{{display:inline-block;text-decoration:none;padding:10px 14px;border-radius:10px;font-weight:700;border:1px solid var(--border)}}
    .btn-primary{{background:linear-gradient(90deg,var(--brand1),var(--brand2));color:#fff;border:0}}
    .mono{{font-family:ui-monospace, SFMono-Regular, Menlo, monospace; font-size:12px}}
    .note{{margin-top:10px;color:var(--muted);font-size:13px;text-align:center}}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <h1>Scan in WireGuard</h1>
      <div class="muted">Device: <strong>{safe_device_name}</strong> · Platform: <strong>{safe_platform}</strong></div>
      <div class="qr">
        <img src="data:image/png;base64,{img_b64}" alt="WireGuard config QR" />
      </div>
      <div class="note">Scan the code with your phone. It will download the config file.</div>
      <div class="row">
        <a class="btn" href="{url_for('dashboard.dashboard')}">Back</a>
        <a class="btn btn-primary" href="{cfg_url}">Open on this device</a>
      </div>
    </div>
  </div>
</body>
</html>"""
    return html

@dashboard_bp.route('/qr-config/<token>')
def qr_token_config(token):
    """
    Validates the short token from the QR and returns the .conf as a download.
    No login required; token is the auth (short-lived).
    """
    s = _qr_serializer()
    try:
        # 10 minutes validity
        payload = s.loads(token, max_age=600)
    except SignatureExpired:
        flash("This QR expired. Generate a new one.", "error")
        return redirect(url_for('dashboard.dashboard'))
    except BadSignature:
        flash("Invalid QR.", "error")
        return redirect(url_for('dashboard.dashboard'))

    user_id = payload.get("u")
    device_id = payload.get("d")
    if not user_id or not device_id:
        flash("Invalid QR.", "error")
        return redirect(url_for('dashboard.dashboard'))

    # Fetch config ensuring ownership
    conn = get_db()
    row = conn.execute(
        """
        SELECT d.name AS device_name, dc.config
        FROM devices d
        JOIN device_configs dc ON dc.device_id = d.id
        WHERE d.id = ? AND d.user_id = ?
        """,
        (device_id, user_id),
    ).fetchone()
    conn.close()

    if not row or not row["config"]:
        flash("Config not found. Generate it first.", "error")
        return redirect(url_for('dashboard.dashboard'))

    # Serve as a file download; mobile OS will offer “Open in WireGuard”
    resp = make_response(row["config"])
    resp.headers["Content-Type"] = "text/plain"
    safe_filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", row["device_name"] or "device")
    resp.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}_privana.conf"'
    return resp



@dashboard_bp.route("/device/<int:device_id>/qr", methods=["GET"])
def ensure_config_then_show_qr(device_id):
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    user_id = session["user_id"]
    conn = get_db()

    # Owns device?
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "error")
        return redirect(url_for("dashboard.dashboard"))

    # Has config?
    config_row = conn.execute(
        "SELECT 1 FROM device_configs WHERE device_id = ?",
        (device_id,),
    ).fetchone()
    conn.close()

    if config_row:
        # Already have a config → show QR immediately
        return redirect(url_for("dashboard.show_qr", device_id=device_id))
    else:
        # No config yet → generate it, then come back to QR
        nxt = url_for("dashboard.show_qr", device_id=device_id)
        return redirect(url_for("dashboard.generate_config", device_id=device_id, next=nxt))

@dashboard_bp.route("/mobile-config/<int:device_id>")
def mobile_config(device_id):
    """Redirects to the QR flow which handles mobile config display securely."""
    guard = require_active_dashboard()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action()
    if guard:
        return guard

    return redirect(url_for("dashboard.show_qr", device_id=device_id))


@dashboard_bp.route("/update-device-status/<int:device_id>/<int:status>", methods=["POST"])
def update_device_status(device_id, status):
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard

    user_id = session["user_id"]
    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        return jsonify({"success": False, "message": "Device not found"}), 404

    if status == 1:
        conn.execute(
            "UPDATE devices SET is_connected = 1, last_connected = CURRENT_TIMESTAMP WHERE id = ?",
            (device_id,),
        )
    else:
        conn.execute(
            "UPDATE devices SET is_connected = 0 WHERE id = ?",
            (device_id,),
        )
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Device status updated"})

# ----------------------------
# Panama API passthroughs (signed HMAC)
# These are under /dashboard because app.py registers: url_prefix="/dashboard"
# ----------------------------

@dashboard_bp.get("/sg-status")
def ui_sg_status():
    guard = require_active_dashboard_json()
    if guard:
        return guard
    r = sg_status()
    return jsonify(r.json()), r.status_code

@dashboard_bp.post("/peer/add")
def ui_peer_add():
    """
    Body JSON: { "public_key": "...", "device_id": 123 } 
    user_id is taken from session when available.
    """
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard

    data = request.get_json(silent=True) or {}
    public_key = (data.get("public_key") or "").strip()
    device_id = data.get("device_id")

    if not public_key:
        return jsonify({"success": False, "message": "public_key required"}), 400

    user_id = int(session["user_id"])
    r = sg_add_peer(public_key=public_key, user_id=user_id, device_id=device_id)
    return jsonify(r.json()), r.status_code

@dashboard_bp.get("/peer/config/<public_key>")
def ui_peer_config(public_key):
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard
    r = sg_get_peer_config(public_key)
    return jsonify(r.json()), r.status_code

@dashboard_bp.post("/peer/remove")
def ui_peer_remove():
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    public_key = (data.get("public_key") or "").strip()
    if not public_key:
        return jsonify({"success": False, "message": "public_key required"}), 400
    r = sg_remove_peer(public_key)
    return jsonify(r.json()), r.status_code

@dashboard_bp.post("/peer/heartbeat")
def ui_peer_heartbeat():
    """
    Optional: clients can call this to record 'last connected'.
    Body JSON: { "public_key": "..." }
    """
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard
    data = request.get_json(silent=True) or {}
    public_key = (data.get("public_key") or "").strip()
    if not public_key:
        return jsonify({"success": False, "message": "public_key required"}), 400
    r = sg_update_peer_last_connected(public_key)
    return jsonify(r.json()), r.status_code

@dashboard_bp.get("/sg-stats")
def ui_sg_stats():
    guard = require_active_dashboard_json()
    if guard:
        return guard

    guard = require_passkey_for_sensitive_action_json()
    if guard:
        return guard
    r = sg_stats()
    return jsonify(r.json()), r.status_code
