from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify, make_response
import sqlite3
import os
from datetime import datetime, timezone
from web.utils.wireguard import (
    generate_wireguard_keys,
    generate_wireguard_config,
    check_wireguard_status,
    toggle_wireguard_protection,
    generate_platform_config,
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



# Blueprint
dashboard_bp = Blueprint("dashboard", __name__)

# ---- DB helper (use your local version to keep behavior) ----
def get_db():
    # keep your local DB helper (same as before)
    conn = sqlite3.connect("privana.db")
    conn.row_factory = sqlite3.Row
    return conn

# Ensure users.token column exists (runs once, harmless later)
def _ensure_user_token_column():
    conn = get_db()
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "token" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN token TEXT")
        conn.commit()
    conn.close()

_ensure_user_token_column()

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
    Return a dict describing trial state for the first authenticator:
      - status: 'active' | 'ended' | 'not_started'
      - days_left: int | None
      - has_passkey: bool
      - raw fields: trial_started_at, trial_consumed_at
    """
    conn = get_db()
    row = conn.execute(
        """
        SELECT id, first_seen_at, trial_started_at, trial_consumed_at
        FROM authenticators
        WHERE user_id = ?
        ORDER BY first_seen_at ASC
        LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    conn.close()

    has_passkey = bool(row)
    trial = {
        "status": "not_started",
        "days_left": None,
        "trial_started_at": None,
        "trial_consumed_at": None,
        "has_passkey": has_passkey,
    }

    if not row:
        return trial

    trial["trial_started_at"] = row["trial_started_at"]
    trial["trial_consumed_at"] = row["trial_consumed_at"]

    if row["trial_consumed_at"]:
        trial["status"] = "ended"
        trial["days_left"] = 0
        return trial

    if row["trial_started_at"]:
        try:
            started = datetime.fromisoformat(row["trial_started_at"])
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
        except Exception:
            started = None

        if started:
            now = datetime.now(timezone.utc)
            elapsed_days = (now - started).days  # floor on purpose
            remaining = TRIAL_DAYS - elapsed_days
            if remaining <= 0:
                trial["status"] = "ended"
                trial["days_left"] = 0
            else:
                trial["status"] = "active"
                trial["days_left"] = remaining
        else:
            trial["status"] = "active"
            trial["days_left"] = TRIAL_DAYS
    else:
        trial["status"] = "not_started"
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

# ----------------------------
# Routes
# ----------------------------

@dashboard_bp.route("/")
def root_to_dashboard():
    # single source of truth: /dashboard
    return redirect(url_for("dashboard.dashboard"))

@dashboard_bp.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    TRIAL_DAYS = 7  # adjust if your free-trial length changes

    # Flip trial to "consumed" after 7 days if needed
    consume_trial_if_expired(user_id)

    conn = get_db()

    # Load user (dict so we can fill defaults easily)
    user_row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_row:
        conn.close()
        flash("User not found. Please log in again.", "error")
        return redirect(url_for("auth.logout"))
    user = dict(user_row)

    user["token"] = ensure_user_token(user_id)


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
    def _parse_iso(val):
        if not val:
            return None
        try:
            return datetime.fromisoformat(val)
        except Exception:
            return None

    started_iso = user.get("trial_started_at")
    consumed_iso = user.get("trial_consumed_at")
    trial = {"status": "not_started", "days_left": TRIAL_DAYS, "has_passkey": has_passkey}

    if consumed_iso:
        trial["status"] = "ended"
        trial["days_left"] = 0
    elif started_iso:
        started_dt = _parse_iso(started_iso)
        if started_dt:
            now = datetime.now(timezone.utc)
            # Coerce naive to UTC if needed
            if started_dt.tzinfo is None:
                started_dt = started_dt.replace(tzinfo=timezone.utc)
            elapsed_days = max(0, int((now - started_dt).total_seconds() // 86400))
            days_left = max(0, TRIAL_DAYS - elapsed_days)
            trial["status"] = "active" if days_left > 0 else "ended"
            trial["days_left"] = days_left

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
        user_email=session.get("email"),
    )

# ---- Protection toggle (support both old and new URLs) ----
@dashboard_bp.route("/dashboard/toggle-protection", methods=["POST"])
@dashboard_bp.route("/toggle-protection", methods=["POST"])
def toggle_protection():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

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
            config_path = os.path.join(os.path.expanduser("~"), "privana.conf")
            with open(config_path, "w") as f:
                f.write(cfg[0])

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
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

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

@dashboard_bp.route("/account/token/regenerate", methods=["POST"])
def regenerate_token():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
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
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    name = request.form.get("name")
    platform = request.form.get("platform")

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


@dashboard_bp.route("/remove-device/<int:device_id>")
def remove_device(device_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

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

@dashboard_bp.route("/generate-config/<int:device_id>")
def generate_config(device_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "error")
        return redirect(url_for("dashboard.dashboard"))

    cfg_row = conn.execute(
        "SELECT * FROM device_configs WHERE device_id = ?",
        (device_id,),
    ).fetchone()

    if cfg_row:
        private_key = cfg_row["private_key"]
        config = cfg_row["config"]
    else:
        private_key, public_key = generate_wireguard_keys()
        server_public_key = "SERVER_PUBLIC_KEY_HERE"
        server_endpoint = "vpn.privana.pro:51820"

        config, content_type = generate_platform_config(
            user_id,
            device["name"],
            private_key,
            server_public_key,
            server_endpoint,
            device["platform"],
        )

        conn.execute(
            "INSERT INTO device_configs (device_id, private_key, public_key, config) VALUES (?, ?, ?, ?)",
            (device_id, private_key, public_key, config),
        )
        conn.commit()

    conn.close()

    # ⭐ NEW: honor ?next=... if present (works for both mobile & desktop flows)
    nxt = request.args.get("next")
    if nxt:
        return redirect(nxt)

    if device["platform"] in ["android", "ios"]:
        return redirect(url_for("dashboard.show_qr", device_id=device_id))
    else:
        response = make_response(config)
        response.headers["Content-Type"] = "text/plain"
        response.headers["Content-Disposition"] = f'attachment; filename={device["name"]}_privana.conf'
        return response

@dashboard_bp.route("/download-config/<int:device_id>")
def download_config(device_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "error")
        return redirect(url_for("dashboard.dashboard"))

    cfg_row = conn.execute(
        "SELECT config FROM device_configs WHERE device_id = ?",
        (device_id,),
    ).fetchone()

    if not cfg_row:
        # generate on the fly if missing
        private_key, public_key = generate_wireguard_keys()
        server_public_key = "SERVER_PUBLIC_KEY_HERE"
        server_endpoint = "vpn.privana.pro:51820"

        config, content_type = generate_platform_config(
            user_id,
            device["name"],
            private_key,
            server_public_key,
            server_endpoint,
            device["platform"],
        )

        conn.execute(
            "INSERT INTO device_configs (device_id, private_key, public_key, config) VALUES (?, ?, ?, ?)",
            (device_id, private_key, public_key, config),
        )
        conn.commit()
        config_to_download = config
    else:
        config_to_download = cfg_row[0]

    conn.close()

    response = make_response(config_to_download)
    response.headers["Content-Type"] = "text/plain"
    response.headers["Content-Disposition"] = f'attachment; filename={device["name"]}_privana.conf'
    return response

@dashboard_bp.route('/show-qr/<int:device_id>')
def show_qr(device_id):
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

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
    cfg_url = url_for('dashboard.qr_token_config', token=token, _external=True)

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
    img.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode('ascii')

    # Simple, fixed-width page with the QR
    html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Privana QR – {device["name"]}</title>
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
      <div class="muted">Device: <strong>{device["name"]}</strong> · Platform: <strong>{device["platform"].capitalize()}</strong></div>
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
    resp.headers["Content-Disposition"] = f'attachment; filename={row["device_name"]}_privana.conf'
    return resp



@dashboard_bp.route("/device/<int:device_id>/qr", methods=["GET"])
def ensure_config_then_show_qr(device_id):
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

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
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    conn = get_db()
    device = conn.execute(
        "SELECT * FROM devices WHERE id = ? AND user_id = ?",
        (device_id, user_id),
    ).fetchone()

    if not device:
        conn.close()
        flash("Device not found.", "error")
        return redirect(url_for("dashboard.dashboard"))

    cfg_row = conn.execute(
        "SELECT config FROM device_configs WHERE device_id = ?",
        (device_id,),
    ).fetchone()

    if not cfg_row:
        conn.close()
        flash("Configuration not found for device", "error")
        return redirect(url_for("dashboard.dashboard"))

    config = cfg_row[0]
    conn.close()

    # QR creation (same as show_qr; duplicated for stand-alone mobile page)
    try:
        lines = config.strip().split("\n")
        private_key = address = public_key = endpoint = None
        for line in lines:
            s = line.strip()
            if s.startswith("PrivateKey = "):
                private_key = s.split(" = ")[1]
            elif s.startswith("Address = "):
                address = s.split(" = ")[1]
            elif s.startswith("PublicKey = "):
                public_key = s.split(" = ")[1]
            elif s.startswith("Endpoint = "):
                endpoint = s.split(" = ")[1]

        if private_key and address and public_key and endpoint:
            simple = f"{private_key},{address},{public_key},{endpoint}"
        else:
            simple = config[:500]

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(simple)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
    except Exception:
        img_str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="

    html_content = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Privana Configuration for {device["name"]}</title>
  <style>
    body {{ font-family: Arial, sans-serif; text-align: center; margin: 40px; }}
    .qr-container {{ margin: 20px auto; display: inline-block; }}
    .instructions {{ max-width: 600px; margin: 20px auto; text-align: left; }}
    .download-btn {{ background: #4a6fa5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px; }}
  </style>
</head>
<body>
  <h1>Privana Configuration for {device["name"]}</h1>
  <div class="qr-container">
    <img src="data:image/png;base64,{img_str}" alt="WireGuard Configuration QR Code">
  </div>
  <div class="instructions">
    <h2>Instructions:</h2>
    <ol>
      <li>Install the WireGuard app from your app store</li>
      <li>Open the WireGuard app</li>
      <li>Tap the "+" button to add a new tunnel</li>
      <li>Choose "Scan from QR code"</li>
      <li>Scan the QR code shown above</li>
      <li>Name the tunnel "{device["name"]}"</li>
      <li>Toggle the tunnel to connect</li>
    </ol>
  </div>
  <a href="#" class="download-btn" onclick="downloadConfig()">Download Config File</a>

  <script>
  function downloadConfig() {{
    const configData = `{base64.b64encode(config.encode()).decode()}`;
    const blob = new Blob([atob(configData)], {{type: 'text/plain'}});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = '{device["name"]}_privana.conf';
    a.click();
    URL.revokeObjectURL(url);
  }}
  </script>
</body>
</html>
"""
    return html_content

@dashboard_bp.route("/update-device-status/<int:device_id>/<int:status>", methods=["POST"])
def update_device_status(device_id, status):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

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
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401
    r = sg_status()
    return jsonify(r.json()), r.status_code

@dashboard_bp.post("/peer/add")
def ui_peer_add():
    """
    Body JSON: { "public_key": "...", "device_id": 123 } 
    user_id is taken from session when available.
    """
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401

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
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401
    r = sg_get_peer_config(public_key)
    return jsonify(r.json()), r.status_code

@dashboard_bp.post("/peer/remove")
def ui_peer_remove():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401
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
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401
    data = request.get_json(silent=True) or {}
    public_key = (data.get("public_key") or "").strip()
    if not public_key:
        return jsonify({"success": False, "message": "public_key required"}), 400
    r = sg_update_peer_last_connected(public_key)
    return jsonify(r.json()), r.status_code

@dashboard_bp.get("/sg-stats")
def ui_sg_stats():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "auth required"}), 401
    r = sg_stats()
    return jsonify(r.json()), r.status_code
