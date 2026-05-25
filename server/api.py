# server/api.py
from flask import Flask, request, jsonify
import os
import sqlite3
import json
from functools import wraps
import hmac
import hashlib
import time
import logging
import pathlib
from pathlib import Path

from dotenv import load_dotenv
import config

# -------------------------------------------------------------------
# Load .env from project root (parent of /server), override defaults
# -------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env", override=True)

# -------------------------------------------------------------------
# Flask app & config
# -------------------------------------------------------------------
app = Flask(__name__)
app.config.from_object(config.get_config())

# Force .env to override config defaults (explicit and clear)
app.config["API_SECRET"] = os.getenv("API_SECRET", app.config.get("API_SECRET", ""))
app.config["ENVIRONMENT"] = os.getenv("ENVIRONMENT", app.config.get("ENVIRONMENT", "development"))

# Debug banner (don’t print full secret)
sec = app.config.get("API_SECRET", "")
print("🔍 Flask app config loaded:")
print("   Environment:", app.config.get("ENVIRONMENT"))
print("   API_SECRET configured:", bool(sec))


# -------------------------------------------------------------------
# API security headers
# -------------------------------------------------------------------
@app.after_request
def _add_api_security_headers(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if app.config.get("ENVIRONMENT") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# -------------------------------------------------------------------
# Simple file logger for security/auth failures (server/logs/security.log)
# -------------------------------------------------------------------
LOG_DIR = pathlib.Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
api_log = logging.getLogger("api_security")
api_log.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_DIR / "security.log", encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
if not api_log.handlers:
    api_log.addHandler(fh)

# -------------------------------------------------------------------
# Replay protection (nonce cache)
# -------------------------------------------------------------------
NONCE_TTL = 90  # seconds; must be >= timestamp window

NONCE_DB_PATH = Path(os.getenv("NONCE_DB_PATH", str(ROOT_DIR / "server" / "nonces.db")))


def _nonce_db():
    conn = sqlite3.connect(NONCE_DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce TEXT PRIMARY KEY,
            used_at INTEGER NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def _purge_nonces(now: int) -> None:
    cutoff = now - NONCE_TTL
    conn = _nonce_db()
    conn.execute("DELETE FROM used_nonces WHERE used_at < ?", (cutoff,))
    conn.commit()
    conn.close()


def _nonce_already_used(nonce: str, now: int) -> bool:
    conn = _nonce_db()
    row = conn.execute(
        "SELECT used_at FROM used_nonces WHERE nonce = ?",
        (nonce,),
    ).fetchone()
    conn.close()

    if not row:
        return False

    return now - int(row[0]) <= NONCE_TTL


def _mark_nonce_used(nonce: str, now: int) -> bool:
    """
    Return True if nonce was stored.
    Return False if it was already present.
    """
    conn = _nonce_db()
    try:
        conn.execute(
            "INSERT INTO used_nonces (nonce, used_at) VALUES (?, ?)",
            (nonce, now),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


# -------------------------------------------------------------------
# WireGuard manager
# -------------------------------------------------------------------
wg_manager = None
try:
    try:
        from server.wireguard import WireGuardManager
    except (ImportError, ModuleNotFoundError):
        from wireguard import WireGuardManager

    wg_manager = WireGuardManager()
    print("✅ WireGuard manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize WireGuard manager: {e}")
    wg_manager = None



def _validate_api_wg_public_key(value):
    """
    Validate WireGuard public keys at the API boundary.

    WireGuard public keys are base64 strings with 43 base64 characters plus
    one trailing "=" padding character. Rejecting invalid values here prevents
    malformed input from reaching wg subprocess calls or peer lookups.
    """
    try:
        try:
            from server.wireguard import validate_wg_public_key
        except (ImportError, ModuleNotFoundError):
            from wireguard import validate_wg_public_key

        return validate_wg_public_key(value)
    except ValueError:
        return None


# -------------------------------------------------------------------
# HMAC auth middleware
#   - Authorization: <hex sha256 hmac>
#   - X-Timestamp: <unix seconds>
#   - Message = "{ts}:{METHOD}:{PATH}:{body}"
#   - NOTE: This provides integrity + simple anti-replay window (±30s).
#           For true replay prevention, add a nonce store later.
# -------------------------------------------------------------------
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        timestamp = request.headers.get("X-Timestamp")
        nonce = request.headers.get("X-Nonce")

        if not auth_header or not timestamp:
            api_log.warning(f"auth_failed reason=missing_headers ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Missing auth headers"}), 401

        if not nonce:
            api_log.warning(f"auth_failed reason=missing_nonce ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Missing nonce"}), 401

        try:
            ts = int(timestamp)
        except ValueError:
            api_log.warning(f"auth_failed reason=bad_timestamp ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Invalid timestamp"}), 401

        now = int(time.time())

        # Reject requests older than 30 seconds
        if abs(now - ts) > 30:
            api_log.warning(f"auth_failed reason=expired ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Request expired"}), 401

        # Purge old nonces and check replay
        _purge_nonces(now)

        if _nonce_already_used(nonce, now):
            api_log.warning(f"auth_failed reason=replay nonce={nonce[:8]} ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Replay detected"}), 401

        # Compute expected HMAC (note the nonce included in the message)
        method = request.method.upper()
        path = request.path
        body = request.get_data(as_text=True) or ""  # client signs deterministic JSON

        message = f"{ts}:{method}:{path}:{body}:{nonce}"
        expected_sig = hmac.new(
            app.config["API_SECRET"].encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        # DEBUG (optional)
        if os.getenv("HMAC_DEBUG", "").lower() == "true":
            print(
                "HMAC debug:",
                "method=", method,
                "path=", path,
                "len(body)=", len(body),
                "nonce=", nonce[:8],
                "expected=", expected_sig[:16],
                "got=", (auth_header or "")[:16],
            )

        if not hmac.compare_digest(auth_header, expected_sig):
            api_log.warning(f"auth_failed reason=bad_hmac ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        # Mark nonce as used after successful verification
        if not _mark_nonce_used(nonce, now):
            api_log.warning(f"auth_failed reason=replay_insert nonce={nonce[:8]} ip={request.remote_addr} path={request.path}")
            return jsonify({"success": False, "message": "Replay detected"}), 401

        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
def _api_error_response(client_message: str = "Internal server error", status: int = 500):
    """Return a generic API error without leaking internal exception details."""
    return jsonify({"success": False, "message": client_message}), status


@app.route("/api/status", methods=["GET"])
@auth_required
def get_status():
    """Get the status of the WireGuard server"""
    if not wg_manager:
        return jsonify({
            "success": False,
            "message": "WireGuard manager not available",
            "is_running": False,
            "status_output": "Manager not initialized",
            "peers_count": 0,
            "peers": []
        })

    try:
        is_running, status_output = wg_manager.get_interface_status()
        peers = wg_manager.list_peers()
        return jsonify({
            "success": True,
            "is_running": is_running,
            "status_output": status_output,
            "peers_count": len(peers),
            "peers": peers
        })
    except Exception as e:
        api_log.exception("status endpoint failed")
        return _api_error_response("Failed to get status")

@app.route("/api/start", methods=["POST"])
@auth_required
def start_server():
    """Start the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        success, message = wg_manager.start_interface()
        return jsonify({"success": success, "message": message})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/stop", methods=["POST"])
@auth_required
def stop_server():
    """Stop the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        success, message = wg_manager.stop_interface()
        return jsonify({"success": success, "message": message})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/restart", methods=["POST"])
@auth_required
def restart_server():
    """Restart the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        wg_manager.stop_interface()
        success, message = wg_manager.start_interface()
        return jsonify({"success": success, "message": message})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/peer/add", methods=["POST"])
@auth_required
def add_peer():
    """Add a new peer to the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data or "user_id" not in data:
        return jsonify({"success": False, "message": "Missing required parameters"}), 400

    public_key = _validate_api_wg_public_key(data["public_key"])
    if not public_key:
        return jsonify({"success": False, "message": "Invalid WireGuard public key"}), 400

    user_id = data["user_id"]
    device_id = data.get("device_id")

    try:
        success, result_or_message, assigned_ip = wg_manager.add_peer(public_key, user_id, device_id)
        if success:
            peer_config = wg_manager.get_peer_config(public_key)
            return jsonify({
                "success": True,
                "message": "Peer added successfully",
                "peer_id": result_or_message,
                "assigned_ip": assigned_ip,
                "config": peer_config
            })
        else:
            return jsonify({"success": False, "message": result_or_message})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()


@app.route("/api/peer/remove", methods=["POST"])
@auth_required
def remove_peer():
    """Remove a peer from the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data:
        return jsonify({"success": False, "message": "Missing public key"}), 400

    public_key = _validate_api_wg_public_key(data["public_key"])
    if not public_key:
        return jsonify({"success": False, "message": "Invalid WireGuard public key"}), 400

    try:
        success, message = wg_manager.remove_peer(public_key)
        return jsonify({"success": success, "message": message})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/peer/config/<path:public_key>", methods=["GET"])
@auth_required
def get_peer_config(public_key):
    """Get the configuration for a specific peer"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    public_key = _validate_api_wg_public_key(public_key)
    if not public_key:
        return jsonify({"success": False, "message": "Invalid WireGuard public key"}), 400

    try:
        peer_config = wg_manager.get_peer_config(public_key)
        if peer_config:
            return jsonify({"success": True, "config": peer_config})
        else:
            return jsonify({"success": False, "message": "Peer not found"})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/peer/update", methods=["POST"])
@auth_required
def update_peer():
    """Update peer information (e.g., last connected timestamp)"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data:
        return jsonify({"success": False, "message": "Missing public key"}), 400

    public_key = _validate_api_wg_public_key(data["public_key"])
    if not public_key:
        return jsonify({"success": False, "message": "Invalid WireGuard public key"}), 400

    try:
        wg_manager.update_peer_last_connected(public_key)
        return jsonify({"success": True, "message": "Peer updated successfully"})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/stats", methods=["GET"])
@auth_required
def get_stats():
    """Get WireGuard interface statistics"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        stats = wg_manager.get_stats()
        if stats:
            return jsonify({"success": True, "stats": stats})
        else:
            return jsonify({"success": False, "message": "Failed to get stats"})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

@app.route("/api/config", methods=["GET"])
@auth_required
def get_server_config():
    """Get the server configuration"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        return jsonify({"success": True, "config": wg_manager.generate_config(include_private_key=False)})
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()

# Optional: simple health snapshot (still HMAC-protected)
@app.route("/api/health", methods=["GET"])
@auth_required
def api_health():
    ok = bool(wg_manager)
    try:
        is_running, _ = wg_manager.get_interface_status() if wg_manager else (False, "")
        peers = wg_manager.list_peers() if wg_manager else []
        return jsonify({
            "success": True,
            "wg_manager": ok,
            "is_running": is_running,
            "peers_count": len(peers)
        })
    except Exception as e:
        api_log.exception("API endpoint failed")
        return _api_error_response()
    
@app.get("/healthz")
def healthz():
    """
    Public liveness endpoint.

    Security: keep this intentionally minimal. Do not expose WireGuard,
    filesystem, dependency, or infrastructure state here.
    """
    return jsonify({"ok": True})

# -------------------------------------------------------------------
# PQC blueprint
# -------------------------------------------------------------------
try:
    try:
        from server.pqc_routes import pqc_bp
    except (ImportError, ModuleNotFoundError):
        from pqc_routes import pqc_bp
    app.register_blueprint(pqc_bp)

    # Protect the PQC KEM endpoint with the same HMAC+nonce auth as the rest
    # of the API. Wrapping after blueprint registration avoids a circular import
    # between server/api.py and server/pqc_routes.py.
    pqc_endpoint = "pqc.pqc_init"
    if pqc_endpoint in app.view_functions:
        app.view_functions[pqc_endpoint] = auth_required(app.view_functions[pqc_endpoint])
    else:
        raise RuntimeError("PQC endpoint was not registered as expected.")

    print("✅ PQC blueprint registered and protected (/api/pqc/init)")
except Exception as e:
    print(f"❌ Failed to register PQC blueprint: {e}")

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    # single-thread, no reloader, no debug to avoid thread mix-ups with sqlite
    app.run(host="127.0.0.1", port=8080, debug=False, threaded=False)