# server/api.py
from flask import Flask, request, jsonify
import os
import json
from functools import wraps
import hmac
import hashlib
import time
import logging
import pathlib

from dotenv import load_dotenv
from pathlib import Path
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
print("   API_SECRET set:", bool(sec), "| first8:", (sec[:8] if sec else "None"))

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
NONCE_TTL = 90  # seconds; must be >= timestamp window, here we use 90s for safety
_recent_nonces: dict[str, int] = {}

def _purge_nonces(now: int) -> None:
    # Drop entries older than TTL
    stale = [n for n, t in _recent_nonces.items() if now - t > NONCE_TTL]
    for n in stale:
        _recent_nonces.pop(n, None)


# -------------------------------------------------------------------
# WireGuard manager
# -------------------------------------------------------------------
wg_manager = None
try:
    import wireguard
    wg_manager = wireguard.WireGuardManager()
    print("✅ WireGuard manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize WireGuard manager: {e}")
    wg_manager = None

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
        prev = _recent_nonces.get(nonce)
        if prev is not None and now - prev <= NONCE_TTL:
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
        _recent_nonces[nonce] = now

        return f(*args, **kwargs)
    return decorated_function


# Initialize WireGuard manager with error handling
wg_manager = None
try:
    # If your file is server/wireguard.py
    try:
        from server.wireguard import WireGuardManager
    except Exception:
        from wireguard import WireGuardManager  # fallback if running from server/ directly

    wg_manager = WireGuardManager()
    print("✅ WireGuard manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize WireGuard manager: {e}")
    wg_manager = None

# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------
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
        return jsonify({"success": False, "message": f"Error getting status: {str(e)}"})

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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route("/api/peer/add", methods=["POST"])
@auth_required
def add_peer():
    """Add a new peer to the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data or "user_id" not in data:
        return jsonify({"success": False, "message": "Missing required parameters"}), 400

    public_key = data["public_key"]
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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})
    
@app.route("/api/peer/issue-config", methods=["POST"])
@auth_required
def issue_config():
    """
    Server generates a client keypair, binds a peer to (user_id, device_id),
    and returns a complete WireGuard client config.
    """
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "user_id" not in data or "device_id" not in data:
        return jsonify({"success": False, "message": "Missing user_id/device_id"}), 400

    user_id = data["user_id"]
    device_id = data["device_id"]

    try:
        # Generate client keys (private never stored on server DB; only included in config for delivery)
        client_priv, client_pub = wg_manager.generate_client_keypair()

        # Create/Bind peer with the generated public key
        ok, peer_or_msg, assigned_ip = wg_manager.add_peer(client_pub, user_id, device_id)
        if not ok:
            return jsonify({"success": False, "message": peer_or_msg}), 400

        # Build client config with client private key + assigned IP + server details
        client_cfg = wg_manager.build_client_config(client_priv, assigned_ip)

        return jsonify({
            "success": True,
            "peer_id": peer_or_msg,
            "assigned_ip": assigned_ip,
            "public_key": client_pub,
            "config": client_cfg
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/api/peer/remove", methods=["POST"])
@auth_required
def remove_peer():
    """Remove a peer from the WireGuard server"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data:
        return jsonify({"success": False, "message": "Missing public key"}), 400

    public_key = data["public_key"]
    try:
        success, message = wg_manager.remove_peer(public_key)
        return jsonify({"success": success, "message": message})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route("/api/peer/config/<path:public_key>", methods=["GET"])
@auth_required
def get_peer_config(public_key):
    """Get the configuration for a specific peer"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        peer_config = wg_manager.get_peer_config(public_key)
        if peer_config:
            return jsonify({"success": True, "config": peer_config})
        else:
            return jsonify({"success": False, "message": "Peer not found"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route("/api/peer/update", methods=["POST"])
@auth_required
def update_peer():
    """Update peer information (e.g., last connected timestamp)"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})

    data = request.get_json(silent=True) or {}
    if "public_key" not in data:
        return jsonify({"success": False, "message": "Missing public key"}), 400

    public_key = data["public_key"]
    try:
        wg_manager.update_peer_last_connected(public_key)
        return jsonify({"success": True, "message": "Peer updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route("/api/config", methods=["GET"])
@auth_required
def get_server_config():
    """Get the server configuration"""
    if not wg_manager:
        return jsonify({"success": False, "message": "WireGuard manager not available"})
    try:
        return jsonify({"success": True, "config": wg_manager.generate_config()})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

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
        return jsonify({"success": False, "message": f"Error: {str(e)}"})
    
@app.get("/healthz")
def healthz():
    # Be robust even if wg_manager isn't defined yet / import path differs
    mgr = globals().get("wg_manager", None)
    wg_ok = bool(mgr and getattr(mgr, "wg_available", False))
    return jsonify({"ok": True, "wg_available": wg_ok})

# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------
if __name__ == "__main__":
    # single-thread, no reloader, no debug to avoid thread mix-ups with sqlite
    app.run(host="127.0.0.1", port=8080, debug=False, threaded=False)
