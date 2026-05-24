# server/pqc_routes.py
"""
Server-side Kyber-768 KEM handshake endpoint.

POST /api/pqc/init
  Request:  { "client_public_key": "<hex>" }
  Response: { "kem_ciphertext": "<hex>", "session_id": "<str>" }

The server encapsulates a shared secret under the client's ephemeral public key.
The KEM ciphertext is returned; the shared secret is stored server-side keyed by
session_id and later used to authenticate/encrypt session traffic.

This module is registered in api.py with:
    from pqc_routes import pqc_bp
    app.register_blueprint(pqc_bp)
"""

import os
import time
import hashlib
import secrets
import threading
from flask import Blueprint, request, jsonify

from kyber_py.kyber import Kyber768

pqc_bp = Blueprint("pqc", __name__)

# ---------------------------------------------------------------------------
# In-memory session store
# { session_id: { "shared_secret": bytes, "created_at": float } }
# Replace with Redis or a signed-token scheme in production.
# ---------------------------------------------------------------------------
_SESSION_TTL = 3600  # 1 hour
_sessions: dict = {}
_sessions_lock = threading.Lock()


def _purge_expired() -> None:
    cutoff = time.time() - _SESSION_TTL
    with _sessions_lock:
        expired = [sid for sid, s in _sessions.items() if s["created_at"] < cutoff]
        for sid in expired:
            del _sessions[sid]


def get_session_secret(session_id: str) -> bytes | None:
    """Retrieve the shared secret for a session (called by other routes)."""
    _purge_expired()
    with _sessions_lock:
        entry = _sessions.get(session_id)
        return entry["shared_secret"] if entry else None


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@pqc_bp.route("/api/pqc/init", methods=["POST"])
def pqc_init():
    """
    Kyber-768 KEM encapsulation.

    The client sends its ephemeral public key.
    The server encapsulates a fresh shared secret under it and returns the
    KEM ciphertext.  Both sides independently hold the same shared_secret;
    it never appears on the wire.
    """
    data = request.get_json(silent=True) or {}
    client_pub_hex = data.get("client_public_key", "")

    if not client_pub_hex:
        return jsonify({"success": False, "message": "Missing client_public_key"}), 400

    try:
        client_pub = bytes.fromhex(client_pub_hex)
    except ValueError:
        return jsonify({"success": False, "message": "Invalid hex in client_public_key"}), 400

    # Encapsulate: server derives shared_secret and produces kem_ct for client
    try:
        shared_secret, kem_ct = Kyber768.encaps(client_pub)
    except Exception:
        return jsonify({"success": False, "message": "KEM encapsulation failed"}), 500

    # Store server-side (keyed by a random session ID)
    session_id = secrets.token_hex(32)
    _purge_expired()
    with _sessions_lock:
        _sessions[session_id] = {
            "shared_secret": shared_secret,
            "created_at": time.time(),
        }

    return jsonify({
        "success":        True,
        "kem_ciphertext": kem_ct.hex(),
        "session_id":     session_id,
    })