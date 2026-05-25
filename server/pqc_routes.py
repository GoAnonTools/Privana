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

import base64
import hashlib
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path

from Crypto.Cipher import AES

from flask import Blueprint, jsonify, request
from kyber_py.kyber import Kyber768

pqc_bp = Blueprint("pqc", __name__)

KYBER768_PUBLIC_KEY_BYTES = 1184

log = logging.getLogger("privana.server.pqc")

# ---------------------------------------------------------------------------
# Durable PQC session store
#
# Shared secrets are stored in SQLite with TTL handling instead of process-local
# memory. This survives server restarts and is visible to multiple workers that
# share the same database file.
# ---------------------------------------------------------------------------
ROOT_DIR = Path(__file__).resolve().parents[1]
PQC_SESSION_DB_PATH = Path(
    os.getenv("PQC_SESSION_DB_PATH", str(ROOT_DIR / "server" / "pqc_sessions.db"))
)
_SESSION_TTL = int(os.getenv("PQC_SESSION_TTL", "3600"))  # 1 hour
_PQC_SESSION_ENC_KEY_ENV = "PQC_SESSION_ENC_KEY"


def _get_session_encryption_key() -> bytes:
    """
    Return a 32-byte AES key for encrypting PQC session secrets at rest.

    Production should set PQC_SESSION_ENC_KEY to either:
    - a 64-character hex string, or
    - a base64-encoded 32-byte value.

    Development falls back to a deterministic local-only key so tests and local
    workflows do not break, but production refuses to run without a real key.
    """
    raw = (os.getenv(_PQC_SESSION_ENC_KEY_ENV) or "").strip()

    if raw:
        try:
            if len(raw) == 64:
                key = bytes.fromhex(raw)
            else:
                key = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise RuntimeError(
                f"{_PQC_SESSION_ENC_KEY_ENV} must be 32 bytes as hex or base64."
            ) from exc

        if len(key) != 32:
            raise RuntimeError(f"{_PQC_SESSION_ENC_KEY_ENV} must decode to 32 bytes.")

        return key

    if os.getenv("ENVIRONMENT", "development").strip().lower() == "production":
        raise RuntimeError(f"{_PQC_SESSION_ENC_KEY_ENV} is required in production.")

    # Development/test fallback only. This is intentionally deterministic so
    # local smoke tests can store/retrieve sessions without extra setup.
    return hashlib.sha256(b"privana-dev-only-pqc-session-key").digest()


def _encrypt_session_secret(shared_secret: bytes) -> tuple[bytes, bytes, bytes]:
    """Encrypt a PQC shared secret using AES-256-GCM."""
    cipher = AES.new(_get_session_encryption_key(), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(shared_secret)
    return cipher.nonce, tag, ciphertext


def _decrypt_session_secret(nonce: bytes, tag: bytes, ciphertext: bytes) -> bytes:
    """Decrypt and authenticate a stored PQC shared secret."""
    cipher = AES.new(_get_session_encryption_key(), AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _pqc_db() -> sqlite3.Connection:
    """Open a short-lived SQLite connection for PQC session storage."""
    PQC_SESSION_DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(PQC_SESSION_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pqc_sessions (
            session_id TEXT PRIMARY KEY,
            encrypted_secret BLOB NOT NULL,
            nonce BLOB NOT NULL,
            tag BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_pqc_sessions_expires_at
        ON pqc_sessions(expires_at)
        """
    )
    conn.commit()
    return conn


def _purge_expired(now: int | None = None) -> None:
    """Delete expired PQC sessions."""
    now = int(time.time()) if now is None else int(now)

    conn = _pqc_db()
    try:
        conn.execute("DELETE FROM pqc_sessions WHERE expires_at <= ?", (now,))
        conn.commit()
    finally:
        conn.close()


def _store_session(session_id: str, shared_secret: bytes) -> None:
    """Persist an encrypted PQC shared secret with an expiry timestamp."""
    now = int(time.time())
    expires_at = now + _SESSION_TTL
    nonce, tag, encrypted_secret = _encrypt_session_secret(shared_secret)

    conn = _pqc_db()
    try:
        conn.execute(
            """
            INSERT INTO pqc_sessions (
                session_id,
                encrypted_secret,
                nonce,
                tag,
                created_at,
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                sqlite3.Binary(encrypted_secret),
                sqlite3.Binary(nonce),
                sqlite3.Binary(tag),
                now,
                expires_at,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def get_session_secret(session_id: str) -> bytes | None:
    """Retrieve the shared secret for a non-expired PQC session."""
    if not session_id:
        return None

    now = int(time.time())
    conn = _pqc_db()

    try:
        conn.execute("DELETE FROM pqc_sessions WHERE expires_at <= ?", (now,))
        row = conn.execute(
            """
            SELECT encrypted_secret, nonce, tag
            FROM pqc_sessions
            WHERE session_id = ?
              AND expires_at > ?
            """,
            (session_id, now),
        ).fetchone()
        conn.commit()

        if row is None:
            return None

        return _decrypt_session_secret(
            bytes(row["nonce"]),
            bytes(row["tag"]),
            bytes(row["encrypted_secret"]),
        )
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@pqc_bp.route("/api/pqc/init", methods=["POST"])
def pqc_init():
    """
    Kyber-768 KEM encapsulation.

    The client sends its ephemeral public key.
    The server encapsulates a fresh shared secret under it and returns the
    KEM ciphertext. Both sides independently hold the same shared_secret;
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

    if len(client_pub) != KYBER768_PUBLIC_KEY_BYTES:
        return jsonify({
            "success": False,
            "message": "Invalid client_public_key length",
        }), 400

    try:
        shared_secret, kem_ct = Kyber768.encaps(client_pub)
    except Exception:
        log.exception("PQC KEM encapsulation failed")
        return jsonify({"success": False, "message": "KEM encapsulation failed"}), 500

    session_id = secrets.token_hex(32)
    _purge_expired()
    _store_session(session_id, shared_secret)

    return jsonify({
        "success": True,
        "kem_ciphertext": kem_ct.hex(),
        "session_id": session_id,
    })
