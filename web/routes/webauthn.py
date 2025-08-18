# web/routes/webauthn.py
from flask import Blueprint, request, jsonify, session
import base64, hashlib, sqlite3, os
from datetime import datetime, timezone

from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialDescriptor,
    AttestationObject,
    CollectedClientData,
    AuthenticatorData,
)

# ---------- Config ----------
RP_ID   = os.getenv("WEBAUTHN_RP_ID", "localhost")              # e.g. "privana.pro"
RP_NAME = "Privana"
ORIGIN  = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5000") # e.g. "https://privana.pro"

DB_PATH = os.path.join(os.getcwd(), "privana.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ---------- Tables ----------
def init_tables():
    conn = get_db()
    cur = conn.cursor()

    # authenticators table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS authenticators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        credential_id BLOB UNIQUE NOT NULL,
        credential_id_hash TEXT UNIQUE,
        public_key BLOB NOT NULL,
        sign_count INTEGER DEFAULT 0,
        aaguid TEXT,
        first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
    """)

    # Ensure users table has user-bound trial columns
    cur.execute("PRAGMA table_info(users)")
    cols = {r[1] for r in cur.fetchall()}
    if "trial_started_at" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN trial_started_at TIMESTAMP")
    if "trial_consumed_at" not in cols:
        cur.execute("ALTER TABLE users ADD COLUMN trial_consumed_at TIMESTAMP")

    conn.commit()
    conn.close()

init_tables()

# ---------- FIDO2 ----------
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
fido_server = Fido2Server(rp, attestation="none")

webauthn_bp = Blueprint("webauthn", __name__, url_prefix="/webauthn")

# ---------- helpers ----------
def b64url(x: bytes) -> str:
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()

def b64url_decode(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def options_to_json(options):
    """Make register_begin() / authenticate_begin() options JSON-friendly across fido2 versions."""
    if hasattr(options, "to_json") and callable(options.to_json):
        data = options.to_json()
        if isinstance(data.get("user", {}).get("id"), (bytes, bytearray)):
            data["user"]["id"] = b64url(data["user"]["id"])
        if isinstance(data.get("challenge"), (bytes, bytearray)):
            data["challenge"] = b64url(data["challenge"])
        return data

    pk = getattr(options, "public_key", options)
    out = {
        "rp": {
            "name": getattr(getattr(pk, "rp", None), "name", None),
            "id":   getattr(getattr(pk, "rp", None), "id",   None),
        },
        "user": {
            "id":  b64url(getattr(getattr(pk, "user", None), "id", b"") or b""),
            "name": getattr(getattr(pk, "user", None), "name", None),
            "displayName": getattr(getattr(pk, "user", None), "display_name", None),
        },
        "challenge": b64url(getattr(pk, "challenge", b"") or b""),
        "pubKeyCredParams": [
            {"type": getattr(p, "type", "public-key"), "alg": getattr(p, "alg", -7)}
            for p in (getattr(pk, "pub_key_cred_params", []) or [])
        ],
        "timeout": getattr(pk, "timeout", None),
        "attestation": getattr(pk, "attestation", "none"),
        "authenticatorSelection": {},
        "excludeCredentials": [
            {
                "type": getattr(c, "type", "public-key"),
                "id": b64url(getattr(c, "id", b"") or b""),
                **({"transports": c.transports} if getattr(c, "transports", None) else {}),
            }
            for c in (getattr(pk, "exclude_credentials", []) or [])
        ],
        "extensions": getattr(pk, "extensions", {}) or {},
    }
    return out

# =========================================================
# Registration (Create Passkey)
# =========================================================

@webauthn_bp.route("/register/options", methods=["POST"])
def register_options():
    try:
        user_id = session.get("user_id")
        email = session.get("email")
        if not user_id or not email:
            return jsonify({"error": "Not authenticated"}), 401

        user = PublicKeyCredentialUserEntity(
            id=str(user_id).encode("utf-8"),
            name=email,
            display_name=email,
        )

        # Exclude existing credentials for this user (cross-version safe)
        conn = get_db()
        rows = conn.execute(
            "SELECT credential_id FROM authenticators WHERE user_id = ?",
            (user_id,)
        ).fetchall()
        conn.close()

        exclude = []
        for r in (rows or []):
            try:
                exclude.append(PublicKeyCredentialDescriptor(id=r["credential_id"], type="public-key"))
            except TypeError:
                exclude.append(PublicKeyCredentialDescriptor(r["credential_id"]))
        exclude = exclude or None

        # Minimal args for widest compatibility
        options, state = fido_server.register_begin(
            user=user,
            credentials=exclude,
            user_verification="required",
        )
        session["webauthn_register_state"] = state

        data = options_to_json(options)
        exts = data.get("extensions") or {}
        exts["credProps"] = True
        data["extensions"] = exts

        return jsonify(data)

    except Exception as e:
        return jsonify({"error": "register_options_failed", "detail": str(e)}), 500


@webauthn_bp.route("/register/verify", methods=["POST"])
def register_verify():
    """
    Completes registration. On success:
      - stores authenticator bound to the user
      - starts user-bound trial if missing (users.trial_started_at)
    """
    import sqlite3, traceback
    try:
        user_id = session.get("user_id")
        email   = session.get("email")
        state   = session.get("webauthn_register_state")
        if not user_id or not email or not state:
            return jsonify({"error": "Bad state"}), 400

        data = request.get_json(force=True)

        # Modern mapping first (base64url strings, id == rawId)
        raw_id_str = data.get("rawId")
        if not raw_id_str:
            return jsonify({"error": "Missing rawId"}), 400

        response_mapping = {
            "rawId": raw_id_str,
            "id":   data.get("id") or raw_id_str,  # some browsers send both; keep equal
            "type": data.get("type", "public-key"),
            "response": {
                "attestationObject": data.get("attestationObject"),
                "clientDataJSON":    data.get("clientDataJSON"),
            },
        }

        try:
            auth_data = fido_server.register_complete(state, response_mapping)
        except TypeError:
            # Legacy fallback (3-arg signature): convert to bytes
            client_b  = b64url_decode(data.get("clientDataJSON") or "")
            att_obj_b = b64url_decode(data.get("attestationObject") or "")
            if not client_b or not att_obj_b:
                return jsonify({"error": "Missing fields"}), 400
            auth_data = fido_server.register_complete(
                state,
                CollectedClientData(client_b),
                AttestationObject(att_obj_b),
            )

        # ---- Extract attested credential details across python-fido2 versions ----
        from fido2.cose import CoseKey

        cred_id = None
        pub_key = None
        sign_count = getattr(auth_data, "sign_count", 0) or 0
        aaguid = getattr(auth_data, "aaguid", None)

        def _pick_pk(pk):
            # Normalize different COSE key shapes into bytes
            if pk is None:
                return None
            if isinstance(pk, (bytes, bytearray)):
                return bytes(pk)
            if isinstance(pk, CoseKey):
                try:
                    return pk.encode()
                except Exception:
                    pass
            if hasattr(pk, "encode") and callable(pk.encode):
                try:
                    return pk.encode()
                except Exception:
                    pass
            try:
                from fido2.cbor import encode as cbor_encode
                return cbor_encode(dict(pk))  # Mapping-like COSE
            except Exception:
                return None

        # Layout A: auth_data.auth_data.attested_credential_data
        ad = getattr(auth_data, "auth_data", None)
        if ad is not None:
            acd = getattr(ad, "attested_credential_data", None) or getattr(ad, "credential_data", None)
            if acd is not None:
                cred_id = cred_id or getattr(acd, "credential_id", None)
                pub_key = pub_key or getattr(acd, "public_key", None) or getattr(acd, "credential_public_key", None)
                aaguid  = aaguid  or getattr(acd, "aaguid", None)

        # Layout B: auth_data.credential_data
        if cred_id is None or pub_key is None:
            cd = getattr(auth_data, "credential_data", None)
            if cd is not None:
                cred_id = cred_id or getattr(cd, "credential_id", None)
                pub_key = pub_key or getattr(cd, "public_key", None) or getattr(cd, "credential_public_key", None)
                aaguid  = aaguid  or getattr(cd, "aaguid", None)

        # Layout C: direct fields
        if cred_id is None:
            cred_id = getattr(auth_data, "credential_id", None)
        if pub_key is None:
            pub_key = getattr(auth_data, "credential_public_key", None) or getattr(auth_data, "public_key", None)

        pub_key = _pick_pk(pub_key)

        if not (isinstance(cred_id, (bytes, bytearray)) and isinstance(pub_key, (bytes, bytearray))):
            return jsonify({
                "error": "register_verify_failed",
                "detail": "Could not extract credential_id/public_key as bytes."
            }), 500

        cred_hash = sha256_hex(cred_id)

        # Persist authenticator & start user-bound trial if needed
        conn = get_db()
        cur = conn.cursor()

        cur.execute("SELECT id FROM authenticators WHERE credential_id_hash = ?", (cred_hash,))
        existing = cur.fetchone()
        now = datetime.now(timezone.utc).isoformat()

        if existing:
            cur.execute("""
                UPDATE authenticators
                   SET user_id = ?, public_key = ?, sign_count = ?, aaguid = ?, first_seen_at = COALESCE(first_seen_at, ?)
                 WHERE id = ?
            """, (user_id, sqlite3.Binary(pub_key), int(sign_count), aaguid, now, existing["id"]))
        else:
            cur.execute("""
                INSERT INTO authenticators
                    (user_id, credential_id, credential_id_hash, public_key, sign_count, aaguid, first_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, sqlite3.Binary(cred_id), cred_hash, sqlite3.Binary(pub_key), int(sign_count), aaguid, now))

        # Start the user-bound trial if it hasn't started yet
        cur.execute("SELECT trial_started_at FROM users WHERE id = ?", (user_id,))
        u = cur.fetchone()
        if u and not u["trial_started_at"]:
            cur.execute("UPDATE users SET trial_started_at = ? WHERE id = ?", (now, user_id))

        conn.commit()
        conn.close()

        session["has_passkey"] = True

        return jsonify({"ok": True})

    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        return jsonify({"error": "register_verify_failed", "detail": str(e), "trace": tb}), 500


# =====================================================================
# Assertion PRECHECK (signup gate) — no login side-effects, trial guard
# =====================================================================

@webauthn_bp.route("/assert/options-precheck", methods=["POST"])
def assert_options_precheck():
    try:
        options, state = fido_server.authenticate_begin(
            credentials=None,  # allow any resident credential for this RP
            user_verification="required",
        )
        session["webauthn_assert_state_precheck"] = state
        return jsonify(options)
    except Exception as e:
        return jsonify({"error": "assert_options_failed", "detail": str(e)}), 500


@webauthn_bp.route("/assert/verify-precheck", methods=["POST"])
def assert_verify_precheck():
    try:
        state = session.get("webauthn_assert_state_precheck")
        if not state:
            return jsonify({"error": "Bad state"}), 400

        data = request.get_json(force=True)
        raw_id = b64url_decode(data["rawId"])
        credential_id_hash = sha256_hex(raw_id)

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM authenticators WHERE credential_id_hash = ?", (credential_id_hash,))
        rec = cur.fetchone()

        # Unknown authenticator → allow trial
        if not rec:
            conn.close()
            return jsonify({"ok": True, "recognized": False, "blocked": False})

        # Verify signature using stored public key
        from fido2.cose import CoseKey
        public_key = CoseKey.from_cose(rec["public_key"])

        client_data = CollectedClientData(b64url_decode(data["clientDataJSON"]))
        auth_data = AuthenticatorData(b64url_decode(data["authenticatorData"]))
        signature = b64url_decode(data["signature"])

        fido_server.authenticate_complete(
            state=state,
            credentials=[{"id": raw_id, "public_key": public_key, "sign_count": rec["sign_count"]}],
            credential_id=raw_id,
            client_data=client_data,
            auth_data=auth_data,
            signature=signature,
        )

        # Update sign count
        cur.execute("UPDATE authenticators SET sign_count = ? WHERE id = ?", (auth_data.sign_count, rec["id"]))

        # Block if the owning user has consumed trial
        blocked = False
        if rec["user_id"]:
            cur.execute("SELECT trial_consumed_at FROM users WHERE id = ?", (rec["user_id"],))
            u = cur.fetchone()
            blocked = bool(u and u["trial_consumed_at"])

        conn.commit()
        conn.close()

        return jsonify({"ok": True, "recognized": True, "blocked": blocked})

    except Exception as e:
        return jsonify({"error": "assert_verify_failed", "detail": str(e)}), 500


# ===========================================
# Safe recovery: reset passkeys for this user
# ===========================================

@webauthn_bp.route("/reset", methods=["POST"])
def reset_authenticators_for_user():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM authenticators WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})
