# web/routes/webauthn.py
from flask import Blueprint, request, jsonify, session
import base64, hashlib, sqlite3, os, time
from datetime import datetime, timezone, timedelta
from web.routes.auth import TRIAL_DAYS

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
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()
PASSKEY_RESET_FRESH_SECONDS = int(os.getenv("PASSKEY_RESET_FRESH_SECONDS", "300"))

RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost").strip()
RP_NAME = "Privana"
ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:5000").strip()

if ENVIRONMENT == "production":
    if RP_ID in {"", "localhost", "127.0.0.1"}:
        raise RuntimeError("WEBAUTHN_RP_ID must be set to your production domain in production.")
    if not ORIGIN.startswith("https://") or "localhost" in ORIGIN or "127.0.0.1" in ORIGIN:
        raise RuntimeError("WEBAUTHN_ORIGIN must be set to your HTTPS production origin in production.")

from web.db import DB_PATH, get_db
from rate_limit import limiter


# ---------- Tables ----------

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
@limiter.limit("5 per minute")
def register_options():
    try:
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Not authenticated"}), 401

        conn = get_db()
        user_row = conn.execute("SELECT account_number FROM users WHERE id = ?", (user_id,)).fetchone()
        conn.close()

        if not user_row:
            return jsonify({"error": "User not found"}), 404

        account_number = user_row["account_number"]
        display_account = f"Privana {account_number[:4]}••••{account_number[-4:]}"

        user = PublicKeyCredentialUserEntity(
            id=str(user_id).encode("utf-8"),
            name=account_number,
            display_name=display_account,
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

    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"error": "register_options_failed"}), 500


@webauthn_bp.route("/register/verify", methods=["POST"])
@limiter.limit("5 per minute")
def register_verify():
    """
    Completes registration. On success:
      - stores authenticator bound to the user
      - starts user-bound trial if missing (users.trial_started_at)
    """
    import sqlite3, traceback
    try:
        user_id = session.get("user_id")
        state   = session.get("webauthn_register_state")
        if not user_id or not state:
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
            return jsonify({"error": "register_verify_failed"}), 500

        cred_hash = sha256_hex(cred_id)

        # Persist authenticator & start user-bound trial if needed
        conn = get_db()
        cur = conn.cursor()

        cur.execute(
            "SELECT id, user_id FROM authenticators WHERE credential_id_hash = ?",
            (cred_hash,)
        )
        existing = cur.fetchone()
        now = datetime.now(timezone.utc).isoformat()

        if existing:
            existing_user_id = int(existing["user_id"])

            # SECURITY: never allow a passkey credential to be reassigned
            # from one account to another.
            if existing_user_id != int(user_id):
                conn.close()
                return jsonify({"error": "credential_already_registered"}), 409

            # Same user registering the same credential again: update harmless fields only.
            cur.execute("""
                UPDATE authenticators
                SET public_key = ?, sign_count = ?, aaguid = ?, first_seen_at = COALESCE(first_seen_at, ?)
                WHERE id = ?
            """, (sqlite3.Binary(pub_key), int(sign_count), aaguid, now, existing["id"]))
        else:
            cur.execute("""
                INSERT INTO authenticators
                    (user_id, credential_id, credential_id_hash, public_key, sign_count, aaguid, first_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, sqlite3.Binary(cred_id), cred_hash, sqlite3.Binary(pub_key), int(sign_count), aaguid, now))

        # Start the user-bound trial if it hasn't started yet
        cur.execute("SELECT trial_started_at, trial_expires_at FROM users WHERE id = ?", (user_id,))
        u = cur.fetchone()
        if u and not u["trial_started_at"]:
            trial_expires = (datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)).isoformat()
            cur.execute(
                "UPDATE users SET trial_started_at = ?, trial_expires_at = ? WHERE id = ?",
                (now, trial_expires, user_id),
            )

        conn.commit()
        conn.close()

        session["has_passkey"] = True
        session["passkey_verified_at"] = int(time.time())

        return jsonify({"ok": True})

    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"error": "register_verify_failed"}), 500

# =========================================================
# Login assertion - completes pending account-number login
# =========================================================

@webauthn_bp.route("/login/options", methods=["POST"])
@limiter.limit("10 per minute")
def login_options():
    try:
        pending_user_id = session.get("pending_login_user_id")
        if not pending_user_id:
            return jsonify({"error": "No pending login"}), 401

        conn = get_db()
        rows = conn.execute(
            "SELECT credential_id FROM authenticators WHERE user_id = ?",
            (pending_user_id,),
        ).fetchall()
        conn.close()

        if not rows:
            return jsonify({"error": "No passkey registered for this account"}), 403

        credentials = []
        for row in rows:
            try:
                credentials.append(PublicKeyCredentialDescriptor(id=row["credential_id"], type="public-key"))
            except TypeError:
                credentials.append(PublicKeyCredentialDescriptor(row["credential_id"]))

        options, state = fido_server.authenticate_begin(
            credentials=credentials,
            user_verification="required",
        )
        session["webauthn_login_state"] = state
        return jsonify(options_to_json(options))

    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"error": "login_options_failed"}), 500


@webauthn_bp.route("/login/verify", methods=["POST"])
@limiter.limit("10 per minute")
def login_verify():
    try:
        pending_user_id = session.get("pending_login_user_id")
        state = session.get("webauthn_login_state")
        if not pending_user_id or not state:
            return jsonify({"ok": False, "error": "Bad login state"}), 400

        data = request.get_json(force=True)
        raw_id = b64url_decode(data["rawId"])
        credential_id_hash = sha256_hex(raw_id)

        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT *
            FROM authenticators
            WHERE credential_id_hash = ?
              AND user_id = ?
            """,
            (credential_id_hash, pending_user_id),
        )
        rec = cur.fetchone()

        if not rec:
            conn.close()
            return jsonify({"ok": False, "error": "Passkey not recognized for this account"}), 403

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

        cur.execute("UPDATE authenticators SET sign_count = ? WHERE id = ?", (auth_data.sign_count, rec["id"]))

        user = cur.execute(
            "SELECT * FROM users WHERE id = ?",
            (pending_user_id,),
        ).fetchone()
        conn.commit()
        conn.close()

        session.pop("pending_login_user_id", None)
        session.pop("pending_login_account_hint", None)
        session.pop("webauthn_login_state", None)
        session["user_id"] = int(pending_user_id)
        session["has_passkey"] = True
        session["passkey_verified_at"] = int(time.time())
        session.permanent = True

        redirect_url = "/dashboard"
        if user and user["subscription_plan"] == "trial" and user["trial_expires_at"]:
            try:
                expires = datetime.fromisoformat(user["trial_expires_at"])
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if datetime.now(timezone.utc) > expires:
                    redirect_url = "/auth/trial-ended"
            except Exception:
                pass

        return jsonify({"ok": True, "redirect": redirect_url})

    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"ok": False, "error": "login_verify_failed"}), 500

# =====================================================================
# Assertion PRECHECK (signup gate) — no login side-effects, trial guard
# =====================================================================

@webauthn_bp.route("/assert/options-precheck", methods=["POST"])
@limiter.limit("10 per minute")
def assert_options_precheck():
    try:
        options, state = fido_server.authenticate_begin(
            credentials=None,  # allow any resident credential for this RP
            user_verification="required",
        )
        session["webauthn_assert_state_precheck"] = state
        return jsonify(options)
    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"error": "assert_options_failed"}), 500


@webauthn_bp.route("/assert/verify-precheck", methods=["POST"])
@limiter.limit("10 per minute")
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

    except Exception:
        if ENVIRONMENT != "production":
            import traceback
            print(traceback.format_exc())
        return jsonify({"error": "assert_options_failed"}), 500


# ===========================================
# Safe recovery: reset passkeys for this user
# ===========================================

@webauthn_bp.route("/reset", methods=["POST"])
@limiter.limit("3 per minute")
def reset_authenticators_for_user():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"ok": False, "error": "Not authenticated"}), 401

    verified_at = int(session.get("passkey_verified_at") or 0)
    if int(time.time()) - verified_at > PASSKEY_RESET_FRESH_SECONDS:
        return jsonify({
            "ok": False,
            "error": "Fresh passkey verification required before resetting passkeys."
        }), 403

    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM authenticators WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()

    session.pop("has_passkey", None)
    session.pop("passkey_verified_at", None)

    return jsonify({"ok": True})
