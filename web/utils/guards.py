from flask import session, redirect, url_for, flash, jsonify

from web.db import get_db


def user_has_passkey(user_id: int) -> bool:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM authenticators WHERE user_id = ? LIMIT 1",
            (user_id,),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def require_passkey_for_sensitive_action():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    if not user_has_passkey(int(user_id)):
        flash("Passkey is required for this security-sensitive action.", "error")
        return redirect(url_for("dashboard.dashboard"))

    return None


def require_passkey_for_sensitive_action_json():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Authentication required"}), 401

    if not user_has_passkey(int(user_id)):
        return jsonify({
            "success": False,
            "message": "Passkey is required for this security-sensitive action."
        }), 403

    return None
