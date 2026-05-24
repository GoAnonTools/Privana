from flask import session, flash, redirect, url_for, jsonify
import sqlite3
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "privana.db"

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def user_has_passkey(user_id: int) -> bool:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM authenticators WHERE user_id = ? LIMIT 1",
            (user_id,),
        ).fetchone()
        return bool(row)
    finally:
        conn.close()

def require_passkey_for_sensitive_action():
    user_id = session.get("user_id")
    if not user_id:
        flash("Please log in first.", "error")
        return redirect(url_for("auth.login"))

    if not user_has_passkey(user_id):
        flash("Please create a passkey before managing VPN devices or downloading configurations.", "error")
        return redirect(url_for("dashboard.dashboard"))

    return None

def require_passkey_for_sensitive_action_json():
    user_id = session.get("user_id")
    if not user_id:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    if not user_has_passkey(user_id):
        return jsonify({
            "success": False,
            "message": "Passkey required for this action. Please create one on the dashboard first.",
            "redirect": url_for("dashboard.dashboard")
        }), 403

    return None
