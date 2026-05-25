# web/routes/public.py
from flask import Blueprint, render_template, session, redirect, url_for
import sqlite3
import os

public_bp = Blueprint("public", __name__)

from web.db import get_db

def _get_user(user_id):
    conn = get_db()
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user

@public_bp.get("/welcome")
def welcome():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    user = _get_user(session["user_id"])
    return render_template("welcome.html", user=user)