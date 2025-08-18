from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

# Rate limiter (root-level helper); if you placed it in web/, use: from web.rate_limit import limiter
from rate_limit import limiter

# ----------------------------
# Config & DB helpers
# ----------------------------

DB_PATH = os.path.join(os.getcwd(), "privana.db")
TRIAL_DAYS = 7

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def generate_token() -> str:
    return secrets.token_urlsafe(32)

def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,)
    )
    return cur.fetchone() is not None

def init_db():
    """
    Non-destructive DB init: creates tables if they don't exist.
    DOES NOT drop data.
    """
    conn = get_db()
    cur = conn.cursor()

    # users
    if not table_exists(conn, "users"):
        cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                token TEXT,                         -- email confirmation token
                confirmed INTEGER DEFAULT 0,
                subscription_plan TEXT DEFAULT 'trial',
                subscription_status TEXT DEFAULT 'inactive',
                device_limit INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # devices
    if not table_exists(conn, "devices"):
        cur.execute("""
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                platform TEXT,
                is_connected INTEGER DEFAULT 0,
                last_connected TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

    # device_configs
    if not table_exists(conn, "device_configs"):
        cur.execute("""
            CREATE TABLE device_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                private_key TEXT,
                public_key TEXT,
                config TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        """)

    # login_tokens (for passwordless magic links)
    if not table_exists(conn, "login_tokens"):
        cur.execute("""
            CREATE TABLE login_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

    # authenticators (WebAuthn binding for one-trial-per-device)
    if not table_exists(conn, "authenticators"):
        cur.execute("""
            CREATE TABLE authenticators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,                      -- first owner of this authenticator
                credential_id BLOB UNIQUE NOT NULL,   -- raw credential id
                credential_id_hash TEXT UNIQUE,       -- sha256(credential_id)
                public_key BLOB NOT NULL,
                sign_count INTEGER DEFAULT 0,
                aaguid TEXT,
                first_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                trial_started_at TIMESTAMP,
                trial_consumed_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)

    conn.commit()
    conn.close()

def get_device_limit_for_plan(plan: str) -> int:
    """Get device limit for a subscription plan."""
    limits = {
        'trial': 1,
        'individual': 3,
        'family': 6,
        'small team': 10
    }
    try:
        return limits.get((plan or "").lower(), 1)
    except Exception:
        return 1

def cleanup_user_devices(user_id: int):
    """Clean up any existing devices for a user (for new signups)."""
    conn = get_db()
    try:
        devices = conn.execute(
            "SELECT COUNT(*) AS count FROM devices WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        if devices and devices["count"] > 0:
            conn.execute(
                "DELETE FROM device_configs WHERE device_id IN (SELECT id FROM devices WHERE user_id = ?)",
                (user_id,)
            )
            conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))
            conn.commit()
    finally:
        conn.close()

def consume_trial_if_expired(user_id: int):
    """
    If the user's trial (bound to their first authenticator) is older than TRIAL_DAYS,
    set trial_consumed_at so the device can't start a new trial later.
    """
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
      SELECT id, trial_started_at, trial_consumed_at
      FROM authenticators
      WHERE user_id = ?
      ORDER BY first_seen_at ASC
      LIMIT 1
    """, (user_id,))
    row = cur.fetchone()
    if not row:
        conn.close(); return
    if row["trial_consumed_at"]:
        conn.close(); return
    if row["trial_started_at"]:
        try:
            started = datetime.fromisoformat(row["trial_started_at"])
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
        except Exception:
            conn.close(); return
        if datetime.now(timezone.utc) >= started + timedelta(days=TRIAL_DAYS):
            cur.execute(
                "UPDATE authenticators SET trial_consumed_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"])
            )
            conn.commit()
    conn.close()

# Initialize DB once at import (non-destructive)
init_db()

# ----------------------------
# Blueprint
# ----------------------------

auth_bp = Blueprint("auth", __name__)

# ----------------------------
# Routes
# ----------------------------

@auth_bp.route("/")
def index():
    return redirect(url_for("auth.signup"))

@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        plan = request.form.get("plan") or request.args.get("plan") or "trial"

        if not email:
            flash("Email is required.", "error")
            return render_template("signup.html", plan=plan), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if user:
            conn.close()
            flash("Email already registered. Please log in.", "error")
            return redirect(url_for("auth.login"))

        device_limit = get_device_limit_for_plan(plan)

        # Email confirmation token (store in users.token)
        email_token = generate_token()

        cur.execute(
            "INSERT INTO users (email, token, subscription_plan, device_limit) VALUES (?, ?, ?, ?)",
            (email, email_token, plan, device_limit)
        )
        conn.commit()
        user_id = cur.lastrowid

        cleanup_user_devices(user_id)
        conn.close()

        # For testing
        confirm_link = request.host_url.rstrip('/') + url_for('auth.confirm_email', token=email_token)
        print(f"[DEBUG] Confirmation token for {email}: {email_token}")
        print(f"[DEBUG] Confirmation link: {confirm_link}")

        flash("A confirmation link has been sent to your email.", "success")
        return redirect(url_for("auth.signup", plan=plan, sent=1, email=email))

    plan = request.args.get("plan", "trial")
    return render_template("signup.html", plan=plan)

@auth_bp.route("/resend-confirmation")
def resend_confirmation():
    email = (request.args.get("email") or "").strip().lower()
    if not email:
        flash("Email is required.", "error")
        return redirect(url_for("auth.signup"))

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("No account found with that email.", "error")
        return redirect(url_for("auth.signup"))

    if user["confirmed"]:
        conn.close()
        flash("Your email is already confirmed.", "info")
        return redirect(url_for("auth.login"))

    new_token = generate_token()
    cur.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, user["id"]))
    conn.commit()
    conn.close()

    confirm_link = request.host_url.rstrip('/') + url_for('auth.confirm_email', token=new_token)
    print(f"[DEBUG] Resent confirmation token for {email}: {new_token}")
    print(f"[DEBUG] Resent confirmation link: {confirm_link}")

    flash("We’ve resent your confirmation link.", "success")
    return redirect(url_for("auth.signup", plan=user["subscription_plan"], sent=1, email=email))

@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE token = ?", (token,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("Invalid or expired confirmation link.", "error")
        return redirect(url_for("auth.signup"))

    cur.execute("UPDATE users SET confirmed = 1, token = NULL WHERE id = ?", (user["id"],))
    conn.commit()
    conn.close()

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session.permanent = True  # ensure 30-day session on email-confirm login

    flash("Your email has been confirmed!", "success")
    return redirect(url_for("auth.welcome"))

@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # limit magic-link issuance
def login():
    """
    Passwordless login: POST issues a one-time magic link (15 minutes),
    then redirects back to /login with a 'sent' flag. GET renders the page.
    """
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()

        if not email:
            flash("Email is required.", "error")
            return render_template("login.html"), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            conn.close()
            # keep message generic to avoid user enumeration feel
            flash("No account found with that email.", "error")
            return render_template("login.html"), 404

        if not user["confirmed"]:
            conn.close()
            flash("Please confirm your email first. We can resend the confirmation link.", "info")
            return redirect(url_for("auth.login", email=email, needs_confirm=1))

        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()

        cur.execute(
            "INSERT INTO login_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, expires_at)
        )
        conn.commit()
        conn.close()

        magic_link = request.host_url.rstrip('/') + url_for('auth.login_with_token', token=token)
        print(f"[DEBUG] Login link for {email}: {magic_link}")

        flash("We’ve sent you a secure login link. Check your email.", "success")
        return redirect(url_for("auth.login", sent=1, email=email))

    return render_template("login.html")

@auth_bp.route("/login/<token>")
@limiter.limit("10 per minute")  # limit token consumption
def login_with_token(token):
    """Consume magic link token and sign the user in if valid."""
    now = datetime.now(timezone.utc)

    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        SELECT lt.id as lt_id, lt.token, lt.expires_at, lt.used,
               u.id as user_id, u.email
        FROM login_tokens lt
        JOIN users u ON u.id = lt.user_id
        WHERE lt.token = ?
        LIMIT 1
    """, (token,))
    row = cur.fetchone()

    if not row:
        conn.close()
        flash("Invalid or expired login link.", "error")
        return redirect(url_for("auth.login"))

    # Check expiry and used flag
    try:
        exp = datetime.fromisoformat(row["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
    except Exception:
        exp = now  # treat as expired on parsing error

    if row["used"] or exp < now:
        conn.close()
        flash("This login link has expired or was already used.", "error")
        return redirect(url_for("auth.login"))

    # Mark token as used
    cur.execute("UPDATE login_tokens SET used = 1 WHERE id = ?", (row["lt_id"],))
    conn.commit()
    conn.close()

    session["user_id"] = row["user_id"]
    session["email"] = row["email"]
    session.permanent = True  # ensure 30-day session on magic-link login

    flash("You’re logged in.", "success")
    return redirect(url_for("dashboard.dashboard"))

@auth_bp.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))

@auth_bp.route("/welcome")
def welcome():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))

    user_id = session["user_id"]
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    return render_template("welcome.html", user=user)

@auth_bp.route("/debug/users")
def debug_users():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    conn.close()

    result = "<h1>Users in Database</h1><table border='1'><tr><th>ID</th><th>Email</th><th>Token</th><th>Confirmed</th><th>Plan</th><th>Device Limit</th></tr>"
    for u in users:
        result += f"<tr><td>{u['id']}</td><td>{u['email']}</td><td>{u['token']}</td><td>{u['confirmed']}</td><td>{u['subscription_plan']}</td><td>{u['device_limit']}</td></tr>"
    result += "</table>"
    return result

@auth_bp.route("/trial-ended")
def trial_ended():
    # Optional query params: ?email=...&plan=...
    email = request.args.get("email")
    plan = request.args.get("plan", "individual")
    return render_template("trial_ended.html", email=email, plan=plan)
