# web/routes/auth.py
from markupsafe import Markup
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import os
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

from rate_limit import limiter
from web.utils.api_client import sg_status

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
TRIAL_DAYS  = 7

# -----------------------------------------------------------------------------
# DB helpers
# -----------------------------------------------------------------------------
DB_PATH = os.path.join(os.getcwd(), "privana.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def table_exists(conn, table: str) -> bool:
    return conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone() is not None

# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------

def _client_ip() -> str:
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or (request.remote_addr or "unknown")

def log_event(event_type: str, user_id=None, details: str | None = None, severity: str = "info") -> None:
    """Write a security/audit event. Never raises."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO security_events (event_type, user_id, details, ip, severity) VALUES (?,?,?,?,?)",
            (event_type, user_id, details, _client_ip(), severity),
        )
        conn.commit()
    except Exception:
        pass
    finally:
        try: conn.close()
        except Exception: pass

def recent_count(event_types: tuple, ip: str, minutes: int) -> int:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM security_events WHERE ip=? AND event_type IN (%s) AND created_at>=DATETIME('now',?)"
            % ",".join("?" * len(event_types)),
            (ip, f"-{minutes} minutes", *event_types),
        ).fetchone()
        return int(row["c"] if row and row["c"] is not None else 0)
    finally:
        conn.close()

def flag_suspicious_if_needed(ip: str) -> None:
    fails = recent_count(("login_invalid_account",), ip, minutes=10)
    if fails > 10:
        log_event("suspicious_bruteforce_ip", None, f"ip={ip} fails={fails}", severity="warn")

# -----------------------------------------------------------------------------
# Account number helpers
# -----------------------------------------------------------------------------

def generate_account_number() -> str:
    """Generate a 16-digit numeric account number formatted as XXXX XXXX XXXX XXXX."""
    digits = "".join([str(secrets.randbelow(10)) for _ in range(16)])
    return f"{digits[:4]} {digits[4:8]} {digits[8:12]} {digits[12:]}"

def normalise_account_number(raw: str) -> str:
    """Strip spaces/dashes so storage and comparison are consistent."""
    return raw.replace(" ", "").replace("-", "").strip()

def generate_recovery_code() -> str:
    """Generate a one-time recovery code (5 groups of 5 alphanumeric chars)."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I confusion
    groups = ["".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(5)]
    return "-".join(groups)

def hash_secret(value: str) -> str:
    """SHA-256 hash for storing recovery codes."""
    return hashlib.sha256(value.encode()).hexdigest()

# -----------------------------------------------------------------------------
# Plan helpers
# -----------------------------------------------------------------------------

def get_device_limit_for_plan(plan: str) -> int:
    return {"trial": 1, "individual": 3, "family": 6, "small team": 10}.get((plan or "").lower(), 1)

def cleanup_user_devices(user_id: int):
    conn = get_db()
    try:
        conn.execute("DELETE FROM device_configs WHERE device_id IN (SELECT id FROM devices WHERE user_id=?)", (user_id,))
        conn.execute("DELETE FROM devices WHERE user_id=?", (user_id,))
        conn.commit()
    finally:
        conn.close()


def consume_trial_if_expired(user_id: int) -> None:
    """Mark trial as consumed on the first authenticator if 7 days have elapsed."""
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT id, trial_started_at, trial_consumed_at
            FROM authenticators
            WHERE user_id = ?
            ORDER BY first_seen_at ASC
            LIMIT 1
            """,
            (user_id,),
        ).fetchone()

        if not row or row["trial_consumed_at"] or not row["trial_started_at"]:
            return

        started = datetime.fromisoformat(row["trial_started_at"])
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)

        elapsed_days = (datetime.now(timezone.utc) - started).days
        if elapsed_days >= TRIAL_DAYS:
            conn.execute(
                "UPDATE authenticators SET trial_consumed_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"]),
            )
            conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

# -----------------------------------------------------------------------------
# DB init
# -----------------------------------------------------------------------------

def init_db():
    conn = get_db()
    cur  = conn.cursor()

    if not table_exists(conn, "users"):
        cur.execute("""
            CREATE TABLE users (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                account_number   TEXT UNIQUE NOT NULL,        -- 16 digits, no spaces, e.g. 1234567890123456
                recovery_hash    TEXT,                        -- SHA-256 of recovery code shown once at signup
                subscription_plan    TEXT DEFAULT 'trial',
                subscription_status  TEXT DEFAULT 'active',
                device_limit         INTEGER DEFAULT 1,
                trial_expires_at     TEXT,                    -- ISO-8601 UTC
                created_at           TEXT DEFAULT (datetime('now'))
            )
        """)

    if not table_exists(conn, "devices"):
        cur.execute("""
            CREATE TABLE devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                platform TEXT NOT NULL,
                is_connected INTEGER DEFAULT 0,
                has_config INTEGER DEFAULT 0,
                config_created_at TEXT,
                last_connected TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

    if not table_exists(conn, "device_configs"):
        cur.execute("""
            CREATE TABLE device_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER UNIQUE NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                assigned_ip TEXT NOT NULL,
                config TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

    if not table_exists(conn, "authenticators"):
        cur.execute("""
            CREATE TABLE authenticators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                credential_id BLOB UNIQUE NOT NULL,
                credential_id_hash TEXT UNIQUE,
                public_key BLOB NOT NULL,
                sign_count INTEGER DEFAULT 0,
                aaguid TEXT,
                first_seen_at TEXT DEFAULT (datetime('now')),
                trial_started_at TEXT,
                trial_consumed_at TEXT
            )
        """)

    if not table_exists(conn, "security_events"):
        cur.execute("""
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                details TEXT,
                ip TEXT,
                severity TEXT DEFAULT 'info',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)

    if not table_exists(conn, "suspicious_ips"):
        cur.execute("""
            CREATE TABLE suspicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                noted_at TEXT DEFAULT (datetime('now'))
            )
        """)

    cur.execute("CREATE INDEX IF NOT EXISTS ix_users_account ON users(account_number)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_devices_user  ON devices(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_sec_ip        ON security_events(ip)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_sec_time      ON security_events(created_at)")
    conn.commit()
    conn.close()

init_db()

# -----------------------------------------------------------------------------
# Blueprint
# -----------------------------------------------------------------------------
auth_bp = Blueprint("auth", __name__)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@auth_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def signup():
    if request.method == "POST":
        plan = (request.form.get("plan") or request.args.get("plan") or "trial").lower()

        # Generate account number + recovery code
        account_number  = generate_account_number()
        account_stored  = normalise_account_number(account_number)  # 16 digits, no spaces
        recovery_code   = generate_recovery_code()
        recovery_hash   = hash_secret(recovery_code)
        device_limit    = get_device_limit_for_plan(plan)
        trial_expires   = (datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)).isoformat()

        conn = get_db()
        # Extremely unlikely collision guard
        while conn.execute("SELECT id FROM users WHERE account_number=?", (account_stored,)).fetchone():
            account_number = generate_account_number()
            account_stored = normalise_account_number(account_number)

        conn.execute(
            "INSERT INTO users (account_number, recovery_hash, subscription_plan, device_limit, trial_expires_at) VALUES (?,?,?,?,?)",
            (account_stored, recovery_hash, plan, device_limit, trial_expires),
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()

        log_event("signup_created", user_id, f"plan={plan}")

        # Store in session so the reveal page can display them
        session["reveal_account_number"] = account_number   # formatted with spaces
        session["reveal_recovery_code"]  = recovery_code
        session["reveal_user_id"]        = user_id

        return redirect(url_for("auth.reveal"))

    plan = request.args.get("plan", "trial")
    return render_template("signup.html", plan=plan)


@auth_bp.route("/reveal")
def reveal():
    """Show the account number and recovery code once. Clears them from the session after."""
    account_number = session.pop("reveal_account_number", None)
    recovery_code  = session.pop("reveal_recovery_code",  None)
    user_id        = session.pop("reveal_user_id",        None)

    if not account_number:
        # Already seen or direct navigation — just go to login
        return redirect(url_for("auth.login"))

    # Log the user in immediately after signup
    session["user_id"] = user_id
    session.permanent  = True

    log_event("account_revealed", user_id)
    return render_template("reveal.html",
                           account_number=account_number,
                           recovery_code=recovery_code)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    """Login with account number only."""
    if request.method == "GET":
        return render_template("login.html")

    raw = (request.form.get("account_number") or "").strip()
    account_stored = normalise_account_number(raw)

    if len(account_stored) != 16 or not account_stored.isdigit():
        flash("Please enter a valid 16-digit account number.", "error")
        return render_template("login.html"), 400

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE account_number=?", (account_stored,)).fetchone()
    conn.close()

    if not user:
        flash("Account not found.", "error")
        log_event("login_invalid_account", None, f"account={account_stored[:4]}xxxx")
        flag_suspicious_if_needed(_client_ip())
        return render_template("login.html"), 404

    # Check trial
    if user["subscription_plan"] == "trial" and user["trial_expires_at"]:
        try:
            expires = datetime.fromisoformat(user["trial_expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires:
                session["user_id"] = user["id"]
                session.permanent  = True
                return redirect(url_for("auth.trial_ended"))
        except Exception:
            pass

    session["user_id"] = user["id"]
    session.permanent  = True

    log_event("login_success", user["id"])
    return redirect(url_for("dashboard.dashboard"))


@auth_bp.route("/recover", methods=["GET", "POST"])
@limiter.limit("5 per hour", methods=["POST"])
def recover():
    """Account recovery via one-time recovery code."""
    if request.method == "GET":
        return render_template("recover.html")

    recovery_input = (request.form.get("recovery_code") or "").strip().upper().replace(" ", "")
    recovery_hash  = hash_secret(recovery_input)

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE recovery_hash=?", (recovery_hash,)).fetchone()

    if not user:
        conn.close()
        flash("Recovery code not found. Please check and try again.", "error")
        log_event("recovery_failed", None, severity="warn")
        return render_template("recover.html"), 404

    # Invalidate the old recovery code immediately and issue a new one
    new_recovery_code = generate_recovery_code()
    new_recovery_hash = hash_secret(new_recovery_code)
    conn.execute("UPDATE users SET recovery_hash=? WHERE id=?", (new_recovery_hash, user["id"]))
    conn.commit()
    conn.close()

    log_event("recovery_success", user["id"])

    # Show new account number + fresh recovery code
    session["reveal_account_number"] = " ".join([
        user["account_number"][i:i+4] for i in range(0, 16, 4)
    ])
    session["reveal_recovery_code"] = new_recovery_code
    session["reveal_user_id"]       = user["id"]

    flash("Recovery successful. Here are your new credentials — save them now.", "success")
    return redirect(url_for("auth.reveal"))


@auth_bp.route("/logout")
def logout():
    if "user_id" in session:
        log_event("logout", session["user_id"])
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/welcome")
def welcome():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()
    return render_template("welcome.html", user=user)


@auth_bp.route("/trial-ended")
def trial_ended():
    plan = request.args.get("plan", "individual")
    return render_template("trial_ended.html", plan=plan)


@auth_bp.route("/admin/health")
def admin_health():
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "auth required"}), 401

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.close()

    if not user or not ADMIN_EMAIL:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # Admin identified by account number stored in env (no email anymore)
    admin_account = normalise_account_number(os.getenv("ADMIN_ACCOUNT", ""))
    if user["account_number"] != admin_account:
        return jsonify({"ok": False, "error": "forbidden"}), 403

    db_ok, db_err = True, None
    try:
        conn = get_db(); conn.execute("SELECT 1"); conn.close()
    except Exception as e:
        db_ok, db_err = False, str(e)

    sg_ok, sg_info = False, {}
    try:
        r = sg_status()
        js = r.json()
        sg_ok = js.get("success", False)
        sg_info = {"http_status": r.status_code, "success": sg_ok,
                   "is_running": js.get("is_running"), "peers_count": js.get("peers_count")}
    except Exception as e:
        sg_info = {"error": str(e)}

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM security_events WHERE event_type='login_invalid_account' AND created_at>=DATETIME('now','-60 minutes')"
        ).fetchone()
        failed = int(row["c"] if row and row["c"] is not None else 0)
    finally:
        conn.close()

    return jsonify({"ok": True, "time": datetime.now(timezone.utc).isoformat(),
                    "db_ok": db_ok, "db_error": db_err,
                    "sg_api": sg_info, "failed_logins_last_hour": failed})