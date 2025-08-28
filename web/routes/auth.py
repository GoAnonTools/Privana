from markupsafe import Markup

# web/routes/auth.py
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

# Rate limiter (root-level helper). If you moved it to web/, use: from web.rate_limit import limiter
from rate_limit import limiter
from web.utils.api_client import sg_status  # for health endpoint
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")  # set in .env


def _client_ip():
    # supports proxies later
    xf = request.headers.get("X-Forwarded-For", "")
    return (xf.split(",")[0].strip() if xf else request.remote_addr) or "?"

def log_event(event_type: str, user_id: int | None, details: str = ""):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO event_logs (user_id, event_type, details, ip) VALUES (?, ?, ?, ?)",
            (user_id, event_type, details, _client_ip()),
        )
        conn.commit()
    finally:
        conn.close()


# -----------------------------------------------------------------------------
# Config & DB helpers
# -----------------------------------------------------------------------------
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
        (table,),
    )
    return cur.fetchone() is not None


def init_db():
    """
    Non-destructive DB init: creates tables and indexes if they don't exist.
    DOES NOT drop data.
    """
    conn = get_db()
    cur = conn.cursor()

    # users
    if not table_exists(conn, "users"):
        cur.execute(
            """
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
        """
        )

    # devices
    if not table_exists(conn, "devices"):
        cur.execute(
            """
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
        """
        )

    # device_configs
    if not table_exists(conn, "device_configs"):
        cur.execute(
            """
            CREATE TABLE device_configs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                private_key TEXT,
                public_key TEXT,
                config TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        """
        )

    # login_tokens (for passwordless magic links)
    if not table_exists(conn, "login_tokens"):
        cur.execute(
            """
            CREATE TABLE login_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """
        )

    # authenticators (WebAuthn binding for one-trial-per-device)
    if not table_exists(conn, "authenticators"):
        cur.execute(
            """
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
        """
        )

    # config_download_tokens (short-lived tokens for secure config delivery)
    if not table_exists(conn, "config_download_tokens"):
        cur.execute(
            """
            CREATE TABLE config_download_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id INTEGER,
                token TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """
        )

    # event_logs (basic monitoring)
    if not table_exists(conn, "event_logs"):
        cur.execute("""
            CREATE TABLE event_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                event_type TEXT NOT NULL,
                details TEXT,
                ip TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


        # security_events (simple audit log)
    if not table_exists(conn, "security_events"):
        cur.execute("""
            CREATE TABLE security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                user_id INTEGER,
                details TEXT,
                ip TEXT,
                severity TEXT DEFAULT 'info',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

    # suspicious_ips (lightweight marker list)
    if not table_exists(conn, "suspicious_ips"):
        cur.execute("""
            CREATE TABLE suspicious_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT UNIQUE NOT NULL,
                noted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


    # Helpful indexes (idempotent)
    cur.execute("CREATE INDEX IF NOT EXISTS ix_users_email ON users(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_devices_user_id ON devices(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_login_tokens_token ON login_tokens(token)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_config_tokens_token ON config_download_tokens(token)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_sec_events_time ON security_events(created_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS ix_sec_events_ip ON security_events(ip)")

    conn.commit()
    conn.close()


def get_device_limit_for_plan(plan: str) -> int:
    """Get device limit for a subscription plan."""
    limits = {
        "trial": 1,
        "individual": 3,
        "family": 6,
        "small team": 10,
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
            "SELECT COUNT(*) AS count FROM devices WHERE user_id = ?", (user_id,)
        ).fetchone()
        if devices and devices["count"] > 0:
            conn.execute(
                "DELETE FROM device_configs WHERE device_id IN (SELECT id FROM devices WHERE user_id = ?)",
                (user_id,),
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
    cur.execute(
        """
      SELECT id, trial_started_at, trial_consumed_at
      FROM authenticators
      WHERE user_id = ?
      ORDER BY first_seen_at ASC
      LIMIT 1
    """,
        (user_id,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return
    if row["trial_consumed_at"]:
        conn.close()
        return
    if row["trial_started_at"]:
        try:
            started = datetime.fromisoformat(row["trial_started_at"])
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
        except Exception:
            conn.close()
            return
        if datetime.now(timezone.utc) >= started + timedelta(days=TRIAL_DAYS):
            cur.execute(
                "UPDATE authenticators SET trial_consumed_at = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), row["id"]),
            )
            conn.commit()
    conn.close()

def _client_ip() -> str:
    """Best-effort client IP (works behind proxies when X-Forwarded-For is set)."""
    xff = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
    return xff or (request.remote_addr or "unknown")


def log_event(event_type: str, user_id: int | None, details: str = "", severity: str = "info") -> None:
    """Write a security/audit event to the DB (fire-and-forget)."""
    try:
        conn = get_db()
        conn.execute(
            "INSERT INTO security_events (event_type, user_id, details, ip, severity) VALUES (?,?,?,?,?)",
            (event_type, user_id, details, _client_ip(), severity),
        )
        conn.commit()
    except Exception:
        # do not explode the request flow for logging failures
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def flag_suspicious_if_needed(ip: str, window_minutes: int = 10, threshold: int = 5) -> None:
    """
    If there are >= threshold events from this IP in the last N minutes, mark it suspicious.
    You can later consult this table to show captchas / add friction.
    """
    try:
        conn = get_db()
        # Count recent events for this IP
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM security_events WHERE ip = ? AND created_at > datetime('now', ?)",
            (ip, f"-{window_minutes} minutes"),
        ).fetchone()
        count = int(row["c"]) if row and "c" in row.keys() else 0
        if count >= threshold:
            # Upsert-ish: try insert, ignore if exists
            try:
                conn.execute("INSERT INTO suspicious_ips (ip) VALUES (?)", (ip,))
                conn.commit()
                # Also log the flagging itself
                conn.execute(
                    "INSERT INTO security_events (event_type, user_id, details, ip, severity) VALUES (?,?,?,?,?)",
                    ("ip_marked_suspicious", None, f"count={count}", ip, "warn"),
                )
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass

def _client_ip() -> str:
    # When behind a proxy later (nginx), X-Forwarded-For will be set
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def log_event(event_type: str, user_id: int | None = None, details: str | None = None):
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO security_events (user_id, ip, event_type, details) VALUES (?,?,?,?)",
            (user_id, _client_ip(), event_type, details),
        )
        conn.commit()
    finally:
        conn.close()

def recent_count(event_types: tuple[str, ...], ip: str, minutes: int) -> int:
    conn = get_db()
    try:
        rows = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM security_events
            WHERE ip = ?
              AND event_type IN (%s)
              AND created_at >= DATETIME('now', ?)
            """ % (",".join("?" * len(event_types))),
            (ip, f"-{minutes} minutes", *event_types),
        ).fetchone()
        return int(rows["c"] if rows and rows["c"] is not None else 0)
    finally:
        conn.close()

def flag_suspicious_if_needed(ip: str):
    # Very simple heuristic: >10 failed auth-like events in 10 minutes from same IP
    fails = recent_count(
        ("login_email_not_found", "login_token_invalid", "login_token_expired_used"),
        ip,
        minutes=10,
    )
    if fails > 10:
        log_event("suspicious_bruteforce_ip", None, f"ip={ip} fails_10min={fails}")



# Initialize DB once at import (non-destructive)
init_db()

# -----------------------------------------------------------------------------
# Blueprint
# -----------------------------------------------------------------------------
auth_bp = Blueprint("auth", __name__)

# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------

@auth_bp.route("/signup", methods=["GET", "POST"])
@limiter.limit("3 per minute", methods=["POST"])  # gentle anti-abuse
def signup():

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        plan = request.form.get("plan") or request.args.get("plan") or "trial"

        if not email:
            flash("Email is required.", "error")
            return render_template("signup.html", plan=plan), 400

        conn = get_db()
        cur = conn.cursor()
        cur.execute("SELECT id, confirmed, subscription_plan FROM users WHERE email = ?", (email,))
        existing = cur.fetchone()

        if existing:
            conn.close()
            flash("Email already registered. Please log in.", "error")
            try:
                log_event("signup_email_exists", existing["id"], f"email={email}")
            except Exception:
                pass
            return redirect(url_for("auth.login"))

        device_limit = get_device_limit_for_plan(plan)
        email_token = generate_token()

        cur.execute(
            "INSERT INTO users (email, token, subscription_plan, device_limit) VALUES (?, ?, ?, ?)",
            (email, email_token, plan, device_limit),
        )
        conn.commit()
        user_id = cur.lastrowid

        # reset any pre-existing devices for fresh accounts
        cleanup_user_devices(user_id)
        conn.close()

        confirm_link = request.host_url.rstrip("/") + url_for("auth.confirm_email", token=email_token)
        print(f"[DEBUG] Confirmation token for {email}: {email_token}")
        print(f"[DEBUG] Confirmation link: {confirm_link}")

        # DEV-ONLY: show a clickable link if DEV_ECHO_LINKS=true or ENVIRONMENT=development
        if (os.getenv("DEV_ECHO_LINKS", "").lower() == "true") or (os.getenv("ENVIRONMENT", "").lower() == "development"):
            flash(Markup(f"Dev shortcut: <a href='{confirm_link}'>Confirm this email</a>"), "info")

        flash("A confirmation link has been sent to your email.", "success")
        try:
            log_event("signup_created", user_id, f"email={email} plan={plan}")
            log_event("email_confirm_sent", user_id, f"email={email}")
        except Exception:
            pass
        return redirect(url_for("auth.signup", plan=plan, sent=1, email=email))

    # GET
    plan = request.args.get("plan", "trial")
    return render_template("signup.html", plan=plan)

@auth_bp.route("/resend-confirmation")
@limiter.limit("5 per hour")  # friendly but safe
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
        log_event("resend_unknown_email", None, f"email={email}")
        return redirect(url_for("auth.signup"))

    if user["confirmed"]:
        conn.close()
        flash("Your email is already confirmed.", "info")
        log_event("resend_already_confirmed", user["id"], f"email={email}")
        return redirect(url_for("auth.login"))

    new_token = generate_token()
    cur.execute("UPDATE users SET token = ? WHERE id = ?", (new_token, user["id"]))
    conn.commit()
    conn.close()

    confirm_link = request.host_url.rstrip("/") + url_for(
        "auth.confirm_email", token=new_token
    )
    print(f"[DEBUG] Resent confirmation token for {email}: {new_token}")
    print(f"[DEBUG] Resent confirmation link: {confirm_link}")

    log_event("email_confirm_resent", user["id"], f"email={email}")

    flash("We’ve resent your confirmation link.", "success")
    return redirect(
        url_for("auth.signup", plan=user["subscription_plan"], sent=1, email=email)
    )


@auth_bp.route("/confirm/<token>")
def confirm_email(token):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE token = ?", (token,))
    user = cur.fetchone()

    if not user:
        conn.close()
        flash("Invalid or expired confirmation link.", "error")
        log_event("confirm_invalid_token", None, f"token={token[:8]}...")
        return redirect(url_for("auth.signup"))

    cur.execute(
        "UPDATE users SET confirmed = 1, token = NULL WHERE id = ?", (user["id"],)
    )
    conn.commit()
    conn.close()

    session["user_id"] = user["id"]
    session["email"] = user["email"]
    session.permanent = True  # 30-day session (configured in app)

    flash("Your email has been confirmed!", "success")
    log_event("confirm_success", user["id"], f"email={user['email']}")
    return redirect(url_for("auth.welcome"))


@auth_bp.route("/login", methods=["GET", "POST"])
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])  # limit magic-link issuance
def login():
    """
    Passwordless login:
      - GET renders the form
      - POST issues a one-time magic link (15 minutes) and shows dev-echo link (if enabled)
    """
    if request.method == "GET":
        return render_template("login.html")

    # POST
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        flash("Email is required.", "error")
        return render_template("login.html"), 400

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            # keep message generic to avoid enumeration
            flash("No account found with that email.", "error")
            log_event("login_email_not_found", None, f"email={email}")
            flag_suspicious_if_needed(_client_ip())
            return render_template("login.html"), 404

        if not user["confirmed"]:
            flash("Please confirm your email first. We can resend the confirmation link.", "info")
            log_event("login_unconfirmed", user["id"], f"email={email}")
            return redirect(url_for("auth.login", email=email, needs_confirm=1))

        # Issue one-time token (15 min)
        token = generate_token()
        expires_at = (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat()
        cur.execute(
            "INSERT INTO login_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, expires_at),
        )
        conn.commit()

    finally:
        conn.close()

    magic_link = request.host_url.rstrip("/") + url_for("auth.login_with_token", token=token)
    log_event("login_magic_issued", user["id"], f"email={email}")
    print(f"[DEBUG] Login link for {email}: {magic_link}")

    # DEV-ONLY: clickable link if enabled
    if (os.getenv("DEV_ECHO_LINKS", "").lower() == "true") or (os.getenv("ENVIRONMENT", "").lower() == "development"):
        flash(Markup(f"Dev shortcut: <a href='{magic_link}'>Log in now</a>"), "info")

    flash("We’ve sent you a secure login link. Check your email.", "success")
    return redirect(url_for("auth.login", sent=1, email=email))


@auth_bp.route("/login/<token>")
@limiter.limit("10 per minute")  # limit token consumption
def login_with_token(token):
    """Consume magic link token and sign the user in if valid."""
    now = datetime.now(timezone.utc)

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT lt.id as lt_id, lt.token, lt.expires_at, lt.used,
                   u.id as user_id, u.email
            FROM login_tokens lt
            JOIN users u ON u.id = lt.user_id
            WHERE lt.token = ?
            LIMIT 1
            """,
            (token,),
        )
        row = cur.fetchone()

        if not row:
            flash("Invalid or expired login link.", "error")
            log_event("login_token_invalid", None, f"token={token[:8]}...")
            flag_suspicious_if_needed(_client_ip())
            return redirect(url_for("auth.login"))

        # Expiration / used checks
        try:
            exp = datetime.fromisoformat(row["expires_at"])
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
        except Exception:
            exp = now  # if parsing fails treat as expired

        if row["used"] or exp < now:
            flash("This login link has expired or was already used.", "error")
            return redirect(url_for("auth.login"))

        # Mark used
        cur.execute("UPDATE login_tokens SET used = 1 WHERE id = ?", (row["lt_id"],))
        conn.commit()

    finally:
        conn.close()

    # Set session
    session["user_id"] = row["user_id"]
    session["email"] = row["email"]
    session.permanent = True  # 30-day session (configured in app)

    flash("You’re logged in.", "success")
    return redirect(url_for("dashboard.dashboard"))

@auth_bp.route("/signin")
def signin_alias():
    return redirect(url_for("auth.login"))

@auth_bp.route("/logout")
def logout():
    # 👇 audit before clearing the session
    if "user_id" in session:
        log_event("logout", session["user_id"], f"email={session.get('email')}")
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

@auth_bp.route("/debug/events")
def debug_events():
    # Only allow the admin email to view events
    admin_email = os.getenv("ADMIN_EMAIL", "")
    if session.get("email") != admin_email:
        return "Forbidden", 403

    conn = get_db()
    rows = conn.execute(
        "SELECT id, event_type, user_id, details, ip, severity, created_at FROM security_events ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()

    # super lightweight HTML
    out = ["<h1>Recent security events</h1>",
           "<table border='1' cellpadding='4'><tr><th>ID</th><th>When</th><th>Type</th><th>User</th><th>IP</th><th>Severity</th><th>Details</th></tr>"]
    for r in rows:
        out.append(
            f"<tr><td>{r['id']}</td><td>{r['created_at']}</td><td>{r['event_type']}</td>"
            f"<td>{r['user_id']}</td><td>{r['ip']}</td><td>{r['severity']}</td><td>{(r['details'] or '')[:200]}</td></tr>"
        )
    out.append("</table>")
    return "".join(out)

@auth_bp.route("/trial-ended")
def trial_ended():
    # Optional query params: ?email=...&plan=...
    email = request.args.get("email")
    plan = request.args.get("plan", "individual")
    return render_template("trial_ended.html", email=email, plan=plan)

@auth_bp.route("/admin/health")
def admin_health():
    # Very simple admin check — set ADMIN_EMAIL in .env
    if "user_id" not in session:
        return jsonify({"ok": False, "error": "auth required"}), 401
    if not ADMIN_EMAIL or (session.get("email") or "").lower() != ADMIN_EMAIL.lower():
        return jsonify({"ok": False, "error": "forbidden"}), 403

    # DB check
    try:
        conn = get_db()
        conn.execute("SELECT 1")
        db_ok = True
    except Exception as e:
        db_ok = False
        db_err = str(e)
    finally:
        try:
            conn.close()
        except Exception:
            pass

    # SG API status (uses HMAC client)
    sg_ok, sg_info = False, {}
    try:
        r = sg_status()
        js = r.json()
        sg_ok = js.get("success", False)
        sg_info = {
            "http_status": r.status_code,
            "success": js.get("success"),
            "is_running": js.get("is_running"),
            "peers_count": js.get("peers_count"),
        }
    except Exception as e:
        sg_ok = False
        sg_info = {"error": str(e)}

    # Last hour failed logins
    conn = get_db()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c
            FROM security_events
            WHERE event_type IN ('login_email_not_found','login_token_invalid','login_token_expired_used')
              AND created_at >= DATETIME('now','-60 minutes')
            """
        ).fetchone()
        failed_last_hour = int(row["c"] if row and row["c"] is not None else 0)
    finally:
        conn.close()

    return jsonify(
        {
            "ok": True,
            "time": datetime.now(timezone.utc).isoformat(),
            "db_ok": db_ok,
            "db_error": (db_ok and None) or db_err,
            "sg_api": sg_info,
            "failed_logins_last_hour": failed_last_hour,
        }
    )
