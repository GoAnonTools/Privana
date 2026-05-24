# web/app.py
import os
import secrets
from pathlib import Path
from datetime import timedelta

from dotenv import load_dotenv
from flask import (
    Flask, send_from_directory, render_template, abort,
    request, session, url_for, flash, jsonify, redirect
)

# --------------------------------------------------------------------------------------
# Paths & environment
# --------------------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parents[1]      # <project root>
SITE_DIR = BASE_DIR / "site"                        # static marketing site next to /web
WEB_DIR  = Path(__file__).resolve().parent          # .../web
load_dotenv(BASE_DIR / ".env", override=True)       # load .env once, early

# --------------------------------------------------------------------------------------
# Create the ONE app (static points to web/static; we’ll mount /site manually)
# --------------------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=str(WEB_DIR / "templates"),
    static_folder=str(WEB_DIR / "static"),
)

# --------------------------------------------------------------------------------------
# Core config
# --------------------------------------------------------------------------------------
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").strip().lower()

SECRET_KEY = (os.getenv("SECRET_KEY") or "").strip()
SECURITY_PASSWORD_SALT = (os.getenv("SECURITY_PASSWORD_SALT") or "").strip()

_INSECURE_SECRET_VALUES = {
    "",
    "CHANGE_ME",
    "change-me",
    "change-me-dev-secret",
    "change-me-dev-salt",
}

def _is_weak_secret(value: str) -> bool:
    lowered = value.lower()
    return (
        value in _INSECURE_SECRET_VALUES
        or lowered.startswith("change-me")
        or lowered.startswith("dev-insecure")
        or len(value) < 32
    )

if ENVIRONMENT == "production":
    if _is_weak_secret(SECRET_KEY):
        raise RuntimeError("SECRET_KEY must be set to a strong random value in production.")
    if _is_weak_secret(SECURITY_PASSWORD_SALT):
        raise RuntimeError("SECURITY_PASSWORD_SALT must be set to a strong random value in production.")
else:
    # Development only. Never used in production.
    SECRET_KEY = SECRET_KEY or "dev-only-local-secret-not-for-production"
    SECURITY_PASSWORD_SALT = SECURITY_PASSWORD_SALT or "dev-only-local-salt-not-for-production"

app.config["SECRET_KEY"] = SECRET_KEY
app.config["SECURITY_PASSWORD_SALT"] = SECURITY_PASSWORD_SALT
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=12)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "True").lower() != "false"
# --------------------------------------------------------------------------------------
# Rate limiter
# --------------------------------------------------------------------------------------
from rate_limit import limiter
limiter.init_app(app)

# --------------------------------------------------------------------------------------
# CSRF protection (lightweight, no extra dependency)
# --------------------------------------------------------------------------------------
import hmac
from flask import g

def _csrf_token() -> str:
    """Generate (once per session) or return the existing CSRF token."""
    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(32)
    return session["_csrf_token"]

@app.before_request
def _csrf_check():
    """Validate CSRF token on every state-changing request."""
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return

    # Only skip CSRF for true machine/API routes that use their own HMAC auth.
    # Browser-session JSON endpoints, especially /dashboard/*, must still send CSRF.
    csrf_exempt_prefixes = (
        "/api/",
    )

    if any(request.path.startswith(prefix) for prefix in csrf_exempt_prefixes):
        return

    expected = session.get("_csrf_token")
    submitted = (
        request.form.get("_csrf_token", "")
        or request.headers.get("X-CSRF-Token", "")
        or request.headers.get("X-CSRFToken", "")
    )

    if not expected or not hmac.compare_digest(expected, submitted):
        abort(403)

# Expose csrf_token() as a template global so every template can call it
app.jinja_env.globals["csrf_token"] = _csrf_token

@app.errorhandler(429)
def _handle_ratelimit(e):
    try:
        from web.routes.auth import log_event, _client_ip  # lazy import to avoid cycles
        log_event("rate_limited", session.get("user_id"), f"path={request.path}", severity="warn")
    except Exception:
        pass

    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({"success": False, "message": "Rate limit exceeded"}), 429

    flash("Too many requests — please slow down.", "error")
    return redirect(request.referrer or url_for("auth.login")), 429

# --------------------------------------------------------------------------------------
# Marketing site mounting
# --------------------------------------------------------------------------------------
@app.route("/")
def landing():
    """Serve <project>/site/index.html at root."""
    idx = SITE_DIR / "index.html"
    if idx.is_file():
        return send_from_directory(str(SITE_DIR), "index.html")
    # Fallback to a Jinja template if you ever add one:
    try:
        return render_template("index.html")
    except Exception:
        abort(404)

@app.route("/site/<path:filename>")
def site_static(filename: str):
    """Expose the whole /site folder at /site/..."""
    if not SITE_DIR.is_dir():
        abort(404)
    return send_from_directory(str(SITE_DIR), filename)

@app.route("/favicon.ico")
def favicon():
    # Try /site/assets/favicon.ico first, then /web/static/favicon.ico
    site_fav = SITE_DIR / "assets" / "favicon.ico"
    if site_fav.is_file():
        return send_from_directory(str(site_fav.parent), site_fav.name)
    web_fav = WEB_DIR / "static" / "favicon.ico"
    if web_fav.is_file():
        return send_from_directory(str(web_fav.parent), web_fav.name)
    abort(404)

# --------------------------------------------------------------------------------------
# Blueprints (don’t create another app, just register here)
# --------------------------------------------------------------------------------------
from web.routes import auth_bp, dashboard_bp, downloads_bp, webauthn_bp, public_bp  # noqa

# If public_bp also serves "/", it’s fine as long as it uses a different endpoint.
# (Your 404 came from redefining 'app', not from a route clash.)
app.register_blueprint(public_bp)                         # marketing/auth helpers
app.register_blueprint(auth_bp, url_prefix="/auth")                            # /signup, /login, etc.
app.register_blueprint(dashboard_bp, url_prefix="/dashboard")
app.register_blueprint(downloads_bp)
app.register_blueprint(webauthn_bp)

from web.db import init_db
with app.app_context():
    init_db()
# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return jsonify({"ok": True})

@app.route("/signup")
def _legacy_signup():
    return redirect(url_for("auth.signup"), code=308)

@app.route("/login")
def _legacy_login():
    return redirect(url_for("auth.login"), code=308)

@app.route("/manifest.webmanifest")
def manifest():
    # served from <project>/site/manifest.webmanifest
    return send_from_directory(str(SITE_DIR), "manifest.webmanifest",
                               mimetype="application/manifest+json")

@app.route("/sw.js")
def service_worker():
    # served from <project>/site/sw.js
    resp = send_from_directory(str(SITE_DIR), "sw.js",
                               mimetype="application/javascript")
    # avoid sticky caching while iterating
    resp.headers["Cache-Control"] = "no-cache"
    return resp