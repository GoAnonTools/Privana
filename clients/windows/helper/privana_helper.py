# privana/clients/windows/helper/privana_helper.py
# Local helper for Windows to control WireGuard from the browser.
# Runs on 127.0.0.1:51821 and exposes:
#   GET  /health
#   GET  /status?name=...
#   POST /import-config   (JSON: {"name":"...", "config":"<wireguard conf text>"})
#   POST /connect         (JSON: {"name":"TUNNEL_NAME"})
#   POST /disconnect      (JSON: {"name":"TUNNEL_NAME"})
#
# Requires Administrator to install/start/stop services.

from __future__ import annotations

import os
import re
import hmac
import ctypes
import logging
import subprocess
from typing import Tuple, Optional

from flask import Flask, request, jsonify, make_response

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
APP_HOST = "127.0.0.1"
APP_PORT = int(os.getenv("PRIVANA_HELPER_PORT", "51821"))

PROGRAMDATA = os.environ.get("ProgramData", r"C:\ProgramData")
PROGRAMDATA_WG_DIR = os.path.join(PROGRAMDATA, "WireGuard")  # where we'll write <name>.conf
os.makedirs(PROGRAMDATA_WG_DIR, exist_ok=True)

# Comma-separated allowed origins; defaults cover local dev
DEFAULT_ALLOWED = "http://127.0.0.1:5000,http://localhost:5000"
ALLOWED_ORIGINS = {
    o.strip()
    for o in os.getenv("PRIVANA_ALLOWED_ORIGINS", DEFAULT_ALLOWED).split(",")
    if o.strip() and o.strip() != "*"
}

if "*" in os.getenv("PRIVANA_ALLOWED_ORIGINS", ""):
    log.warning("Wildcard CORS origin '*' is not allowed and has been ignored.")

logging.basicConfig(
    level=os.environ.get("PRIVANA_HELPER_LOGLEVEL", "INFO"),
    format="%(asctime)s %(levelname)s: %(message)s",
)
log = logging.getLogger("privana-helper")

HELPER_TOKEN = os.getenv("PRIVANA_HELPER_TOKEN", "").strip()

if not HELPER_TOKEN:
    log.warning(
        "PRIVANA_HELPER_TOKEN is not set. Sensitive helper routes will refuse requests."
    )

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Utilities
# -----------------------------------------------------------------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0  # type: ignore[attr-defined]
    except Exception:
        return False


def wireguard_paths() -> Tuple[Optional[str], Optional[str]]:
    r"""
    Returns (wireguard.exe, wg.exe) if found.
    Typical install: C:\Program Files\WireGuard\wireguard.exe / wg.exe
    """
    candidates = [
        r"C:\Program Files\WireGuard",
        r"C:\Program Files (x86)\WireGuard",
    ]
    wg_gui = None
    wg_cli = None
    for base in candidates:
        w1 = os.path.join(base, "wireguard.exe")
        w2 = os.path.join(base, "wg.exe")
        if os.path.exists(w1):
            wg_gui = w1
        if os.path.exists(w2):
            wg_cli = w2
    return wg_gui, wg_cli


def run(cmd: list[str], timeout: int = 30) -> Tuple[int, str, str]:
    """
    Run a command without shell, return (code, stdout, stderr).
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, shell=False
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except Exception as e:
        return 1, "", str(e)


def safe_name(name: str) -> str:
    """
    Allow only letters, numbers, dash, underscore. Replace others with '-'.
    Limit to 64 chars. Must match WireGuard service naming expectations.
    """
    name = (name or "").strip()
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", name)
    return (name or "Privana")[:64]


def service_name_for(name: str) -> str:
    """
    Windows WireGuard service naming convention:
      WireGuardTunnel$<conf_name_without_ext>
    """
    return f"WireGuardTunnel${name}"


def conf_path_for(name: str) -> str:
    return os.path.join(PROGRAMDATA_WG_DIR, f"{name}.conf")


def service_exists(name: str) -> bool:
    svc = service_name_for(name)
    code, out, err = run(["sc", "query", svc], timeout=15)
    txt = (out + "\n" + err).lower()
    if "does not exist" in txt:
        return False
    # sc may return non-zero for STOPPED; check presence of STATE line
    return ("state" in txt) or code == 0


def service_running(name: str) -> bool:
    svc = service_name_for(name)
    code, out, err = run(["sc", "query", svc], timeout=15)
    txt = (out + "\n" + err).upper()
    return "RUNNING" in txt


def sc_start(name: str) -> Tuple[int, str, str]:
    return run(["sc", "start", service_name_for(name)], timeout=30)


def sc_stop(name: str) -> Tuple[int, str, str]:
    return run(["sc", "stop", service_name_for(name)], timeout=30)


def wg_install_tunnel(wireguard_exe: str, conf_path: str) -> Tuple[int, str, str]:
    # wireguard.exe /installtunnelservice <path.conf>
    return run([wireguard_exe, "/installtunnelservice", conf_path], timeout=60)


def wg_uninstall_tunnel(wireguard_exe: str, name: str) -> Tuple[int, str, str]:
    # wireguard.exe /uninstalltunnelservice <name>
    return run([wireguard_exe, "/uninstalltunnelservice", name], timeout=60)


# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------
def with_cors(resp):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Privana-Helper-Token"
    return resp


def require_helper_token():
    """
    Require a local helper token for browser-driven helper actions.
    This prevents random websites from controlling the local WireGuard helper.
    """
    if request.method == "OPTIONS":
        return None

    if not HELPER_TOKEN:
        return with_cors(jsonify({"ok": False, "error": "helper token not configured"})), 503

    submitted = request.headers.get("X-Privana-Helper-Token", "").strip()
    if not submitted or not hmac.compare_digest(submitted, HELPER_TOKEN):
        return with_cors(jsonify({"ok": False, "error": "unauthorized helper request"})), 401

    return None


@app.after_request
def _after(resp):
    return with_cors(resp)


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    if request.method == "OPTIONS":
        return with_cors(make_response("", 204))
    wg_gui, wg_cli = wireguard_paths()
    return with_cors(
        jsonify(
            {
                "ok": True,
                "admin": is_admin(),
                "wireguard_exe": wg_gui,
                "wg_exe": wg_cli,
                "hint": "Run this helper as Administrator to install/start/stop tunnels.",
            }
        )
    )


@app.route("/status", methods=["GET", "OPTIONS"])
def status():
    if request.method == "OPTIONS":
        return with_cors(make_response("", 204))

    auth_error = require_helper_token()
    if auth_error:
        return auth_error

    name = safe_name(request.args.get("name") or request.args.get("tunnel") or "Privana")
    installed = service_exists(name)
    running = installed and service_running(name)
    svc = service_name_for(name)
    return with_cors(
        jsonify({"ok": True, "name": name, "service": svc, "installed": installed, "running": running})
    )


@app.route("/import-config", methods=["POST", "OPTIONS"])
def import_config():
    r"""
    Install/refresh a WireGuard tunnel service from raw config text.
    Body: {"name":"Laptop-1", "config":"[Interface] ..."}
    - Writes to C:\ProgramData\WireGuard\<name>.conf
    - If a service with that name already exists, it will be reinstalled.
    """
    if request.method == "OPTIONS":
        return with_cors(make_response("", 204))

    auth_error = require_helper_token()
    if auth_error:
        return auth_error

    if not is_admin():
        return with_cors(jsonify({"ok": False, "error": "Helper must run as Administrator"})), 403

    wg_gui, _ = wireguard_paths()
    if not wg_gui:
        return with_cors(jsonify({"ok": False, "error": "wireguard.exe not found"})), 500

    payload = request.get_json(silent=True) or {}
    name = safe_name(payload.get("name") or "Privana")
    config_text = (payload.get("config") or "").strip()
    if not config_text:
        return with_cors(jsonify({"ok": False, "error": "Missing config"})), 400

    path = conf_path_for(name)

    # Write/overwrite file on disk
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, config_text.encode("utf-8"))
        finally:
            os.close(fd)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except Exception as e:
        return with_cors(jsonify({"ok": False, "error": f"write failed: {e}"})), 500

    # If service exists, uninstall first so changes apply cleanly.
    if service_exists(name):
        log.info("Service %s exists; uninstalling before reinstall", name)
        # Best effort stop
        if service_running(name):
            sc_stop(name)
        code_u, out_u, err_u = wg_uninstall_tunnel(wg_gui, name)
        if code_u != 0 and "does not exist" not in (out_u + err_u).lower():
            return with_cors(
                jsonify({"ok": False, "error": "uninstall failed", "stdout": out_u, "stderr": err_u})
            ), 500

    # Install (copies & encrypts config internally)
    code_i, out_i, err_i = wg_install_tunnel(wg_gui, path)
    if code_i != 0 and "already installed" not in (out_i + err_i).lower():
        return with_cors(
            jsonify({"ok": False, "error": "install failed", "stdout": out_i, "stderr": err_i})
        ), 500

    return with_cors(
        jsonify({"ok": True, "name": name, "service": service_name_for(name), "path": path})
    )


@app.route("/connect", methods=["POST", "OPTIONS"])
def connect():
    if request.method == "OPTIONS":
        return with_cors(make_response("", 204))

    auth_error = require_helper_token()
    if auth_error:
        return auth_error

    if not is_admin():
        return with_cors(jsonify({"ok": False, "error": "Helper must run as Administrator"})), 403

    data = request.get_json(silent=True) or {}
    name = safe_name(data.get("name") or "Privana")

    # Auto-install if service missing but config exists on disk
    if not service_exists(name):
        wg_gui, _ = wireguard_paths()
        if not wg_gui:
            return with_cors(jsonify({"ok": False, "error": "wireguard.exe not found"})), 500
        path = conf_path_for(name)
        if os.path.exists(path):
            code_i, out_i, err_i = wg_install_tunnel(wg_gui, path)
            if code_i != 0 and "already installed" not in (out_i + err_i).lower():
                return with_cors(
                    jsonify({"ok": False, "error": "install failed", "stdout": out_i, "stderr": err_i})
                ), 500
        else:
            return with_cors(
                jsonify({"ok": False, "error": "tunnel not installed and no config on disk"})
            ), 400

    # Start service
    code, out, err = sc_start(name)
    combined = (out + "\n" + err).upper()
    ok = (code == 0) or ("ALREADY" in combined) or service_running(name)
    if not ok:
        return with_cors(jsonify({"ok": False, "error": "start failed", "stdout": out, "stderr": err})), 500

    return with_cors(jsonify({"ok": True, "name": name, "service": service_name_for(name)}))


@app.route("/disconnect", methods=["POST", "OPTIONS"])
def disconnect():
    if request.method == "OPTIONS":
        return with_cors(make_response("", 204))

    auth_error = require_helper_token()
    if auth_error:
        return auth_error

    if not is_admin():
        return with_cors(jsonify({"ok": False, "error": "Helper must run as Administrator"})), 403

    data = request.get_json(silent=True) or {}
    name = safe_name(data.get("name") or "Privana")

    # Stop service
    code, out, err = sc_stop(name)
    combined = (out + "\n" + err).upper()
    ok = (code == 0) or ("STOPPED" in combined) or ("SERVICE_NOT_ACTIVE" in combined)
    if not ok:
        return with_cors(jsonify({"ok": False, "error": "stop failed", "stdout": out, "stderr": err})), 500

    return with_cors(jsonify({"ok": True, "name": name, "service": service_name_for(name)}))


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    log.info("Privana helper listening on http://%s:%s", APP_HOST, APP_PORT)
    # Important: no auto reloader (avoid double-binding), single process
    app.run(host=APP_HOST, port=APP_PORT, debug=False, threaded=True, use_reloader=False)
