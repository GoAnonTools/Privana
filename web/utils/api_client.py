# web/utils/api_client.py
import os
import time
import hmac
import hashlib
import json
import secrets
from typing import Dict, Any, Optional
from urllib.parse import quote

import requests


# ---- Config helpers ---------------------------------------------------------

def _api_base() -> str:
    # Points to your API (Panama) when live; default is local dev.
    # Keep the var name for backward-compat.
    return os.getenv("SINGAPORE_API_BASE", "http://127.0.0.1:8080").rstrip("/")

def _api_secret() -> str:
    secret = os.getenv("API_SECRET", "")
    if not secret:
        raise RuntimeError(
            "API_SECRET is not set. Ensure .env has API_SECRET and web/app.py loads it."
        )
    return secret

def _session() -> requests.Session:
    s = requests.Session()
    # Optional: custom CA bundle or pinned cert path
    cert_path = os.getenv("SG_CERT_PATH", "").strip()
    if cert_path:
        s.verify = cert_path
    return s


# ---- HMAC signing -----------------------------------------------------------

def _sign(method: str, path: str, body: str = "") -> Dict[str, str]:
    """
    Very simple HMAC auth:
      signature = HMAC_SHA256(API_SECRET, f"{ts}:{METHOD}:{path}:{body}:{nonce}")
    Sent as: Authorization, X-Timestamp, X-Nonce
    """
    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)  # 128-bit nonce
    msg = f"{ts}:{method.upper()}:{path}:{body}:{nonce}"
    sig = hmac.new(_api_secret().encode(), msg.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": sig,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "Content-Type": "application/json",
    }


# ---- Low-level HTTP ---------------------------------------------------------

def api_get(path: str, timeout: int = 10) -> requests.Response:
    if not path.startswith("/"):
        path = "/" + path
    headers = _sign("GET", path, "")
    return _session().get(_api_base() + path, headers=headers, timeout=timeout)

def api_post_json(path: str, payload: Dict[str, Any], timeout: int = 10) -> requests.Response:
    if not path.startswith("/"):
        path = "/" + path
    body = json.dumps(payload, separators=(",", ":"))
    headers = _sign("POST", path, body)
    return _session().post(_api_base() + path, headers=headers, data=body, timeout=timeout)


# ---- Convenience wrappers (server API) --------------------------------------

def sg_status() -> requests.Response:
    return api_get("/api/status")

def sg_start() -> requests.Response:
    return api_post_json("/api/start", {})

def sg_stop() -> requests.Response:
    return api_post_json("/api/stop", {})

def sg_restart() -> requests.Response:
    return api_post_json("/api/restart", {})

def sg_add_peer(public_key: str, user_id: int, device_id: Optional[int] = None) -> requests.Response:
    payload: Dict[str, Any] = {"public_key": public_key, "user_id": user_id}
    if device_id is not None:
        payload["device_id"] = device_id
    return api_post_json("/api/peer/add", payload)

def sg_issue_config(user_id: int, device_id: int) -> requests.Response:
    payload = {"user_id": user_id, "device_id": device_id}
    return api_post_json("/api/peer/issue-config", payload)

def sg_remove_peer(public_key: str) -> requests.Response:
    return api_post_json("/api/peer/remove", {"public_key": public_key})

def sg_update_peer_last_connected(public_key: str) -> requests.Response:
    return api_post_json("/api/peer/update", {"public_key": public_key})

def sg_get_peer_config(public_key: str) -> requests.Response:
    # URL-encode so + / = don’t break the path
    pk = quote(public_key, safe="")
    return api_get(f"/api/peer/config/{pk}")

def sg_stats() -> requests.Response:
    return api_get("/api/stats")

def sg_server_config() -> requests.Response:
    return api_get("/api/config")
