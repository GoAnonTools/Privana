# web/utils/api_client.py
import os
import time
import hmac
import hashlib
import json
import requests
from typing import Dict, Any, Optional

# Base URL of your Singapore API (set this in .env on the PH web app)
API_BASE = os.getenv("SINGAPORE_API_BASE", "http://127.0.0.1:8080")
API_SECRET = os.getenv("API_SECRET", "")

# Optional: certificate pinning later
# PINNED_CERT_PATH = os.getenv("PINNED_CERT_PATH")  # e.g. "/etc/privana/sg_cert.pem"

def _sign(method: str, path: str, body: str = "") -> Dict[str, str]:
    ts = str(int(time.time()))
    message = f"{ts}:{method.upper()}:{path}:{body}"
    sig = hmac.new(API_SECRET.encode(), message.encode(), hashlib.sha256).hexdigest()
    return {
        "Authorization": sig,
        "X-Timestamp": ts,
        "Content-Type": "application/json",
    }

def _session() -> requests.Session:
    s = requests.Session()
    # If you enable pinning later:
    # if PINNED_CERT_PATH:
    #     s.verify = PINNED_CERT_PATH
    return s

def api_get(path: str, timeout: int = 10) -> requests.Response:
    headers = _sign("GET", path, "")
    return _session().get(API_BASE + path, headers=headers, timeout=timeout)

def api_post_json(path: str, payload: Dict[str, Any], timeout: int = 10) -> requests.Response:
    body = json.dumps(payload, separators=(",", ":"))  # deterministic JSON
    headers = _sign("POST", path, body)
    return _session().post(API_BASE + path, headers=headers, data=body, timeout=timeout)

# Convenience wrappers matching your current API -------------------------------

def sg_status() -> requests.Response:
    return api_get("/api/status")

def sg_start() -> requests.Response:
    return api_post_json("/api/start", {})

def sg_stop() -> requests.Response:
    return api_post_json("/api/stop", {})

def sg_restart() -> requests.Response:
    return api_post_json("/api/restart", {})

def sg_add_peer(public_key: str, user_id: int, device_id: Optional[int] = None) -> requests.Response:
    payload = {"public_key": public_key, "user_id": user_id}
    if device_id is not None:
        payload["device_id"] = device_id
    return api_post_json("/api/peer/add", payload)

def sg_remove_peer(public_key: str) -> requests.Response:
    return api_post_json("/api/peer/remove", {"public_key": public_key})

def sg_update_peer_last_connected(public_key: str) -> requests.Response:
    return api_post_json("/api/peer/update", {"public_key": public_key})

def sg_get_peer_config(public_key: str) -> requests.Response:
    return api_get(f"/api/peer/config/{public_key}")

def sg_stats() -> requests.Response:
    return api_get("/api/stats")

def sg_server_config() -> requests.Response:
    return api_get("/api/config")
