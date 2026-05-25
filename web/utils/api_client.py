import os
import time
import hmac
import json
import hashlib
import secrets
import requests


VPN_API_BASE = os.getenv("VPN_API_BASE", "http://127.0.0.1:8080").rstrip("/")
API_SECRET = os.getenv("API_SECRET", "").strip()
TIMEOUT = (5, 20)


class APIClientError(RuntimeError):
    pass


def _canonical_body(data: dict | None) -> str:
    return json.dumps(data or {}, separators=(",", ":"), sort_keys=True)


def _headers(method: str, path: str, body: dict | None = None) -> dict:
    """
    Build HMAC headers for the local/server VPN API.

    Must match server/api.py auth_required:
      message = f"{ts}:{METHOD}:{PATH}:{body}:{nonce}"
    """
    if not API_SECRET:
        raise APIClientError("API_SECRET is not configured.")

    ts = str(int(time.time()))
    nonce = secrets.token_hex(16)
    body_text = _canonical_body(body)

    message = f"{ts}:{method.upper()}:{path}:{body_text}:{nonce}"
    sig = hmac.new(API_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()

    return {
        "Content-Type": "application/json",
        "Authorization": sig,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
    }


def _request(method: str, path: str, body: dict | None = None):
    url = VPN_API_BASE + path
    headers = _headers(method, path, body)

    if method.upper() == "GET":
        return requests.get(url, headers=headers, timeout=TIMEOUT)

    return requests.request(
        method.upper(),
        url,
        headers=headers,
        data=_canonical_body(body),
        timeout=TIMEOUT,
    )


def sg_status():
    return _request("GET", "/api/status")


def sg_add_peer(public_key: str, user_id: int | None = None, device_id: int | None = None):
    payload = {
        "public_key": public_key,
        "user_id": user_id,
        "device_id": device_id,
    }
    return _request("POST", "/api/peer/add", payload)


def sg_get_peer_config(public_key: str):
    # public_key is path-bound by dashboard route; server should validate format too.
    return _request("GET", f"/api/peer/config/{public_key}")


def sg_remove_peer(public_key: str):
    payload = {"public_key": public_key}
    return _request("POST", "/api/peer/remove", payload)


def sg_update_peer_last_connected(public_key: str):
    payload = {"public_key": public_key}
    return _request("POST", "/api/peer/heartbeat", payload)


def sg_stats():
    return _request("GET", "/api/stats")
