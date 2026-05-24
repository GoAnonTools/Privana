import hmac
import hashlib
import json
import os
import time
import requests


class PrivanaAPIClient:
    def __init__(self, base_url="https://api.privana.pro"):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "Privana/1.0",
        }

    def _build_auth_headers(
        self,
        shared_secret: bytes,
        session_id: str,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> dict:
        """
        Build HMAC auth headers using the PQC-derived shared secret.

        The shared secret itself is never sent over the wire.
        """
        ts = str(int(time.time()))
        nonce = os.urandom(32).hex()
        body_json = json.dumps(body or {}, separators=(",", ":"), sort_keys=True)

        message = f"{ts}:{method.upper()}:{path}:{nonce}:{body_json}".encode("utf-8")
        mac = hmac.new(shared_secret, message, hashlib.sha256).hexdigest()

        return {
            "Authorization": mac,
            "X-Timestamp": ts,
            "X-Nonce": nonce,
            "X-PQC-Session": session_id,
        }

    def _headers_for(
        self,
        shared_secret: bytes,
        session_id: str,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> dict:
        headers = dict(self.headers)
        headers.update(self._build_auth_headers(shared_secret, session_id, method, path, body))
        return headers

    def get_wg_config(self, shared_secret: bytes, session_id: str):
        """Get WireGuard configuration from server using PQC-HMAC auth."""
        path = "/vpn/config"
        endpoint = f"{self.base_url}{path}"
        payload = {
            "client_info": {
                "os": "linux",
                "version": "1.0",
            }
        }

        headers = self._headers_for(shared_secret, session_id, "POST", path, payload)

        try:
            response = requests.post(endpoint, headers=headers, json=payload, timeout=15)
            response.raise_for_status()
            return response.json().get("config", "")
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get WireGuard config: {str(e)}")

    def check_status(self, shared_secret: bytes, session_id: str):
        """Check VPN connection status using PQC-HMAC auth."""
        path = "/vpn/status"
        endpoint = f"{self.base_url}{path}"
        payload = {}

        headers = self._headers_for(shared_secret, session_id, "GET", path, payload)

        try:
            response = requests.get(endpoint, headers=headers, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to check status: {str(e)}")
