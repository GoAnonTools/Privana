import hmac
import hashlib
import json
import os
import time
import requests


class PrivanaAPIError(RuntimeError):
    """Raised when Privana API communication fails."""


class PrivanaAPIClient:
    def __init__(self, base_url="https://api.privana.pro", user_agent: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = float(os.getenv("PRIVANA_API_TIMEOUT", "15"))
        self.verify_tls = os.getenv("PRIVANA_API_VERIFY_TLS", "true").lower() != "false"
        self.user_agent = user_agent or os.getenv("PRIVANA_USER_AGENT", "Privana Client")

        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": self.user_agent,
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

        Replay protection note:
        - Client sends timestamp + nonce.
        - Server must enforce timestamp skew limits and nonce de-duplication.
        - The client never reuses a nonce because it is generated with OS entropy per request.
        """
        if len(shared_secret) != 32:
            raise ValueError("PQC shared secret must be exactly 32 bytes.")
        if not session_id:
            raise ValueError("PQC session_id is required.")

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
                "os": os.getenv("PRIVANA_CLIENT_OS", "linux"),
                "version": os.getenv("PRIVANA_CLIENT_VERSION", "1.0"),
            }
        }

        headers = self._headers_for(shared_secret, session_id, "POST", path, payload)

        try:
            response = requests.post(
                endpoint,
                headers=headers,
                json=payload,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            return response.json().get("config", "")
        except requests.exceptions.RequestException as e:
            raise PrivanaAPIError("Failed to get WireGuard config.") from e

    def check_status(self, shared_secret: bytes, session_id: str):
        """Check VPN connection status using PQC-HMAC auth."""
        path = "/vpn/status"
        endpoint = f"{self.base_url}{path}"
        payload = {}

        headers = self._headers_for(shared_secret, session_id, "GET", path, payload)

        try:
            response = requests.get(
                endpoint,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise PrivanaAPIError("Failed to check status.") from e
