import os
import logging
import requests


log = logging.getLogger("privana.qrng")


class QRNGError(RuntimeError):
    """Raised when QRNG data cannot be fetched and fallback is disabled."""


class QRNGClient:
    """
    ANU QRNG client.

    Security behavior:
    - Uses a network timeout so connection flow cannot hang forever.
    - Falls back to os.urandom only when PRIVANA_QRNG_ALLOW_FALLBACK=true.
    - Logs every fallback as WARNING so downgrades are visible.
    """

    def __init__(self, api_url: str | None = None, timeout: float | None = None):
        self.api_url = api_url or os.getenv(
            "PRIVANA_QRNG_API_URL",
            "https://qrng.anu.edu.au/API/jsonI.php",
        )
        self.timeout = float(os.getenv("PRIVANA_QRNG_TIMEOUT", str(timeout or 10)))
        self.allow_fallback = os.getenv("PRIVANA_QRNG_ALLOW_FALLBACK", "true").lower() == "true"
        self.last_used_fallback = False

    def _fallback(self, length: int, reason: Exception | str) -> bytes:
        self.last_used_fallback = True
        log.warning(
            "QRNG unavailable; using os.urandom fallback. length=%s reason=%s",
            length,
            reason,
        )

        if not self.allow_fallback:
            raise QRNGError("QRNG unavailable and fallback is disabled.") from (
                reason if isinstance(reason, Exception) else None
            )

        return os.urandom(length)

    def get_random_data(self, length: int = 32) -> bytes:
        """Get random bytes from ANU QRNG, with logged/configurable fallback."""
        if length <= 0:
            raise ValueError("length must be positive")

        self.last_used_fallback = False

        # ANU hex16 returns 16-bit values as hex strings.
        # Need ceil(length / 2) values to produce at least `length` bytes.
        values_needed = (length + 1) // 2
        params = {
            "length": values_needed,
            "type": "hex16",
            "size": 1,
        }

        try:
            response = requests.get(self.api_url, params=params, timeout=self.timeout)
            response.raise_for_status()
            payload = response.json()

            if not payload.get("success"):
                return self._fallback(length, f"QRNG API returned success={payload.get('success')}")

            data = payload.get("data")
            if not isinstance(data, list) or not data:
                return self._fallback(length, "QRNG API returned no data")

            hex_data = "".join(str(x).strip() for x in data)
            raw = bytes.fromhex(hex_data)

            if len(raw) < length:
                return self._fallback(length, f"QRNG returned too few bytes: {len(raw)}")

            return raw[:length]

        except Exception as exc:
            return self._fallback(length, exc)
