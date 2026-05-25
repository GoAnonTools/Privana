# web/crypto.py
import base64
import hashlib
import os

from Crypto.Cipher import AES

_PREFIX = "enc:v1:"
_ENV_KEY = "WEB_CONFIG_ENC_KEY"


def _key() -> bytes:
    """
    Return a 32-byte AES key for encrypting sensitive web DB values.

    Production should set WEB_CONFIG_ENC_KEY to either:
    - a 64-character hex string, or
    - a base64-encoded 32-byte value.

    Development falls back to a deterministic local-only key so tests/local
    flows do not require extra setup.
    """
    raw = (os.getenv(_ENV_KEY) or "").strip()

    if raw:
        try:
            if len(raw) == 64:
                key = bytes.fromhex(raw)
            else:
                key = base64.b64decode(raw, validate=True)
        except Exception as exc:
            raise RuntimeError(f"{_ENV_KEY} must be 32 bytes as hex or base64.") from exc

        if len(key) != 32:
            raise RuntimeError(f"{_ENV_KEY} must decode to 32 bytes.")

        return key

    if os.getenv("ENVIRONMENT", "development").strip().lower() == "production":
        raise RuntimeError(f"{_ENV_KEY} is required in production.")

    return hashlib.sha256(b"privana-dev-only-web-config-key").digest()


def encrypt_text(value: str) -> str:
    """Encrypt text with AES-256-GCM. Already-encrypted values are returned unchanged."""
    if value is None:
        return value

    value = str(value)
    if value.startswith(_PREFIX):
        return value

    cipher = AES.new(_key(), AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(value.encode("utf-8"))

    parts = [
        base64.b64encode(cipher.nonce).decode("ascii"),
        base64.b64encode(tag).decode("ascii"),
        base64.b64encode(ciphertext).decode("ascii"),
    ]
    return _PREFIX + ":".join(parts)


def decrypt_text(value: str) -> str:
    """
    Decrypt text encrypted by encrypt_text().

    Legacy plaintext fallback: values without enc:v1: are returned unchanged.
    """
    if value is None:
        return value

    value = str(value)
    if not value.startswith(_PREFIX):
        return value

    payload = value[len(_PREFIX):]
    nonce_b64, tag_b64, ciphertext_b64 = payload.split(":", 2)

    cipher = AES.new(_key(), AES.MODE_GCM, nonce=base64.b64decode(nonce_b64))
    plaintext = cipher.decrypt_and_verify(
        base64.b64decode(ciphertext_b64),
        base64.b64decode(tag_b64),
    )
    return plaintext.decode("utf-8")
