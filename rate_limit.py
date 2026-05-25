# rate_limit.py
import os
import warnings
from flask_limiter import Limiter
from flask import request


def _rate_limit_client_ip() -> str:
    """
    Rate-limit key function.

    By default, use request.remote_addr only. X-Forwarded-For is trusted only
    when TRUST_PROXY_HEADERS=true and the app is deployed behind a trusted
    reverse proxy that strips/rebuilds forwarded headers.
    """
    trust_proxy = os.getenv("TRUST_PROXY_HEADERS", "false").lower() == "true"
    if trust_proxy:
        forwarded = (request.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
        if forwarded:
            return forwarded
    return request.remote_addr or "unknown"


_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
_ENV = os.getenv("ENVIRONMENT", "development").lower()

# Warn loudly if running in production without a persistent storage backend.
# In-memory limits reset on every restart and don't work across multiple workers.
if _STORAGE_URI == "memory://" and _ENV != "development":
    raise RuntimeError(
        "RATELIMIT_STORAGE_URI must be set to a shared backend outside development. "
        "Use Redis, for example: redis://localhost:6379/0"
    )

limiter = Limiter(
    key_func=_rate_limit_client_ip,
    default_limits=[],       # per-route limits defined explicitly on each route
    storage_uri=_STORAGE_URI,
)