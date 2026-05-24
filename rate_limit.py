# rate_limit.py
import os
import warnings
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")
_ENV = os.getenv("ENVIRONMENT", "development").lower()

# Warn loudly if running in production without a persistent storage backend.
# In-memory limits reset on every restart and don't work across multiple workers.
if _STORAGE_URI == "memory://" and _ENV == "production":
    warnings.warn(
        "Rate limiter is using in-memory storage in a production environment. "
        "Limits will reset on restart and won't work across workers. "
        "Set RATELIMIT_STORAGE_URI=redis://localhost:6379/0 in your .env file.",
        RuntimeWarning,
        stacklevel=2,
    )

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],       # per-route limits defined explicitly on each route
    storage_uri=_STORAGE_URI,
)