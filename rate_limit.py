# rate_limit.py
import os
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Use in-memory by default. In prod, set: RATELIMIT_STORAGE_URI=redis://localhost:6379/0
_STORAGE_URI = os.getenv("RATELIMIT_STORAGE_URI", "memory://")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],            # we’ll attach per-route limits explicitly
    storage_uri=_STORAGE_URI
)
