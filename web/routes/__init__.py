from .auth import auth_bp
from .dashboard import dashboard_bp
from .downloads import downloads_bp
from .webauthn import webauthn_bp 

__all__ = ["auth_bp", "dashboard_bp", "downloads_bp", "webauthn_bp"]
