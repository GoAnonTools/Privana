from flask import Flask
from web.routes import auth_bp, dashboard_bp
import os
from web.routes import auth_bp, dashboard_bp, downloads_bp, webauthn_bp

# Get the absolute path of the current file
basedir = os.path.abspath(os.path.dirname(__file__))

# Create Flask app with custom template and static folders
app = Flask(__name__, 
            template_folder=os.path.join(basedir, 'templates'),
            static_folder=os.path.join(basedir, 'static'))

from datetime import timedelta

# Configure the app
# Use env vars from .env or environment. Fallbacks are dev-only.
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "dev-insecure-change-me")
app.config['SECURITY_PASSWORD_SALT'] = os.getenv("SECURITY_PASSWORD_SALT", "dev-insecure-salt")

# 30-day session (token) expiration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)

# Harden cookies
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'   # consider 'Strict' if your flows allow it
# Set this to True in production behind HTTPS
app.config['SESSION_COOKIE_SECURE'] = os.getenv("SESSION_COOKIE_SECURE", "False").lower() == "true"

# Rate limiting
from rate_limit import limiter
limiter.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(dashboard_bp, url_prefix='/dashboard')
app.register_blueprint(downloads_bp)
app.register_blueprint(webauthn_bp)

if __name__ == '__main__':
    app.run(debug=True)