import os
import sys

# Add the server directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Production-safe environment defaults.
# Do NOT use 0.0.0.0 as WG_HOST: it is invalid inside client WireGuard configs.
os.environ.setdefault("WG_PORT", "51820")
os.environ.setdefault("WG_INTERFACE", "wg0")
os.environ.setdefault("API_HOST", "127.0.0.1")
os.environ.setdefault("API_PORT", "8080")
os.environ.setdefault("DATABASE_URL", "sqlite:///server.db")
os.environ.setdefault("CLIENT_IP_RANGE", "10.0.1.0/24")

api_secret = os.getenv("API_SECRET", "").strip()
if not api_secret:
    raise RuntimeError("API_SECRET is not set. Refusing to start server.")

wg_host = os.getenv("WG_HOST", "").strip()
if not wg_host:
    raise RuntimeError("WG_HOST is not set. Set it to your public VPN hostname or VPS public IP.")

if wg_host in {"0.0.0.0", "127.0.0.1", "localhost"}:
    raise RuntimeError("WG_HOST must be a real public VPN hostname or IP, not 0.0.0.0/localhost.")

api_host = os.getenv("API_HOST", "127.0.0.1").strip()
if api_host == "0.0.0.0":
    raise RuntimeError("API_HOST must not be 0.0.0.0 for this deployment. Use 127.0.0.1 behind Nginx/systemd.")

os.environ["API_SECRET"] = api_secret
os.environ["WG_HOST"] = wg_host
os.environ["API_HOST"] = api_host

# Import and run the main server
from main import WireGuardServer

server = WireGuardServer()
server.start()