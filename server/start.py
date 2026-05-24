import os
import sys

# Add the server directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set environment variables
os.environ['WG_HOST'] = '0.0.0.0'
os.environ['WG_PORT'] = '51820'
os.environ['WG_INTERFACE'] = 'wg0'
os.environ['API_HOST'] = '0.0.0.0'
os.environ['API_PORT'] = '8080'
api_secret = os.getenv("API_SECRET", "")

if not api_secret:
    raise RuntimeError("API_SECRET is not set. Refusing to start server.")

os.environ["API_SECRET"] = api_secret
os.environ['DATABASE_URL'] = 'sqlite:///server.db'
os.environ['CLIENT_IP_RANGE'] = '10.0.1.0/24'

# Import and run the main server
from main import WireGuardServer

server = WireGuardServer()
server.start()