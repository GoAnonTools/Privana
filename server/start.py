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
os.environ['API_SECRET'] = os.getenv('API_SECRET', '')
if not os.environ['API_SECRET']:
    import secrets
    os.environ['API_SECRET'] = secrets.token_hex(32)
    print("⚠️  API_SECRET not set. Generated temporary secret. Set API_SECRET in .env for production.")
os.environ['DATABASE_URL'] = 'sqlite:///server.db'
os.environ['CLIENT_IP_RANGE'] = '10.0.1.0/24'

# Import and run the main server
from main import WireGuardServer

server = WireGuardServer()
server.start()