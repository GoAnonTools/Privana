#!/usr/bin/env python3
"""
Development server startup script for local testing in France
"""
import os
import sys

# Set development environment
os.environ['ENVIRONMENT'] = 'development'
os.environ.setdefault('WG_HOST', '127.0.0.1')  # Override locally via .env or shell

# Add the project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from main import WireGuardServer
import config
from web.routes.auth import DB_PATH

RESET_DEV_DB = os.getenv("RESET_DEV_DB", "false").lower() == "true"

if __name__ == '__main__':
    print("🇫🇷 Starting WireGuard Server - DEVELOPMENT MODE (France)")
    print("This is for local testing only!\n")
    
    # Show configuration
    config.Config.print_info()

    if RESET_DEV_DB:
        if os.path.exists(DB_PATH):
            print(f"⚠️ RESET_DEV_DB=true — deleting development database: {DB_PATH}")
            os.remove(DB_PATH)
    
    # Start the server
    server = WireGuardServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
        server.stop()
    except Exception as e:
        print(f"\n❌ Server error: {e}")
        server.stop()
        sys.exit(1)