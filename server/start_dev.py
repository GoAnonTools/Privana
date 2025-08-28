#!/usr/bin/env python3
"""
Development server startup script for local testing in France
"""
import os
import sys

# Set development environment
os.environ['ENVIRONMENT'] = 'development'
os.environ['WG_HOST'] = '91.163.90.105'  # Your current French IP

# Add the project root to Python path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from main import WireGuardServer
import config
from web.routes.auth import DB_PATH # Import DB_PATH

if __name__ == '__main__':
    print("🇫🇷 Starting WireGuard Server - DEVELOPMENT MODE (France)")
    print("This is for local testing only!\n")
    
    # Show configuration
    config.Config.print_info()

    # --- Start: Added for testing new user workflow ---
    if os.path.exists(DB_PATH):
        print(f"🗑️ Deleting existing database: {DB_PATH}")
        os.remove(DB_PATH)
    # --- End: Added for testing new user workflow ---
    
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