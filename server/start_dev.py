#!/usr/bin/env python3
"""
Development server startup script for local testing in France
"""
import os
import sys

# Set development environment
os.environ['ENVIRONMENT'] = 'development'
os.environ['WG_HOST'] = '91.163.90.105'  # Your current French IP

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import WireGuardServer
import config

if __name__ == '__main__':
    print("🇫🇷 Starting WireGuard Server - DEVELOPMENT MODE (France)")
    print("This is for local testing only!\n")
    
    # Show configuration
    config.Config.print_info()
    
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