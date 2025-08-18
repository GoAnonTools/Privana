#!/usr/bin/env python3
"""
Production server startup script for Singapore deployment
"""
import os
import sys

# Set production environment
os.environ['ENVIRONMENT'] = 'production'

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from main import WireGuardServer
import config

def check_production_requirements():
    """Check if all production requirements are met"""
    missing = []
    
    # Check required environment variables
    required_vars = ['WG_HOST', 'API_SECRET']
    for var in required_vars:
        if not os.environ.get(var):
            missing.append(f"Environment variable {var} is not set")
    
    # Check if WireGuard is installed
    import shutil
    if not shutil.which('wg'):
        missing.append("WireGuard tools not installed (apt install wireguard-tools)")
    
    return missing

if __name__ == '__main__':
    print("🇸🇬 Starting WireGuard Server - PRODUCTION MODE (Singapore)")
    
    # Check requirements
    issues = check_production_requirements()
    if issues:
        print("❌ Production Requirements Not Met:")
        for issue in issues:
            print(f"   - {issue}")
        print("\n📖 For setup instructions, run:")
        print("   python -c \"from config import ProductionConfig; print(ProductionConfig.get_deployment_guide())\"")
        sys.exit(1)
    
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