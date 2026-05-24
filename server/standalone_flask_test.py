#!/usr/bin/env python3
"""
Standalone Flask test to isolate the API issues
"""
import os
import sys

# Set development environment
os.environ['ENVIRONMENT'] = 'development'
os.environ.setdefault('WG_HOST', '127.0.0.1')

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify
from functools import wraps

print("🔍 Starting standalone Flask test...")

# Import and test config
try:
    import config
    cfg = config.get_config()
    print(f"✅ Config loaded: Environment={cfg.ENVIRONMENT}, API_SECRET={cfg.API_SECRET}")
except Exception as e:
    print(f"❌ Config error: {e}")
    sys.exit(1)

# Create Flask app
app = Flask(__name__)
app.config['DEBUG'] = True
app.config['API_SECRET'] = cfg.API_SECRET

print(f"✅ Flask app created")

# Test WireGuard import
wg_manager = None
try:
    import wireguard
    print(f"✅ WireGuard module imported")
    wg_manager = wireguard.WireGuardManager()
    print(f"✅ WireGuard manager created")
except Exception as e:
    print(f"❌ WireGuard error: {e}")
    print(f"   This is likely the source of your 500 errors!")
    import traceback
    traceback.print_exc()

# Simple auth
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token or token != f"Bearer {app.config['API_SECRET']}":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated_function

# Test endpoints
@app.route('/test', methods=['GET'])
def test_simple():
    return jsonify({'success': True, 'message': 'Simple endpoint works!'})

@app.route('/test-auth', methods=['GET'])
@auth_required
def test_auth():
    return jsonify({'success': True, 'message': 'Auth endpoint works!'})

@app.route('/test-wg', methods=['GET'])
@auth_required
def test_wireguard():
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        is_running, status = wg_manager.get_interface_status()
        return jsonify({'success': True, 'is_running': is_running, 'status': status})
    except Exception as e:
        return jsonify({'success': False, 'message': f'WireGuard error: {str(e)}'})

if __name__ == '__main__':
    print("🚀 Starting Flask server on http://127.0.0.1:5000")
    print("Test endpoints:")
    print("  curl http://127.0.0.1:5000/test")
    print("  curl -H 'Authorization: Bearer dev_secret_key_123456' http://127.0.0.1:5000/test-auth")
    print("  curl -H 'Authorization: Bearer dev_secret_key_123456' http://127.0.0.1:5000/test-wg")
    app.run(debug=True, host='127.0.0.1', port=5000)