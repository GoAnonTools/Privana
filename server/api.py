from flask import Flask, request, jsonify
import os
import json
import base64
from datetime import datetime
from functools import wraps
import config
import hmac
import hashlib
import time

from dotenv import load_dotenv
load_dotenv()  # ensures API_SECRET is loaded from .env when you run `python api.py`

# Create Flask app
app = Flask(__name__)
app.config.from_object(config.get_config())

# Debug: Print config to verify it's working
print(f"🔍 Flask app config loaded:")
print(f"   Environment: {app.config.get('ENVIRONMENT')}")
print(f"   API_SECRET: {app.config.get('API_SECRET')}")

# Initialize WireGuard manager with error handling
wg_manager = None
try:
    import wireguard
    wg_manager = wireguard.WireGuardManager()
    print("✅ WireGuard manager initialized successfully")
except Exception as e:
    print(f"❌ Failed to initialize WireGuard manager: {e}")
    wg_manager = None

# Simple authentication middleware
def auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        timestamp = request.headers.get("X-Timestamp")

        if not auth_header or not timestamp:
            return jsonify({"success": False, "message": "Missing auth headers"}), 401

        try:
            ts = int(timestamp)
        except ValueError:
            return jsonify({"success": False, "message": "Invalid timestamp"}), 401

        # Reject requests older than 30 seconds
        if abs(int(time.time()) - ts) > 30:
            return jsonify({"success": False, "message": "Request expired"}), 401

        # Compute expected HMAC
        method = request.method
        path = request.path
        body = request.get_data(as_text=True) or ""

        message = f"{ts}:{method}:{path}:{body}"
        expected_sig = hmac.new(
            app.config["API_SECRET"].encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(auth_header, expected_sig):
            return jsonify({"success": False, "message": "Unauthorized"}), 401

        return f(*args, **kwargs)
    return decorated_function


@app.route('/api/status', methods=['GET'])
@auth_required
def get_status():
    """Get the status of the WireGuard server"""
    if not wg_manager:
        return jsonify({
            'success': False,
            'message': 'WireGuard manager not available',
            'is_running': False,
            'status_output': 'Manager not initialized',
            'peers_count': 0,
            'peers': []
        })
    
    try:
        is_running, status_output = wg_manager.get_interface_status()
        peers = wg_manager.list_peers()
        
        return jsonify({
            'success': True,
            'is_running': is_running,
            'status_output': status_output,
            'peers_count': len(peers),
            'peers': peers
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Error getting status: {str(e)}'
        })

@app.route('/api/start', methods=['POST'])
@auth_required
def start_server():
    """Start the WireGuard server"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        success, message = wg_manager.start_interface()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/stop', methods=['POST'])
@auth_required
def stop_server():
    """Stop the WireGuard server"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        success, message = wg_manager.stop_interface()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/restart', methods=['POST'])
@auth_required
def restart_server():
    """Restart the WireGuard server"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        wg_manager.stop_interface()
        success, message = wg_manager.start_interface()
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/peer/add', methods=['POST'])
@auth_required
def add_peer():
    """Add a new peer to the WireGuard server"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    data = request.get_json()
    
    if not data or 'public_key' not in data or 'user_id' not in data:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400
    
    public_key = data['public_key']
    user_id = data['user_id']
    device_id = data.get('device_id')
    
    try:
        success, result_or_message, assigned_ip = wg_manager.add_peer(public_key, user_id, device_id)
        
        if success:
            # Get the peer configuration
            peer_config = wg_manager.get_peer_config(public_key)
            
            return jsonify({
                'success': True,
                'message': 'Peer added successfully',
                'peer_id': result_or_message,
                'assigned_ip': assigned_ip,
                'config': peer_config
            })
        else:
            return jsonify({
                'success': False,
                'message': result_or_message
            })
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/peer/remove', methods=['POST'])
@auth_required
def remove_peer():
    """Remove a peer from the WireGuard server"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    data = request.get_json()
    
    if not data or 'public_key' not in data:
        return jsonify({'success': False, 'message': 'Missing public key'}), 400
    
    public_key = data['public_key']
    
    try:
        success, message = wg_manager.remove_peer(public_key)
        return jsonify({'success': success, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/peer/config/<public_key>', methods=['GET'])
@auth_required
def get_peer_config(public_key):
    """Get the configuration for a specific peer"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        peer_config = wg_manager.get_peer_config(public_key)
        
        if peer_config:
            return jsonify({'success': True, 'config': peer_config})
        else:
            return jsonify({'success': False, 'message': 'Peer not found'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/peer/update', methods=['POST'])
@auth_required
def update_peer():
    """Update peer information (e.g., last connected timestamp)"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    data = request.get_json()
    
    if not data or 'public_key' not in data:
        return jsonify({'success': False, 'message': 'Missing public key'}), 400
    
    public_key = data['public_key']
    
    try:
        wg_manager.update_peer_last_connected(public_key)
        return jsonify({'success': True, 'message': 'Peer updated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/stats', methods=['GET'])
@auth_required
def get_stats():
    """Get WireGuard interface statistics"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        stats = wg_manager.get_stats()
        
        if stats:
            return jsonify({'success': True, 'stats': stats})
        else:
            return jsonify({'success': False, 'message': 'Failed to get stats'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

@app.route('/api/config', methods=['GET'])
@auth_required
def get_server_config():
    """Get the server configuration"""
    if not wg_manager:
        return jsonify({'success': False, 'message': 'WireGuard manager not available'})
    
    try:
        return jsonify({'success': True, 'config': wg_manager.generate_config()})
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error: {str(e)}'})

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=8080)