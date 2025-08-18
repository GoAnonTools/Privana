import subprocess
import os
import json
import sqlite3
import ipaddress
from datetime import datetime
import config

class WireGuardManager:
    def __init__(self):
        self.config = config.Config()
        # Check WireGuard availability FIRST
        self.wg_available = self._check_wireguard_availability()
        # Then initialize database and ensure keys exist
        self.init_database()
        self.ensure_keys_exist()
    
    def _check_wireguard_availability(self):
        """Check if WireGuard tools are available"""
        # Common Windows installation paths
        possible_paths = [
            r"C:\Program Files\WireGuard\wg.exe",
            r"C:\Program Files (x86)\WireGuard\wg.exe",
            "wg"  # If in PATH
        ]
        
        for wg_path in possible_paths:
            try:
                result = subprocess.run([wg_path, '--version'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    self.wg_command = wg_path
                    self.wg_quick_command = wg_path.replace('wg.exe', 'wg-quick.exe') if wg_path.endswith('wg.exe') else 'wg-quick'
                    print(f"WireGuard found at: {wg_path}")
                    return True
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue
        
        print("WireGuard not found. Please install from https://www.wireguard.com/install/")
        return False
    
    def init_database(self):
        """Initialize the server database"""
        self.conn = sqlite3.connect(self.config.DATABASE_URL.replace('sqlite:///', ''))
        cursor = self.conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS peers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_key TEXT UNIQUE NOT NULL,
            private_key TEXT,
            assigned_ip TEXT UNIQUE NOT NULL,
            user_id INTEGER,
            device_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_connected TIMESTAMP,
            is_active INTEGER DEFAULT 1
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            device_id INTEGER,
            peer_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (peer_id) REFERENCES peers (id)
        )
        ''')
        
        self.conn.commit()
    
    def ensure_keys_exist(self):
        """Generate WireGuard keys if they don't exist"""
        if not self.config.WG_PRIVATE_KEY or not self.config.WG_PUBLIC_KEY:
            private_key = self._generate_private_key()
            public_key = self._generate_public_key(private_key)
            
            # Update config with generated keys
            self.config.WG_PRIVATE_KEY = private_key
            self.config.WG_PUBLIC_KEY = public_key
            
            print(f"Generated WireGuard keys:")
            print(f"Private Key: {private_key}")
            print(f"Public Key:  {public_key}")
    
    def _generate_private_key(self):
        """Generate a WireGuard private key"""
        if self.wg_available:
            try:
                result = subprocess.run([self.wg_command, 'genkey'], capture_output=True, text=True, check=True, timeout=10)
                return result.stdout.strip()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        # Fallback method using cryptographically secure random
        import base64
        import secrets
        return base64.b64encode(secrets.token_bytes(32)).decode('utf-8')
    
    def _generate_public_key(self, private_key):
        """Generate a WireGuard public key from a private key"""
        if self.wg_available:
            try:
                result = subprocess.run([self.wg_command, 'pubkey'], input=private_key, capture_output=True, text=True, check=True, timeout=10)
                return result.stdout.strip()
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                pass
        
        # Fallback method - Note: This is not the correct WireGuard key derivation
        # For production use, you should have WireGuard tools installed
        import base64
        import hashlib
        return base64.b64encode(hashlib.sha256(private_key.encode()).digest()).decode('utf-8')
    
    def generate_config(self):
        """Generate the WireGuard configuration file"""
        config = f'''[Interface]
Address = {self.config.WG_ADDRESS}
ListenPort = {self.config.PORT}
PrivateKey = {self.config.WG_PRIVATE_KEY}
'''
        return config
    
    def save_config(self, config_path=None):
        """Save the WireGuard configuration to a file"""
        if not config_path:
            # Use Windows path format
            config_path = os.path.join(os.path.expanduser('~'), f'{self.config.WG_INTERFACE}.conf')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        with open(config_path, 'w') as f:
            f.write(self.generate_config())
        
        return config_path
    
    def start_interface(self):
        """Start the WireGuard interface"""
        if not self.wg_available:
            return False, "WireGuard tools not found. Please install WireGuard from https://www.wireguard.com/install/"
        
        # Skip interface management in development on Windows
        if os.name == 'nt' and os.environ.get('ENVIRONMENT') == 'development':
            print("🚀 Development Mode: Skipping WireGuard interface management on Windows")
            print("   - API server will run for testing")
            print("   - Peer management and config generation will work")
            print("   - Actual VPN server will run on your Singapore production server")
            return True, "Development mode - interface management skipped"
        
        try:
            # For Linux production servers
            config_path = self.save_config()
            
            try:
                subprocess.run([self.wg_quick_command, 'up', config_path], check=True, timeout=30)
                print(f"WireGuard interface {self.config.WG_INTERFACE} started successfully")
                return True, "Interface started successfully"
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False, "WireGuard interface management failed"
                
        except subprocess.TimeoutExpired:
            return False, "Timeout starting interface"
        except Exception as e:
            return False, f"Error starting interface: {str(e)}"
    
    def stop_interface(self):
        """Stop the WireGuard interface"""
        if not self.wg_available:
            return False, "WireGuard tools not found"
        
        try:
            subprocess.run([self.wg_quick_command, 'down', self.config.WG_INTERFACE], check=True, timeout=30)
            print(f"WireGuard interface {self.config.WG_INTERFACE} stopped successfully")
            return True, "Interface stopped successfully"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to stop interface: {str(e)}"
        except subprocess.TimeoutExpired:
            return False, "Timeout stopping interface"
        except Exception as e:
            return False, f"Error stopping interface: {str(e)}"
    
    def get_interface_status(self):
        """Check if the WireGuard interface is running"""
        if not self.wg_available:
            return False, "WireGuard tools not found"
        
        try:
            result = subprocess.run([self.wg_command, 'show', self.config.WG_INTERFACE], capture_output=True, text=True, timeout=10)
            return result.returncode == 0, result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False, "Interface not running"
    
    def add_peer(self, public_key, user_id, device_id=None):
        """Add a new peer to the WireGuard interface"""
        # Generate an IP address for the peer
        assigned_ip = self._assign_ip_address()
        
        # Save peer to database
        cursor = self.conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO peers (public_key, assigned_ip, user_id, device_id) VALUES (?, ?, ?, ?)',
                (public_key, assigned_ip, user_id, device_id)
            )
            peer_id = cursor.lastrowid
            
            # Add peer to WireGuard interface if WireGuard is available
            if self.wg_available:
                try:
                    subprocess.run([
                        self.wg_command, 'set', self.config.WG_INTERFACE, 
                        'peer', public_key, 
                        'allowed-ips', assigned_ip
                    ], check=True, timeout=10)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    # If adding to WireGuard fails, just continue
                    pass
            
            self.conn.commit()
            return True, peer_id, assigned_ip
        except sqlite3.IntegrityError:
            self.conn.rollback()
            return False, "Peer with this public key already exists"
        except Exception as e:
            self.conn.rollback()
            return False, f"Error adding peer: {str(e)}"
    
    def remove_peer(self, public_key):
        """Remove a peer from the WireGuard interface"""
        cursor = self.conn.cursor()
        try:
            # Remove from WireGuard interface if WireGuard is available
            if self.wg_available:
                try:
                    subprocess.run([
                        self.wg_command, 'set', self.config.WG_INTERFACE, 
                        'peer', public_key, 'remove'
                    ], check=True, timeout=10)
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    # If removing from WireGuard fails, just continue
                    pass
            
            # Mark as inactive in database
            cursor.execute(
                'UPDATE peers SET is_active = 0 WHERE public_key = ?',
                (public_key,)
            )
            
            self.conn.commit()
            return True, "Peer removed successfully"
        except Exception as e:
            return False, f"Error removing peer: {str(e)}"
    
    def get_peer_config(self, public_key):
        """Get the configuration for a specific peer"""
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT assigned_ip FROM peers WHERE public_key = ? AND is_active = 1',
            (public_key,)
        )
        result = cursor.fetchone()
        
        if not result:
            return None
        
        assigned_ip = result[0]
        
        config = f'''[Interface]
PrivateKey = [CLIENT_PRIVATE_KEY]
Address = {assigned_ip}
DNS = {self.config.WG_DNS}

[Peer]
PublicKey = {self.config.WG_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.config.get_host()}:{self.config.PORT}
PersistentKeepalive = 25
'''
        return config
    
    def list_peers(self):
        """List all active peers"""
        cursor = self.conn.cursor()
        cursor.execute(
            'SELECT id, public_key, assigned_ip, user_id, device_id, created_at, last_connected FROM peers WHERE is_active = 1'
        )
        return cursor.fetchall()
    
    def update_peer_last_connected(self, public_key):
        """Update the last connected timestamp for a peer"""
        cursor = self.conn.cursor()
        cursor.execute(
            'UPDATE peers SET last_connected = CURRENT_TIMESTAMP WHERE public_key = ?',
            (public_key,)
        )
        self.conn.commit()
    
    def _assign_ip_address(self):
        """Assign an IP address to a new peer"""
        # Get the client IP range
        network = ipaddress.IPv4Network(self.config.CLIENT_IP_RANGE, strict=False)
        
        # Get all assigned IPs
        cursor = self.conn.cursor()
        cursor.execute('SELECT assigned_ip FROM peers WHERE is_active = 1')
        assigned_ips = [row[0] for row in cursor.fetchall()]
        
        # Find an available IP
        for host in network.hosts():
            ip_str = str(host)
            if f"{ip_str}/32" not in assigned_ips:
                return f"{ip_str}/32"
        
        # If no available IP found, return the first available in the range
        return f"{str(network.network_address + 1)}/32"
    
    def get_stats(self):
        """Get WireGuard interface statistics"""
        if not self.wg_available:
            return None
        
        try:
            result = subprocess.run([self.wg_command, 'show', self.config.WG_INTERFACE, 'dump'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                return result.stdout
            return None
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None