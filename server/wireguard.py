import logging
import subprocess
import os
import stat
import re
import json
import sqlite3
import ipaddress
from datetime import datetime
import hashlib
import threading
from pathlib import Path
import config

# WireGuard base64 public key format: 43 chars plus "="
_WG_PUBKEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")

# wg-quick executes these directives as shell commands / routing changes.
_DANGEROUS_WG_DIRECTIVES = re.compile(
    r"^\s*(PostUp|PostDown|PreUp|PreDown|Table)\s*=",
    re.MULTILINE | re.IGNORECASE
)

def validate_wg_public_key(key: str) -> str:
    key = (key or "").strip()
    if not _WG_PUBKEY_RE.fullmatch(key):
        raise ValueError("Invalid WireGuard public key format.")
    return key

def sanitize_wg_config(config_text: str) -> str:
    if not config_text:
        return config_text
    return _DANGEROUS_WG_DIRECTIVES.sub(
        lambda m: "# REMOVED FOR SECURITY: " + m.group(0).strip(),
        config_text,
    )

def validate_wg_config_path(config_path: str, config_dir: str) -> str:
    """
    Resolve and validate a server WireGuard config path before writing or
    passing it to wg-quick.

    Only *.conf files directly inside WG_CONFIG_DIR are allowed.
    """
    if not config_path:
        raise ValueError("Missing WireGuard config path.")

    base_dir = Path(config_dir).expanduser().resolve(strict=False)
    target = Path(config_path).expanduser().resolve(strict=False)

    if target.suffix != ".conf":
        raise ValueError("WireGuard config path must end with .conf.")

    if target.parent != base_dir:
        raise ValueError("WireGuard config path must be inside WG_CONFIG_DIR.")

    return str(target)


def secure_write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass



log = logging.getLogger("privana.server.wireguard")


class WireGuardManager:
    def __init__(self):
        self.config = config.Config()
        self.db_lock = threading.Lock()  # serialize SQLite writes

        # Check WireGuard availability FIRST
        self.wg_available = self._check_wireguard_availability()

        # Then initialize database and ensure keys exist
        self.init_database()
        self.ensure_keys_exist()

    # ---------------------------
    # DB helpers
    # ---------------------------
    def _db_conn(self) -> sqlite3.Connection:
        """Open a short-lived SQLite connection (thread-safe)."""
        db_path = self.config.DATABASE_URL.replace("sqlite:///", "")
        conn = sqlite3.connect(db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ---------------------------
    # WireGuard / system helpers
    # ---------------------------
    def _check_wireguard_availability(self):
        """Check if WireGuard tools are available"""
        possible_paths = [
            r"C:\Program Files\WireGuard\wg.exe",
            r"C:\Program Files (x86)\WireGuard\wg.exe",
            "wg",  # If in PATH
        ]
        for wg_path in possible_paths:
            try:
                result = subprocess.run(
                    [wg_path, "--version"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    self.wg_command = wg_path
                    self.wg_quick_command = (
                        wg_path.replace("wg.exe", "wg-quick.exe")
                        if wg_path.endswith("wg.exe")
                        else "wg-quick"
                    )
                    print(f"WireGuard found at: {wg_path}")
                    return True
            except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
                continue

        print("WireGuard not found. Please install from https://www.wireguard.com/install/")
        return False

    # ---------------------------
    # Database init / schema
    # ---------------------------
    def init_database(self):
        """Initialize the server database (idempotent)."""
        with self._db_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS peers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    public_key TEXT UNIQUE NOT NULL,
                    assigned_ip TEXT UNIQUE NOT NULL,
                    user_id INTEGER,
                    device_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_connected TIMESTAMP,
                    is_active INTEGER DEFAULT 1
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS user_devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    device_id INTEGER,
                    peer_id INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (peer_id) REFERENCES peers (id)
                )
                """
            )
            conn.commit()

    def ensure_keys_exist(self):
        """Generate WireGuard keys if they don't exist"""
        if not self.config.WG_PRIVATE_KEY or not self.config.WG_PUBLIC_KEY:
            private_key = self._generate_private_key()
            public_key = self._generate_public_key(private_key)

            # Update config with generated keys
            self.config.WG_PRIVATE_KEY = private_key
            self.config.WG_PUBLIC_KEY = public_key

            print(f"Generated WireGuard keys. Public Key: {public_key}")

    def _generate_private_key(self):
        """Generate a real WireGuard private key using wg."""
        if not self.wg_available:
            raise RuntimeError(
                "WireGuard tools are required to generate valid keys. "
                "Install wireguard-tools; refusing to generate fake keys."
            )

        result = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    def _generate_public_key(self, private_key):
        """Derive a real WireGuard public key from a private key using wg."""
        if not self.wg_available:
            raise RuntimeError(
                "WireGuard tools are required to derive valid public keys. "
                "Install wireguard-tools; refusing to generate fake keys."
            )

        result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()

    # ---------------------------
    # Config files / interface mgmt
    # ---------------------------
    def generate_config(self, include_private_key=False):
        """Generate the WireGuard configuration file for the server interface"""
        cfg = f"""[Interface]
Address = {self.config.WG_ADDRESS}
ListenPort = {self.config.PORT}
PrivateKey = {self.config.WG_PRIVATE_KEY if include_private_key else '[REDACTED - server-side only]'}
"""
        return cfg

    def save_config(self, config_path=None):
        """Save the WireGuard configuration to a validated file path."""
        if not config_path:
            config_path = os.path.join(
                self.config.WG_CONFIG_DIR,
                f"{self.config.WG_INTERFACE}.conf",
            )

        config_path = validate_wg_config_path(config_path, self.config.WG_CONFIG_DIR)
        config_content = sanitize_wg_config(self.generate_config(include_private_key=True))
        secure_write_file(config_path, config_content)
        return config_path

    def start_interface(self):
        """Start the WireGuard interface"""
        if not self.wg_available:
            return (
                False,
                "WireGuard tools not found. Please install WireGuard from https://www.wireguard.com/install/",
            )

        # Skip interface management in development on Windows
        if os.name == "nt" and os.environ.get("ENVIRONMENT") == "development":
            print("🚀 Development Mode: Skipping WireGuard interface management on Windows")
            print("   - API server will run for testing")
            print("   - Peer management and config generation will work")
            print("   - Actual VPN server will run on your Panama production server")
            return True, "Development mode - interface management skipped"

        try:
            config_path = self.save_config()
            try:
                subprocess.run([self.wg_quick_command, "up", config_path], check=True, timeout=30)
                print(f"WireGuard interface {self.config.WG_INTERFACE} started successfully")
                return True, "Interface started successfully"
            except (subprocess.CalledProcessError, FileNotFoundError):
                return False, "WireGuard interface management failed"
        except subprocess.TimeoutExpired:
            return False, "Timeout starting interface"
        except Exception:
            log.exception("Unexpected error starting WireGuard interface")
            return False, "Error starting interface"

    def stop_interface(self):
        """Stop the WireGuard interface"""
        if not self.wg_available:
            return False, "WireGuard tools not found"

        try:
            subprocess.run([self.wg_quick_command, "down", self.config.WG_INTERFACE], check=True, timeout=30)
            print(f"WireGuard interface {self.config.WG_INTERFACE} stopped successfully")
            return True, "Interface stopped successfully"
        except subprocess.CalledProcessError:
            log.exception("WireGuard interface stop command failed")
            return False, "Failed to stop interface"
        except subprocess.TimeoutExpired:
            return False, "Timeout stopping interface"
        except Exception:
            log.exception("Unexpected error stopping WireGuard interface")
            return False, "Error stopping interface"

    def get_interface_status(self):
        """Check if the WireGuard interface is running"""
        if not self.wg_available:
            return False, "WireGuard tools not found"

        try:
            result = subprocess.run(
                [self.wg_command, "show", self.config.WG_INTERFACE],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0, result.stdout
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False, "Interface not running"
    
    def build_client_config(self, client_private_key: str, assigned_ip: str) -> str:
        """Build a full WireGuard client config for this server."""
        return f"""[Interface]
PrivateKey = {client_private_key}
Address = {assigned_ip}
DNS = {self.config.WG_DNS}

[Peer]
PublicKey = {self.config.WG_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.config.get_host()}:{self.config.PORT}
PersistentKeepalive = 25
"""


    # ---------------------------
    # Peer management (DB-backed)
    # ---------------------------
    def add_peer(self, public_key, user_id, device_id=None):
        """Add a new peer to the WireGuard interface"""
        # Writes → lock (SQLite is single-writer)
        with self.db_lock, self._db_conn() as conn:
            # Compute next IP using the same connection while locked
            assigned_ip = self._assign_ip_address(conn)

            cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT INTO peers (public_key, assigned_ip, user_id, device_id) VALUES (?, ?, ?, ?)",
                    (public_key, assigned_ip, user_id, device_id),
                )
                peer_id = cur.lastrowid

                # Add to interface if available (best-effort)
                if self.wg_available:
                    try:
                        subprocess.run(
                            [
                                self.wg_command,
                                "set",
                                self.config.WG_INTERFACE,
                                "peer",
                                public_key,
                                "allowed-ips",
                                assigned_ip,
                            ],
                            check=True,
                            timeout=10,
                        )
                    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                        pass  # ignore, DB state is still valid

                conn.commit()
                return True, peer_id, assigned_ip
            except sqlite3.IntegrityError:
                conn.rollback()
                return False, "Peer with this public key already exists"
            except Exception:
                conn.rollback()
                log.exception("Unexpected error adding WireGuard peer")
                return False, "Error adding peer"

    def remove_peer(self, public_key):
        """Soft-remove a peer (mark inactive) and detach from interface"""
        with self.db_lock, self._db_conn() as conn:
            # Best-effort removal from interface
            if self.wg_available:
                try:
                    subprocess.run(
                        [self.wg_command, "set", self.config.WG_INTERFACE, "peer", public_key, "remove"],
                        check=True,
                        timeout=10,
                    )
                except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                    pass

            cur = conn.cursor()
            try:
                cur.execute("UPDATE peers SET is_active = 0 WHERE public_key = ?", (public_key,))
                conn.commit()
                return True, "Peer removed successfully"
            except Exception:
                conn.rollback()
                log.exception("Unexpected error removing WireGuard peer")
                return False, "Error removing peer"

    def get_peer_config(self, public_key):
        """Get the configuration for a specific peer"""
        with self._db_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT assigned_ip FROM peers WHERE public_key = ? AND is_active = 1",
                (public_key,),
            )
            row = cur.fetchone()

        if not row:
            return None

        assigned_ip = row["assigned_ip"]
        cfg = f"""[Interface]
PrivateKey = [CLIENT_PRIVATE_KEY]
Address = {assigned_ip}
DNS = {self.config.WG_DNS}

[Peer]
PublicKey = {self.config.WG_PUBLIC_KEY}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {self.config.get_host()}:{self.config.PORT}
PersistentKeepalive = 25
"""
        return cfg

    def list_peers(self):
        """List all active peers (JSON-serializable)"""
        with self._db_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, public_key, assigned_ip, user_id, device_id, created_at, last_connected
                FROM peers
                WHERE is_active = 1
                """
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def update_peer_last_connected(self, public_key):
        """Update the last connected timestamp for a peer"""
        with self.db_lock, self._db_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE peers SET last_connected = CURRENT_TIMESTAMP WHERE public_key = ?",
                (public_key,),
            )
            conn.commit()

    # ---------------------------
    # Internal helpers
    # ---------------------------
    def _assign_ip_address(self, conn: sqlite3.Connection) -> str:
        """Assign an IP address to a new peer using the given connection."""
        network = ipaddress.IPv4Network(self.config.CLIENT_IP_RANGE, strict=False)

        cur = conn.cursor()
        cur.execute("SELECT assigned_ip FROM peers WHERE is_active = 1")
        assigned_ips = {row[0] for row in cur.fetchall()}

        for host in network.hosts():
            ip_str = f"{str(host)}/32"
            if ip_str not in assigned_ips:
                return ip_str

        raise RuntimeError(
            f"IP address pool exhausted: all addresses in {self.config.CLIENT_IP_RANGE} are assigned."
            " Add more capacity or remove inactive peers."
        )

    # ---------------------------
    # Diagnostics
    # ---------------------------
    def get_stats(self):
        """Get WireGuard interface statistics"""
        if not self.wg_available:
            return None

        try:
            result = subprocess.run(
                [self.wg_command, "show", self.config.WG_INTERFACE, "dump"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return result.stdout
            return None
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return None