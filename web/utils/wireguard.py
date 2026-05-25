import logging
import os
import subprocess
import stat
import re
import json
from markupsafe import escape
import uuid
import base64
from datetime import datetime
import qrcode
import io


log = logging.getLogger("privana.web.wireguard")


_DANGEROUS_WG_DIRECTIVES = re.compile(
    r"^\s*(PostUp|PostDown|PreUp|PreDown|Table)\s*=",
    re.MULTILINE | re.IGNORECASE
)

def sanitize_wg_config(config_text: str) -> str:
    if not config_text:
        return config_text
    return _DANGEROUS_WG_DIRECTIVES.sub(
        lambda m: "# REMOVED FOR SECURITY: " + m.group(0).strip(),
        config_text,
    )

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


def generate_wireguard_keys():
    """Generate a real WireGuard keypair using wg. Never generate fake fallback keys."""
    try:
        private_result = subprocess.run(
            ["wg", "genkey"],
            capture_output=True,
            text=True,
            check=True,
        )
        private_key = private_result.stdout.strip()

        public_result = subprocess.run(
            ["wg", "pubkey"],
            input=private_key + "\n",
            capture_output=True,
            text=True,
            check=True,
        )
        public_key = public_result.stdout.strip()

        return private_key, public_key

    except FileNotFoundError as exc:
        raise RuntimeError(
            "WireGuard tools are required to generate valid keys. Install wireguard-tools."
        ) from exc
    except subprocess.CalledProcessError as exc:
        log.exception("WireGuard key generation command failed")
        raise RuntimeError("WireGuard key generation failed.") from exc

def generate_wireguard_config(user_id, device_name, private_key, server_public_key, server_endpoint):
    """Generate a complete WireGuard configuration for a device"""
    # Generate a unique IP address for this device
    ip_address = f"10.0.{(user_id % 256)}.{uuid.uuid4().bytes[0] % 254 + 1}/32"
    
    config = f'''[Interface]
PrivateKey = PLACEHOLDER
Address = {ip_address}
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
PersistentKeepalive = 25
'''
    return config

def check_wireguard_status():
    """Check if WireGuard is currently active"""
    try:
        # Check if WireGuard interface is up
        result = subprocess.run(['wg', 'show'], capture_output=True, text=True)
        return result.returncode == 0 and 'privana' in result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        # If wg command is not available, assume not connected
        return False

def toggle_wireguard_protection(config_path, enable=True):
    """Start or stop WireGuard protection"""
    try:
        if enable:
            # Start WireGuard
            if os.path.exists(config_path):
                with open(config_path, "r", encoding="utf-8") as f:
                    cfg = f.read()
                sanitized = sanitize_wg_config(cfg)
                if sanitized != cfg:
                    secure_write_file(config_path, sanitized)
            subprocess.run(['wg-quick', 'up', config_path], check=True)
            return True, "Protection enabled"
        else:
            # Stop WireGuard
            subprocess.run(['wg-quick', 'down', 'privana'], check=True)
            return True, "Protection disabled"
    except subprocess.CalledProcessError:
        log.exception("WireGuard toggle command failed")
        return False, "Failed to toggle WireGuard protection."
    except Exception:
        log.exception("Unexpected WireGuard toggle error")
        return False, "WireGuard protection could not be toggled."
    
def generate_platform_config(user_id, device_name, private_key, server_public_key, server_endpoint, platform):
    """Generate platform-specific WireGuard configuration"""
    
    # Generate a unique IP address for this device
    ip_address = f"10.0.{(user_id % 256)}.{uuid.uuid4().bytes[0] % 254 + 1}/32"
    
    if platform in ['windows', 'linux', 'mac']:
        # Standard INI format for desktop platforms
        config = f'''[Interface]
PrivateKey = PLACEHOLDER
Address = {ip_address}
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
PersistentKeepalive = 25
'''
        return config, 'text/plain'
    
    elif platform in ['android', 'ios']:
        # Mobile platforms need a different format
        mobile_config = {
            "interface": {
                "privateKey": private_key,
                "addresses": [ip_address],
                "dns": ["1.1.1.1", "1.0.0.1"]
            },
            "peer": {
                "publicKey": server_public_key,
                "allowedIPs": ["0.0.0.0/0", "::/0"],
                "endpoint": server_endpoint,
                "persistentKeepalive": 25
            }
        }
        
        # Generate QR code for mobile
        qr_img = qrcode.make(str(mobile_config))
        qr_buffer = io.BytesIO()
        qr_img.save(qr_buffer)
        qr_base64 = base64.b64encode(qr_buffer.getvalue()).decode()
        
        # Capitalize the platform name properly
        platform_capitalized = platform.capitalize()
        
        safe_device_name = escape(device_name)
        safe_platform = escape(platform)
        safe_platform_capitalized = escape(platform_capitalized)
        safe_download_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", device_name or "device")
        safe_download_name_js = json.dumps(f"{safe_download_name}_privana.conf")

        # Create HTML page with QR code and download option
        html_content = f'''<!DOCTYPE html>
<html>
<head>
    <title>Privana Configuration for {safe_device_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; text-align: center; margin: 40px; }}
        .qr-container {{ margin: 20px auto; display: inline-block; }}
        .instructions {{ max-width: 600px; margin: 20px auto; text-align: left; }}
        .download-btn {{ background: #4a6fa5; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 20px; }}
    </style>
</head>
<body>
    <h1>Privana Configuration for {safe_device_name}</h1>
    <div class="qr-container">
        <img src="data:image/png;base64,{qr_base64}" alt="WireGuard Configuration QR Code">
    </div>
    <div class="instructions">
        <h2>Instructions for {safe_platform_capitalized}:</h2>
        <ol>
            <li>Install the WireGuard app from your app store</li>
            <li>Open the WireGuard app</li>
            <li>Tap the "+" button to add a new tunnel</li>
            <li>Choose "Scan from QR code"</li>
            <li>Scan the QR code shown above</li>
            <li>Name the tunnel "{safe_device_name}"</li>
            <li>Toggle the tunnel to connect</li>
        </ol>
    </div>
    <a href="#" class="download-btn" onclick="downloadConfig()">Download Config File</a>
    
    <script>
    function downloadConfig() {{
        const configData = `{base64.b64encode(str(mobile_config).encode()).decode()}`;
        const blob = new Blob([atob(configData)], {{type: 'application/json'}});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = {safe_download_name_js};
        a.click();
        URL.revokeObjectURL(url);
    }}
    </script>
</body>
</html>
'''
        return html_content, 'text/html'
    
    else:
        # Fallback to standard format
        config = f'''[Interface]
PrivateKey = PLACEHOLDER
Address = {ip_address}
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
PersistentKeepalive = 25
'''
        return config, 'text/plain'