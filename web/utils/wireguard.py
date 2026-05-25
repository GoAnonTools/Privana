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
from pathlib import Path


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

def validate_wg_config_path(config_path: str) -> str:
    """
    Resolve and validate a WireGuard config path before passing it to wg-quick.

    Only ~/.privana/*.conf is allowed. This prevents accidental execution of
    attacker-controlled paths or unexpected files through wg-quick.
    """
    if not config_path:
        raise ValueError("Missing WireGuard config path.")

    base_dir = (Path.home() / ".privana").resolve()
    target = Path(config_path).expanduser().resolve(strict=False)

    if target.suffix != ".conf":
        raise ValueError("WireGuard config path must end with .conf.")

    if target.parent != base_dir:
        raise ValueError("WireGuard config path must be inside ~/.privana.")

    return str(target)


def secure_write_file(path: str, content: str) -> None:
    path = validate_wg_config_path(path)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    try:
        os.chmod(path, 0o600)
    except Exception:
        log.warning("Could not chmod WireGuard config to 0600: %s", path, exc_info=True)


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
    """
    Deprecated unsafe local config generator.

    Production config allocation must go through the server-side WireGuard API
    so IP assignment is centralized and private keys never leave the client.
    """
    raise NotImplementedError(
        "Local WireGuard config generation is disabled; use the server-side registration flow."
    )

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
        config_path = validate_wg_config_path(config_path)

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
    """
    Deprecated unsafe platform config generator.

    This legacy helper could embed private keys in mobile/QR output and used
    non-authoritative IP assignment. Use the server-side registration flow.
    """
    raise NotImplementedError(
        "Platform-specific local WireGuard config generation is disabled; use the server-side registration flow."
    )
