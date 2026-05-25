# src/app/core/protection.py

import os
import re
import stat
import subprocess
from pathlib import Path

from .api_client import PrivanaAPIClient
from .qrng import QRNGClient
from .pqc import PQCClient


DANGEROUS_WG_DIRECTIVES = re.compile(
    r"^\s*(PostUp|PostDown|PreUp|PreDown|Table)\s*=",
    re.MULTILINE | re.IGNORECASE,
)


class ProtectionError(RuntimeError):
    pass


def sanitize_wg_config(config_text: str) -> str:
    """
    Remove WireGuard directives that wg-quick may execute or use for unsafe routing changes.
    """
    if not config_text:
        raise ProtectionError("Empty WireGuard configuration received.")

    sanitized = DANGEROUS_WG_DIRECTIVES.sub(
        lambda m: "# REMOVED FOR SECURITY: " + m.group(0).strip(),
        config_text,
    )

    if "[Interface]" not in sanitized or "[Peer]" not in sanitized:
        raise ProtectionError("Invalid WireGuard configuration: missing required sections.")

    return sanitized


def validate_wg_config_path(config_path: str) -> str:
    """
    Resolve and validate a WireGuard config path before writing or passing it to wg-quick.

    Only ~/.privana/*.conf is allowed. This prevents accidental execution of
    attacker-controlled paths or unexpected files through wg-quick.
    """
    if not config_path:
        raise ProtectionError("Missing WireGuard configuration path.")

    base_dir = (Path.home() / ".privana").resolve()
    target = Path(config_path).expanduser().resolve(strict=False)

    if target.suffix != ".conf":
        raise ProtectionError("WireGuard configuration path must end with .conf.")

    if target.parent != base_dir:
        raise ProtectionError("WireGuard configuration path must be inside ~/.privana.")

    return str(target)


def secure_write_config(path: str, content: str) -> None:
    """
    Write WireGuard config with owner-only permissions.
    """
    target = Path(validate_wg_config_path(path))
    target.parent.mkdir(parents=True, exist_ok=True)

    fd = os.open(
        str(target),
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        stat.S_IRUSR | stat.S_IWUSR,
    )
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)

    try:
        os.chmod(str(target), 0o600)
    except Exception:
        pass


class PrivanaProtection:
    def __init__(self, config_path=None, interface_name: str = "privana"):
        self.config_path = validate_wg_config_path(
            config_path or os.path.expanduser("~/.privana/privana.conf")
        )
        self.interface_name = interface_name
        self.api_client = PrivanaAPIClient()
        self.qrng_client = QRNGClient()
        self.pqc_client = PQCClient()

    def connect(self):
        config_written = False

        try:
            # Step 1: Get quantum-random entropy for the KEM seed.
            qrng_data = self.qrng_client.get_random_data(32)

            # Step 2: Perform the Kyber-768 KEM handshake with the server.
            shared_secret, session_id = self.pqc_client.key_exchange(qrng_data)

            # Step 3: Fetch WireGuard config using PQC-bound API auth.
            wg_config = self.api_client.get_wg_config(shared_secret, session_id)

            # Step 4: Validate/sanitize config before writing.
            safe_config = sanitize_wg_config(wg_config)
            secure_write_config(self.config_path, safe_config)
            config_written = True

            # Step 5: Defense-in-depth: re-read exact file before wg-quick executes it.
            with open(self.config_path, "r", encoding="utf-8") as f:
                on_disk = f.read()

            sanitized_on_disk = sanitize_wg_config(on_disk)
            if sanitized_on_disk != on_disk:
                secure_write_config(self.config_path, sanitized_on_disk)

            subprocess.run(["wg-quick", "up", self.config_path], check=True, timeout=30)

        except Exception as exc:
            # Cleanup if config was written but the tunnel failed to start.
            if config_written:
                try:
                    os.remove(self.config_path)
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
            raise ProtectionError(f"Failed to enable Privana protection: {exc}") from exc

    def disconnect(self):
        try:
            subprocess.run(["wg-quick", "down", self.config_path], check=True, timeout=30)
        except subprocess.CalledProcessError as exc:
            raise ProtectionError("Failed to disable Privana protection.") from exc

        if self.is_connected():
            raise ProtectionError("WireGuard still appears to be connected after disconnect.")

    def is_connected(self):
        try:
            result = subprocess.run(
                ["wg", "show", self.interface_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False
