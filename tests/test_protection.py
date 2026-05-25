"""
Tests for the current Privana protection implementation.
"""

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from app.core.protection import (
    PrivanaProtection,
    ProtectionError,
    sanitize_wg_config,
    secure_write_config,
)


VALID_WG_CONFIG = """
[Interface]
PrivateKey = PLACEHOLDER
Address = 10.8.0.2/32

[Peer]
PublicKey = server-public-key
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0
"""


class TestWireGuardConfigSanitization(unittest.TestCase):
    def test_sanitize_accepts_valid_config(self):
        result = sanitize_wg_config(VALID_WG_CONFIG)

        self.assertIn("[Interface]", result)
        self.assertIn("[Peer]", result)
        self.assertIn("AllowedIPs", result)

    def test_sanitize_rejects_empty_config(self):
        with self.assertRaises(ProtectionError):
            sanitize_wg_config("")

    def test_sanitize_rejects_missing_required_sections(self):
        with self.assertRaises(ProtectionError):
            sanitize_wg_config("[Interface]\nPrivateKey = PLACEHOLDER\n")

    def test_sanitize_comments_dangerous_directives(self):
        unsafe = """
[Interface]
PrivateKey = PLACEHOLDER
Address = 10.8.0.2/32
PostUp = rm -rf /
PreDown = echo unsafe
Table = off

[Peer]
PublicKey = server-public-key
Endpoint = vpn.example.test:51820
AllowedIPs = 0.0.0.0/0
"""
        result = sanitize_wg_config(unsafe)

        self.assertIn("# REMOVED FOR SECURITY: PostUp =", result)
        self.assertIn("# REMOVED FOR SECURITY: PreDown =", result)
        self.assertIn("# REMOVED FOR SECURITY: Table =", result)
        self.assertNotIn("\nPostUp =", result)
        self.assertNotIn("\nPreDown =", result)
        self.assertNotIn("\nTable =", result)


class TestSecureWriteConfig(unittest.TestCase):
    def test_secure_write_config_writes_owner_only_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "privana.conf"

            secure_write_config(str(path), VALID_WG_CONFIG)

            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(encoding="utf-8"), VALID_WG_CONFIG)

            mode = stat.S_IMODE(path.stat().st_mode)
            self.assertEqual(mode, 0o600)


class TestPrivanaProtection(unittest.TestCase):
    def test_init_defaults(self):
        protection = PrivanaProtection(config_path="/tmp/privana-test.conf", interface_name="privana-test")

        self.assertEqual(protection.config_path, "/tmp/privana-test.conf")
        self.assertEqual(protection.interface_name, "privana-test")
        self.assertIsNotNone(protection.api_client)
        self.assertIsNotNone(protection.qrng_client)
        self.assertIsNotNone(protection.pqc_client)

    @patch("app.core.protection.subprocess.run")
    @patch("app.core.protection.secure_write_config")
    @patch("builtins.open", new_callable=mock_open, read_data=VALID_WG_CONFIG)
    def test_connect_fetches_sanitizes_writes_and_starts_wg(
        self,
        mock_file,
        mock_secure_write,
        mock_run,
    ):
        protection = PrivanaProtection(config_path="/tmp/privana-test.conf")

        protection.qrng_client = Mock()
        protection.qrng_client.get_random_data.return_value = b"q" * 32

        protection.pqc_client = Mock()
        protection.pqc_client.key_exchange.return_value = (b"s" * 32, "session-id")

        protection.api_client = Mock()
        protection.api_client.get_wg_config.return_value = VALID_WG_CONFIG

        protection.connect()

        protection.qrng_client.get_random_data.assert_called_once_with(32)
        protection.pqc_client.key_exchange.assert_called_once_with(b"q" * 32)
        protection.api_client.get_wg_config.assert_called_once_with(b"s" * 32, "session-id")

        self.assertGreaterEqual(mock_secure_write.call_count, 1)
        first_write_path, first_write_config = mock_secure_write.call_args_list[0].args
        self.assertEqual(first_write_path, "/tmp/privana-test.conf")
        self.assertIn("[Interface]", first_write_config)
        self.assertIn("[Peer]", first_write_config)

        mock_file.assert_called_with("/tmp/privana-test.conf", "r", encoding="utf-8")
        mock_run.assert_called_once_with(
            ["wg-quick", "up", "/tmp/privana-test.conf"],
            check=True,
            timeout=30,
        )

    @patch("app.core.protection.os.remove")
    @patch("app.core.protection.subprocess.run")
    @patch("app.core.protection.secure_write_config")
    @patch("builtins.open", new_callable=mock_open, read_data=VALID_WG_CONFIG)
    def test_connect_removes_config_if_wg_start_fails(
        self,
        mock_file,
        mock_secure_write,
        mock_run,
        mock_remove,
    ):
        mock_run.side_effect = RuntimeError("wg failed")

        protection = PrivanaProtection(config_path="/tmp/privana-test.conf")
        protection.qrng_client = Mock()
        protection.qrng_client.get_random_data.return_value = b"q" * 32
        protection.pqc_client = Mock()
        protection.pqc_client.key_exchange.return_value = (b"s" * 32, "session-id")
        protection.api_client = Mock()
        protection.api_client.get_wg_config.return_value = VALID_WG_CONFIG

        with self.assertRaises(ProtectionError):
            protection.connect()

        mock_remove.assert_called_once_with("/tmp/privana-test.conf")

    @patch("app.core.protection.subprocess.run")
    def test_is_connected_true_when_wg_show_returns_output(self, mock_run):
        mock_run.return_value = Mock(returncode=0, stdout="interface: privana\n")

        protection = PrivanaProtection(config_path="/tmp/privana-test.conf", interface_name="privana")
        self.assertTrue(protection.is_connected())

        mock_run.assert_called_once_with(
            ["wg", "show", "privana"],
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("app.core.protection.subprocess.run")
    def test_is_connected_false_when_wg_show_fails(self, mock_run):
        mock_run.return_value = Mock(returncode=1, stdout="")

        protection = PrivanaProtection(config_path="/tmp/privana-test.conf", interface_name="privana")
        self.assertFalse(protection.is_connected())

    @patch.object(PrivanaProtection, "is_connected", return_value=False)
    @patch("app.core.protection.subprocess.run")
    def test_disconnect_runs_wg_quick_down(self, mock_run, mock_is_connected):
        protection = PrivanaProtection(config_path="/tmp/privana-test.conf")

        protection.disconnect()

        mock_run.assert_called_once_with(
            ["wg-quick", "down", "/tmp/privana-test.conf"],
            check=True,
            timeout=30,
        )
        mock_is_connected.assert_called_once()

    @patch("app.core.protection.subprocess.run")
    def test_disconnect_raises_on_wg_quick_failure(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.CalledProcessError(1, ["wg-quick", "down"])

        protection = PrivanaProtection(config_path="/tmp/privana-test.conf")

        with self.assertRaises(ProtectionError):
            protection.disconnect()


if __name__ == "__main__":
    unittest.main()
