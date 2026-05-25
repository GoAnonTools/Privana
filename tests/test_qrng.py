"""
Tests for the current QRNG client implementation.
"""

import os
import sys
import unittest
from unittest.mock import Mock, patch

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from app.core.qrng import QRNGClient, QRNGError


class TestQRNGClient(unittest.TestCase):
    """Tests for QRNGClient."""

    def setUp(self):
        self.env_patcher = patch.dict(
            os.environ,
            {
                "PRIVANA_QRNG_API_URL": "https://example.test/qrng",
                "PRIVANA_QRNG_TIMEOUT": "1",
                "PRIVANA_QRNG_ALLOW_FALLBACK": "true",
            },
            clear=False,
        )
        self.env_patcher.start()

    def tearDown(self):
        self.env_patcher.stop()

    def test_init_uses_environment_defaults(self):
        client = QRNGClient()

        self.assertEqual(client.api_url, "https://example.test/qrng")
        self.assertEqual(client.timeout, 1.0)
        self.assertTrue(client.allow_fallback)
        self.assertFalse(client.last_used_fallback)

    @patch("app.core.qrng.requests.get")
    def test_get_random_data_success(self, mock_get):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "success": True,
            "data": ["0011", "2233", "4455", "6677"],
        }
        mock_get.return_value = response

        client = QRNGClient()
        result = client.get_random_data(6)

        self.assertEqual(result, bytes.fromhex("001122334455"))
        self.assertFalse(client.last_used_fallback)

        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        self.assertEqual(kwargs["params"]["length"], 3)
        self.assertEqual(kwargs["params"]["type"], "hex16")
        self.assertEqual(kwargs["params"]["size"], 1)
        self.assertEqual(kwargs["timeout"], 1.0)

    @patch("app.core.qrng.os.urandom")
    @patch("app.core.qrng.requests.get")
    def test_fallback_when_request_fails_and_fallback_allowed(self, mock_get, mock_urandom):
        mock_get.side_effect = RuntimeError("network down")
        mock_urandom.return_value = b"x" * 32

        client = QRNGClient()
        result = client.get_random_data(32)

        self.assertEqual(result, b"x" * 32)
        self.assertTrue(client.last_used_fallback)
        mock_urandom.assert_called_once_with(32)

    @patch.dict(os.environ, {"PRIVANA_QRNG_ALLOW_FALLBACK": "false"}, clear=False)
    @patch("app.core.qrng.requests.get")
    def test_raises_when_request_fails_and_fallback_disabled(self, mock_get):
        mock_get.side_effect = RuntimeError("network down")

        client = QRNGClient()

        with self.assertRaises(QRNGError):
            client.get_random_data(32)

        self.assertTrue(client.last_used_fallback)

    @patch("app.core.qrng.os.urandom")
    @patch("app.core.qrng.requests.get")
    def test_fallback_when_api_returns_unsuccessful_payload(self, mock_get, mock_urandom):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {"success": False, "data": []}
        mock_get.return_value = response
        mock_urandom.return_value = b"f" * 16

        client = QRNGClient()
        result = client.get_random_data(16)

        self.assertEqual(result, b"f" * 16)
        self.assertTrue(client.last_used_fallback)

    @patch("app.core.qrng.os.urandom")
    @patch("app.core.qrng.requests.get")
    def test_fallback_when_api_returns_too_few_bytes(self, mock_get, mock_urandom):
        response = Mock()
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "success": True,
            "data": ["abcd"],
        }
        mock_get.return_value = response
        mock_urandom.return_value = b"z" * 8

        client = QRNGClient()
        result = client.get_random_data(8)

        self.assertEqual(result, b"z" * 8)
        self.assertTrue(client.last_used_fallback)

    def test_rejects_non_positive_length(self):
        client = QRNGClient()

        with self.assertRaises(ValueError):
            client.get_random_data(0)

        with self.assertRaises(ValueError):
            client.get_random_data(-1)


if __name__ == "__main__":
    unittest.main()
