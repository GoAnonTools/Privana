"""
Tests for the current EndpointChecker implementation.
"""

import os
import sys
import unittest
from unittest.mock import patch

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from app.core.endpoint_check import EndpointChecker


class TestEndpointChecker(unittest.TestCase):
    def test_init_sets_os_info(self):
        with patch("app.core.endpoint_check.platform.system", return_value="Linux"):
            with patch("app.core.endpoint_check.platform.release", return_value="6.8.0-test"):
                checker = EndpointChecker()

        self.assertEqual(checker.os_info, "Linux 6.8.0-test")

    def test_check_returns_true_for_supported_os(self):
        with patch("app.core.endpoint_check.platform.system", return_value="Linux"):
            with patch("app.core.endpoint_check.platform.release", return_value="6.8.0-test"):
                checker = EndpointChecker()

        self.assertTrue(checker.check())

    def test_check_returns_false_for_unsupported_os(self):
        with patch("app.core.endpoint_check.platform.system", return_value="TempleOS"):
            with patch("app.core.endpoint_check.platform.release", return_value="1.0"):
                checker = EndpointChecker()
                self.assertFalse(checker.check())

    def test_status_for_supported_os_makes_no_security_claim(self):
        with patch("app.core.endpoint_check.platform.system", return_value="Linux"):
            with patch("app.core.endpoint_check.platform.release", return_value="6.8.0-test"):
                checker = EndpointChecker()

        status = checker.status()

        self.assertEqual(
            status,
            {
                "supported_os": True,
                "os_info": "Linux 6.8.0-test",
                "integrity_attestation": "unavailable",
                "security_claim": "none",
            },
        )

    def test_status_for_unsupported_os(self):
        with patch("app.core.endpoint_check.platform.system", return_value="Plan9"):
            with patch("app.core.endpoint_check.platform.release", return_value="unknown"):
                checker = EndpointChecker()
                status = checker.status()

        self.assertEqual(status["supported_os"], False)
        self.assertEqual(status["os_info"], "Plan9 unknown")
        self.assertEqual(status["integrity_attestation"], "unavailable")
        self.assertEqual(status["security_claim"], "none")

    def test_supported_os_values(self):
        for os_name in ["Linux", "Darwin", "Windows"]:
            with self.subTest(os_name=os_name):
                with patch("app.core.endpoint_check.platform.system", return_value=os_name):
                    checker = EndpointChecker()

                self.assertTrue(checker._check_os())

    def test_unsupported_os_value(self):
        with patch("app.core.endpoint_check.platform.system", return_value="UnsupportedOS"):
            checker = EndpointChecker()
            self.assertFalse(checker._check_os())


if __name__ == "__main__":
    unittest.main()
