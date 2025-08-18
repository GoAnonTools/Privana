"""
Tests for protection module

Unit tests for the core protection functionality.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from app.core.protection import ProtectionManager


class TestProtectionManager(unittest.TestCase):
    """Test cases for ProtectionManager class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.protection_manager = ProtectionManager()
    
    def test_init(self):
        """Test ProtectionManager initialization."""
        self.assertIsNotNone(self.protection_manager)
        self.assertFalse(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 0)
    
    def test_enable_protection_level_1(self):
        """Test enabling protection level 1."""
        result = self.protection_manager.enable_protection(level=1)
        
        self.assertTrue(result)
        self.assertTrue(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 1)
    
    def test_enable_protection_level_2(self):
        """Test enabling protection level 2."""
        result = self.protection_manager.enable_protection(level=2)
        
        self.assertTrue(result)
        self.assertTrue(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 2)
    
    def test_enable_protection_level_3(self):
        """Test enabling protection level 3."""
        result = self.protection_manager.enable_protection(level=3)
        
        self.assertTrue(result)
        self.assertTrue(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 3)
    
    def test_enable_protection_invalid_level(self):
        """Test enabling protection with invalid level."""
        # Test level too low
        result = self.protection_manager.enable_protection(level=0)
        self.assertFalse(result)
        
        # Test level too high
        result = self.protection_manager.enable_protection(level=4)
        self.assertFalse(result)
        
        # Protection should remain inactive
        self.assertFalse(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 0)
    
    def test_disable_protection(self):
        """Test disabling protection."""
        # First enable protection
        self.protection_manager.enable_protection(level=2)
        self.assertTrue(self.protection_manager.is_active)
        
        # Then disable it
        result = self.protection_manager.disable_protection()
        self.assertTrue(result)
        self.assertFalse(self.protection_manager.is_active)
        self.assertEqual(self.protection_manager.protection_level, 0)
    
    def test_get_status_inactive(self):
        """Test getting status when protection is inactive."""
        status = self.protection_manager.get_status()
        
        expected_status = {
            'active': False,
            'level': 0,
            'features': [],
            'metrics': {
                'uptime': 0,
                'blocked_requests': 0,
                'encrypted_data': 0,
                'anonymized_connections': 0
            }
        }
        
        self.assertEqual(status, expected_status)
    
    def test_get_status_active_level_1(self):
        """Test getting status when protection level 1 is active."""
        self.protection_manager.enable_protection(level=1)
        status = self.protection_manager.get_status()
        
        self.assertTrue(status['active'])
        self.assertEqual(status['level'], 1)
        self.assertIn('network_filtering', status['features'])
        self.assertIn('basic_encryption', status['features'])
    
    def test_get_status_active_level_3(self):
        """Test getting status when protection level 3 is active."""
        self.protection_manager.enable_protection(level=3)
        status = self.protection_manager.get_status()
        
        self.assertTrue(status['active'])
        self.assertEqual(status['level'], 3)
        expected_features = [
            'network_filtering', 'basic_encryption',
            'traffic_obfuscation', 'advanced_encryption',
            'full_anonymization', 'post_quantum_crypto', 'qrng'
        ]
        
        for feature in expected_features:
            self.assertIn(feature, status['features'])
    
    @patch('app.core.protection.ProtectionManager._enable_basic_protection')
    def test_enable_basic_protection_called(self, mock_basic):
        """Test that basic protection is called for all levels."""
        self.protection_manager.enable_protection(level=1)
        mock_basic.assert_called_once()
    
    @patch('app.core.protection.ProtectionManager._enable_advanced_protection')
    def test_enable_advanced_protection_called(self, mock_advanced):
        """Test that advanced protection is called for levels 2+."""
        self.protection_manager.enable_protection(level=2)
        mock_advanced.assert_called_once()
        
        # Reset mock and test level 1 doesn't call it
        mock_advanced.reset_mock()
        self.protection_manager.enable_protection(level=1)
        mock_advanced.assert_not_called()
    
    @patch('app.core.protection.ProtectionManager._enable_maximum_protection')
    def test_enable_maximum_protection_called(self, mock_maximum):
        """Test that maximum protection is called for level 3."""
        self.protection_manager.enable_protection(level=3)
        mock_maximum.assert_called_once()
        
        # Reset mock and test level 2 doesn't call it
        mock_maximum.reset_mock()
        self.protection_manager.enable_protection(level=2)
        mock_maximum.assert_not_called()
    
    @patch('app.core.protection.ProtectionManager._cleanup_protection_components')
    def test_cleanup_called_on_disable(self, mock_cleanup):
        """Test that cleanup is called when disabling protection."""
        self.protection_manager.enable_protection(level=2)
        self.protection_manager.disable_protection()
        mock_cleanup.assert_called_once()


class TestProtectionManagerIntegration(unittest.TestCase):
    """Integration tests for ProtectionManager."""
    
    def test_enable_disable_cycle(self):
        """Test enabling and disabling protection multiple times."""
        pm = ProtectionManager()
        
        # Test multiple enable/disable cycles
        for level in [1, 2, 3, 2, 1]:
            result = pm.enable_protection(level=level)
            self.assertTrue(result)
            self.assertTrue(pm.is_active)
            self.assertEqual(pm.protection_level, level)
            
            result = pm.disable_protection()
            self.assertTrue(result)
            self.assertFalse(pm.is_active)
            self.assertEqual(pm.protection_level, 0)
    
    def test_upgrade_protection_level(self):
        """Test upgrading protection level without disabling first."""
        pm = ProtectionManager()
        
        # Start with level 1
        pm.enable_protection(level=1)
        self.assertEqual(pm.protection_level, 1)
        
        # Upgrade to level 2
        pm.enable_protection(level=2)
        self.assertEqual(pm.protection_level, 2)
        
        # Upgrade to level 3
        pm.enable_protection(level=3)
        self.assertEqual(pm.protection_level, 3)


if __name__ == '__main__':
    unittest.main()