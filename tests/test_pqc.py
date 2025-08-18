"""
Tests for post-quantum cryptography module

Unit tests for the PQC functionality.
"""

import unittest
from unittest.mock import Mock, patch
import sys
import os

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from app.core.pqc import PostQuantumCrypto


class TestPostQuantumCrypto(unittest.TestCase):
    """Test cases for PostQuantumCrypto class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.pqc = PostQuantumCrypto()
    
    def test_init(self):
        """Test PostQuantumCrypto initialization."""
        self.assertIsNotNone(self.pqc)
        self.assertIsNotNone(self.pqc.qrng)
        self.assertIsInstance(self.pqc._key_cache, dict)
    
    def test_generate_kyber_keypair(self):
        """Test Kyber keypair generation."""
        public_key, private_key = self.pqc.generate_kyber_keypair()
        
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(private_key, bytes)
        self.assertNotEqual(public_key, private_key)
        self.assertGreater(len(public_key), 0)
        self.assertGreater(len(private_key), 0)
    
    def test_generate_dilithium_keypair(self):
        """Test Dilithium keypair generation."""
        public_key, private_key = self.pqc.generate_dilithium_keypair()
        
        self.assertIsInstance(public_key, bytes)
        self.assertIsInstance(private_key, bytes)
        self.assertNotEqual(public_key, private_key)
        self.assertGreater(len(public_key), 0)
        self.assertGreater(len(private_key), 0)
    
    def test_keypair_uniqueness(self):
        """Test that generated keypairs are unique."""
        # Test Kyber keypairs
        kyber_keys1 = self.pqc.generate_kyber_keypair()
        kyber_keys2 = self.pqc.generate_kyber_keypair()
        
        self.assertNotEqual(kyber_keys1[0], kyber_keys2[0])  # Public keys different
        self.assertNotEqual(kyber_keys1[1], kyber_keys2[1])  # Private keys different
        
        # Test Dilithium keypairs
        dilithium_keys1 = self.pqc.generate_dilithium_keypair()
        dilithium_keys2 = self.pqc.generate_dilithium_keypair()
        
        self.assertNotEqual(dilithium_keys1[0], dilithium_keys2[0])  # Public keys different
        self.assertNotEqual(dilithium_keys1[1], dilithium_keys2[1])  # Private keys different
    
    def test_encrypt_decrypt_simple(self):
        """Test simple encryption and decryption."""
        test_data = b"Hello, World! This is a test message."
        key = self.pqc.qrng.generate_quantum_key()
        
        # Encrypt data
        encrypted = self.pqc.encrypt(test_data, key)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, test_data)
        
        # Decrypt data
        decrypted = self.pqc.decrypt(encrypted, key)
        self.assertEqual(decrypted, test_data)
    
    def test_encrypt_without_key(self):
        """Test encryption without providing a key."""
        test_data = b"Test data without explicit key"
        
        encrypted = self.pqc.encrypt(test_data)
        self.assertIsInstance(encrypted, bytes)
        self.assertNotEqual(encrypted, test_data)
    
    def test_hybrid_encrypt_decrypt(self):
        """Test hybrid encryption and decryption."""
        test_data = b"This is test data for hybrid encryption"
        public_key, private_key = self.pqc.generate_kyber_keypair()
        
        # Encrypt data
        encrypted_package = self.pqc.encrypt_hybrid(test_data, public_key)
        
        # Verify package structure
        self.assertIsInstance(encrypted_package, dict)
        expected_keys = ['algorithm', 'encrypted_data', 'encrypted_key', 'key_algorithm', 'data_algorithm']
        for key in expected_keys:
            self.assertIn(key, encrypted_package)
        
        # Decrypt data
        decrypted = self.pqc.decrypt_hybrid(encrypted_package, private_key)
        self.assertEqual(decrypted, test_data)
    
    def test_sign_verify_dilithium(self):
        """Test Dilithium digital signature and verification."""
        message = b"This message needs to be signed"
        public_key, private_key = self.pqc.generate_dilithium_keypair()
        
        # Sign message
        signature = self.pqc.sign_dilithium(message, private_key)
        self.assertIsInstance(signature, bytes)
        self.assertGreater(len(signature), 0)
        
        # Verify signature
        is_valid = self.pqc.verify_dilithium(message, signature, public_key)
        self.assertTrue(is_valid)
    
    def test_signature_verification_with_wrong_key(self):
        """Test signature verification with wrong public key."""
        message = b"This message is signed with one key"
        
        # Generate two different keypairs
        public_key1, private_key1 = self.pqc.generate_dilithium_keypair()
        public_key2, private_key2 = self.pqc.generate_dilithium_keypair()
        
        # Sign with first private key
        signature = self.pqc.sign_dilithium(message, private_key1)
        
        # Try to verify with second public key (should fail)
        is_valid = self.pqc.verify_dilithium(message, signature, public_key2)
        self.assertFalse(is_valid)
    
    def test_signature_verification_with_modified_message(self):
        """Test signature verification with modified message."""
        original_message = b"Original message"
        modified_message = b"Modified message"
        public_key, private_key = self.pqc.generate_dilithium_keypair()
        
        # Sign original message
        signature = self.pqc.sign_dilithium(original_message, private_key)
        
        # Try to verify modified message (should fail)
        is_valid = self.pqc.verify_dilithium(modified_message, signature, public_key)
        self.assertFalse(is_valid)
    
    def test_kyber_encapsulate_decapsulate(self):
        """Test Kyber key encapsulation and decapsulation."""
        test_data = b"Test data for encapsulation"
        public_key, private_key = self.pqc.generate_kyber_keypair()
        
        # Encapsulate
        encapsulated = self.pqc._kyber_encapsulate(test_data, public_key)
        self.assertIsInstance(encapsulated, bytes)
        
        # Decapsulate
        decapsulated = self.pqc._kyber_decapsulate(encapsulated, private_key)
        self.assertIsInstance(decapsulated, bytes)
    
    def test_benchmark_algorithms(self):
        """Test algorithm benchmarking."""
        results = self.pqc.benchmark_algorithms()
        
        # Check that all expected metrics are present
        expected_metrics = [
            'kyber_keygen_ms',
            'dilithium_keygen_ms',
            'hybrid_encrypt_ms',
            'hybrid_decrypt_ms',
            'dilithium_sign_ms',
            'dilithium_verify_ms',
            'test_data_size',
            'signature_valid'
        ]
        
        for metric in expected_metrics:
            self.assertIn(metric, results)
        
        # Check that timing metrics are reasonable
        for metric in expected_metrics[:-2]:  # Exclude non-timing metrics
            self.assertGreaterEqual(results[metric], 0)
            self.assertLess(results[metric], 10000)  # Should be less than 10 seconds
        
        # Check that signature validation worked
        self.assertTrue(results['signature_valid'])


class TestPostQuantumCryptoIntegration(unittest.TestCase):
    """Integration tests for PostQuantumCrypto."""
    
    def test_end_to_end_hybrid_encryption(self):
        """Test complete end-to-end hybrid encryption workflow."""
        pqc = PostQuantumCrypto()
        
        # Generate recipient keypair
        recipient_public, recipient_private = pqc.generate_kyber_keypair()
        
        # Test data of various sizes
        test_data_sets = [
            b"Short message",
            b"Medium length message with more content to encrypt",
            b"Very long message " * 100,  # ~2000 bytes
            b"\x00\x01\x02\x03" * 256,   # Binary data
        ]
        
        for test_data in test_data_sets:
            with self.subTest(data_length=len(test_data)):
                # Encrypt
                encrypted_package = pqc.encrypt_hybrid(test_data, recipient_public)
                
                # Decrypt
                decrypted = pqc.decrypt_hybrid(encrypted_package, recipient_private)
                
                # Verify
                self.assertEqual(decrypted, test_data)
    
    def test_multiple_signatures_same_key(self):
        """Test multiple signatures with the same key."""
        pqc = PostQuantumCrypto()
        public_key, private_key = pqc.generate_dilithium_keypair()
        
        messages = [
            b"First message",
            b"Second message",
            b"Third message with different content",
            b"",  # Empty message
            b"\x00\xFF\x42",  # Binary message
        ]
        
        signatures = []
        
        # Sign all messages
        for message in messages:
            signature = pqc.sign_dilithium(message, private_key)
            signatures.append(signature)
        
        # Verify all signatures
        for i, (message, signature) in enumerate(zip(messages, signatures)):
            with self.subTest(message_index=i):
                is_valid = pqc.verify_dilithium(message, signature, public_key)
                self.assertTrue(is_valid)
        
        # Cross-verify (each signature should only work with its message)
        for i, message in enumerate(messages):
            for j, signature in enumerate(signatures):
                if i != j:
                    with self.subTest(msg_index=i, sig_index=j):
                        is_valid = pqc.verify_dilithium(message, signature, public_key)
                        self.assertFalse(is_valid)
    
    def test_performance_characteristics(self):
        """Test performance characteristics of PQC operations."""
        pqc = PostQuantumCrypto()
        
        # Run benchmark
        results = pqc.benchmark_algorithms()
        
        # Basic performance expectations (these are loose bounds)
        # Key generation should be reasonably fast
        self.assertLess(results['kyber_keygen_ms'], 1000)  # < 1 second
        self.assertLess(results['dilithium_keygen_ms'], 1000)  # < 1 second
        
        # Encryption/decryption should be fast
        self.assertLess(results['hybrid_encrypt_ms'], 1000)  # < 1 second
        self.assertLess(results['hybrid_decrypt_ms'], 1000)  # < 1 second
        
        # Signing/verification should be reasonable
        self.assertLess(results['dilithium_sign_ms'], 1000)  # < 1 second
        self.assertLess(results['dilithium_verify_ms'], 1000)  # < 1 second


if __name__ == '__main__':
    unittest.main()