"""
Tests for endpoint check module

Unit tests for the endpoint security checking functionality.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import ssl
import requests

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from app.core.endpoint_check import EndpointChecker


class TestEndpointChecker(unittest.TestCase):
    """Test cases for EndpointChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.checker = EndpointChecker()
    
    def test_init(self):
        """Test EndpointChecker initialization."""
        self.assertIsNotNone(self.checker)
        self.assertIsInstance(self.checker.security_headers, list)
        self.assertIsInstance(self.checker.trusted_cas, list)
        self.assertIsNotNone(self.checker.api_client)
    
    @patch('app.core.endpoint_check.requests.get')
    @patch('app.core.endpoint_check.socket.create_connection')
    @patch('app.core.endpoint_check.dns.resolver.resolve')
    def test_check_endpoint_basic(self, mock_dns_resolve, mock_socket, mock_requests_get):
        """Test basic endpoint checking functionality."""
        # Mock DNS resolution
        mock_dns_resolve.return_value = []
        
        # Mock socket connection for SSL check
        mock_ssl_socket = MagicMock()
        mock_ssl_socket.version.return_value = 'TLSv1.3'
        mock_ssl_socket.cipher.return_value = ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.3', 256)
        mock_ssl_socket.getpeercert.return_value = {
            'issuer': [('CN', 'Test CA')],
            'subject': [('CN', 'test.example.com')],
            'notAfter': 'Dec 31 23:59:59 2025 GMT',
            'subjectAltName': [('DNS', 'test.example.com')]
        }
        
        mock_context = MagicMock()
        mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
        
        with patch('app.core.endpoint_check.ssl.create_default_context', return_value=mock_context):
            mock_socket.return_value.__enter__.return_value = MagicMock()
            
            # Mock HTTP response
            mock_response = MagicMock()
            mock_response.headers = {
                'strict-transport-security': 'max-age=31536000',
                'x-frame-options': 'DENY'
            }
            mock_requests_get.return_value = mock_response
            
            # Test endpoint check
            result = self.checker.check_endpoint('https://test.example.com')
            
            # Verify result structure
            self.assertIsInstance(result, dict)
            self.assertIn('url', result)
            self.assertIn('ssl_check', result)
            self.assertIn('dns_check', result)
            self.assertIn('headers_check', result)
            self.assertIn('certificate_check', result)
            self.assertIn('overall_score', result)
            self.assertIn('recommendations', result)
    
    def test_check_ssl_configuration_success(self):
        """Test successful SSL configuration check."""
        with patch('app.core.endpoint_check.socket.create_connection') as mock_socket:
            with patch('app.core.endpoint_check.ssl.create_default_context') as mock_ssl_context:
                # Mock SSL socket
                mock_ssl_socket = MagicMock()
                mock_ssl_socket.version.return_value = 'TLSv1.3'
                mock_ssl_socket.cipher.return_value = ('ECDHE-RSA-AES256-GCM-SHA384', 'TLSv1.3', 256)
                mock_ssl_socket.getpeercert.return_value = {'subject': [('CN', 'test.com')]}
                
                mock_context = MagicMock()
                mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
                mock_ssl_context.return_value = mock_context
                
                mock_socket.return_value.__enter__.return_value = MagicMock()
                
                result = self.checker._check_ssl_configuration('test.example.com', 443)
                
                self.assertTrue(result['supported'])
                self.assertEqual(result['version'], 'TLSv1.3')
                self.assertTrue(result['certificate_valid'])
                self.assertIsInstance(result['vulnerabilities'], list)
    
    def test_check_ssl_configuration_failure(self):
        """Test SSL configuration check with connection failure."""
        with patch('app.core.endpoint_check.socket.create_connection') as mock_socket:
            mock_socket.side_effect = Exception("Connection failed")
            
            result = self.checker._check_ssl_configuration('invalid.example.com', 443)
            
            self.assertFalse(result['supported'])
            self.assertIn('error', result)
    
    def test_check_security_headers_present(self):
        """Test security headers check with headers present."""
        with patch('app.core.endpoint_check.requests.get') as mock_get:
            # Mock response with security headers
            mock_response = MagicMock()
            mock_response.headers = {
                'strict-transport-security': 'max-age=31536000; includeSubDomains',
                'content-security-policy': "default-src 'self'",
                'x-frame-options': 'DENY',
                'x-content-type-options': 'nosniff',
                'referrer-policy': 'strict-origin'
            }
            mock_get.return_value = mock_response
            
            result = self.checker._check_security_headers('https://test.example.com')
            
            self.assertEqual(len(result['missing_headers']), 0)
            self.assertEqual(len(result['present_headers']), 5)
            self.assertIn('strict-transport-security', result['present_headers'])
    
    def test_check_security_headers_missing(self):
        """Test security headers check with missing headers."""
        with patch('app.core.endpoint_check.requests.get') as mock_get:
            # Mock response with no security headers
            mock_response = MagicMock()
            mock_response.headers = {}
            mock_get.return_value = mock_response
            
            result = self.checker._check_security_headers('https://test.example.com')
            
            self.assertEqual(len(result['missing_headers']), len(self.checker.security_headers))
            self.assertEqual(len(result['present_headers']), 0)
    
    def test_check_certificate_validity(self):
        """Test certificate validity check."""
        with patch('app.core.endpoint_check.socket.create_connection') as mock_socket:
            with patch('app.core.endpoint_check.ssl.create_default_context') as mock_ssl_context:
                # Mock certificate data
                mock_cert = {
                    'issuer': [('CN', 'Test CA'), ('O', 'Test Organization')],
                    'subject': [('CN', 'test.example.com')],
                    'notAfter': 'Dec 31 23:59:59 2025 GMT',
                    'subjectAltName': [('DNS', 'test.example.com'), ('DNS', 'www.test.example.com')]
                }
                
                mock_ssl_socket = MagicMock()
                mock_ssl_socket.getpeercert.return_value = mock_cert
                mock_ssl_socket.getpeercert.side_effect = [mock_cert, b'mock_cert_der']
                
                mock_context = MagicMock()
                mock_context.wrap_socket.return_value.__enter__.return_value = mock_ssl_socket
                mock_ssl_context.return_value = mock_context
                
                mock_socket.return_value.__enter__.return_value = MagicMock()
                
                result = self.checker._check_certificate_validity('test.example.com', 443)
                
                self.assertTrue(result['valid'])
                self.assertIn('CN', result['issuer'])
                self.assertIn('CN', result['subject'])
                self.assertEqual(len(result['san']), 2)
                self.assertIn('fingerprint', result)
    
    def test_check_ssl_vulnerabilities(self):
        """Test SSL vulnerability detection."""
        # Test vulnerable version
        mock_socket_vulnerable = MagicMock()
        mock_socket_vulnerable.version.return_value = 'TLSv1'
        mock_socket_vulnerable.cipher.return_value = ('RC4-SHA', 'TLSv1', 128)
        
        vulnerabilities = self.checker._check_ssl_vulnerabilities(mock_socket_vulnerable)
        
        self.assertGreater(len(vulnerabilities), 0)
        self.assertTrue(any('Insecure protocol version' in vuln for vuln in vulnerabilities))
        self.assertTrue(any('Weak cipher suite' in vuln for vuln in vulnerabilities))
        
        # Test secure configuration
        mock_socket_secure = MagicMock()
        mock_socket_secure.version.return_value = 'TLSv1.3'
        mock_socket_secure.cipher.return_value = ('TLS_AES_256_GCM_SHA384', 'TLSv1.3', 256)
        
        vulnerabilities = self.checker._check_ssl_vulnerabilities(mock_socket_secure)
        
        self.assertEqual(len(vulnerabilities), 0)
    
    def test_score_header(self):
        """Test security header scoring."""
        # Test various headers
        test_cases = [
            ('strict-transport-security', 'max-age=31536000', 10),
            ('strict-transport-security', 'no-max-age', 5),
            ('x-frame-options', 'DENY', 10),
            ('x-frame-options', 'ALLOW-FROM example.com', 5),
            ('x-content-type-options', 'nosniff', 10),
            ('referrer-policy', 'no-referrer', 10),
        ]
        
        for header_name, header_value, expected_score in test_cases:
            with self.subTest(header=header_name, value=header_value):
                score = self.checker._score_header(header_name, header_value)
                self.assertEqual(score, expected_score)
    
    def test_calculate_security_score(self):
        """Test overall security score calculation."""
        # Test high security result
        high_security_result = {
            'ssl_check': {
                'supported': True,
                'version': 'TLSv1.3',
                'vulnerabilities': []
            },
            'headers_check': {
                'header_scores': {
                    'strict-transport-security': 10,
                    'content-security-policy': 10,
                    'x-frame-options': 10,
                    'x-content-type-options': 10,
                    'referrer-policy': 10
                }
            },
            'certificate_check': {
                'valid': True,
                'san': ['test.com'],
                'signature_algorithm': 'sha256'
            },
            'dns_check': {
                'dnssec_enabled': True,
                'caa_records': ['0 issue "ca.example.com"']
            }
        }
        
        score = self.checker._calculate_security_score(high_security_result)
        self.assertGreaterEqual(score, 90)
        
        # Test low security result
        low_security_result = {
            'ssl_check': {'supported': False},
            'headers_check': {'header_scores': {}},
            'certificate_check': {'valid': False},
            'dns_check': {}
        }
        
        score = self.checker._calculate_security_score(low_security_result)
        self.assertLessEqual(score, 30)
    
    def test_generate_recommendations(self):
        """Test security recommendations generation."""
        # Test result with issues
        problematic_result = {
            'ssl_check': {
                'supported': False,
                'vulnerabilities': ['Weak cipher']
            },
            'headers_check': {
                'missing_headers': ['strict-transport-security', 'x-frame-options']
            },
            'certificate_check': {
                'valid': False
            },
            'dns_check': {
                'dnssec_enabled': False,
                'caa_records': []
            }
        }
        
        recommendations = self.checker._generate_recommendations(problematic_result)
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('HTTPS' in rec for rec in recommendations))
        self.assertTrue(any('strict-transport-security' in rec for rec in recommendations))
        self.assertTrue(any('certificate' in rec for rec in recommendations))
        self.assertTrue(any('DNSSEC' in rec for rec in recommendations))


class TestEndpointCheckerIntegration(unittest.TestCase):
    """Integration tests for EndpointChecker."""
    
    def test_check_localhost(self):
        """Test checking localhost (should handle gracefully)."""
        checker = EndpointChecker()
        
        # This should not crash, even if localhost doesn't have proper SSL
        result = checker.check_endpoint('http://localhost:8080')
        
        self.assertIsInstance(result, dict)
        self.assertIn('url', result)
        self.assertEqual(result['url'], 'http://localhost:8080')
    
    def test_check_invalid_url(self):
        """Test checking invalid URL format."""
        checker = EndpointChecker()
        
        result = checker.check_endpoint('not-a-valid-url')
        
        self.assertIsInstance(result, dict)
        self.assertIn('url', result)
        # Should handle gracefully without crashing
    
    @patch('app.core.endpoint_check.requests.get')
    def test_timeout_handling(self, mock_get):
        """Test handling of network timeouts."""
        mock_get.side_effect = requests.Timeout("Request timed out")
        
        checker = EndpointChecker()
        result = checker.check_endpoint('https://timeout.example.com')
        
        # Should handle timeout gracefully
        self.assertIsInstance(result, dict)
        self.assertIn('url', result)


if __name__ == '__main__':
    unittest.main()