# Privana API Specification

## Overview

This document describes the internal APIs and external service interfaces for the Privana privacy protection application.

## Table of Contents

1. [Core Protection API](#core-protection-api)
2. [Quantum Random Number Generation API](#quantum-random-number-generation-api)
3. [Post-Quantum Cryptography API](#post-quantum-cryptography-api)
4. [Endpoint Security API](#endpoint-security-api)
5. [Configuration API](#configuration-api)
6. [External Service APIs](#external-service-apis)
7. [Error Handling](#error-handling)
8. [Authentication](#authentication)

## Core Protection API

### ProtectionManager Class

#### `enable_protection(level: int) -> bool`

Enables privacy protection with the specified level.

**Parameters:**
- `level` (int): Protection level (1-3)
  - 1: Basic protection (network filtering, basic encryption)
  - 2: Advanced protection (traffic obfuscation, advanced encryption)
  - 3: Maximum protection (full anonymization, post-quantum crypto, QRNG)

**Returns:**
- `bool`: True if protection was enabled successfully, False otherwise

**Raises:**
- `ValueError`: If protection level is not between 1 and 3

**Example:**
```python
protection_manager = ProtectionManager()
success = protection_manager.enable_protection(level=2)
if success:
    print("Protection enabled successfully")
```

#### `disable_protection() -> bool`

Disables all privacy protection features.

**Returns:**
- `bool`: True if protection was disabled successfully, False otherwise

**Example:**
```python
success = protection_manager.disable_protection()
```

#### `get_status() -> Dict[str, Any]`

Gets the current protection status.

**Returns:**
- `dict`: Status information containing:
  - `active` (bool): Whether protection is currently active
  - `level` (int): Current protection level (0-3)
  - `features` (list): List of active protection features
  - `metrics` (dict): Performance and usage metrics

**Example:**
```python
status = protection_manager.get_status()
print(f"Protection active: {status['active']}")
print(f"Current level: {status['level']}")
```

## Quantum Random Number Generation API

### QuantumRandomGenerator Class

#### `generate_random_bytes(num_bytes: int) -> bytes`

Generates quantum random bytes.

**Parameters:**
- `num_bytes` (int): Number of random bytes to generate

**Returns:**
- `bytes`: Quantum-generated random bytes

**Example:**
```python
qrng = QuantumRandomGenerator()
random_data = qrng.generate_random_bytes(32)
print(f"Generated: {random_data.hex()}")
```

#### `generate_quantum_key(key_length: int = 32) -> bytes`

Generates a quantum encryption key.

**Parameters:**
- `key_length` (int, optional): Length of key in bytes (default: 32 for AES-256)

**Returns:**
- `bytes`: Quantum-generated encryption key

**Example:**
```python
key = qrng.generate_quantum_key(32)
```

#### `test_randomness(sample_size: int = 1000) -> dict`

Tests the quality of generated random numbers.

**Parameters:**
- `sample_size` (int, optional): Number of bytes to test (default: 1000)

**Returns:**
- `dict`: Randomness test results containing:
  - `sample_size` (int): Size of tested sample
  - `chi_square` (float): Chi-square test statistic
  - `entropy` (float): Calculated entropy
  - `max_entropy` (float): Maximum possible entropy
  - `uniformity_score` (float): Uniformity score (0-1)

**Example:**
```python
results = qrng.test_randomness(5000)
print(f"Entropy: {results['entropy']:.2f}")
```

## Post-Quantum Cryptography API

### PostQuantumCrypto Class

#### `generate_kyber_keypair() -> Tuple[bytes, bytes]`

Generates a Kyber key encapsulation mechanism (KEM) keypair.

**Returns:**
- `tuple`: (public_key, private_key) as bytes

**Example:**
```python
pqc = PostQuantumCrypto()
public_key, private_key = pqc.generate_kyber_keypair()
```

#### `generate_dilithium_keypair() -> Tuple[bytes, bytes]`

Generates a Dilithium digital signature keypair.

**Returns:**
- `tuple`: (public_key, private_key) as bytes

**Example:**
```python
public_key, private_key = pqc.generate_dilithium_keypair()
```

#### `encrypt_hybrid(data: bytes, recipient_public_key: bytes) -> dict`

Performs hybrid encryption using post-quantum and classical algorithms.

**Parameters:**
- `data` (bytes): Data to encrypt
- `recipient_public_key` (bytes): Recipient's public key

**Returns:**
- `dict`: Encrypted data package with metadata

**Example:**
```python
encrypted_package = pqc.encrypt_hybrid(b"secret data", public_key)
```

#### `decrypt_hybrid(package: dict, private_key: bytes) -> bytes`

Decrypts hybrid-encrypted data.

**Parameters:**
- `package` (dict): Encrypted data package
- `private_key` (bytes): Recipient's private key

**Returns:**
- `bytes`: Decrypted data

**Example:**
```python
decrypted_data = pqc.decrypt_hybrid(encrypted_package, private_key)
```

#### `sign_dilithium(message: bytes, private_key: bytes) -> bytes`

Signs a message using Dilithium digital signature.

**Parameters:**
- `message` (bytes): Message to sign
- `private_key` (bytes): Signing private key

**Returns:**
- `bytes`: Digital signature

**Example:**
```python
signature = pqc.sign_dilithium(b"important message", private_key)
```

#### `verify_dilithium(message: bytes, signature: bytes, public_key: bytes) -> bool`

Verifies a Dilithium digital signature.

**Parameters:**
- `message` (bytes): Original message
- `signature` (bytes): Digital signature to verify
- `public_key` (bytes): Verification public key

**Returns:**
- `bool`: True if signature is valid, False otherwise

**Example:**
```python
is_valid = pqc.verify_dilithium(message, signature, public_key)
```

## Endpoint Security API

### EndpointChecker Class

#### `check_endpoint(url: str) -> Dict[str, Any]`

Performs comprehensive endpoint security check.

**Parameters:**
- `url` (str): URL to check

**Returns:**
- `dict`: Comprehensive security assessment containing:
  - `url` (str): Checked URL
  - `timestamp` (str): Check timestamp
  - `ssl_check` (dict): SSL/TLS configuration results
  - `dns_check` (dict): DNS security results
  - `headers_check` (dict): Security headers results
  - `certificate_check` (dict): Certificate validation results
  - `overall_score` (int): Overall security score (0-100)
  - `recommendations` (list): Security improvement recommendations

**Example:**
```python
checker = EndpointChecker()
results = checker.check_endpoint('https://example.com')
print(f"Security score: {results['overall_score']}")
```

## Configuration API

### Settings Class

#### `get(key: str, default: Any = None) -> Any`

Gets a configuration setting value.

**Parameters:**
- `key` (str): Setting key
- `default` (Any, optional): Default value if key not found

**Returns:**
- `Any`: Setting value or default

**Example:**
```python
settings = get_settings()
api_url = settings.get('api_base_url', 'https://api.privana.pro')
```

#### `set(key: str, value: Any) -> None`

Sets a configuration setting value.

**Parameters:**
- `key` (str): Setting key
- `value` (Any): Setting value

**Example:**
```python
settings.set('debug', True)
```

#### `validate_settings() -> Dict[str, str]`

Validates current settings and returns any issues.

**Returns:**
- `dict`: Validation errors (empty dict if all valid)

**Example:**
```python
errors = settings.validate_settings()
if errors:
    print(f"Configuration errors: {errors}")
```

## External Service APIs

### API Client

#### Authentication Endpoint

**POST** `/auth/verify`

Verifies API key authentication.

**Headers:**
- `Authorization: Bearer <api_key>`

**Response:**
```json
{
  "valid": true,
  "expires_at": "2024-12-31T23:59:59Z",
  "permissions": ["read", "write"]
}
```

#### Protection Configuration Endpoint

**GET** `/config/protection`

Retrieves protection configuration.

**Response:**
```json
{
  "version": "1.0",
  "protection_levels": {
    "basic": {
      "features": ["network_filtering", "basic_encryption"],
      "performance_impact": "low"
    },
    "advanced": {
      "features": ["traffic_obfuscation", "advanced_encryption"],
      "performance_impact": "medium"
    },
    "maximum": {
      "features": ["full_anonymization", "post_quantum_crypto"],
      "performance_impact": "high"
    }
  }
}
```

#### Telemetry Endpoint

**POST** `/telemetry`

Submits anonymized telemetry data.

**Request:**
```json
{
  "data": "<encrypted_telemetry_data>",
  "timestamp": "2024-01-01T00:00:00Z",
  "version": "0.1.0"
}
```

**Response:**
```json
{
  "status": "received",
  "id": "telemetry-12345"
}
```

#### Threat Intelligence Endpoint

**GET** `/threats/latest`

Retrieves latest threat intelligence data.

**Response:**
```json
{
  "threats": [
    {
      "id": "threat-001",
      "type": "malware",
      "severity": "high",
      "indicators": ["example.malware.com"],
      "first_seen": "2024-01-01T00:00:00Z"
    }
  ],
  "updated_at": "2024-01-01T12:00:00Z"
}
```

## Error Handling

### Error Response Format

All API errors follow a consistent format:

```json
{
  "error": {
    "code": 1001,
    "message": "Invalid argument",
    "details": "Protection level must be between 1 and 3",
    "timestamp": "2024-01-01T00:00:00Z"
  }
}
```

### Error Codes

| Code | Category | Description |
|------|----------|-------------|
| 1000-1999 | General | General application errors |
| 2000-2999 | Network | Network and communication errors |
| 3000-3999 | Cryptography | Cryptographic operation errors |
| 4000-4999 | Protection | Protection system errors |
| 5000-5999 | Quantum | Quantum operation errors |
| 6000-6999 | GUI | User interface errors |

### Exception Classes

```python
class PrivanaError(Exception):
    """Base exception for Privana-specific errors."""
    pass

class ProtectionError(PrivanaError):
    """Protection system errors."""
    pass

class CryptographyError(PrivanaError):
    """Cryptographic operation errors."""
    pass

class NetworkError(PrivanaError):
    """Network and communication errors."""
    pass

class QuantumError(PrivanaError):
    """Quantum operation errors."""
    pass
```

## Authentication

### API Key Authentication

External API calls use Bearer token authentication:

```
Authorization: Bearer <api_key>
```

### Local Authentication

Local operations require no authentication, but sensitive operations may require user confirmation through the interface.

## Rate Limiting

### External API Limits

- Authentication: 100 requests per hour
- Configuration: 10 requests per hour
- Telemetry: 1000 requests per day
- Threat Intelligence: 60 requests per hour

### Error Response for Rate Limiting

```json
{
  "error": {
    "code": 2429,
    "message": "Rate limit exceeded",
    "details": "Too many requests. Try again in 60 seconds.",
    "retry_after": 60
  }
}
```

## Versioning

The API uses semantic versioning (MAJOR.MINOR.PATCH):

- **MAJOR**: Breaking changes to API interface
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

Current API version: `v1.0.0`

API version is included in all requests via header:
```
API-Version: 1.0.0
```

## Security Considerations

### Input Validation

- All inputs are validated and sanitized
- Maximum payload sizes enforced
- Malformed requests rejected with appropriate errors

### Data Protection

- All sensitive data encrypted in transit and at rest
- PII data is never logged or transmitted in plain text
- Quantum-resistant encryption for future protection

### Access Control

- Principle of least privilege
- Regular API key rotation recommended
- Audit logging for all sensitive operations

This API specification is subject to change as the Privana project evolves. Always refer to the latest version for current interface definitions.