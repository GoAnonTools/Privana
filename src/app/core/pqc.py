# src/app/core/pqc.py
"""
Post-Quantum Cryptography Module

Real PQC implementation using:
  - Kyber-768 (ML-KEM, NIST FIPS 203) for key encapsulation
  - Dilithium-3 (ML-DSA, NIST FIPS 204) for digital signatures
  - AES-256-GCM for symmetric encryption in hybrid mode

Install: pip install kyber-py dilithium-py pycryptodome
"""

import os
import threading
import logging
import time
import hashlib
import struct
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

from kyber_py.kyber import Kyber768
from dilithium_py.dilithium import Dilithium3

log = logging.getLogger("privana.pqc")

_KYBER_DRBG_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# QRNG adapter
# ---------------------------------------------------------------------------
class _QRNGAdapter:
    """
    Wraps QRNGClient when available; falls back to os.urandom().
    Exposes generate_quantum_key() as expected by tests.
    """

    def __init__(self):
        try:
            from .qrng import QRNGClient
            self._client = QRNGClient()
        except Exception as exc:
            log.warning("QRNGClient unavailable in PQC adapter; fallback policy will apply. reason=%s", exc)
            self._client = None

    def generate_quantum_key(self, length: int = 32) -> bytes:
        if self._client is not None:
            try:
                return self._client.get_random_data(length)
            except Exception as exc:
                log.warning("QRNGClient failed inside PQC adapter; considering fallback. reason=%s", exc)

        allow_fallback = os.getenv("PRIVANA_QRNG_ALLOW_FALLBACK", "true").lower() == "true"
        log.warning("Using os.urandom fallback for PQC QRNG adapter. length=%s", length)

        if not allow_fallback:
            raise RuntimeError("QRNG unavailable and PRIVANA_QRNG_ALLOW_FALLBACK=false")

        return os.urandom(length)

    def get_random_data(self, length: int = 32) -> bytes:
        return self.generate_quantum_key(length)


# ---------------------------------------------------------------------------
# PostQuantumCrypto — core crypto primitives
# ---------------------------------------------------------------------------
class PostQuantumCrypto:
    """
    High-level PQC interface.

    Key operations
    --------------
    generate_kyber_keypair()        → (public_key, private_key)
    generate_dilithium_keypair()    → (public_key, private_key)
    encrypt(data[, key])            → ciphertext bytes
    decrypt(ciphertext[, key])      → plaintext bytes
    encrypt_hybrid(data, pub_key)   → dict package
    decrypt_hybrid(package, priv)   → plaintext bytes
    sign_dilithium(msg, priv)       → signature bytes
    verify_dilithium(msg, sig, pub) → bool
    benchmark_algorithms()          → timing dict
    """

    HYBRID_ALG_TAG    = "kyber768+aes256gcm"
    KYBER_ALG_TAG     = "kyber768"
    AES_ALG_TAG       = "aes-256-gcm"
    DILITHIUM_ALG_TAG = "dilithium3"

    def __init__(self):
        self.qrng = _QRNGAdapter()
        # Compatibility placeholder for older tests/API expectations.
        # Not used for cryptographic key caching.
        self._key_cache: dict = {}

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def generate_kyber_keypair(self) -> tuple[bytes, bytes]:
        """Generate a Kyber-768 keypair. Returns (public_key, private_key)."""
        return Kyber768.keygen()

    def generate_dilithium_keypair(self) -> tuple[bytes, bytes]:
        """Generate a Dilithium-3 keypair. Returns (public_key, private_key)."""
        return Dilithium3.keygen()


    def _allow_test_key_embedding(self) -> bool:
        """
        Key-embedding mode is only allowed for tests/backward compatibility.

        Production code must pass an explicit 32-byte AES key.
        """
        return (
            os.getenv("PRIVANA_ALLOW_TEST_KEY_EMBEDDING", "false").lower() == "true"
            or os.getenv("ENVIRONMENT", "").lower() == "test"
            or "PYTEST_CURRENT_TEST" in os.environ
        )

    # ------------------------------------------------------------------
    # AES-256-GCM helpers
    # ------------------------------------------------------------------

    def _aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        """Wire format: [ nonce (12 B) | tag (16 B) | ciphertext ]"""
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes.")
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return nonce + tag + ciphertext

    def _aes_decrypt(self, blob: bytes, key: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes.")
        if len(blob) < 28:
            raise ValueError("Ciphertext too short.")
        nonce      = blob[:12]
        tag        = blob[12:28]
        ciphertext = blob[28:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)

    # ------------------------------------------------------------------
    # Simple symmetric encrypt/decrypt
    # ------------------------------------------------------------------

    def encrypt(self, data: bytes, key: Optional[bytes] = None) -> bytes:
        """
        Encrypt data with AES-256-GCM.

        Production callers must provide a 32-byte key. The legacy no-key mode
        embeds the key in the ciphertext and is only allowed in tests.
        """
        if key is None:
            if not self._allow_test_key_embedding():
                raise ValueError("encrypt(key=None) is disabled outside tests.")
            key = self.qrng.generate_quantum_key(32)
            blob = self._aes_encrypt(data, key)
            return struct.pack(">H", len(key)) + key + blob
        return self._aes_encrypt(data, key)

    def decrypt(self, ciphertext: bytes, key: Optional[bytes] = None) -> bytes:
        if key is None:
            if not self._allow_test_key_embedding():
                raise ValueError("decrypt(key=None) is disabled outside tests.")
            if len(ciphertext) < 2:
                raise ValueError("Ciphertext too short.")
            key_len = struct.unpack(">H", ciphertext[:2])[0]
            if key_len != 32 or len(ciphertext) < 2 + key_len + 28:
                raise ValueError("Invalid embedded-key ciphertext.")
            key = ciphertext[2:2 + key_len]
            blob = ciphertext[2 + key_len:]
            return self._aes_decrypt(blob, key)
        return self._aes_decrypt(ciphertext, key)

    # ------------------------------------------------------------------
    # Kyber KEM encapsulate/decapsulate (used by encrypt_hybrid)
    # ------------------------------------------------------------------

    def _kyber_encapsulate(self, data: bytes, public_key: bytes) -> bytes:
        """
        KEM-encrypt data under public_key.
        Wire format: [ kem_ct_len (4 B) | kem_ct | aes_blob ]
        """
        shared_secret, kem_ct = Kyber768.encaps(public_key)
        aes_blob = self._aes_encrypt(data, shared_secret)
        return struct.pack(">I", len(kem_ct)) + kem_ct + aes_blob

    def _kyber_decapsulate(self, blob: bytes, private_key: bytes) -> bytes:
        kem_ct_len    = struct.unpack(">I", blob[:4])[0]
        kem_ct        = blob[4:4 + kem_ct_len]
        aes_blob      = blob[4 + kem_ct_len:]
        shared_secret = Kyber768.decaps(private_key, kem_ct)
        return self._aes_decrypt(aes_blob, shared_secret)

    # ------------------------------------------------------------------
    # Hybrid encryption
    # ------------------------------------------------------------------

    def encrypt_hybrid(self, data: bytes, public_key: bytes) -> dict:
        """
        Hybrid-encrypt data for a Kyber-768 public key.
        Returns a dict with: algorithm, key_algorithm, data_algorithm,
                             encrypted_key (hex), encrypted_data (hex).
        """
        shared_secret, kem_ct = Kyber768.encaps(public_key)
        aes_blob = self._aes_encrypt(data, shared_secret)
        return {
            "algorithm":      self.HYBRID_ALG_TAG,
            "key_algorithm":  self.KYBER_ALG_TAG,
            "data_algorithm": self.AES_ALG_TAG,
            "encrypted_key":  kem_ct.hex(),
            "encrypted_data": aes_blob.hex(),
        }

    def decrypt_hybrid(self, package: dict, private_key: bytes) -> bytes:
        kem_ct        = bytes.fromhex(package["encrypted_key"])
        aes_blob      = bytes.fromhex(package["encrypted_data"])
        shared_secret = Kyber768.decaps(private_key, kem_ct)
        return self._aes_decrypt(aes_blob, shared_secret)

    # ------------------------------------------------------------------
    # Dilithium signatures
    # ------------------------------------------------------------------

    def sign_dilithium(self, message: bytes, private_key: bytes) -> bytes:
        return Dilithium3.sign(private_key, message)

    def verify_dilithium(
        self, message: bytes, signature: bytes, public_key: bytes
    ) -> bool:
        try:
            return Dilithium3.verify(public_key, message, signature)
        except ValueError:
            return False

    # ------------------------------------------------------------------
    # Benchmarking
    # ------------------------------------------------------------------

    def benchmark_algorithms(self) -> dict:
        test_data = b"Privana PQC benchmark payload" * 10

        t0 = time.perf_counter()
        kyber_pub, kyber_priv = self.generate_kyber_keypair()
        kyber_keygen_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        dil_pub, dil_priv = self.generate_dilithium_keypair()
        dil_keygen_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        pkg = self.encrypt_hybrid(test_data, kyber_pub)
        hybrid_encrypt_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        self.decrypt_hybrid(pkg, kyber_priv)
        hybrid_decrypt_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        sig = self.sign_dilithium(test_data, dil_priv)
        dil_sign_ms = (time.perf_counter() - t0) * 1000

        t0 = time.perf_counter()
        sig_valid = self.verify_dilithium(test_data, sig, dil_pub)
        dil_verify_ms = (time.perf_counter() - t0) * 1000

        return {
            "kyber_keygen_ms":     round(kyber_keygen_ms, 3),
            "dilithium_keygen_ms": round(dil_keygen_ms, 3),
            "hybrid_encrypt_ms":   round(hybrid_encrypt_ms, 3),
            "hybrid_decrypt_ms":   round(hybrid_decrypt_ms, 3),
            "dilithium_sign_ms":   round(dil_sign_ms, 3),
            "dilithium_verify_ms": round(dil_verify_ms, 3),
            "test_data_size":      len(test_data),
            "signature_valid":     sig_valid,
        }


# ---------------------------------------------------------------------------
# PQCClient — real client-side KEM handshake
#
# Protocol (standard Kyber KEM, client-initiates):
#
#   Step 1 — client_hello():
#     Client generates an ephemeral Kyber keypair.
#     Sends the public key to the server via POST /api/pqc/init.
#     Server calls Kyber768.encaps(client_pub) → (shared_secret, kem_ct).
#     Server stores shared_secret (keyed by session_id), returns kem_ct + session_id.
#
#   Step 2 — client_finish(kem_ct, client_priv):
#     Client calls Kyber768.decaps(client_priv, kem_ct) → shared_secret.
#     Both sides now hold the same shared_secret without it ever crossing the wire.
#     Client uses session_id + shared_secret for all subsequent requests.
#
#   key_exchange() below is the convenience wrapper that performs both steps.
#   It requires the server to have the matching /api/pqc/init endpoint —
#   see server/api.py for the implementation that must be added.
# ---------------------------------------------------------------------------
class PQCClient:
    """
    Client-side Kyber-768 KEM handshake against the Privana server.

    The server MUST expose POST /api/pqc/init (see server/api.py).
    Request body:  { "client_public_key": "<hex>" }
    Response body: { "kem_ciphertext": "<hex>", "session_id": "<str>" }
    """

    KEM_INIT_PATH = "/api/pqc/init"

    def __init__(self, base_url: str = "https://api.privana.pro"):
        self._base_url = base_url.rstrip("/")

    def key_exchange(self, client_randomness: bytes) -> tuple[bytes, str]:
        """
        Perform a full Kyber-768 KEM handshake with the server.

        *client_randomness* (e.g. from QRNG) is mixed into the keypair seed
        so the client's entropy contributes to the key material.

        Returns
        -------
        (shared_secret: bytes, session_id: str)
            shared_secret — 32-byte key both sides derived independently
            session_id    — opaque server-issued token to identify this session
        """
        import requests

        # Derive a 48-byte Kyber DRBG seed with HKDF, using explicit context.
        os_entropy = os.urandom(48)
        seed48 = HKDF(
            master=client_randomness + os_entropy,
            key_len=48,
            salt=os_entropy,
            hashmod=SHA256,
            context=b"Privana PQCClient Kyber768 ephemeral keygen v1",
        )

        # kyber-py uses global DRBG state; serialize seed/keygen/reset to avoid races.
        with _KYBER_DRBG_LOCK:
            Kyber768.set_drbg_seed(seed48)
            client_pub, client_priv = Kyber768.keygen()
            Kyber768.set_drbg_seed(os.urandom(48))

        # Step 2: send client public key → server encapsulates
        response = requests.post(
            self._base_url + self.KEM_INIT_PATH,
            json={"client_public_key": client_pub.hex()},
            timeout=15,
            verify=True,
        )
        response.raise_for_status()
        body = response.json()

        kem_ct     = bytes.fromhex(body["kem_ciphertext"])
        session_id = body["session_id"]

        # Step 3: decapsulate — recover the shared secret the server derived
        shared_secret = Kyber768.decaps(client_priv, kem_ct)

        return shared_secret, session_id