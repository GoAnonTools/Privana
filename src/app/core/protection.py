# src/app/core/protection.py

import subprocess
import os
from .api_client import PrivanaAPIClient
from .qrng import QRNGClient
from .pqc import PQCClient


class PrivanaProtection:
    def __init__(self, config_path=None):
        self.config_path = config_path or os.path.expanduser("~/.privana.conf")
        self.api_client  = PrivanaAPIClient()
        self.qrng_client = QRNGClient()
        self.pqc_client  = PQCClient()

    def connect(self):
        # Step 1: Get quantum-random entropy for the KEM seed
        qrng_data = self.qrng_client.get_random_data(32)

        # Step 2: Perform the Kyber-768 KEM handshake with the server.
        #   - Client generates an ephemeral keypair seeded with qrng_data
        #   - Server encapsulates under the client public key → kem_ciphertext
        #   - Client decapsulates → both sides hold the same shared_secret
        #   - session_id is the server's opaque handle for this session
        shared_secret, session_id = self.pqc_client.key_exchange(qrng_data)

        # Step 3: Fetch WireGuard config; authenticate with session_id.
        #   The shared_secret can additionally be used to derive a MAC key
        #   for the config request, binding the WG session to the KEM handshake.
        wg_config = self.api_client.get_wg_config(shared_secret, session_id)

        # Step 4: Save config
        with open(self.config_path, "w") as f:
            f.write(wg_config)

        # Step 5: Bring up WireGuard
        subprocess.run(["wg-quick", "up", self.config_path], check=True)

    def disconnect(self):
        subprocess.run(["wg-quick", "down", self.config_path], check=True)

    def is_connected(self):
        result = subprocess.run(["wg", "show"], capture_output=True, text=True)
        return result.returncode == 0 and "privana" in result.stdout