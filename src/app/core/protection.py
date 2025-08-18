# src/app/core/protection.py

import subprocess
import os
from .api_client import PrivanaAPIClient
from .qrng import QRNGClient
from .pqc import PQCClient

class PrivanaProtection:
    def __init__(self, config_path=None):
        self.config_path = config_path or os.path.expanduser("~/.privana.conf")
        self.api_client = PrivanaAPIClient()
        self.qrng_client = QRNGClient()
        self.pqc_client = PQCClient()
    
    def connect(self):
        # Step 1: Get quantum random numbers for key generation
        qrng_data = self.qrng_client.get_random_data(32)  # 32 bytes of quantum randomness
        
        # Step 2: Perform post-quantum key exchange with server
        # This is a simplified example; in reality, this would involve a handshake
        shared_secret = self.pqc_client.key_exchange(qrng_data)
        
        # Step 3: Get WireGuard configuration from server
        # The configuration will include the shared secret and other parameters
        wg_config = self.api_client.get_wg_config(shared_secret)
        
        # Step 4: Save the configuration
        with open(self.config_path, 'w') as f:
            f.write(wg_config)
        
        # Step 5: Start WireGuard
        subprocess.run(['wg-quick', 'up', self.config_path], check=True)
    
    def disconnect(self):
        # Bring down WireGuard interface
        subprocess.run(['wg-quick', 'down', self.config_path], check=True)
    
    def is_connected(self):
        # Check if WireGuard interface is up
        result = subprocess.run(['wg', 'show'], capture_output=True, text=True)
        return result.returncode == 0 and 'privana' in result.stdout