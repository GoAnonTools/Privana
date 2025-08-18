import requests
import json

class PrivanaAPIClient:
    def __init__(self, base_url="https://api.privana.pro"):
        self.base_url = base_url
        self.headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Privana/1.0'
        }
    
    def get_wg_config(self, shared_secret):
        """Get WireGuard configuration from server"""
        endpoint = f"{self.base_url}/vpn/config"
        payload = {
            'shared_secret': shared_secret.hex(),
            'client_info': {
                'os': 'linux',  # This would be detected dynamically
                'version': '1.0'
            }
        }
        
        try:
            response = requests.post(endpoint, headers=self.headers, json=payload)
            response.raise_for_status()
            return response.json().get('config', '')
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get WireGuard config: {str(e)}")
    
    def check_status(self):
        """Check VPN connection status"""
        endpoint = f"{self.base_url}/vpn/status"
        try:
            response = requests.get(endpoint, headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to check status: {str(e)}")