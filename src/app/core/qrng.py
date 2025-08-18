import requests

class QRNGClient:
    def __init__(self, api_url="https://qrng.anu.edu.au/API/jsonI.php"):
        self.api_url = api_url
    
    def get_random_data(self, length=32):
        """Get quantum random data from ANU QRNG API"""
        params = {
            'length': length,
            'type': 'hex16'  # Get hex string of 16-bit values
        }
        try:
            response = requests.get(self.api_url, params=params)
            response.raise_for_status()
            data = response.json()
            # Convert hex string to bytes
            hex_str = ''.join(data['data'])
            return bytes.fromhex(hex_str)
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get quantum random data: {str(e)}")