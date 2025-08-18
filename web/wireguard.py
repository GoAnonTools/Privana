import uuid

def generate_wireguard_config(user_id, platform):
    # This is a simplified version. In a real application, you would:
    # 1. Generate a key pair for the client
    # 2. Generate a key pair for the server
    # 3. Create a configuration that includes these keys and server details
    
    # For now, we'll generate a placeholder configuration
    private_key = f"{uuid.uuid4().hex}"
    public_key = f"{uuid.uuid4().hex}"
    server_public_key = f"{uuid.uuid4().hex}"
    server_endpoint = "vpn.privana.pro:51820"
    
    config = f"""[Interface]
PrivateKey = {private_key}
Address = 10.0.0.{user_id % 256}/32
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = {server_public_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {server_endpoint}
"""
    
    return config