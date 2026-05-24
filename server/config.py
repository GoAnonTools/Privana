import os
import secrets
import requests
import socket

class Config:
    # Environment detection
    ENVIRONMENT = os.environ.get('ENVIRONMENT', 'development')  # development, production
    
    # Server settings
    HOST = os.environ.get('WG_HOST', None)  # Will auto-detect if None
    PORT = int(os.environ.get('WG_PORT', 51820))
    
    # WireGuard settings
    WG_INTERFACE = os.environ.get('WG_INTERFACE', 'wg0')
    WG_PRIVATE_KEY = os.environ.get('WG_PRIVATE_KEY', '')
    WG_PUBLIC_KEY = os.environ.get('WG_PUBLIC_KEY', '')
    WG_ADDRESS = os.environ.get('WG_ADDRESS', '10.0.0.1/24')  # Server's VPN IP
    WG_DNS = os.environ.get('WG_DNS', '1.1.1.1,1.0.0.1')  # Cloudflare DNS
    
    # Database settings
    DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///server.db')
    
    # API settings
    API_HOST = os.environ.get('API_HOST', '127.0.0.1')  # Localhost for security
    API_PORT = int(os.environ.get('API_PORT', 8080))
    API_SECRET = os.environ.get('API_SECRET', secrets.token_urlsafe(32))
    
    # Client settings
    CLIENT_IP_RANGE = os.environ.get('CLIENT_IP_RANGE', '10.0.1.0/24')
    
    # Config directory
    WG_CONFIG_DIR = os.environ.get('WG_CONFIG_DIR', os.path.join(os.path.expanduser('~'), 'wireguard'))
    
    @classmethod
    def get_public_ip(cls):
        """Automatically detect public IP address"""
        services = [
            "https://api.ipify.org",
            "https://ifconfig.me/ip", 
            "https://api.my-ip.io/ip",
            "https://checkip.amazonaws.com"
        ]
        
        for service in services:
            try:
                response = requests.get(service, timeout=5)
                if response.status_code == 200:
                    ip = response.text.strip()
                    # Validate it's a proper IP
                    socket.inet_aton(ip)
                    return ip
            except (requests.RequestException, socket.error):
                continue
        
        return None
    
    @classmethod
    def get_host(cls):
        """Get the host IP, auto-detecting if not set"""
        if cls.HOST is None:
            detected_ip = cls.get_public_ip()
            if detected_ip:
                print(f"Auto-detected public IP: {detected_ip}")
                return detected_ip
            else:
                print("WARNING: Could not detect public IP. Using localhost - external clients won't connect!")
                return "127.0.0.1"
        return cls.HOST
    
    @classmethod
    def validate(cls):
        """Validate configuration settings"""
        issues = []
        
        # Check if server and client IP ranges overlap
        import ipaddress
        try:
            server_network = ipaddress.IPv4Network(cls.WG_ADDRESS, strict=False)
            client_network = ipaddress.IPv4Network(cls.CLIENT_IP_RANGE, strict=False)
            
            if server_network.overlaps(client_network):
                issues.append("WG_ADDRESS and CLIENT_IP_RANGE should not overlap")
        except ValueError as e:
            issues.append(f"Invalid IP configuration: {e}")
        
        # Check if HOST is set properly for external access
        current_host = cls.get_host()
        if current_host in ['0.0.0.0', '127.0.0.1', 'localhost']:
            issues.append("WARNING: HOST is set to localhost - external clients won't be able to connect.")
        
        # Environment-specific warnings
        if cls.ENVIRONMENT == 'production':
            if not cls.WG_PRIVATE_KEY:
                issues.append("PRODUCTION: WireGuard private key should be set via environment variable")
            if 'token_urlsafe' in str(cls.API_SECRET):
                issues.append("PRODUCTION: Set a fixed API_SECRET environment variable")
        
        return issues
    
    @classmethod
    def print_info(cls):
        """Print configuration information"""
        current_host = cls.get_host()
        print("=" * 50)
        print(f"WireGuard Server - {cls.ENVIRONMENT.upper()} Environment")
        print("=" * 50)
        print(f"Server Host: {current_host}:{cls.PORT}")
        print(f"Server VPN Address: {cls.WG_ADDRESS}")
        print(f"Client IP Range: {cls.CLIENT_IP_RANGE}")
        print(f"Interface: {cls.WG_INTERFACE}")
        print(f"API Server: {cls.API_HOST}:{cls.API_PORT}")
        print(f"DNS Servers: {cls.WG_DNS}")
        print(f"Config Directory: {cls.WG_CONFIG_DIR}")
        
        if cls.HOST is None:
            print(f"Public IP: Auto-detected ({current_host})")
        else:
            print(f"Public IP: Manually set ({current_host})")
        
        # Show environment-specific info
        if cls.ENVIRONMENT == 'development':
            print("\n📝 Development Notes:")
            print("- This is for local testing only")
            print("- External clients may not connect without port forwarding")
            print("- Use 'ENVIRONMENT=production' on your Panama server")
        elif cls.ENVIRONMENT == 'production':
            print("\n🚀 Production Environment:")
            print("- Ensure firewall allows UDP port 51820")
            print("- Set environment variables for security")
            print("- Consider using a process manager (systemd, pm2)")
        
        # Validate and show issues
        issues = cls.validate()
        if issues:
            print(f"\n⚠️  Configuration Issues:")
            for issue in issues:
                print(f"   - {issue}")
        else:
            print(f"\n✅ Configuration looks good!")
        
        print("=" * 50)

class DevelopmentConfig(Config):
    """Configuration for local development — inherits random API_SECRET from Config."""

class ProductionConfig(Config):
    """Configuration for Panama production server"""
    # More restrictive settings for production
    API_HOST = '127.0.0.1'  # API only accessible locally
    
    @classmethod
    def get_deployment_guide(cls):
        """Return deployment instructions for Panama"""
        return """
🇸🇬 Panama SERVER DEPLOYMENT GUIDE:

1. VPS Setup:
   - Choose a Panama VPS (DigitalOcean SGP1, Vultr Panama, etc.)
   - Minimum: 1GB RAM, 1 CPU, Ubuntu 20.04/22.04 LTS
   
2. Server Preparation:
   sudo apt update && sudo apt upgrade -y
   sudo apt install python3-pip python3-venv wireguard-tools -y
   
3. Environment Setup:
   export ENVIRONMENT=production
   export WG_HOST=YOUR_Panama_SERVER_IP
   export API_SECRET=your-super-secure-secret-key
   export WG_PRIVATE_KEY=your-generated-private-key
   export WG_PUBLIC_KEY=your-generated-public-key
   
4. Firewall Setup:
   sudo ufw allow 51820/udp  # WireGuard
   sudo ufw allow ssh        # SSH access
   sudo ufw enable
   
5. Process Management:
   # Use systemd or pm2 to keep server running
   # Consider using nginx reverse proxy for API
"""

def get_config():
    """Get the appropriate configuration based on environment"""
    env = os.environ.get('ENVIRONMENT', 'development')
    if env == 'production':
        return ProductionConfig()
    return DevelopmentConfig()