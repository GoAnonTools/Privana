# WireGuard Server Deployment to Panama

## 🏠 Current Setup (Development - France)
- **Your IP**: 91.163.90.105 (Saint-Grégoire, Brittany)
- **Purpose**: Local development and testing
- **Usage**: Run `python start_dev.py`

## 🇸🇬 Production Deployment (Panama)

### Step 1: Choose a Panama VPS Provider

**Recommended Providers:**
- **DigitalOcean Panama** (SGP1) - $6/month for 1GB RAM
- **Vultr Panama** - $6/month for 1GB RAM  
- **Linode Panama** - $5/month for 1GB RAM
- **AWS Panama** (ap-southeast-1) - Pay per usage

### Step 2: Server Specifications
**Minimum Requirements:**
- 1GB RAM, 1 CPU core
- 25GB SSD storage
- Ubuntu 20.04 or 22.04 LTS
- Public IP address included

### Step 3: Initial Server Setup

```bash
# Connect to your Panama server
ssh root@YOUR_Panama_IP

# Update system
apt update && apt upgrade -y

# Install required packages
apt install python3-pip python3-venv wireguard-tools git -y

# Create a user for the application
useradd -m -s /bin/bash wireguard
usermod -aG sudo wireguard
su - wireguard
```

### Step 4: Deploy Your Application

```bash
# Clone or upload your project
git clone YOUR_REPO_URL privana-server
# OR upload via scp/rsync

cd privana-server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install flask requests

# Set environment variables
export ENVIRONMENT=production
export WG_HOST=$(curl -s https://api.ipify.org)  # Auto-detect Panama IP
export API_SECRET="your-super-secure-secret-key-here"

# Generate and set WireGuard keys (optional - can auto-generate)
WG_PRIVATE_KEY=$(wg genkey)
WG_PUBLIC_KEY=$(echo $WG_PRIVATE_KEY | wg pubkey)
export WG_PRIVATE_KEY=$WG_PRIVATE_KEY
export WG_PUBLIC_KEY=$WG_PUBLIC_KEY

echo "Generated keys:"
echo "Private: $WG_PRIVATE_KEY"
echo "Public: $WG_PUBLIC_KEY"
```

### Step 5: Configure Firewall

```bash
# Enable UFW firewall
ufw allow ssh
ufw allow 51820/udp  # WireGuard port
ufw --force enable

# Check status
ufw status
```

### Step 6: Test the Server

```bash
# Start in production mode
python start_prod.py

# You should see:
# 🇸🇬 Starting WireGuard Server - PRODUCTION MODE (Panama)
# Auto-detected public IP: YOUR_Panama_IP
# ✅ Configuration looks good!
```

### Step 7: Set Up Process Management

Create a systemd service to keep it running:

```bash
sudo nano /etc/systemd/system/wireguard-server.service
```

```ini
[Unit]
Description=WireGuard VPN Server
After=network.target

[Service]
Type=simple
User=wireguard
WorkingDirectory=/home/wireguard/privana-server
Environment=ENVIRONMENT=production
Environment=WG_HOST=YOUR_Panama_IP
Environment=API_SECRET=your-super-secure-secret-key
ExecStart=/home/wireguard/privana-server/venv/bin/python start_prod.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable wireguard-server
sudo systemctl start wireguard-server

# Check status
sudo systemctl status wireguard-server
```

## 🔧 Environment Variables Reference

| Variable | Development | Production | Description |
|----------|-------------|------------|-------------|
| `ENVIRONMENT` | `development` | `production` | Environment mode |
| `WG_HOST` | `91.163.90.105` | Panama IP | Public IP for clients |
| `WG_PORT` | `51820` | `51820` | WireGuard port |
| `API_HOST` | `127.0.0.1` | `127.0.0.1` | API bind address |
| `API_PORT` | `8080` | `8080` | API port |
| `API_SECRET` | Auto-generated | **Set manually** | API authentication |

## 📱 Client Configuration

Once your Panama server is running, clients will connect to:
- **Endpoint**: `YOUR_Panama_IP:51820`
- **DNS**: `1.1.1.1,1.0.0.1`
- **AllowedIPs**: `0.0.0.0/0, ::/0` (route all traffic)

## 🚨 Security Checklist

- [ ] Change default API_SECRET
- [ ] Use strong WireGuard keys
- [ ] Enable UFW firewall
- [ ] Use non-root user
- [ ] Keep server updated
- [ ] Monitor logs regularly
- [ ] Consider fail2ban for SSH protection

## 📊 Monitoring

```bash
# Check server status
sudo systemctl status wireguard-server

# View logs
sudo journalctl -u wireguard-server -f

# Check WireGuard interface
sudo wg show

# Monitor connections
sudo wg show wg0
```