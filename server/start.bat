@echo off
echo Starting Privana WireGuard Server...

REM Set environment variables
set WG_HOST=127.0.0.1
set WG_PORT=51820
set WG_INTERFACE=wg0
set API_HOST=127.0.0.1
set API_PORT=8080
REM Set API_SECRET in your environment before running this script
set DATABASE_URL=sqlite:///server.db
set CLIENT_IP_RANGE=10.0.1.0/24

REM Start the server
python main.py

pause