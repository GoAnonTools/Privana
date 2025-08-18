import os
import signal
import sys
import time
from threading import Thread
import config
import wireguard
import api

class WireGuardServer:
    def __init__(self):
        self.config = config.get_config()
        self.wg_manager = wireguard.WireGuardManager()
        self.running = False
        self.app = api.app
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the WireGuard server and API"""
        print("Starting Privana WireGuard Server...")
        
        # Try to start WireGuard interface (may fail in development)
        success, message = self.wg_manager.start_interface()
        if success:
            print("✅ WireGuard interface started successfully")
        else:
            print(f"⚠️  WireGuard interface failed: {message}")
            # Continue anyway - API server can still run
            print("📡 Continuing with API server only...")
        
        # Start API server in a separate thread
        self.running = True
        self.api_thread = Thread(target=self._run_api_server)
        self.api_thread.daemon = True
        self.api_thread.start()
        
        print(f"🚀 API server started on http://{self.config.API_HOST}:{self.config.API_PORT}")
        print("📝 Server is running. Press Ctrl+C to stop.")
        
        # Show some helpful info
        environment = os.environ.get('ENVIRONMENT', 'development')
        if environment == 'development':
            print("\n💡 Development Mode Active:")
            print("   - Test API: python test_api.py")
            print(f"   - API Base URL: http://localhost:{self.config.API_PORT}/api")
            print("   - Add peers and generate configs for testing")
        
        # Main thread loop
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        
        return True
    
    def stop(self):
        """Stop the WireGuard server and API"""
        if not self.running:
            return
        
        print("Stopping Privana WireGuard Server...")
        self.running = False
        
        # Try to stop WireGuard interface (may not be running in development)
        success, message = self.wg_manager.stop_interface()
        if success:
            print("✅ WireGuard interface stopped successfully")
        else:
            print(f"⚠️  WireGuard interface stop: {message}")
        
        print("🛑 Server stopped")
    
    def _run_api_server(self):
        """Run the Flask API server"""
        self.app.run(host=self.config.API_HOST, port=self.config.API_PORT, threaded=True, debug=False)

if __name__ == '__main__':
    server = WireGuardServer()
    server.start()