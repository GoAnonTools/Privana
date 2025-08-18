import os
import platform
import hashlib

class EndpointChecker:
    def __init__(self):
        self.os_info = platform.system() + " " + platform.release()
        # This is a placeholder; in reality, we would compute a hash of critical system files/processes
        self.expected_hash = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    
    def check(self):
        """Check if the endpoint is compromised"""
        # Step 1: Check OS
        if not self._check_os():
            return False
        
        # Step 2: Check for root privileges (on Linux/macOS)
        if platform.system() != "Windows" and os.geteuid() != 0:
            # We might require root for WireGuard, so this could be a problem
            # But for security, we might want to avoid running as root
            # This is a design decision
            pass
        
        # Step 3: Compute hash of critical system state
        current_hash = self._compute_system_hash()
        
        # Step 4: Compare with expected hash
        return current_hash == self.expected_hash
    
    def _check_os(self):
        """Check if the OS is supported"""
        supported_os = ["Linux", "Darwin", "Windows"]
        return platform.system() in supported_os
    
    def _compute_system_hash(self):
        """Compute a hash of the current system state"""
        # This is a simplified version
        # In reality, we would check running processes, kernel modules, etc.
        data = self.os_info.encode()
        return hashlib.sha256(data).hexdigest()