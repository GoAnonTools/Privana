"""
Application Configuration

Central configuration management for Privana application settings,
including environment variables, defaults, and configuration validation.
"""

import os
import json
import logging
from typing import Dict, Any, Optional
from pathlib import Path


class Settings:
    """Application settings manager."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._settings = {}
        self._load_default_settings()
        self._load_environment_settings()
        self._load_config_file()
    
    def _load_default_settings(self):
        """Load default application settings."""
        self._settings.update({
            # Application settings
            'app_name': 'Privana',
            'version': '0.1.0',
            'debug': False,
            'log_level': 'INFO',
            
            # API settings
            'api_base_url': 'https://api.privana.com',
            'api_timeout': 30,
            'api_retries': 3,
            
            # Security settings
            'encryption_algorithm': 'aes-256-gcm',
            'key_derivation_iterations': 100000,
            'quantum_entropy_enabled': True,
            'pqc_enabled': True,
            
            # Protection settings
            'default_protection_level': 1,
            'max_protection_level': 3,
            'auto_enable_protection': False,
            
            # Network settings
            'network_timeout': 10,
            'dns_servers': ['1.1.1.1', '8.8.8.8'],
            'check_endpoints': True,
            
            # Logging settings
            'log_file': 'privana.log',
            'log_max_size': 10 * 1024 * 1024,  # 10MB
            'log_backup_count': 5,
            
            # GUI settings
            'gui_theme': 'default',
            'gui_width': 800,
            'gui_height': 600,
            'gui_resizable': True,
            
            # CLI settings
            'cli_colors': True,
            'cli_verbose': False,
            
            # Quantum settings
            'qrng_backend': 'qasm_simulator',
            'qrng_shots': 1024,
            'qrng_cache_size': 1024,
            
            # Performance settings
            'thread_pool_size': 4,
            'connection_pool_size': 10,
            'cache_enabled': True,
            'cache_ttl': 3600,  # 1 hour
            
            # Privacy settings
            'telemetry_enabled': False,
            'analytics_enabled': False,
            'crash_reporting': False,
        })
    
    def _load_environment_settings(self):
        """Load settings from environment variables."""
        env_mappings = {
            'PRIVANA_DEBUG': ('debug', bool),
            'PRIVANA_LOG_LEVEL': ('log_level', str),
            'PRIVANA_API_URL': ('api_base_url', str),
            'PRIVANA_API_TIMEOUT': ('api_timeout', int),
            'PRIVANA_ENCRYPTION_ALGO': ('encryption_algorithm', str),
            'PRIVANA_PROTECTION_LEVEL': ('default_protection_level', int),
            'PRIVANA_QUANTUM_ENABLED': ('quantum_entropy_enabled', bool),
            'PRIVANA_PQC_ENABLED': ('pqc_enabled', bool),
            'PRIVANA_GUI_THEME': ('gui_theme', str),
            'PRIVANA_TELEMETRY': ('telemetry_enabled', bool),
        }
        
        for env_var, (setting_key, setting_type) in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    if setting_type == bool:
                        value = env_value.lower() in ('true', '1', 'yes', 'on')
                    elif setting_type == int:
                        value = int(env_value)
                    else:
                        value = env_value
                    
                    self._settings[setting_key] = value
                    self.logger.debug(f"Loaded setting {setting_key} from environment")
                    
                except (ValueError, TypeError) as e:
                    self.logger.warning(f"Invalid environment value for {env_var}: {env_value}")
    
    def _load_config_file(self):
        """Load settings from configuration file."""
        config_paths = [
            os.path.expanduser('~/.privana/config.json'),
            '/etc/privana/config.json',
            './config.json'
        ]
        
        for config_path in config_paths:
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        file_settings = json.load(f)
                    
                    self._settings.update(file_settings)
                    self.logger.info(f"Loaded configuration from {config_path}")
                    break
                    
                except (json.JSONDecodeError, IOError) as e:
                    self.logger.error(f"Failed to load config from {config_path}: {str(e)}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a setting value.
        
        Args:
            key: Setting key
            default: Default value if key not found
            
        Returns:
            Setting value or default
        """
        return self._settings.get(key, default)
    
    def set(self, key: str, value: Any):
        """
        Set a setting value.
        
        Args:
            key: Setting key
            value: Setting value
        """
        self._settings[key] = value
        self.logger.debug(f"Set setting {key} = {value}")
    
    def update(self, settings: Dict[str, Any]):
        """
        Update multiple settings.
        
        Args:
            settings: Dictionary of settings to update
        """
        self._settings.update(settings)
        self.logger.debug(f"Updated {len(settings)} settings")
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get all settings.
        
        Returns:
            dict: All current settings
        """
        return self._settings.copy()
    
    def save_to_file(self, config_path: Optional[str] = None):
        """
        Save current settings to configuration file.
        
        Args:
            config_path: Path to save config file (default: ~/.privana/config.json)
        """
        if config_path is None:
            config_dir = os.path.expanduser('~/.privana')
            os.makedirs(config_dir, exist_ok=True)
            config_path = os.path.join(config_dir, 'config.json')
        
        try:
            with open(config_path, 'w') as f:
                json.dump(self._settings, f, indent=2)
            
            self.logger.info(f"Settings saved to {config_path}")
            
        except IOError as e:
            self.logger.error(f"Failed to save settings to {config_path}: {str(e)}")
    
    def validate_settings(self) -> Dict[str, str]:
        """
        Validate current settings and return any issues.
        
        Returns:
            dict: Validation errors (empty if all valid)
        """
        errors = {}
        
        # Validate protection level
        protection_level = self.get('default_protection_level')
        max_level = self.get('max_protection_level')
        if not (1 <= protection_level <= max_level):
            errors['default_protection_level'] = f"Must be between 1 and {max_level}"
        
        # Validate API timeout
        api_timeout = self.get('api_timeout')
        if api_timeout <= 0:
            errors['api_timeout'] = "Must be positive"
        
        # Validate log level
        log_level = self.get('log_level')
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if log_level.upper() not in valid_levels:
            errors['log_level'] = f"Must be one of: {', '.join(valid_levels)}"
        
        # Validate GUI dimensions
        gui_width = self.get('gui_width')
        gui_height = self.get('gui_height')
        if gui_width < 400 or gui_height < 300:
            errors['gui_dimensions'] = "Minimum size is 400x300"
        
        # Validate QRNG settings
        qrng_shots = self.get('qrng_shots')
        if qrng_shots < 1 or qrng_shots > 10000:
            errors['qrng_shots'] = "Must be between 1 and 10000"
        
        return errors
    
    def reset_to_defaults(self):
        """Reset all settings to default values."""
        self._settings.clear()
        self._load_default_settings()
        self.logger.info("Settings reset to defaults")


# Global settings instance
_settings = None


def get_settings() -> Settings:
    """
    Get the global settings instance.
    
    Returns:
        Settings: Global settings instance
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings


def configure_logging():
    """Configure logging based on current settings."""
    settings = get_settings()
    
    log_level = getattr(logging, settings.get('log_level', 'INFO').upper())
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(settings.get('log_file', 'privana.log'))
        ]
    )
    
    # Set specific logger levels
    if settings.get('debug'):
        logging.getLogger('privana').setLevel(logging.DEBUG)
    else:
        logging.getLogger('privana').setLevel(log_level)