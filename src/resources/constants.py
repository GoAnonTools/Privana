"""
Application Constants

Global constants and enumerations used throughout the Privana application.
"""

from enum import Enum, IntEnum


class ProtectionLevel(IntEnum):
    """Protection level enumeration."""
    DISABLED = 0
    BASIC = 1
    ADVANCED = 2
    MAXIMUM = 3


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms."""
    AES_256_GCM = "aes-256-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"
    AES_256_CBC = "aes-256-cbc"
    HYBRID_PQC = "hybrid-pqc"


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA256 = "sha256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"
    SHA3_256 = "sha3-256"


class NetworkProtocol(Enum):
    """Network protocols."""
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    TLS = "tls"


class LogLevel(Enum):
    """Logging levels."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class APIEndpoints:
    """API endpoint constants."""
    BASE_URL = "https://api.privana.pro"
    AUTH_VERIFY = "/auth/verify"
    CONFIG_PROTECTION = "/config/protection"
    TELEMETRY = "/telemetry"
    THREATS_LATEST = "/threats/latest"
    ENDPOINTS_STATUS = "/endpoints/status"


class SecurityHeaders:
    """HTTP security headers."""
    STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security"
    CONTENT_SECURITY_POLICY = "Content-Security-Policy"
    X_FRAME_OPTIONS = "X-Frame-Options"
    X_CONTENT_TYPE_OPTIONS = "X-Content-Type-Options"
    REFERRER_POLICY = "Referrer-Policy"
    X_XSS_PROTECTION = "X-XSS-Protection"


class FileExtensions:
    """File extension constants."""
    CONFIG = ".json"
    LOG = ".log"
    KEY = ".key"
    CERT = ".crt"
    PEM = ".pem"


class DefaultValues:
    """Default configuration values."""
    
    # Application defaults
    APP_NAME = "Privana"
    VERSION = "0.1.0"
    
    # Network defaults
    API_TIMEOUT = 30
    CONNECTION_TIMEOUT = 10
    DNS_SERVERS = ["1.1.1.1", "8.8.8.8"]
    
    # Security defaults
    KEY_SIZE = 32  # 256 bits
    SALT_SIZE = 16  # 128 bits
    IV_SIZE = 16   # 128 bits
    PBKDF2_ITERATIONS = 100000
    
    # Quantum defaults
    QRNG_SHOTS = 1024
    QRNG_CACHE_SIZE = 1024
    QUANTUM_BACKEND = "qasm_simulator"
    
    # GUI defaults
    WINDOW_WIDTH = 800
    WINDOW_HEIGHT = 600
    WINDOW_MIN_WIDTH = 400
    WINDOW_MIN_HEIGHT = 300
    
    # CLI defaults
    CLI_COLORS = True
    CLI_VERBOSE = False
    
    # Logging defaults
    LOG_FILE = "privana.log"
    LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5
    
    # Performance defaults
    THREAD_POOL_SIZE = 4
    CONNECTION_POOL_SIZE = 10
    CACHE_TTL = 3600  # 1 hour


class ErrorCodes:
    """Application error codes."""
    
    # General errors (1000-1999)
    UNKNOWN_ERROR = 1000
    INVALID_ARGUMENT = 1001
    CONFIGURATION_ERROR = 1002
    PERMISSION_DENIED = 1003
    FILE_NOT_FOUND = 1004
    
    # Network errors (2000-2999)
    NETWORK_ERROR = 2000
    CONNECTION_TIMEOUT = 2001
    DNS_RESOLUTION_FAILED = 2002
    SSL_ERROR = 2003
    API_ERROR = 2004
    
    # Cryptography errors (3000-3999)
    ENCRYPTION_ERROR = 3000
    DECRYPTION_ERROR = 3001
    KEY_GENERATION_ERROR = 3002
    SIGNATURE_ERROR = 3003
    VERIFICATION_ERROR = 3004
    
    # Protection errors (4000-4999)
    PROTECTION_INIT_ERROR = 4000
    PROTECTION_ENABLE_ERROR = 4001
    PROTECTION_DISABLE_ERROR = 4002
    PROTECTION_STATUS_ERROR = 4003
    
    # Quantum errors (5000-5999)
    QUANTUM_BACKEND_ERROR = 5000
    QRNG_ERROR = 5001
    QUANTUM_CIRCUIT_ERROR = 5002
    
    # GUI errors (6000-6999)
    GUI_INIT_ERROR = 6000
    GUI_RENDER_ERROR = 6001
    GUI_EVENT_ERROR = 6002


class Messages:
    """User-facing messages."""
    
    # Success messages
    PROTECTION_ENABLED = "Protection enabled successfully"
    PROTECTION_DISABLED = "Protection disabled successfully"
    CONFIG_SAVED = "Configuration saved successfully"
    KEY_GENERATED = "Encryption key generated successfully"
    
    # Info messages
    CHECKING_ENDPOINT = "Checking endpoint security..."
    GENERATING_RANDOM = "Generating quantum random data..."
    INITIALIZING_PROTECTION = "Initializing protection..."
    
    # Warning messages
    QUANTUM_FALLBACK = "Quantum backend unavailable, using cryptographic fallback"
    WEAK_ENDPOINT = "Endpoint has security vulnerabilities"
    CONFIG_MISSING = "Configuration file not found, using defaults"
    
    # Error messages
    PROTECTION_FAILED = "Failed to enable protection"
    INVALID_PROTECTION_LEVEL = "Invalid protection level specified"
    API_CONNECTION_FAILED = "Failed to connect to API"
    ENCRYPTION_FAILED = "Encryption operation failed"
    DECRYPTION_FAILED = "Decryption operation failed"


class Patterns:
    """Regular expression patterns."""
    
    # URL patterns
    URL_PATTERN = r"^https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)$"
    DOMAIN_PATTERN = r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$"
    
    # Security patterns
    API_KEY_PATTERN = r"^[a-zA-Z0-9]{32,128}$"
    HEX_PATTERN = r"^[a-fA-F0-9]+$"
    
    # File patterns
    LOG_FILE_PATTERN = r".*\.log$"
    CONFIG_FILE_PATTERN = r".*\.json$"


class Colors:
    """CLI color constants."""
    
    # ANSI color codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    
    # Foreground colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"


# Application metadata
APP_METADATA = {
    "name": DefaultValues.APP_NAME,
    "version": DefaultValues.VERSION,
    "description": "Privacy-focused application with quantum security features",
    "author": "Privana Team",
    "license": "MIT",
    "homepage": "https://privana.pro",
    "repository": "https://github.com/privana/privana",
    "documentation": "https://docs.privana.pro"
}