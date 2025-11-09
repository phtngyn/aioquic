"""Enumerations for covert channel protocol"""

from enum import Enum, IntEnum


class CovertMessageType(IntEnum):
    """Message types for covert channel communication"""

    # Data messages
    TEXT = 0x01  # 'm' in original - text message only

    # Control messages
    KEEP_ALIVE = 0x10  # 'k' in original
    KEY_EXCHANGE = 0x11  # Public key exchange
    ACK = 0x12  # Acknowledgment
    NACK = 0x13  # Negative acknowledgment
    SYNC = 0x14  # Synchronization request
    SYNC_ACK = 0x15  # Synchronization acknowledgment

    # Session management
    SESSION_INIT = 0x20
    SESSION_CLOSE = 0x21
    SESSION_RESUME = 0x22

    # Error messages
    ERROR = 0xF0
    PROTOCOL_ERROR = 0xF1


class CovertKeyType(IntEnum):
    """Key types for cryptographic operations"""

    RSA_2048 = 0x01
    RSA_4096 = 0x02
    ECC_CURVE25519 = 0x03  # X25519 for ECDH
    ECC_CURVE448 = 0x04
    HYBRID = 0x05  # RSA + ECC


class CovertState(Enum):
    """Session states for covert channel"""

    IDLE = "idle"
    KEY_EXCHANGE_INIT = "key_exchange_init"
    KEY_EXCHANGE_PROGRESS = "key_exchange_progress"
    KEY_EXCHANGE_COMPLETE = "key_exchange_complete"
    READY = "ready"
    SENDING = "sending"
    RECEIVING = "receiving"
    ERROR = "error"
    CLOSED = "closed"


class CovertProtocolVersion(IntEnum):
    """Protocol versions"""

    V1 = 0x01  # Original QuiCC implementation
    V2 = 0x02  # Enhanced with synchronization
    V3 = 0x03  # With ECC support and stealth features


class CompressionType(IntEnum):
    """Compression algorithms"""

    NONE = 0x00
    ZLIB = 0x01
    ZSTD = 0x02
    BROTLI = 0x03
    LZ4 = 0x04


class PriorityLevel(IntEnum):
    """Message priority levels"""

    LOW = 0x00
    NORMAL = 0x01
    HIGH = 0x02
    CRITICAL = 0x03
