"""Configuration for covert channel"""

from dataclasses import dataclass
from typing import Optional

from .enums import (
    CompressionType,
    CovertKeyType,
    CovertProtocolVersion,
)


@dataclass
class CovertConfig:
    """Configuration for covert channel operations"""

    # Protocol
    protocol_version: CovertProtocolVersion = CovertProtocolVersion.V3

    # Cryptography
    key_type: CovertKeyType = CovertKeyType.ECC_CURVE25519
    enable_forward_secrecy: bool = True
    key_rotation_interval: Optional[int] = None  # Seconds, None = never

    # Connection ID encoding
    cid_min_length: int = 8
    cid_max_length: int = 20
    cid_dynamic_sizing: bool = True

    # Synchronization
    enable_sync: bool = True
    sliding_window_size: int = 16
    retransmission_timeout: float = 2.0  # Seconds
    max_retransmissions: int = 5

    # Compression
    compression_type: CompressionType = CompressionType.ZSTD
    compression_threshold: int = 128  # Min bytes before compression

    # Chunking
    chunk_size: int = 16  # Bytes per CID chunk (after overhead)
    max_payload_size: int = 1024 * 1024  # 1MB max message

    # Session
    session_timeout: float = 300.0  # 5 minutes
    keep_alive_interval: float = 30.0  # Seconds

    # Security
    enable_authentication: bool = True
    enable_anti_replay: bool = True
    nonce_cache_size: int = 1000

    # Stealth
    enable_traffic_mimicry: bool = True
    enable_timing_randomization: bool = True
    timing_jitter_ms: int = 100  # Max random delay
    enable_decoy_traffic: bool = False
    decoy_traffic_ratio: float = 0.1  # 10% decoy

    # Performance
    enable_connection_pooling: bool = True
    max_concurrent_connections: int = 4

    # Debug
    debug: bool = False
    log_level: str = "INFO"
