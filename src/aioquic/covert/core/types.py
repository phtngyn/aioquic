"""Type definitions for covert channel"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .enums import (
    CompressionType,
    CovertKeyType,
    CovertMessageType,
    CovertState,
    PriorityLevel,
)


@dataclass
class CovertMessage:
    """A covert channel message"""

    message_type: CovertMessageType
    payload: bytes
    sequence_number: int = 0
    chunk_index: int = 0
    total_chunks: int = 1
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    priority: PriorityLevel = PriorityLevel.NORMAL
    compression: CompressionType = CompressionType.NONE
    ttl: Optional[int] = None  # Time to live in seconds
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_bytes(self) -> bytes:
        """Serialize message to bytes (before encryption)"""
        # Format: [type:1][seq:4][chunk_idx:2][total:2][compression:1][priority:1][payload_len:4][payload]
        header = bytes(
            [
                self.message_type,
                (self.sequence_number >> 24) & 0xFF,
                (self.sequence_number >> 16) & 0xFF,
                (self.sequence_number >> 8) & 0xFF,
                self.sequence_number & 0xFF,
                (self.chunk_index >> 8) & 0xFF,
                self.chunk_index & 0xFF,
                (self.total_chunks >> 8) & 0xFF,
                self.total_chunks & 0xFF,
                self.compression,
                self.priority,
            ]
        )

        payload_len = len(self.payload)
        length_bytes = bytes(
            [
                (payload_len >> 24) & 0xFF,
                (payload_len >> 16) & 0xFF,
                (payload_len >> 8) & 0xFF,
                payload_len & 0xFF,
            ]
        )

        return header + length_bytes + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "CovertMessage":
        """Deserialize message from bytes (after decryption)"""
        if len(data) < 15:
            raise ValueError("Invalid message format: too short")

        message_type = CovertMessageType(data[0])
        sequence_number = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4]
        chunk_index = (data[5] << 8) | data[6]
        total_chunks = (data[7] << 8) | data[8]
        compression = CompressionType(data[9])
        priority = PriorityLevel(data[10])
        payload_len = (data[11] << 24) | (data[12] << 16) | (data[13] << 8) | data[14]

        if len(data) < 15 + payload_len:
            raise ValueError("Invalid message format: payload length mismatch")

        payload = data[15 : 15 + payload_len]

        return cls(
            message_type=message_type,
            payload=payload,
            sequence_number=sequence_number,
            chunk_index=chunk_index,
            total_chunks=total_chunks,
            compression=compression,
            priority=priority,
        )


@dataclass
class CovertPayload:
    """A complete payload potentially split across multiple messages"""

    sequence_number: int
    total_chunks: int
    chunks: Dict[int, bytes] = field(default_factory=dict)
    message_type: Optional[CovertMessageType] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

    def add_chunk(self, chunk_index: int, data: bytes) -> bool:
        """Add a chunk and return True if payload is complete"""
        self.chunks[chunk_index] = data
        return len(self.chunks) == self.total_chunks

    def is_complete(self) -> bool:
        """Check if all chunks have been received"""
        if len(self.chunks) != self.total_chunks:
            return False
        return all(i in self.chunks for i in range(self.total_chunks))

    def assemble(self) -> bytes:
        """Assemble all chunks into final payload"""
        if not self.is_complete():
            raise ValueError("Payload incomplete")
        return b"".join(self.chunks[i] for i in range(self.total_chunks))


@dataclass
class CovertSession:
    """Session state for a covert channel peer"""

    peer_address: str
    state: CovertState = CovertState.IDLE

    # Cryptography
    key_type: Optional[CovertKeyType] = None
    private_key: Optional[Any] = None
    public_key: Optional[Any] = None
    peer_public_key: Optional[Any] = None
    shared_secret: Optional[bytes] = None

    # Key exchange
    key_exchange_buffer: List[bytes] = field(default_factory=list)
    key_exchange_complete: bool = False

    # Synchronization
    send_sequence: int = 0
    recv_sequence: int = 0
    send_window: int = 16  # Sliding window size
    recv_window: int = 16

    # Buffering
    send_buffer: List[CovertMessage] = field(default_factory=list)
    recv_buffer: Dict[int, CovertPayload] = field(default_factory=dict)

    # Connection IDs
    cid_queue: List[bytes] = field(default_factory=list)
    cid_history: List[bytes] = field(default_factory=list)

    # Statistics
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    errors: int = 0
    retransmissions: int = 0

    # Timing
    last_activity: float = field(default_factory=lambda: datetime.now().timestamp())
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())

    # Protocol components (stored as metadata to avoid circular imports)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def next_send_sequence(self) -> int:
        """Get next sequence number for sending"""
        seq = self.send_sequence
        self.send_sequence = (self.send_sequence + 1) & 0xFFFFFFFF
        return seq

    def next_recv_sequence(self) -> int:
        """Get expected next receive sequence"""
        return self.recv_sequence

    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = datetime.now().timestamp()
