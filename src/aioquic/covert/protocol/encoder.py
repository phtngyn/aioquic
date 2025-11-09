"""Connection ID encoding for covert channel"""

import logging
import secrets
from typing import List, Optional, Tuple

from ..core.enums import CompressionType
from ..core.types import CovertMessage
from ..crypto.cipher import encrypt_message
from ..utils import chunks

logger = logging.getLogger(__name__)


class CIDEncoder:
    """Encodes messages into Connection IDs and decodes them back"""

    def __init__(
        self,
        cid_length: int = 20,
        chunk_size: int = 16,
        use_ordering: bool = True,
    ):
        """Initialize CID encoder

        Args:
            cid_length: Length of CIDs (8-20 bytes per RFC 9000)
            chunk_size: Size of payload in each CID (rest is ordering)
            use_ordering: Whether to add ordering bytes
        """
        if cid_length < 8 or cid_length > 20:
            msg = "CID length must be between 8 and 20 bytes"
            raise ValueError(msg)

        if use_ordering and chunk_size + 4 > cid_length:
            msg = "Chunk size + ordering (4 bytes) exceeds CID length"
            raise ValueError(msg)

        self.cid_length = cid_length
        self.chunk_size = chunk_size if use_ordering else cid_length
        self.use_ordering = use_ordering
        self.ordering_size = 4 if use_ordering else 0

    def encode_message_to_cids(
        self,
        message: CovertMessage,
        encryption_key: bytes,
        compression_type: CompressionType = CompressionType.ZSTD,
    ) -> List[bytes]:
        """Encode a message into a list of CIDs

        Args:
            message: Message to encode
            encryption_key: Encryption key
            compression_type: Compression algorithm

        Returns:
            List of CID bytes
        """
        # Serialize message
        message_bytes = message.to_bytes()

        # Encrypt and compress
        encrypted_payload, actual_compression = encrypt_message(
            message_bytes,
            encryption_key,
            compression_type=compression_type,
        )

        logger.debug(
            "Encoded message: %d bytes -> %d encrypted bytes (compression: %s)",
            len(message_bytes),
            len(encrypted_payload),
            actual_compression.name,
        )

        # Split into chunks
        payload_chunks = chunks(encrypted_payload, self.chunk_size)

        if not self.use_ordering:
            # Simple mode: just pad to CID length
            cids = [self._pad_to_cid_length(chunk) for chunk in payload_chunks]
            # Shuffle for unpredictability
            secrets.SystemRandom().shuffle(cids)
            return cids

        # With ordering: add sequence markers
        from ..utils import generate_ordered_bytes

        order_bytes = generate_ordered_bytes(
            len(payload_chunks), size=self.ordering_size
        )

        cids = []
        for i, chunk in enumerate(payload_chunks):
            # Format: [order:4][chunk:N] to make total CID length
            padded_chunk = self._pad_to_length(
                chunk, self.cid_length - self.ordering_size
            )
            cid = order_bytes[i] + padded_chunk
            cids.append(cid)

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(cids)

        return cids

    def decode_cids_to_message(
        self,
        cids: List[bytes],
        encryption_key: bytes,
        compression_type: CompressionType = CompressionType.ZSTD,
    ) -> Optional[CovertMessage]:
        """Decode CIDs back into a message

        Args:
            cids: List of CID bytes
            encryption_key: Decryption key
            compression_type: Compression algorithm used

        Returns:
            Decoded message or None if decoding fails
        """
        if not cids:
            return None

        try:
            # Reconstruct encrypted payload
            encrypted_payload = self._reconstruct_payload(cids)

            # Decrypt
            from ..crypto.cipher import decrypt_message

            decrypted_bytes = decrypt_message(
                encrypted_payload,
                encryption_key,
                compression_type=compression_type,
            )

            # Deserialize message
            message = CovertMessage.from_bytes(decrypted_bytes)

            logger.debug(
                "Decoded message: %d CIDs -> %d bytes (type: %s, seq: %d)",
                len(cids),
                len(message.payload),
                message.message_type.name,
                message.sequence_number,
            )

            return message

        except Exception as e:
            logger.debug("Failed to decode CIDs: %s", e)
            return None

    def _reconstruct_payload(self, cids: List[bytes]) -> bytes:
        """Reconstruct encrypted payload from CIDs

        Args:
            cids: List of CID bytes

        Returns:
            Reconstructed encrypted payload
        """
        if not self.use_ordering:
            # Simple mode: concatenate all CIDs
            return b"".join(cids)

        # With ordering: extract and sort chunks
        chunks_with_order = []
        for cid in cids:
            if len(cid) < self.ordering_size:
                continue
            order = cid[: self.ordering_size]
            chunk = cid[self.ordering_size :]
            chunks_with_order.append((order, chunk))

        # Sort by order bytes
        chunks_with_order.sort(key=lambda x: x[0])

        # Concatenate chunks (removing padding)
        payload_parts = [chunk for _, chunk in chunks_with_order]
        return b"".join(payload_parts).rstrip(b"\x00")  # Remove padding

    def _pad_to_cid_length(self, data: bytes) -> bytes:
        """Pad data to CID length with random bytes

        Args:
            data: Data to pad

        Returns:
            Padded data
        """
        if len(data) >= self.cid_length:
            return data[: self.cid_length]

        # Pad with random bytes for stealth
        padding_size = self.cid_length - len(data)
        return data + secrets.token_bytes(padding_size)

    def _pad_to_length(self, data: bytes, target_length: int) -> bytes:
        """Pad data to target length

        Args:
            data: Data to pad
            target_length: Target length

        Returns:
            Padded data
        """
        if len(data) >= target_length:
            return data[:target_length]

        # Pad with zeros (will be encrypted, so not detectable)
        return data + b"\x00" * (target_length - len(data))

    def estimate_cid_count(self, message_size: int) -> int:
        """Estimate number of CIDs needed for a message

        Args:
            message_size: Size of unencrypted message in bytes

        Returns:
            Estimated CID count
        """
        # Add overhead: 15 bytes header + 12 nonce + 16 tag = 43 bytes
        # Plus compression might reduce or increase
        estimated_encrypted_size = message_size + 50

        cids_needed = (
            estimated_encrypted_size + self.chunk_size - 1
        ) // self.chunk_size

        return cids_needed


class CIDBuffer:
    """Buffer for accumulating CIDs until complete message"""

    def __init__(self, max_buffer_size: int = 100):
        """Initialize CID buffer

        Args:
            max_buffer_size: Maximum CIDs to buffer before giving up
        """
        self.max_buffer_size = max_buffer_size
        self.buffer: List[bytes] = []

    def add_cid(self, cid: bytes) -> None:
        """Add CID to buffer"""
        self.buffer.append(cid)

        # Prevent unbounded growth
        if len(self.buffer) > self.max_buffer_size:
            logger.warning("CID buffer overflow, dropping oldest CID")
            self.buffer.pop(0)

    def try_decode(
        self,
        encoder: CIDEncoder,
        encryption_key: bytes,
        compression_type: CompressionType = CompressionType.ZSTD,
    ) -> Optional[Tuple[CovertMessage, int]]:
        """Try to decode buffer into a message

        Args:
            encoder: CID encoder instance
            encryption_key: Decryption key
            compression_type: Compression algorithm

        Returns:
            Tuple of (message, cids_used) if successful, None otherwise
        """
        if not self.buffer:
            return None

        # Try to decode with increasing buffer sizes
        for cid_count in range(1, len(self.buffer) + 1):
            cids_to_try = self.buffer[:cid_count]
            message = encoder.decode_cids_to_message(
                cids_to_try,
                encryption_key,
                compression_type,
            )

            if message is not None:
                # Success! Remove used CIDs from buffer
                self.buffer = self.buffer[cid_count:]
                return message, cid_count

        return None

    def clear(self) -> None:
        """Clear buffer"""
        self.buffer.clear()

    def size(self) -> int:
        """Get buffer size"""
        return len(self.buffer)
