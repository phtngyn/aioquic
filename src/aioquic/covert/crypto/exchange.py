"""Key exchange protocol for covert channel"""

import secrets
from typing import List

from ..utils import chunks, generate_ordered_bytes
from .keys import KeyManager


class KeyExchange:
    """Handles key exchange via connection IDs"""

    def __init__(self, key_manager: KeyManager, cid_chunk_size: int = 16):
        """Initialize key exchange

        Args:
            key_manager: Key manager instance
            cid_chunk_size: Size of each CID chunk (default 16 for 20-byte CIDs)
        """
        self.key_manager = key_manager
        self.cid_chunk_size = cid_chunk_size
        self.exchange_buffer: List[bytes] = []

    def prepare_key_exchange_cids(self, invert: bool = False) -> List[bytes]:
        """Prepare CIDs for key exchange

        Args:
            invert: If True, put ordering bytes at end (server side)

        Returns:
            List of CIDs containing public key chunks
        """
        public_key_bytes = self.key_manager.get_public_key_bytes()
        key_chunks = chunks(public_key_bytes, self.cid_chunk_size)

        # Generate ordering bytes (4 bytes each)
        order_bytes = generate_ordered_bytes(len(key_chunks), size=4)

        # For ECC: pad even number to defeat statistical analysis
        cids = []
        for i, chunk in enumerate(key_chunks):
            if invert:
                # Server: chunk + order (20 bytes total for 16+4)
                cid = chunk + order_bytes[i]
            else:
                # Client: order + chunk (20 bytes total for 4+16)
                cid = order_bytes[i] + chunk

            # Anti-detection: ensure statistical uniformity
            # For RSA modulus (odd), mix in even padding bit
            if self.key_manager.key_type != "ecc" and not invert:
                # XOR last byte with 0x01 to flip odd/even
                cid = cid[:-1] + bytes([cid[-1] ^ 0x01])

            cids.append(cid)

        # Shuffle to avoid predictable ordering
        shuffled_cids = list(cids)
        secrets.SystemRandom().shuffle(shuffled_cids)

        return shuffled_cids

    def add_key_exchange_chunk(self, cid: bytes, invert: bool = False) -> bool:
        """Add CID chunk to key exchange buffer

        Args:
            cid: Connection ID containing key chunk
            invert: If True, ordering bytes are at end

        Returns:
            True if key exchange is complete
        """
        self.exchange_buffer.append(cid)

        # Check if we have all chunks
        expected_chunks = (
            self.key_manager.get_key_exchange_size() // self.cid_chunk_size
        )
        if len(self.key_manager.get_public_key_bytes()) % self.cid_chunk_size != 0:
            expected_chunks += 1

        return len(self.exchange_buffer) >= expected_chunks

    def reconstruct_peer_key(self, invert: bool = False) -> bool:
        """Reconstruct peer's public key from exchange buffer

        Args:
            invert: If True, ordering bytes are at end

        Returns:
            True if successful
        """
        if not self.exchange_buffer:
            return False

        # Extract and sort chunks
        if invert:
            # Server side: chunk + order
            payload_pairs = [(cid[:-4], cid[-4:]) for cid in self.exchange_buffer]
            sort_index = 1  # Sort by order bytes (second element)
            payload_index = 0  # Get chunk (first element)
        else:
            # Client side: order + chunk
            payload_pairs = [(cid[:4], cid[4:]) for cid in self.exchange_buffer]
            sort_index = 0  # Sort by order bytes (first element)
            payload_index = 1  # Get chunk (second element)

        sorted_pairs = sorted(payload_pairs, key=lambda x: x[sort_index])
        payload_chunks = [pair[payload_index] for pair in sorted_pairs]
        peer_key_bytes = b"".join(payload_chunks)

        # Set peer public key
        try:
            self.key_manager.set_peer_public_key(peer_key_bytes)
            return True
        except Exception:
            return False

    def get_expected_chunk_count(self) -> int:
        """Get expected number of CID chunks for key exchange"""
        key_size = self.key_manager.get_key_exchange_size()
        chunk_count = key_size // self.cid_chunk_size
        if key_size % self.cid_chunk_size != 0:
            chunk_count += 1
        return chunk_count

    def is_key_exchange_complete(self) -> bool:
        """Check if key exchange is complete"""
        return len(self.exchange_buffer) >= self.get_expected_chunk_count()

    def clear_exchange_buffer(self) -> None:
        """Clear exchange buffer"""
        self.exchange_buffer.clear()
