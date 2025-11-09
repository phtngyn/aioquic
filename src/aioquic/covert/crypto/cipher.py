"""Encryption and decryption operations"""

import secrets
import zlib
from typing import Optional, Tuple

import zstandard as zstd
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from ..core.enums import CompressionType


class CipherSuite:
    """Handles encryption/decryption with ChaCha20-Poly1305"""

    def __init__(self, encryption_key: bytes):
        """Initialize cipher suite

        Args:
            encryption_key: 32-byte encryption key
        """
        if len(encryption_key) != 32:
            msg = "Encryption key must be 32 bytes"
            raise ValueError(msg)
        self.encryption_key = encryption_key

    def encrypt(self, plaintext: bytes, nonce: Optional[bytes] = None) -> bytes:
        """Encrypt plaintext using ChaCha20-Poly1305

        Args:
            plaintext: Data to encrypt
            nonce: 12-byte nonce (generated if not provided)

        Returns:
            nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        if nonce is None:
            nonce = secrets.token_bytes(12)
        elif len(nonce) != 12:
            msg = "Nonce must be 12 bytes"
            raise ValueError(msg)

        cipher = Cipher(
            algorithms.ChaCha20(self.encryption_key, nonce),
            mode=None,
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # ChaCha20-Poly1305: nonce + ciphertext + tag
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        aead = ChaCha20Poly1305(self.encryption_key)
        encrypted = aead.encrypt(nonce, plaintext, None)

        return nonce + encrypted

    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data encrypted with ChaCha20-Poly1305

        Args:
            encrypted_data: nonce + ciphertext + tag

        Returns:
            Decrypted plaintext
        """
        if len(encrypted_data) < 28:  # 12 (nonce) + 16 (tag minimum)
            msg = "Encrypted data too short"
            raise ValueError(msg)

        nonce = encrypted_data[:12]
        ciphertext_and_tag = encrypted_data[12:]

        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

        aead = ChaCha20Poly1305(self.encryption_key)
        plaintext = aead.decrypt(nonce, ciphertext_and_tag, None)

        return plaintext


def compress_data(
    data: bytes, compression_type: CompressionType = CompressionType.ZSTD
) -> bytes:
    """Compress data using specified algorithm

    Args:
        data: Data to compress
        compression_type: Compression algorithm

    Returns:
        Compressed data
    """
    if compression_type == CompressionType.NONE:
        return data
    elif compression_type == CompressionType.ZLIB:
        return zlib.compress(data, level=6)
    elif compression_type == CompressionType.ZSTD:
        cctx = zstd.ZstdCompressor(level=3)
        return cctx.compress(data)
    else:
        msg = f"Unsupported compression type: {compression_type}"
        raise ValueError(msg)


def decompress_data(
    data: bytes, compression_type: CompressionType = CompressionType.ZSTD
) -> bytes:
    """Decompress data

    Args:
        data: Compressed data
        compression_type: Compression algorithm used

    Returns:
        Decompressed data
    """
    if compression_type == CompressionType.NONE:
        return data
    elif compression_type == CompressionType.ZLIB:
        return zlib.decompress(data)
    elif compression_type == CompressionType.ZSTD:
        dctx = zstd.ZstdDecompressor()
        return dctx.decompress(data)
    else:
        msg = f"Unsupported compression type: {compression_type}"
        raise ValueError(msg)


def encrypt_message(
    plaintext: bytes,
    encryption_key: bytes,
    compression_type: CompressionType = CompressionType.ZSTD,
    compress_threshold: int = 128,
) -> Tuple[bytes, CompressionType]:
    """Encrypt and optionally compress a message

    Args:
        plaintext: Message to encrypt
        encryption_key: 32-byte encryption key
        compression_type: Compression algorithm to use
        compress_threshold: Minimum size to enable compression

    Returns:
        Tuple of (encrypted_data, actual_compression_used)
    """
    # Compress if data is large enough
    actual_compression = CompressionType.NONE
    if (
        len(plaintext) >= compress_threshold
        and compression_type != CompressionType.NONE
    ):
        compressed = compress_data(plaintext, compression_type)
        if len(compressed) < len(plaintext):
            plaintext = compressed
            actual_compression = compression_type

    # Encrypt
    cipher = CipherSuite(encryption_key)
    encrypted = cipher.encrypt(plaintext)

    return encrypted, actual_compression


def decrypt_message(
    encrypted_data: bytes,
    encryption_key: bytes,
    compression_type: CompressionType = CompressionType.NONE,
) -> bytes:
    """Decrypt and decompress a message

    Args:
        encrypted_data: Encrypted message
        encryption_key: 32-byte encryption key
        compression_type: Compression algorithm used

    Returns:
        Decrypted plaintext
    """
    # Decrypt
    cipher = CipherSuite(encryption_key)
    plaintext = cipher.decrypt(encrypted_data)

    # Decompress if needed
    if compression_type != CompressionType.NONE:
        plaintext = decompress_data(plaintext, compression_type)

    return plaintext
