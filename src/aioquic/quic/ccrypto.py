# Improved covert channel crypto using cryptography library
import hashlib
import logging
import math
import os
import random
import time
import zlib
from random import shuffle
from typing import List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from reedsolo import ReedSolomonError, RSCodec

logger = logging.getLogger(__name__)

# Constants - imported from connection module
RSA_BIT_STRENGTH = 4096
RSA_PUBLIC_EXPONENT = 65537
AES_BLOCK_SIZE = 16
GLOBAL_BYTE_ORDER = "big"
SEQUENCE_BYTES = 2

# FEC Constants
# Small Message Mode Limit: 196 bytes payload + ~60 bytes parity < 255 total symbols
MAX_FEC_PAYLOAD = 196

# Chunk Size: 20 byte CID - 4 byte FEC Header = 16 bytes Data
FEC_CHUNK_SIZE = 16


def fec_encode(data: bytes, fec_rate: float = 0.30) -> List[bytes]:
    """
    Encode data with Reed-Solomon FEC parity shards using Interleaving.

    Args:
        data: Raw bytes to encode (Must be <= MAX_FEC_PAYLOAD)
        fec_rate: Fraction of parity shards (0.30 = 30% overhead)

    Returns:
        List of (header + chunk_bytes) where header = [orig_len%256, n_data, n_parity, shard_idx].
        Total CID size = 4 bytes header + 16 bytes chunk = 20 bytes.
    """
    if not data:
        return []

    # Pad data to multiple of chunk size
    padded_len = math.ceil(len(data) / FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE
    padded_data = data.ljust(padded_len, b"\x00")

    # Split into data chunks
    data_chunks = [
        padded_data[i : i + FEC_CHUNK_SIZE]
        for i in range(0, len(padded_data), FEC_CHUNK_SIZE)
    ]
    n_data = len(data_chunks)

    # Calculate parity with a floor of 2 to survive single-packet loss
    n_parity = max(2, math.ceil(n_data * fec_rate))

    # RS codec over n_data symbols with n_parity parity
    # Note: For interleaving, this works as long as n_data + n_parity <= 255
    rs = RSCodec(n_parity)

    # Build shards by encoding each byte position (column) across all chunks
    # This is "Interleaved Reed-Solomon"
    shards = []
    for pos in range(FEC_CHUNK_SIZE):
        column = bytes(chunk[pos] for chunk in data_chunks)
        encoded = rs.encode(column)  # returns column_data + column_parity
        shards.append(encoded)

    # Transpose back: shard[i] = byte i from each position
    total_shards = n_data + n_parity
    result = []
    for shard_idx in range(total_shards):
        chunk = bytes(shards[pos][shard_idx] for pos in range(FEC_CHUNK_SIZE))

        # 4-byte header: orig_len%256, n_data, n_parity, shard_idx
        # This acts as the sequence number, so no legacy sorting prefix is needed.
        header = bytes([len(data) % 256, n_data, n_parity, shard_idx])
        result.append(header + chunk)

    logger.debug(
        "FEC encode: %d bytes -> %d data + %d parity shards (Total %d CIDs)",
        len(data),
        n_data,
        n_parity,
        total_shards,
    )
    return result


def fec_decode(shards: List[bytes], fec_rate: float = 0.30) -> Optional[bytes]:
    """
    Decode data from received shards (some may be missing/corrupted).

    Args:
        shards: List of (header + chunk) bytes, may have gaps
        fec_rate: Same rate used during encoding (used as fallback hint)

    Returns:
        Reconstructed data bytes, or None if unrecoverable.
    """
    if not shards:
        return None

    # Filter out empty/None shards and parse 4-byte headers
    # Header: [orig_len%256, n_data, n_parity, shard_idx]
    valid = []
    for s in shards:
        if s and len(s) >= 4 + FEC_CHUNK_SIZE:
            orig_mod, n_data, n_parity, shard_idx = s[0], s[1], s[2], s[3]
            chunk = s[4 : 4 + FEC_CHUNK_SIZE]
            valid.append((orig_mod, n_data, n_parity, shard_idx, chunk))

    if not valid:
        return None

    # Use first shard's header for parameters
    orig_len_mod, n_data, n_parity, _, _ = valid[0]

    # Check we have enough shards for recovery (need at least n_data)
    if len(valid) < n_data:
        logger.debug(
            "FEC: only %d/%d shards received, cannot recover", len(valid), n_data
        )
        return None

    rs = RSCodec(n_parity)

    # Build indexed shard map
    shard_map = {}
    for _, _, _, shard_idx, chunk in valid:
        shard_map[shard_idx] = chunk

    # Check if all data shards present (fast path)
    all_data_present = all(i in shard_map for i in range(n_data))

    try:
        if all_data_present:
            # Fast path: just concatenate data shards
            result = b"".join(shard_map[i] for i in range(n_data))
            result = result.rstrip(b"\x00")
            # Adjust to original length using mod hint
            if orig_len_mod != 0:
                while len(result) > 0 and len(result) % 256 != orig_len_mod:
                    result = result[:-1]
            logger.debug("FEC decode: all data shards present, fast path")
            return result

        # Need RS decoding - some data shards missing
        result_chunks = [bytearray(FEC_CHUNK_SIZE) for _ in range(n_data)]

        for pos in range(FEC_CHUNK_SIZE):
            # Build column with erasures
            column = bytearray(n_data + n_parity)
            erasures = []
            for shard_idx in range(n_data + n_parity):
                if shard_idx in shard_map:
                    column[shard_idx] = shard_map[shard_idx][pos]
                else:
                    column[shard_idx] = 0  # placeholder
                    erasures.append(shard_idx)

            # Decode with erasure positions
            decoded = rs.decode(bytes(column), erase_pos=erasures)
            data_bytes = decoded[0] if isinstance(decoded, tuple) else bytes(decoded)
            for i in range(n_data):
                result_chunks[i][pos] = data_bytes[i]

        result = b"".join(bytes(c) for c in result_chunks)
        result = result.rstrip(b"\x00")

        # Adjust to original length
        if orig_len_mod != 0:
            while len(result) > 0 and len(result) % 256 != orig_len_mod:
                result = result[:-1]

        logger.debug("FEC decode: recovered with RS, result=%d bytes", len(result))
        return result

    except ReedSolomonError as e:
        logger.warning("FEC decode failed: %s", e)
        return None


def generate_rsa(bits=RSA_BIT_STRENGTH):
    """Generate RSA key pair with specified bit strength."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=bits, backend=default_backend()
    )
    return private_key


def obfuscate_modulus(n_bytes: bytes) -> bytes:
    """
    Obfuscate N modulus to mitigate statistical detection of odd numbers.

    Limitation addressed: "Statistical Analysis of Odd Numbered Connection IDs"

    XOR with deterministic position-based mask for reversibility.
    The mask is derived from a fixed seed + position to maintain high entropy.
    """
    # Use fixed seed for deterministic, reversible obfuscation
    # This seed should be agreed upon between client/server
    OBFUSCATION_SEED = b"QuiCC_Obfuscation_v1"

    mask = bytearray()
    for i in range(len(n_bytes)):
        # Generate mask bytes from fixed seed + position
        mask_byte = hashlib.sha256(OBFUSCATION_SEED + i.to_bytes(4, "big")).digest()[0]
        mask.append(mask_byte)

    # XOR obfuscation maintains entropy but hides parity
    obfuscated = bytes(a ^ b for a, b in zip(n_bytes, mask))
    return obfuscated


def deobfuscate_modulus(obfuscated: bytes) -> bytes:
    """
    Reverse obfuscation to recover original N modulus.

    Since XOR with the same mask is self-inverse, we just apply the same operation.
    """
    return obfuscate_modulus(obfuscated)


def generate_rsa_public_key(n_bytes):
    """Construct RSA public key from N modulus bytes."""
    n = int.from_bytes(n_bytes, GLOBAL_BYTE_ORDER)

    # Construct public key from modulus
    public_numbers = rsa.RSAPublicNumbers(e=RSA_PUBLIC_EXPONENT, n=n)
    public_key = public_numbers.public_key(default_backend())
    return public_key


def _pad_aes(data: bytes) -> bytes:
    """Apply PKCS7 padding for AES."""
    padding_length = AES_BLOCK_SIZE - (len(data) % AES_BLOCK_SIZE)
    padding = bytes([padding_length] * padding_length)
    return data + padding


def _unpad_aes(data: bytes) -> bytes:
    """Remove PKCS7 padding from AES decrypted data."""
    padding_length = data[-1]
    return data[:-padding_length]


def encrypt_with_sequence(public_key, message: bytes, sequence: int) -> bytes:
    """
    Encrypt message with sequence number for sync recovery.

    Limitation addressed: "Synchronization Disruption"

    Prepends sequence number to payload before encryption to allow
    recipient to detect out-of-order or missing packets.
    """
    # Prepend sequence number (2 bytes)
    seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
    message_with_seq = seq_bytes + message

    # Standard encryption with AES+RSA
    aes_key = os.urandom(AES_BLOCK_SIZE)
    iv = os.urandom(AES_BLOCK_SIZE)

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message_with_seq)
    padded_message = _pad_aes(compressed_message)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return iv + encrypted_aes_key + ciphertext


def reconstruct_payload(buffer, invert=False):
    """
    Reconstructs encrypted payload from CID buffer.

    Supports variable-length CIDs for improved bandwidth.
    """
    if invert:
        # For key exchange: order bytes at end
        payload_pairs = [(v[: len(v) - 4], v[-4:]) for v in buffer]
    else:
        # For encrypted messages: order bytes at start
        payload_pairs = [(v[:4], v[4:]) for v in buffer]

    sort_index = 1 if invert else 0
    payload_index = 0 if invert else 1
    payload_chunks = [
        v[payload_index] for v in sorted(payload_pairs, key=lambda x: x[sort_index])
    ]
    return b"".join(payload_chunks)


def reconstruct_payload_fec(buffer, fec_rate: float = 0.30) -> Optional[bytes]:
    """
    Reconstructs payload directly from FEC headers.

    OPTIMIZED: Does NOT expect a legacy ordering prefix.
    Buffer contains raw 20-byte CIDs: [4-byte FEC Header | 16-byte Data]
    """
    if not buffer:
        return None

    # We pass the raw buffer to fec_decode.
    # fec_decode extracts the header (bytes 0-3) which includes 'shard_idx'.
    # This serves as the sequence number, so no external sorting is required.
    return fec_decode(buffer, fec_rate)


def encrypt_with_session_key(session_key: bytes, message: bytes) -> bytes:
    """
    Fast encryption using session key (AES-256 only, no RSA).

    Reduces overhead from 512+16 bytes to just 16 bytes (IV only).
    """
    iv = os.urandom(AES_BLOCK_SIZE)

    # Encrypt with AES-CBC using session key
    cipher = Cipher(
        algorithms.AES(session_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message)
    padded_message = _pad_aes(compressed_message)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return iv + ciphertext


def decrypt_with_session_key(session_key: bytes, encrypted: bytes) -> Optional[bytes]:
    """
    Fast decryption using session key (AES-256 only).

    Returns decrypted message or None if decryption fails.
    """
    try:
        iv = encrypted[:AES_BLOCK_SIZE]
        ciphertext = encrypted[AES_BLOCK_SIZE:]

        # Decrypt with AES-CBC using session key
        cipher = Cipher(
            algorithms.AES(session_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        decrypted_message = zlib.decompress(compressed_message)

        return decrypted_message
    except Exception as e:
        logger.debug(f"Session key decryption failed: {e}")
        return None


def try_decrypt_with_sequence(
    private_key, buffer, raise_on_error=False
) -> Optional[Tuple[bytes, int]]:
    """
    Decrypt and extract sequence number for sync recovery.

    Returns: (decrypted_message, sequence_number) or None
    """
    encrypted_payload = reconstruct_payload(buffer)
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[
            AES_BLOCK_SIZE : AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8
        ]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8 :]

        # Decrypt AES key with RSA
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt with AES
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        decompressed = zlib.decompress(compressed_message)

        # Extract sequence number
        sequence = int.from_bytes(decompressed[:SEQUENCE_BYTES], GLOBAL_BYTE_ORDER)
        message = decompressed[SEQUENCE_BYTES:]

        return (message, sequence)
    except Exception as e:
        if raise_on_error:
            raise
        logger.debug(f"Decryption failed: {e}")
        return None


def try_decrypt(private_key, buffer, raise_on_error=False) -> Optional[bytes]:
    """Standard decryption without sequence (backward compatible)."""
    encrypted_payload = reconstruct_payload(buffer)
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[
            AES_BLOCK_SIZE : AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8
        ]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8 :]

        # Decrypt AES key with RSA
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        # Decrypt with AES
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        decrypted_message = zlib.decompress(compressed_message)

        return decrypted_message
    except Exception as e:
        if raise_on_error:
            raise
        logger.debug(f"Decryption failed: {e}")
        return None


def get_compact_key(rsa_key):
    """Extract N modulus as compact bytes."""
    # Get public numbers from either private or public key
    if isinstance(rsa_key, rsa.RSAPrivateKey):
        public_numbers = rsa_key.public_key().public_numbers()
    else:
        public_numbers = rsa_key.public_numbers()

    modulus = public_numbers.n
    return modulus.to_bytes(RSA_BIT_STRENGTH // 8, byteorder=GLOBAL_BYTE_ORDER)


def generate_ordered_bytes(n, size=4):
    """
    Generate high-entropy ordered bytes for packet sequencing.

    Uses cryptographically secure random to maintain entropy requirements.
    """
    prefixes = set()
    while len(prefixes) < n:
        prefixes.add(os.urandom(size))
    return sorted(list(prefixes))


def queue_message(
    host_ip,
    payload: bytes,
    queue,
    public_key,
    is_public_key=False,
    sequence=0,
    session_key=None,
    fec_rate: Optional[float] = None,
):
    """
    Queue message with optional FEC strategy.

    Optimization:
    - If FEC is enabled, we skip the legacy 4-byte ordering header (saving 20% bandwidth).
    - We enforce MAX_FEC_PAYLOAD for data messages to ensure 'Small Message Mode' compliance.
    """
    cid_payloads = []

    # 1. Determine Encryption / Obfuscation Strategy
    if is_public_key:
        # Obfuscate modulus
        target_payload = obfuscate_modulus(payload)

        # Public Keys (4096-bit) are ~512 bytes. This violates Small Message Mode (196 bytes).
        # We must fallback to legacy mode for the handshake, or warn.
        if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
            logger.warning(
                "Handshake payload (%dB) exceeds FEC limit (%dB). Falling back to Legacy mode.",
                len(target_payload),
                MAX_FEC_PAYLOAD,
            )
            fec_rate = None  # Fallback to legacy for this specific message

    elif not is_public_key and not public_key and not session_key:
        raise ValueError("RSA key or session key required for encryption.")

    else:
        # Encrypt Data
        if session_key:
            seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
            target_payload = encrypt_with_session_key(session_key, seq_bytes + payload)
        else:
            target_payload = encrypt_with_sequence(public_key, payload, sequence)

        # STRICT ENFORCEMENT for Data Messages
        if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
            logger.error(
                "Error: Payload (%d bytes) exceeds FEC-Block limit (Max %d bytes). Use file mode.",
                len(target_payload),
                MAX_FEC_PAYLOAD,
            )
            raise ValueError(f"Payload exceeds limit of {MAX_FEC_PAYLOAD} bytes")

    # 2. Slice and Packetize
    if fec_rate and fec_rate > 0:
        # === FEC Mode ===
        # Shards already include [Header(4) | Data(16)]
        # We DO NOT add extra ordering bytes.
        cid_payloads = fec_encode(target_payload, fec_rate)

    else:
        # === Legacy Mode ===
        # 1. Slice into 16-byte chunks
        chunk_size = 16
        raw_chunks = [
            target_payload[i : i + chunk_size]
            for i in range(0, len(target_payload), chunk_size)
        ]

        # 2. Add Legacy 4-byte ordering prefix
        # This wastes bandwidth but maintains backward compatibility
        cid_payloads = [
            v[0] + v[1]
            for v in zip(generate_ordered_bytes(len(raw_chunks)), raw_chunks)
        ]

    # 3. Queue with Jitter
    shuffle(cid_payloads)

    for i, cid in enumerate(cid_payloads):
        queue.put(cid)
        if i < len(cid_payloads) - 1:
            # Minor jitter to break traffic analysis fingerprints
            jitter = random.uniform(0.02, 0.05)
            time.sleep(jitter)

    logger.debug(
        "Queued %d CID chunks for %s (Mode: %s)",
        len(cid_payloads),
        host_ip,
        "FEC" if fec_rate else "Legacy",
    )
    return len(cid_payloads)
