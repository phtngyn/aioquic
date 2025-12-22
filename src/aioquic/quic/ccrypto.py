import hashlib
import logging
import math
import os
import random
import struct
import zlib
from functools import lru_cache
from random import shuffle
from typing import List, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from reedsolo import ReedSolomonError, RSCodec

logger = logging.getLogger(__name__)

# Constants
GLOBAL_BYTE_ORDER = "big"
SEQUENCE_BYTES = 2

# Curve25519 / ChaCha20-Poly1305 parameters
CURVE25519_KEY_SIZE = 32
CHACHA20_NONCE_SIZE = 12
CHACHA20_KEY_SIZE = 32

# Handshake framing
CID_CHUNK_SIZE = 16
HANDSHAKE_TAG = b"QK"
HANDSHAKE_VERSION = 1
HANDSHAKE_HEADER_SIZE = len(HANDSHAKE_TAG) + 1
HANDSHAKE_PAYLOAD_SIZE = HANDSHAKE_HEADER_SIZE + CURVE25519_KEY_SIZE
HANDSHAKE_MASK_SEED = b"QuiCC_PublicKey_ChaCha20"
PUBLIC_KEY_CHUNK_COUNT = math.ceil(HANDSHAKE_PAYLOAD_SIZE / CID_CHUNK_SIZE)

# FEC Constants
MAX_FEC_PAYLOAD = 196
FEC_CHUNK_SIZE = 16
MAX_CID_BURST = 50


@lru_cache(maxsize=8)
def _get_rs_codec(n_parity: int) -> RSCodec:
    if n_parity <= 0 or n_parity >= 255:
        raise ValueError("Invalid parity shard count")
    return RSCodec(n_parity)


def _mask_bytes(data: bytes) -> bytes:
    if not data:
        return data
    mask = bytearray(len(data))
    for i in range(len(data)):
        digest = hashlib.sha256(HANDSHAKE_MASK_SEED + struct.pack(">I", i)).digest()
        mask[i] = digest[0]
    return bytes(a ^ b for a, b in zip(data, mask))


def _get_header_mask(
    session_key: Optional[bytes], msg_id: int, length: int = 3
) -> bytes:
    """
    Derives a mask to obfuscate FEC headers using the Session Key and Message ID.
    If no session key is established (Handshake), returns null mask (Plaintext).
    """
    if not session_key:
        return b"\x00" * length
    # HMAC-style construction: Hash(Key + Salt)
    digest = hashlib.sha256(session_key + bytes([msg_id])).digest()
    return digest[:length]


def fec_encode(
    data: bytes, fec_rate: float = 0.30, session_key: Optional[bytes] = None
) -> List[bytes]:
    """
    Encode data using Interleaved Reed-Solomon with Header Obfuscation.
    """
    if not data:
        return []
    if len(data) > MAX_FEC_PAYLOAD:
        raise ValueError(f"Payload {len(data)} exceeds limit {MAX_FEC_PAYLOAD}")

    padded_len = math.ceil(len(data) / FEC_CHUNK_SIZE) * FEC_CHUNK_SIZE
    padded_data = data.ljust(padded_len, b"\x00")

    data_chunks = [
        padded_data[i : i + FEC_CHUNK_SIZE]
        for i in range(0, len(padded_data), FEC_CHUNK_SIZE)
    ]
    n_data = len(data_chunks)
    n_parity = max(2, math.ceil(n_data * fec_rate))

    if n_data + n_parity > 255:
        raise ValueError("FEC configuration exceeds RS symbol limit (255)")

    rs = _get_rs_codec(n_parity)
    shards = []

    for pos in range(FEC_CHUNK_SIZE):
        column = bytes(chunk[pos] for chunk in data_chunks)
        encoded = rs.encode(column)
        shards.append(encoded)

    total_shards = n_data + n_parity
    result = []

    # 1. Generate Random Message ID (Public Salt)
    msg_id = random.randint(0, 255)

    # 2. Derive Mask for Metadata (n_data, n_parity, shard_idx)
    header_mask = _get_header_mask(session_key, msg_id)

    for shard_idx in range(total_shards):
        chunk = bytes(shards[pos][shard_idx] for pos in range(FEC_CHUNK_SIZE))

        # 3. Obfuscate Metadata
        meta = bytes([n_data, n_parity, shard_idx])
        masked_meta = bytes(a ^ b for a, b in zip(meta, header_mask))

        # Header = [Plaintext MsgID] + [Encrypted Metadata]
        header = bytes([msg_id]) + masked_meta
        result.append(header + chunk)

    logger.debug(f"FEC Encoded: {len(data)}B -> {total_shards} CIDs (ID={msg_id})")
    return result


def fec_decode(
    shards: List[bytes], fec_rate: float = 0.30, session_key: Optional[bytes] = None
) -> Optional[Tuple[bytes, int]]:
    """
    Decode interleaved shards with Header De-obfuscation.
    Returns (payload, msg_id).
    """
    if not shards:
        return None

    clusters = {}

    for s in shards:
        if s and len(s) >= 4 + FEC_CHUNK_SIZE:
            msg_id = s[0]

            # 1. Derive Mask to unlock Metadata
            mask = _get_header_mask(session_key, msg_id)

            # 2. De-obfuscate
            encrypted_meta = s[1:4]
            meta = bytes(a ^ b for a, b in zip(encrypted_meta, mask))

            n_data, n_parity, shard_idx = meta[0], meta[1], meta[2]

            # 3. Sanity Check (Filters out garbage/wrong keys)
            if n_data == 0 or n_parity == 0 or (n_data + n_parity) > 255:
                continue

            key = (msg_id, n_data, n_parity)
            if key not in clusters:
                clusters[key] = []

            # Attach the clean metadata for the decoder
            # Structure: [msg_id, n_data, n_parity, shard_idx] + [payload]
            clean_packet = bytes([msg_id, n_data, n_parity, shard_idx]) + s[4:]
            clusters[key].append(clean_packet)

    for (msg_id, n_data, n_parity), cluster_shards in clusters.items():
        if len(cluster_shards) < n_data:
            continue

        try:
            rs = _get_rs_codec(n_parity)
            shard_map = {}
            for s in cluster_shards:
                s_idx = s[3]
                chunk = s[4 : 4 + FEC_CHUNK_SIZE]
                shard_map[s_idx] = chunk

            # FAST PATH
            if all(i in shard_map for i in range(n_data)):
                result = b"".join(shard_map[i] for i in range(n_data))
                result = result.rstrip(b"\x00")
                return (result, msg_id)

            # RECOVERY PATH
            result_chunks = [bytearray(FEC_CHUNK_SIZE) for _ in range(n_data)]
            for pos in range(FEC_CHUNK_SIZE):
                column = bytearray(n_data + n_parity)
                erasures = []
                for idx in range(n_data + n_parity):
                    if idx in shard_map:
                        column[idx] = shard_map[idx][pos]
                    else:
                        column[idx] = 0
                        erasures.append(idx)

                decoded = rs.decode(bytes(column), erase_pos=erasures)
                data_bytes = (
                    decoded[0] if isinstance(decoded, tuple) else bytes(decoded)
                )
                for i in range(n_data):
                    result_chunks[i][pos] = data_bytes[i]

            result = b"".join(bytes(c) for c in result_chunks)
            result = result.rstrip(b"\x00")
            return (result, msg_id)

        except (ReedSolomonError, ValueError):
            continue
        except Exception:
            continue

    return None


def generate_private_key() -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.generate()


def get_public_key_bytes(private_key: x25519.X25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def load_public_key(public_bytes: bytes) -> x25519.X25519PublicKey:
    if len(public_bytes) != CURVE25519_KEY_SIZE:
        raise ValueError("Invalid Curve25519 public key length")
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)


def derive_session_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_bytes: bytes,
) -> bytes:
    peer_public = load_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(peer_public)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=CHACHA20_KEY_SIZE,
        salt=None,
        info=b"QuiCC ChaCha20 Session",
    )
    return hkdf.derive(shared_secret)


def encode_public_key_payload(public_bytes: bytes) -> bytes:
    if len(public_bytes) != CURVE25519_KEY_SIZE:
        raise ValueError("Invalid Curve25519 public key length")
    header = HANDSHAKE_TAG + bytes([HANDSHAKE_VERSION])
    payload = header + public_bytes
    return _mask_bytes(payload)


def decode_public_key_payload(payload: bytes) -> Optional[bytes]:
    if not payload:
        return None
    unmasked = _mask_bytes(payload)
    if len(unmasked) != HANDSHAKE_PAYLOAD_SIZE:
        return None
    if not unmasked.startswith(HANDSHAKE_TAG):
        return None
    version = unmasked[len(HANDSHAKE_TAG)]
    if version != HANDSHAKE_VERSION:
        return None
    return unmasked[HANDSHAKE_HEADER_SIZE:]


def reconstruct_payload(buffer: List[bytes]) -> bytes:
    """
    Reassemble payload from chunks.
    """
    if not buffer:
        return b""
    return b"".join(buffer)


def reconstruct_payload_fec(
    buffer, fec_rate: float = 0.30, session_key: Optional[bytes] = None
):
    """Reconstructs payload directly from FEC headers."""
    if not buffer:
        return None
    return fec_decode(buffer, fec_rate=fec_rate, session_key=session_key)


def encrypt_with_session_key(session_key: bytes, message: bytes) -> bytes:
    if len(session_key) != CHACHA20_KEY_SIZE:
        raise ValueError("ChaCha20-Poly1305 requires 32-byte key")
    nonce = os.urandom(CHACHA20_NONCE_SIZE)
    cipher = ChaCha20Poly1305(session_key)
    compressed_message = zlib.compress(message)
    ciphertext = cipher.encrypt(nonce, compressed_message, None)
    return nonce + ciphertext


def decrypt_with_session_key(session_key: bytes, encrypted: bytes) -> Optional[bytes]:
    # 1. Validation Checks
    if len(session_key) != CHACHA20_KEY_SIZE:
        logger.error(f"Decryption Error: Invalid key size {len(session_key)}")
        return None

    if len(encrypted) <= CHACHA20_NONCE_SIZE:
        logger.debug(f"Decryption Error: Ciphertext too short ({len(encrypted)} bytes)")
        return None

    nonce = encrypted[:CHACHA20_NONCE_SIZE]
    ciphertext = encrypted[CHACHA20_NONCE_SIZE:]

    # 2. Decryption Attempt
    try:
        cipher = ChaCha20Poly1305(session_key)
        # Assuming cipher.decrypt returns bytes on success, raises InvalidTag on failure
        compressed_message = cipher.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        # This implies the Key is wrong, or the Nonce is wrong, or Data is corrupted
        logger.debug(
            f"Session key decryption failed: Integrity check failed (InvalidTag). Len: {len(encrypted)}"
        )
        return None
    except Exception as e:
        logger.error(f"Session key decryption failed: Crypto library error: {e}")
        return None

    # 3. Decompression Attempt
    try:
        return zlib.decompress(compressed_message)
    except zlib.error as e:
        # This implies Decryption WORKED, but the payload is not valid zlib data
        logger.error(f"Session key decryption success, but ZLIB failed: {e}")
        # useful debugging: print hex of compressed_message to see if it looks like garbage
        logger.debug(f"Bad Zlib Payload (hex): {compressed_message.hex()}")
        return None


def parse_public_key_chunks(chunks: List[bytes]) -> Optional[bytes]:
    if not chunks:
        return None
    payload = reconstruct_payload(chunks)
    return decode_public_key_payload(payload)


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
    cid_payloads = []
    target_payload = b""
    if is_public_key:
        target_payload = encode_public_key_payload(payload)
        # Disable FEC for Handshake to avoid complexity before key establishment
        if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
            logger.warning("Handshake payload too large for FEC; disabling FEC.")
            fec_rate = None
    elif session_key:
        seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
        target_payload = encrypt_with_session_key(session_key, seq_bytes + payload)
    else:
        logger.warning("Session key unavailable; dropping payload")
        return 0

    if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
        logger.warning(
            f"Payload ({len(target_payload)}B) exceeds FEC limit. Disabling FEC."
        )
        fec_rate = None

    if fec_rate and fec_rate > 0:
        # FEC Mode
        cid_payloads = fec_encode(target_payload, fec_rate, session_key=session_key)
    else:
        # Legacy Mode
        chunk_size = 16
        cid_payloads = [
            target_payload[i : i + chunk_size]
            for i in range(0, len(target_payload), chunk_size)
        ]

    if len(cid_payloads) > MAX_CID_BURST:
        logger.warning(
            f"Burst cap exceeded ({len(cid_payloads)} > {MAX_CID_BURST}). Dropping."
        )
        return 0

    if fec_rate and fec_rate > 0:
        shuffle(cid_payloads)

    if is_public_key:
        logger.debug(
            "Handshake chunks lens=%s total=%d hex=%s",
            [len(v) for v in cid_payloads],
            len(target_payload),
            [v.hex() for v in cid_payloads],
        )

    for cid in cid_payloads:
        queue.put(cid)

    logger.debug(f"Queued {len(cid_payloads)} chunks (FEC={bool(fec_rate)})")
    return len(cid_payloads)
