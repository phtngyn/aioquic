import hashlib
import logging
import math
import os
import random
import zlib
from functools import lru_cache
from random import shuffle
from typing import List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from reedsolo import ReedSolomonError, RSCodec

logger = logging.getLogger(__name__)

# Constants
RSA_BIT_STRENGTH = 4096
RSA_PUBLIC_EXPONENT = 65537
AES_BLOCK_SIZE = 16
GLOBAL_BYTE_ORDER = "big"
SEQUENCE_BYTES = 2

# FEC Constants
MAX_FEC_PAYLOAD = 196
FEC_CHUNK_SIZE = 16
MAX_CID_BURST = 50


@lru_cache(maxsize=8)
def _get_rs_codec(n_parity: int) -> RSCodec:
    if n_parity <= 0 or n_parity >= 255:
        raise ValueError("Invalid parity shard count")
    return RSCodec(n_parity)


def _pad_aes(data: bytes) -> bytes:
    padder = sym_padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _unpad_aes(data: bytes) -> bytes:
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()


def fec_encode(data: bytes, fec_rate: float = 0.30) -> List[bytes]:
    """Encode data using Interleaved Reed-Solomon with Random IDs."""
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

    # --- CRITICAL FIX: Use Random ID to prevent collisions ---
    msg_id = random.randint(0, 255)
    # ---------------------------------------------------------

    for shard_idx in range(total_shards):
        chunk = bytes(shards[pos][shard_idx] for pos in range(FEC_CHUNK_SIZE))
        header = bytes([msg_id, n_data, n_parity, shard_idx])
        result.append(header + chunk)

    logger.debug(f"FEC Encoded: {len(data)}B -> {total_shards} CIDs (ID={msg_id})")
    return result


def fec_decode(
    shards: List[bytes], fec_rate: float = 0.30
) -> Optional[Tuple[bytes, int]]:
    """
    Decode interleaved shards. Returns (payload, msg_id).
    """
    if not shards:
        return None

    clusters = {}

    for s in shards:
        if s and len(s) >= 4 + FEC_CHUNK_SIZE:
            msg_id, n_data, n_parity, shard_idx = s[0], s[1], s[2], s[3]
            if n_data == 0 or n_parity == 0 or (n_data + n_parity) > 255:
                continue
            key = (msg_id, n_data, n_parity)
            if key not in clusters:
                clusters[key] = []
            clusters[key].append(s)

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
                return (result, msg_id)  # Return Tuple

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
            return (result, msg_id)  # Return Tuple

        except (ReedSolomonError, ValueError):
            continue
        except Exception:
            continue

    return None


def generate_rsa(bits=RSA_BIT_STRENGTH):
    """Generate RSA key pair with specified bit strength."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=bits, backend=default_backend()
    )
    return private_key


def obfuscate_modulus(n_bytes: bytes) -> bytes:
    OBFUSCATION_SEED = b"QuiCC_Obfuscation_v1"
    mask = bytearray()
    for i in range(len(n_bytes)):
        mask_byte = hashlib.sha256(OBFUSCATION_SEED + i.to_bytes(4, "big")).digest()[0]
        mask.append(mask_byte)
    return bytes(a ^ b for a, b in zip(n_bytes, mask))


def deobfuscate_modulus(obfuscated: bytes) -> bytes:
    return obfuscate_modulus(obfuscated)


def generate_rsa_public_key(n_bytes):
    n = int.from_bytes(n_bytes, GLOBAL_BYTE_ORDER)
    public_numbers = rsa.RSAPublicNumbers(e=RSA_PUBLIC_EXPONENT, n=n)
    return public_numbers.public_key(default_backend())


def encrypt_with_sequence(public_key, message: bytes, sequence: int) -> bytes:
    seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
    message_with_seq = seq_bytes + message
    aes_key = os.urandom(AES_BLOCK_SIZE)
    iv = os.urandom(AES_BLOCK_SIZE)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message_with_seq)
    padded_message = _pad_aes(compressed_message)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return iv + encrypted_aes_key + ciphertext


def reconstruct_payload(buffer, invert=False):
    if invert:
        payload_pairs = [(v[: len(v) - 4], v[-4:]) for v in buffer]
    else:
        payload_pairs = [(v[:4], v[4:]) for v in buffer]
    sort_index = 1 if invert else 0
    payload_index = 0 if invert else 1
    payload_chunks = [
        v[payload_index] for v in sorted(payload_pairs, key=lambda x: x[sort_index])
    ]
    return b"".join(payload_chunks)


def reconstruct_payload_fec(buffer, fec_rate: float = 0.30):
    """Reconstructs payload directly from FEC headers."""
    if not buffer:
        return None
    return fec_decode(buffer, fec_rate)


def encrypt_with_session_key(session_key: bytes, message: bytes) -> bytes:
    iv = os.urandom(AES_BLOCK_SIZE)
    cipher = Cipher(
        algorithms.AES(session_key), modes.CBC(iv), backend=default_backend()
    )
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message)
    padded_message = _pad_aes(compressed_message)
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    return iv + ciphertext


def decrypt_with_session_key(session_key: bytes, encrypted: bytes) -> Optional[bytes]:
    try:
        iv = encrypted[:AES_BLOCK_SIZE]
        ciphertext = encrypted[AES_BLOCK_SIZE:]
        cipher = Cipher(
            algorithms.AES(session_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        return zlib.decompress(compressed_message)
    except Exception as e:
        logger.debug(f"Session key decryption failed: {e}")
        return None


def try_decrypt_with_sequence(
    private_key, buffer, raise_on_error=False
) -> Optional[Tuple[bytes, int]]:
    encrypted_payload = reconstruct_payload(buffer)
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[
            AES_BLOCK_SIZE : AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8
        ]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8 :]
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        decompressed = zlib.decompress(compressed_message)
        sequence = int.from_bytes(decompressed[:SEQUENCE_BYTES], GLOBAL_BYTE_ORDER)
        message = decompressed[SEQUENCE_BYTES:]
        return (message, sequence)
    except Exception as e:
        if raise_on_error:
            raise
        logger.debug(f"Decryption failed: {e}")
        return None


def try_decrypt(private_key, buffer, raise_on_error=False) -> Optional[bytes]:
    encrypted_payload = reconstruct_payload(buffer)
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[
            AES_BLOCK_SIZE : AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8
        ]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8 :]
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        cipher = Cipher(
            algorithms.AES(decrypted_aes_key), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        compressed_message = _unpad_aes(padded_message)
        return zlib.decompress(compressed_message)
    except Exception as e:
        if raise_on_error:
            raise
        logger.debug(f"Decryption failed: {e}")
        return None


def get_compact_key(rsa_key):
    if isinstance(rsa_key, rsa.RSAPrivateKey):
        public_numbers = rsa_key.public_key().public_numbers()
    else:
        public_numbers = rsa_key.public_numbers()
    return public_numbers.n.to_bytes(RSA_BIT_STRENGTH // 8, byteorder=GLOBAL_BYTE_ORDER)


def generate_ordered_bytes(n, size=4):
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
    cid_payloads = []
    target_payload = b""
    if is_public_key:
        target_payload = obfuscate_modulus(payload)
        if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
            logger.warning("Handshake payload too large for FEC. Using Legacy mode.")
            fec_rate = None
    elif session_key:
        seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
        target_payload = encrypt_with_session_key(session_key, seq_bytes + payload)
    else:
        target_payload = encrypt_with_sequence(public_key, payload, sequence)

    if fec_rate and len(target_payload) > MAX_FEC_PAYLOAD:
        logger.warning(
            f"Payload ({len(target_payload)}B) exceeds FEC limit. Switching to Legacy Mode."
        )
        fec_rate = None

    if fec_rate and fec_rate > 0:
        cid_payloads = fec_encode(target_payload, fec_rate)
    else:
        chunk_size = 16
        raw_chunks = [
            target_payload[i : i + chunk_size]
            for i in range(0, len(target_payload), chunk_size)
        ]
        cid_payloads = [
            v[0] + v[1]
            for v in zip(generate_ordered_bytes(len(raw_chunks)), raw_chunks)
        ]

    if len(cid_payloads) > MAX_CID_BURST:
        logger.warning(
            f"Burst cap exceeded ({len(cid_payloads)} > {MAX_CID_BURST}). Dropping."
        )
        return 0

    shuffle(cid_payloads)
    for cid in cid_payloads:
        queue.put(cid)
    logger.debug(f"Queued {len(cid_payloads)} chunks (FEC={bool(fec_rate)})")
    return len(cid_payloads)
