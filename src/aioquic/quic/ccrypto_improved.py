# Improved covert channel crypto using cryptography library
import hashlib
import logging
import os
import struct
import time
import zlib
from random import shuffle
from typing import Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

logger = logging.getLogger(__name__)

# Constants - imported from connection module
RSA_BIT_STRENGTH = 4096
RSA_PUBLIC_EXPONENT = 65537
AES_BLOCK_SIZE = 16
GLOBAL_BYTE_ORDER = "big"
SEQUENCE_BYTES = 2
MAX_CID_LENGTH = 20


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

    XOR with deterministic but high-entropy mask derived from the modulus itself.
    This maintains uniqueness while hiding odd/even patterns.
    """
    # Use hash of modulus as seed for consistent obfuscation
    seed = hashlib.sha256(n_bytes).digest()
    mask = bytearray()
    for i in range(len(n_bytes)):
        # Generate mask bytes from seed
        mask_byte = hashlib.sha256(seed + i.to_bytes(4, "big")).digest()[0]
        mask.append(mask_byte)

    # XOR obfuscation maintains entropy but hides parity
    obfuscated = bytes(a ^ b for a, b in zip(n_bytes, mask))
    return obfuscated


def deobfuscate_modulus(obfuscated: bytes) -> bytes:
    """Reverse obfuscation to recover original N modulus."""
    # Same operation as obfuscation (XOR is reversible)
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


def encrypt(public_key, message: bytes) -> bytes:
    """Standard encryption without sequence (backward compatible)."""
    aes_key = os.urandom(AES_BLOCK_SIZE)
    iv = os.urandom(AES_BLOCK_SIZE)

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message)
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


def load_key(pem_file):
    """Load RSA private key from PEM file."""
    with open(pem_file, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None, backend=default_backend()
        )
        if private_key.key_size != RSA_BIT_STRENGTH:
            raise Exception(f"This tool requires {RSA_BIT_STRENGTH} bit RSA keys.")
        return private_key


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


def queue_message_improved(
    host_ip,
    payload: bytes,
    queue,
    public_key,
    is_public_key=False,
    sequence=0,
    cid_length=MAX_CID_LENGTH,
):
    """
    Improved message queuing with variable CID length and sequence support.

    Limitations addressed:
    - Uses larger CIDs for better bandwidth (up to MAX_CID_LENGTH)
    - Adds sequence numbers for sync recovery
    - Obfuscates public keys to prevent statistical detection
    """
    cid_payloads = []

    if is_public_key:
        # Obfuscate modulus to hide odd number pattern
        obfuscated_payload = obfuscate_modulus(payload)

        # Variable chunk size based on CID length
        chunk_size = cid_length - 4  # Reserve 4 bytes for ordering
        cid_payloads = [
            obfuscated_payload[i : i + chunk_size]
            for i in range(0, len(obfuscated_payload), chunk_size)
        ]
        cid_payloads = [
            v[0] + v[1]
            for v in zip(cid_payloads, generate_ordered_bytes(len(cid_payloads)))
        ]
    elif not is_public_key and not public_key:
        logger.error(
            "RSA key required if sending a message or a file. Received %s", public_key
        )
        raise ValueError(f"RSA key required by {public_key} was provided.")
    else:
        # Encrypt with sequence number for sync recovery
        encrypted_payload = encrypt_with_sequence(public_key, payload, sequence)

        # Variable chunk size
        chunk_size = cid_length - 4
        cid_payloads = [
            encrypted_payload[i : i + chunk_size]
            for i in range(0, len(encrypted_payload), chunk_size)
        ]
        # Prepend ordered prefixes
        cid_payloads = [
            v[0] + v[1]
            for v in zip(generate_ordered_bytes(len(cid_payloads)), cid_payloads)
        ]

    # Shuffle to prevent ordering correlation
    shuffle(cid_payloads)

    for cid in cid_payloads:
        queue.put(cid)

    logger.debug(f"Queued {len(cid_payloads)} CID chunks for {host_ip}, seq={sequence}")
    return len(cid_payloads)


def queue_message(host_ip, payload, queue, public_key, is_public_key=False):
    """Backward compatible queue_message (no sequence support)."""
    cid_payloads = []
    if is_public_key:
        # Make the key chunks 160 bits by appending 128 bit chunks with 32 bits of ordered chunks
        cid_payloads = [payload[i : i + 16] for i in range(0, len(payload), 16)]
        cid_payloads = [
            v[0] + v[1]
            for v in zip(cid_payloads, generate_ordered_bytes(len(cid_payloads)))
        ]
    elif not is_public_key and not public_key:
        logger.error(
            "RSA key required if sending a message or a file. Received %s", public_key
        )
        raise ValueError(f"RSA key required by {public_key} was provided.")
    else:
        encrypted_payload = encrypt(public_key, payload)
        cid_payloads = [
            encrypted_payload[i : i + 16] for i in range(0, len(encrypted_payload), 16)
        ]
        cid_payloads = [
            v[0] + v[1]
            for v in zip(generate_ordered_bytes(len(cid_payloads)), cid_payloads)
        ]
    shuffle(cid_payloads)

    for cid in cid_payloads:
        queue.put(cid)
    return len(cid_payloads)


def generate_sync_recovery_message() -> bytes:
    """
    Generate a sync recovery beacon message.

    Used to re-establish synchronization after disruption.
    """
    return b"SYNC_RECOVERY_" + struct.pack(">d", time.time())


def is_sync_recovery_message(message: bytes) -> bool:
    """Check if message is a sync recovery beacon."""
    return message.startswith(b"SYNC_RECOVERY_")
