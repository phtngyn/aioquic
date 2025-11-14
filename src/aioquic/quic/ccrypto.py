# Covert channel crypto using cryptography library - optimized for stealth + bandwidth
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
MAX_CID_LENGTH = 20  # Use maximum CID length for bandwidth


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
    logger.debug(f"generate_rsa_public_key: input length={len(n_bytes)}")
    logger.debug(f"Before deobfuscate: {n_bytes[:32].hex()}...")

    # Deobfuscate if needed (key exchange sends obfuscated modulus)
    n_bytes = deobfuscate_modulus(n_bytes)
    logger.debug(f"After deobfuscate: {n_bytes[:32].hex()}...")

    n = int.from_bytes(n_bytes, GLOBAL_BYTE_ORDER)
    logger.debug(f"Modulus n: {hex(n)[:64]}...")

    # Construct public key from modulus
    public_numbers = rsa.RSAPublicNumbers(e=RSA_PUBLIC_EXPONENT, n=n)
    public_key = public_numbers.public_key(default_backend())
    logger.debug("Public key constructed successfully")
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

    Prepends sequence number to payload before encryption to allow
    recipient to detect out-of-order or missing packets.
    """
    logger.debug(f"encrypt_with_sequence: message_len={len(message)}, seq={sequence}")
    logger.debug(f"public_key type: {type(public_key)}, value: {public_key}")

    # Debug: Show public key modulus (INFO level so it's always visible)
    try:
        pub_modulus = public_key.public_numbers().n
        logger.info(
            f"[QuiCC] Encrypting with public key modulus: {hex(pub_modulus)[:64]}..."
        )
    except Exception as e:
        logger.error(f"Failed to get public key modulus: {type(e).__name__}: {e}")
        raise

    # Prepend sequence number (2 bytes)
    seq_bytes = sequence.to_bytes(SEQUENCE_BYTES, GLOBAL_BYTE_ORDER)
    message_with_seq = seq_bytes + message
    logger.debug(f"After prepend: len={len(message_with_seq)}")

    # Standard encryption with AES+RSA
    aes_key = os.urandom(AES_BLOCK_SIZE)
    iv = os.urandom(AES_BLOCK_SIZE)
    logger.debug("Generated AES key and IV")

    # Encrypt with AES-CBC
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    compressed_message = zlib.compress(message_with_seq)
    logger.debug(f"Compressed: {len(compressed_message)} bytes")
    padded_message = _pad_aes(compressed_message)
    logger.debug(f"Padded: {len(padded_message)} bytes")
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    logger.debug(f"AES encrypted: {len(ciphertext)} bytes")

    # Encrypt AES key with RSA
    logger.debug(f"Starting RSA encryption of AES key, key type: {type(public_key)}")
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    logger.debug(f"RSA encrypted AES key: {len(encrypted_aes_key)} bytes")

    result = iv + encrypted_aes_key + ciphertext
    logger.debug(f"Final payload: {len(result)} bytes")
    return result


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
    logger.debug(f"Attempting RSA decryption on {len(encrypted_payload)} bytes")

    # Debug: Show private key modulus (INFO level so it's always visible)
    priv_modulus = private_key.public_key().public_numbers().n
    logger.info(
        f"[QuiCC] Decrypting with private key modulus: {hex(priv_modulus)[:64]}..."
    )
    try:
        iv = encrypted_payload[:AES_BLOCK_SIZE]
        encrypted_aes_key = encrypted_payload[
            AES_BLOCK_SIZE : AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8
        ]
        ciphertext = encrypted_payload[AES_BLOCK_SIZE + RSA_BIT_STRENGTH // 8 :]

        logger.debug(
            f"Split: IV={len(iv)}, RSA_key={len(encrypted_aes_key)}, ciphertext={len(ciphertext)}"
        )

        # Decrypt AES key with RSA
        logger.debug("Starting RSA decryption...")
        decrypted_aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        logger.debug("RSA decryption successful")

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

        logger.debug(f"Decryption complete: seq={sequence}, msg_len={len(message)}")
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


def queue_message(
    host_ip,
    payload: bytes,
    queue,
    public_key,
    is_public_key=False,
    sequence=0,
    cid_length=MAX_CID_LENGTH,
):
    """
    Message queuing optimized for stealth and bandwidth.

    Features:
    - Uses maximum CID length (20 bytes) for bandwidth
    - Sequence numbers for tracking
    - Obfuscated public key exchange
    """
    cid_payloads = []

    if is_public_key:
        # Obfuscate modulus to hide odd number pattern
        logger.info(
            f"[QuiCC] Queuing public key for {host_ip}, original modulus: {int.from_bytes(payload, 'big'):x}..."
        )
        obfuscated_payload = obfuscate_modulus(payload)
        logger.debug(f"[QuiCC] After obfuscation: {obfuscated_payload[:32].hex()}...")

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
        # Encrypt with sequence number
        try:
            encrypted_payload = encrypt_with_sequence(public_key, payload, sequence)
        except Exception as e:
            logger.error(
                f"encrypt_with_sequence failed: {type(e).__name__}: {e}", exc_info=True
            )
            raise ValueError("Encryption failed") from e

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


def generate_sync_recovery_message() -> bytes:
    """
    Generate a sync recovery beacon message.

    Used to re-establish synchronization after disruption.
    """
    return b"SYNC_RECOVERY_" + struct.pack(">d", time.time())


def is_sync_recovery_message(message: bytes) -> bool:
    """Check if message is a sync recovery beacon."""
    return message.startswith(b"SYNC_RECOVERY_")
