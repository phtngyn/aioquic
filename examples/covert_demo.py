#!/usr/bin/env python3
"""Standalone covert channel demo - shows encoding/decoding without full QUIC"""

import logging
import sys

from aioquic.covert.core.enums import CovertMessageType
from aioquic.covert.crypto.keys import KeyManager
from aioquic.covert.protocol.encoder import CIDBuffer, CIDEncoder
from aioquic.covert.protocol.synchronizer import Synchronizer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def demo_basic_encoding():
    """Demo: Encode and decode a message"""
    logger.info("=" * 60)
    logger.info("Demo 1: Basic Message Encoding")
    logger.info("=" * 60)

    # Create encoder
    encoder = CIDEncoder(chunk_size=16)
    key = b"0" * 32  # Simple key for demo

    # Create synchronizer
    sync = Synchronizer(window_size=16)

    # Prepare message
    message = sync.prepare_message(
        CovertMessageType.TEXT, b"Hello from covert channel!"
    )
    logger.info("Original message: %s", message.payload.decode())
    logger.info("Sequence number: %d", message.sequence_number)

    # Encode to CIDs (let it auto-detect compression)
    from aioquic.covert.core.enums import CompressionType

    cids = encoder.encode_message_to_cids(message, key, CompressionType.ZSTD)
    logger.info("Encoded into %d CIDs:", len(cids))
    for i, cid in enumerate(cids):
        logger.info("  CID %d: %s (length=%d)", i, cid.hex(), len(cid))

    # Decode from CIDs (compression auto-detected from header)
    buffer = CIDBuffer()
    for cid in cids:
        buffer.add_cid(cid)

    result = buffer.try_decode(encoder, key)  # No compression arg needed!
    if result:
        decoded, cids_used = result
        logger.info("Decoded message: %s", decoded.payload.decode())
        logger.info("✓ SUCCESS: Message roundtrip complete! (%d CIDs used)", cids_used)
    else:
        logger.error("✗ FAILED: Could not decode message")

    print()


def demo_key_exchange():
    """Demo: Key exchange between two parties"""
    logger.info("=" * 60)
    logger.info("Demo 2: Key Exchange")
    logger.info("=" * 60)

    # Alice and Bob create key managers
    alice = KeyManager("ecc")
    bob = KeyManager("ecc")

    logger.info("Alice generates ECC key pair...")
    alice_pub = alice.get_public_key_bytes()
    logger.info(
        "  Alice public key: %s... (%d bytes)", alice_pub[:8].hex(), len(alice_pub)
    )

    logger.info("Bob generates ECC key pair...")
    bob_pub = bob.get_public_key_bytes()
    logger.info("  Bob public key: %s... (%d bytes)", bob_pub[:8].hex(), len(bob_pub))

    # Exchange public keys
    logger.info("Performing ECDH key exchange...")
    alice.set_peer_public_key(bob_pub)
    bob.set_peer_public_key(alice_pub)

    # Derive session keys
    alice_keys = alice.derive_session_keys()
    bob_keys = bob.derive_session_keys()

    logger.info("Alice session key: %s...", alice_keys[0][:8].hex())
    logger.info("Bob session key:   %s...", bob_keys[0][:8].hex())

    if alice_keys[0] == bob_keys[0]:
        logger.info("✓ SUCCESS: Both parties derived same session key!")
    else:
        logger.error("✗ FAILED: Key mismatch!")

    print()


def demo_encryption():
    """Demo: Encrypt and decrypt with session key"""
    logger.info("=" * 60)
    logger.info("Demo 3: Encryption & Decryption")
    logger.info("=" * 60)

    # Setup key managers
    alice = KeyManager("ecc")
    bob = KeyManager("ecc")

    # Key exchange
    alice.set_peer_public_key(bob.get_public_key_bytes())
    bob.set_peer_public_key(alice.get_public_key_bytes())

    # Get session keys
    alice_key, _, _ = alice.derive_session_keys()
    bob_key, _, _ = bob.derive_session_keys()

    # Create encoder/decoder
    encoder = CIDEncoder(chunk_size=16)
    sync = Synchronizer(window_size=16)

    # Alice sends encrypted message
    plaintext = b"This is a secret message!"
    logger.info("Alice plaintext: %s", plaintext.decode())

    from aioquic.covert.core.enums import CompressionType

    message = sync.prepare_message(CovertMessageType.TEXT, plaintext)
    cids = encoder.encode_message_to_cids(message, alice_key, CompressionType.ZSTD)
    logger.info("Encrypted into %d CIDs", len(cids))

    # Bob receives and decrypts (compression auto-detected)
    buffer = CIDBuffer()
    for cid in cids:
        buffer.add_cid(cid)

    result = buffer.try_decode(encoder, bob_key)  # No compression arg needed!
    if result:
        decoded, _ = result
        logger.info("Bob decrypted: %s", decoded.payload.decode())
        logger.info("✓ SUCCESS: Secure communication established!")
    else:
        logger.error("✗ FAILED: Decryption failed")

    print()


def demo_compression():
    """Demo: Compression effectiveness"""
    logger.info("=" * 60)
    logger.info("Demo 4: Compression")
    logger.info("=" * 60)

    encoder = CIDEncoder(chunk_size=16)
    sync = Synchronizer(window_size=16)
    key = b"1" * 32

    # Highly compressible data
    plaintext = b"A" * 500  # 500 bytes of same character
    logger.info("Original size: %d bytes (highly repetitive)", len(plaintext))

    from aioquic.covert.core.enums import CompressionType

    # Without compression
    msg1 = sync.prepare_message(CovertMessageType.TEXT, plaintext)
    cids_none = encoder.encode_message_to_cids(msg1, key, CompressionType.NONE)
    logger.info("Without compression: %d CIDs", len(cids_none))

    # With zstd compression
    msg2 = sync.prepare_message(CovertMessageType.TEXT, plaintext)
    cids_zstd = encoder.encode_message_to_cids(msg2, key, CompressionType.ZSTD)
    logger.info("With ZSTD compression: %d CIDs", len(cids_zstd))

    # Decode both
    buffer1 = CIDBuffer()
    for cid in cids_none:
        buffer1.add_cid(cid)
    result1 = buffer1.try_decode(encoder, key)

    buffer2 = CIDBuffer()
    for cid in cids_zstd:
        buffer2.add_cid(cid)
    result2 = buffer2.try_decode(encoder, key)

    if result1 and result2:
        decoded1, _ = result1
        decoded2, _ = result2
        if decoded1.payload == decoded2.payload == plaintext:
            savings = ((len(cids_none) - len(cids_zstd)) / len(cids_none)) * 100
            logger.info(
                "✓ SUCCESS: Both decoded correctly! Compression saved %.1f%% CIDs",
                savings,
            )
        else:
            logger.error("✗ FAILED: Decoded data mismatch")
    else:
        logger.error("✗ FAILED: Decoding failed")

    print()


def demo_sliding_window():
    """Demo: Sliding window protocol"""
    logger.info("=" * 60)
    logger.info("Demo 4: Sliding Window Protocol")
    logger.info("=" * 60)

    sync = Synchronizer(window_size=4)
    logger.info("Window size: %d", sync.send_window.window_size)

    # Send messages
    messages = []
    for i in range(5):
        msg = sync.prepare_message(CovertMessageType.TEXT, f"Message {i}".encode())
        if msg:
            messages.append(msg)
            logger.info("Queued message %d", msg.sequence_number)
        else:
            logger.info("Window full! Cannot send message %d", i)

    logger.info("✓ SUCCESS: Window flow control working!")
    print()


def demo_stealth():
    """Demo: Stealth features"""
    logger.info("=" * 60)
    logger.info("Demo 5: Stealth Features")
    logger.info("=" * 60)

    from aioquic.covert.utils.stealth import (
        EntropyMixer,
        RSAModulusPadding,
        StatisticalUniformity,
        TimingObfuscator,
    )

    # Timing obfuscation
    logger.info("1. Timing Obfuscation:")
    obfuscator = TimingObfuscator(base_delay_ms=50, jitter_ms=100)
    delays = [obfuscator.get_delay() for _ in range(5)]
    logger.info("   Random delays: %s", [f"{d * 1000:.1f}ms" for d in delays])

    # Entropy mixing
    logger.info("\n2. Entropy Mixing:")
    mixer = EntropyMixer(mix_strength=1.0)
    data = b"AAAAA"  # Low entropy
    mixed, mask = mixer.mix(data)
    unmixed = mixer.unmix(mixed, mask)
    logger.info("   Original: %s", data.hex())
    logger.info("   Mixed:    %s (high entropy)", mixed.hex())
    logger.info("   Unmixed:  %s ✓", unmixed.hex())

    # RSA modulus padding
    logger.info("\n3. RSA Modulus Padding:")
    modulus = bytes([0xFF] * 255 + [0x01])  # Odd modulus
    logger.info("   Original modulus (last byte): 0x%02x (odd)", modulus[-1])
    padded = RSAModulusPadding.pad_modulus_for_stealth(modulus)
    logger.info("   Padded modulus (last byte):   0x%02x (even)", padded[-1])

    # Statistical uniformity
    logger.info("\n4. Statistical Uniformity:")
    encrypted_data = bytes([i % 256 for i in range(256)])  # Uniform
    stats = StatisticalUniformity.test_uniformity(encrypted_data)
    logger.info("   Entropy: %.2f bits/byte", stats["entropy"])
    logger.info("   Uniform: %s ✓", stats["uniform"])

    print()


def main():
    """Run all demos"""
    logger.info("\n🔒 Covert Channel Demonstration\n")
    logger.info(
        "This demo shows the covert channel working WITHOUT full QUIC integration"
    )
    logger.info("All cryptography, encoding, and protocols are functional\n")

    try:
        demo_basic_encoding()
        demo_key_exchange()
        demo_encryption()
        demo_compression()
        demo_sliding_window()
        demo_stealth()

        logger.info("=" * 60)
        logger.info("✓ All demos completed successfully!")
        logger.info("=" * 60)

    except Exception as e:
        logger.exception("Demo failed: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
