"""
Test suite for ccrypto.py covert channel crypto functions.

Run with: uv run python ccrypto_test.py
"""

import sys

sys.path.insert(0, "../src")

from queue import Queue

from aioquic.quic.ccrypto import (
    deobfuscate_modulus,
    encrypt,
    encrypt_with_sequence,
    generate_ordered_bytes,
    generate_rsa,
    generate_rsa_public_key,
    get_compact_key,
    obfuscate_modulus,
    queue_message,
    reconstruct_payload,
    try_decrypt,
    try_decrypt_with_sequence,
)


def test_obfuscation_reversibility():
    """Test that obfuscation is reversible."""
    print("Testing obfuscation reversibility...")

    # Generate test key
    private_key = generate_rsa()
    original_bytes = get_compact_key(private_key)

    # Test obfuscation
    obfuscated = obfuscate_modulus(original_bytes)
    deobfuscated = deobfuscate_modulus(obfuscated)

    assert len(obfuscated) == len(original_bytes), "Obfuscated length mismatch"
    assert deobfuscated == original_bytes, (
        "Deobfuscation failed - doesn't match original"
    )

    print(f"  ✓ Original length: {len(original_bytes)} bytes")
    print("  ✓ Obfuscation/deobfuscation reversible")


def test_obfuscation_hides_parity():
    """Test that obfuscation changes odd/even distribution."""
    print("\nTesting obfuscation parity hiding...")

    odd_count_original = 0
    odd_count_obfuscated = 0
    num_tests = 10

    for _ in range(num_tests):
        private_key = generate_rsa()
        original_bytes = get_compact_key(private_key)
        obfuscated = obfuscate_modulus(original_bytes)

        # RSA moduli are always odd
        if original_bytes[-1] % 2 == 1:
            odd_count_original += 1
        if obfuscated[-1] % 2 == 1:
            odd_count_obfuscated += 1

    print(
        f"  ✓ Original odd count: {odd_count_original}/{num_tests} (should be {num_tests})"
    )
    print(
        f"  ✓ Obfuscated odd count: {odd_count_obfuscated}/{num_tests} (should be ~{num_tests // 2})"
    )

    # Original should always be odd (RSA property)
    assert odd_count_original == num_tests, "RSA moduli should always be odd"

    # Obfuscated should be roughly 50/50 (not 100% odd)
    assert odd_count_obfuscated < num_tests, "Obfuscation should change parity"


def test_key_reconstruction():
    """Test that obfuscated key can be reconstructed into valid RSA public key."""
    print("\nTesting key reconstruction...")

    private_key = generate_rsa()
    original_bytes = get_compact_key(private_key)

    # Obfuscate and deobfuscate
    obfuscated = obfuscate_modulus(original_bytes)
    deobfuscated = deobfuscate_modulus(obfuscated)

    # Reconstruct public key
    try:
        reconstructed_key = generate_rsa_public_key(deobfuscated)
        print("  ✓ Key reconstruction successful")
        print(f"  ✓ Key type: {type(reconstructed_key).__name__}")
    except Exception as e:
        raise AssertionError(f"Key reconstruction failed: {e}")


def test_encryption_decryption():
    """Test basic encryption/decryption without sequence."""
    print("\nTesting encryption/decryption...")

    # Generate keys
    receiver_key = generate_rsa()
    receiver_public = receiver_key.public_key()

    # Test message
    message = b"Hello, this is a secret covert message!"

    # Encrypt
    encrypted = encrypt(receiver_public, message)
    print(f"  ✓ Encrypted {len(message)} bytes to {len(encrypted)} bytes")

    # Create buffer with chunks
    chunk_size = 16
    chunks = [
        encrypted[i : i + chunk_size] for i in range(0, len(encrypted), chunk_size)
    ]

    # Add ordering bytes
    ordered = [
        b + order for b, order in zip(generate_ordered_bytes(len(chunks)), chunks)
    ]

    # Decrypt
    decrypted = try_decrypt(receiver_key, ordered)

    assert decrypted is not None, "Decryption failed"
    assert decrypted == message, "Decrypted message doesn't match original"
    print(f"  ✓ Decrypted successfully: {decrypted[:20]}...")


def test_encryption_with_sequence():
    """Test encryption/decryption with sequence numbers."""
    print("\nTesting encryption with sequence...")

    # Generate keys
    receiver_key = generate_rsa()
    receiver_public = receiver_key.public_key()

    # Test message
    message = b"Message with sequence"
    sequence = 42

    # Encrypt with sequence
    encrypted = encrypt_with_sequence(receiver_public, message, sequence)
    print(f"  ✓ Encrypted with sequence {sequence}")

    # Create buffer with chunks
    chunk_size = 16
    chunks = [
        encrypted[i : i + chunk_size] for i in range(0, len(encrypted), chunk_size)
    ]
    ordered = [
        b + order for b, order in zip(generate_ordered_bytes(len(chunks)), chunks)
    ]

    # Decrypt with sequence
    result = try_decrypt_with_sequence(receiver_key, ordered)

    assert result is not None, "Decryption with sequence failed"
    decrypted_msg, decrypted_seq = result
    assert decrypted_msg == message, "Decrypted message doesn't match"
    assert decrypted_seq == sequence, (
        f"Sequence mismatch: {decrypted_seq} != {sequence}"
    )
    print(f"  ✓ Decrypted with correct sequence: {decrypted_seq}")


def test_queue_message_public_key():
    """Test queueing public key with obfuscation."""
    print("\nTesting queue_message for public key...")

    private_key = generate_rsa()
    key_bytes = get_compact_key(private_key)
    queue = Queue()

    # Queue the public key
    count = queue_message(
        host_ip="::1",
        payload=key_bytes,
        queue=queue,
        public_key=None,
        is_public_key=True,
    )

    print(f"  ✓ Queued {count} CID chunks")
    assert count > 0, "Should queue at least 1 chunk"
    assert queue.qsize() == count, "Queue size mismatch"

    # Collect chunks
    chunks = []
    while not queue.empty():
        chunks.append(queue.get())

    # Each chunk should be 20 bytes (16 data + 4 order)
    assert all(len(c) == 20 for c in chunks), "CID chunks should be 20 bytes"
    print(f"  ✓ All {len(chunks)} chunks are 20 bytes")


def test_queue_message_encrypted():
    """Test queueing encrypted message."""
    print("\nTesting queue_message for encrypted payload...")

    # Generate keys
    receiver_key = generate_rsa()
    receiver_public = receiver_key.public_key()

    message = b"Test encrypted message"
    queue = Queue()

    # Queue encrypted message
    count = queue_message(
        host_ip="::1",
        payload=message,
        queue=queue,
        public_key=receiver_public,
        is_public_key=False,
    )

    print(f"  ✓ Queued {count} encrypted CID chunks")
    assert count > 0, "Should queue at least 1 chunk"


def test_ordered_bytes_uniqueness():
    """Test that ordered bytes are unique and properly sized."""
    print("\nTesting ordered bytes generation...")

    n = 50
    ordered = generate_ordered_bytes(n, size=4)

    assert len(ordered) == n, f"Should generate {n} ordered bytes"
    assert len(set(ordered)) == n, "All ordered bytes should be unique"
    assert all(len(b) == 4 for b in ordered), "All bytes should be size 4"
    assert ordered == sorted(ordered), "Bytes should be sorted"
    print(f"  ✓ Generated {n} unique, sorted 4-byte sequences")


def test_reconstruct_payload():
    """Test payload reconstruction from CID chunks."""
    print("\nTesting payload reconstruction...")

    # Create test payload
    original = b"A" * 100
    chunk_size = 16

    # Split into chunks with ordering
    chunks = [original[i : i + chunk_size] for i in range(0, len(original), chunk_size)]
    ordered_bytes = generate_ordered_bytes(len(chunks))

    # Add ordering at start (normal message mode)
    buffer = [order + chunk for order, chunk in zip(ordered_bytes, chunks)]

    # Shuffle to simulate out-of-order arrival
    from random import shuffle as random_shuffle

    random_shuffle(buffer)

    # Reconstruct
    reconstructed = reconstruct_payload(buffer, invert=False)

    assert reconstructed == original, "Reconstructed payload doesn't match original"
    print(f"  ✓ Reconstructed {len(original)} bytes correctly from shuffled chunks")

    # Test invert mode (for public keys)
    buffer_inverted = [chunk + order for chunk, order in zip(chunks, ordered_bytes)]
    random_shuffle(buffer_inverted)

    reconstructed_inverted = reconstruct_payload(buffer_inverted, invert=True)
    assert reconstructed_inverted == original, "Inverted reconstruction failed"
    print("  ✓ Inverted reconstruction also works correctly")


def test_end_to_end_key_exchange():
    """Test complete key exchange with obfuscation."""
    print("\nTesting end-to-end key exchange...")

    # Client generates key
    client_private = generate_rsa()
    client_public_bytes = get_compact_key(client_private)

    # Client obfuscates and queues
    queue = Queue()
    count = queue_message(
        host_ip="::1",
        payload=client_public_bytes,
        queue=queue,
        public_key=None,
        is_public_key=True,
    )

    print(f"  ✓ Client queued {count} chunks")

    # Server receives chunks (simulate with dummy CID at end)
    buffer = []
    while not queue.empty():
        buffer.append(queue.get())
    buffer.append(b"\x00" * 20)  # Dummy CID

    # Server reconstructs and deobfuscates
    obfuscated_bytes = reconstruct_payload(buffer[:-1], invert=True)
    deobfuscated_bytes = deobfuscate_modulus(obfuscated_bytes)

    # Server constructs public key
    server_view_client_public = generate_rsa_public_key(deobfuscated_bytes)

    print("  ✓ Server reconstructed client's public key")

    # Test encryption with reconstructed key
    test_message = b"Hello from server!"
    encrypted = encrypt(server_view_client_public, test_message)

    # Client decrypts
    chunk_size = 16
    chunks = [
        encrypted[i : i + chunk_size] for i in range(0, len(encrypted), chunk_size)
    ]
    ordered = [o + c for o, c in zip(generate_ordered_bytes(len(chunks)), chunks)]

    decrypted = try_decrypt(client_private, ordered)

    assert decrypted == test_message, "End-to-end encryption failed"
    print(f"  ✓ End-to-end encryption successful: {decrypted}")


def run_all_tests():
    """Run all tests."""
    print("=" * 60)
    print("CCRYPTO TEST SUITE")
    print("=" * 60)

    tests = [
        test_obfuscation_reversibility,
        test_obfuscation_hides_parity,
        test_key_reconstruction,
        test_encryption_decryption,
        test_encryption_with_sequence,
        test_queue_message_public_key,
        test_queue_message_encrypted,
        test_ordered_bytes_uniqueness,
        test_reconstruct_payload,
        test_end_to_end_key_exchange,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            failed += 1
            print(f"\n  ✗ FAILED: {e}")
            import traceback

            traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 60)

    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
