"""Tests for covert channel crypto module"""

import unittest

from aioquic.covert.core.enums import CovertKeyType
from aioquic.covert.crypto.cipher import CipherSuite, compress_data, decompress_data
from aioquic.covert.crypto.keys import ECCKeyPair, KeyManager, RSAKeyPair


class TestECCKeyPair(unittest.TestCase):
    """Test ECC key generation and exchange"""

    def test_key_generation(self):
        """Test ECC key pair generation"""
        key_pair = ECCKeyPair.generate()
        self.assertIsNotNone(key_pair.private_key)
        self.assertIsNotNone(key_pair.public_key)

        # Public key should be 32 bytes
        pub_bytes = key_pair.get_public_key_bytes()
        self.assertEqual(len(pub_bytes), 32)

    def test_shared_secret_derivation(self):
        """Test ECDH shared secret"""
        alice = ECCKeyPair.generate()
        bob = ECCKeyPair.generate()

        # Both derive same shared secret
        secret_a = alice.derive_shared_secret(bob.get_public_key_bytes())
        secret_b = bob.derive_shared_secret(alice.get_public_key_bytes())

        self.assertEqual(secret_a, secret_b)
        self.assertEqual(len(secret_a), 32)


class TestRSAKeyPair(unittest.TestCase):
    """Test RSA key generation"""

    def test_key_generation(self):
        """Test RSA key pair generation"""
        key_pair = RSAKeyPair.generate(key_size=2048)
        self.assertIsNotNone(key_pair.private_key)
        self.assertIsNotNone(key_pair.public_key)

        # Public key export
        pub_der = key_pair.get_public_key_der()
        self.assertGreater(len(pub_der), 0)

    def test_modulus_extraction(self):
        """Test RSA modulus extraction"""
        key_pair = RSAKeyPair.generate(key_size=2048)
        modulus = key_pair.get_public_key_modulus()

        # Should be 256 bytes for 2048-bit key
        self.assertEqual(len(modulus), 256)


class TestKeyManager(unittest.TestCase):
    """Test key manager"""

    def test_ecc_manager(self):
        """Test KeyManager with ECC"""
        manager = KeyManager(CovertKeyType.ECC_CURVE25519)
        self.assertEqual(manager.key_type, CovertKeyType.ECC_CURVE25519)
        self.assertIsInstance(manager.key_pair, ECCKeyPair)

    def test_rsa_manager(self):
        """Test KeyManager with RSA"""
        manager = KeyManager(CovertKeyType.RSA_2048)
        self.assertEqual(manager.key_type, CovertKeyType.RSA_2048)
        self.assertIsInstance(manager.key_pair, RSAKeyPair)

    def test_session_key_derivation(self):
        """Test session key derivation"""
        manager = KeyManager(CovertKeyType.ECC_CURVE25519)

        # Set shared secret
        peer = ECCKeyPair.generate()
        manager.set_peer_public_key(peer.get_public_key_bytes())

        # Derive session keys
        enc_key, mac_key, iv = manager.derive_session_keys()

        self.assertEqual(len(enc_key), 32)  # ChaCha20 key
        self.assertEqual(len(mac_key), 32)  # Poly1305 key
        self.assertEqual(len(iv), 12)  # Nonce


class TestCipherSuite(unittest.TestCase):
    """Test encryption/decryption"""

    def test_encrypt_decrypt(self):
        """Test ChaCha20-Poly1305 encryption"""
        plaintext = b"Secret message"
        key = b"0" * 32
        nonce = b"1" * 12

        cipher = CipherSuite(key)
        ciphertext = cipher.encrypt(plaintext, nonce)

        # Ciphertext should be longer (includes tag)
        self.assertGreater(len(ciphertext), len(plaintext))

        # Decrypt
        decrypted = cipher.decrypt(ciphertext, nonce)
        self.assertEqual(decrypted, plaintext)

    def test_invalid_key(self):
        """Test with invalid key length"""
        with self.assertRaises(ValueError):
            CipherSuite(b"short")


class TestCompression(unittest.TestCase):
    """Test compression utilities"""

    def test_zstd_compression(self):
        """Test zstandard compression"""
        data = b"A" * 1000  # Highly compressible

        compressed = compress_data(data, use_zstd=True)
        self.assertLess(len(compressed), len(data))

        decompressed = decompress_data(compressed, use_zstd=True)
        self.assertEqual(decompressed, data)

    def test_zlib_compression(self):
        """Test zlib compression"""
        data = b"B" * 1000

        compressed = compress_data(data, use_zstd=False)
        self.assertLess(len(compressed), len(data))

        decompressed = decompress_data(compressed, use_zstd=False)
        self.assertEqual(decompressed, data)


if __name__ == "__main__":
    unittest.main()
