"""Key management for covert channel cryptography"""

import secrets
from dataclasses import dataclass
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
RSA_BIT_STRENGTH_2048 = 2048
RSA_BIT_STRENGTH_4096 = 4096
RSA_PUBLIC_EXPONENT = 65537
ECC_CURVE25519_KEY_SIZE = 32
GLOBAL_BYTE_ORDER = "big"


@dataclass
class ECCKeyPair:
    """ECC (Curve25519) key pair"""

    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey

    @classmethod
    def generate(cls) -> "ECCKeyPair":
        """Generate new ECC key pair"""
        private_key = x25519.X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key)

    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes (32 bytes)"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def from_public_key_bytes(cls, public_key_bytes: bytes) -> x25519.X25519PublicKey:
        """Load public key from bytes"""
        return x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

    def derive_shared_secret(self, peer_public_key: x25519.X25519PublicKey) -> bytes:
        """Derive shared secret using ECDH"""
        return self.private_key.exchange(peer_public_key)


@dataclass
class RSAKeyPair:
    """RSA key pair"""

    private_key: rsa.RSAPrivateKey
    public_key: rsa.RSAPublicKey
    bit_strength: int

    @classmethod
    def generate(cls, bits: int = RSA_BIT_STRENGTH_4096) -> "RSAKeyPair":
        """Generate new RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=RSA_PUBLIC_EXPONENT,
            key_size=bits,
        )
        public_key = private_key.public_key()
        return cls(private_key=private_key, public_key=public_key, bit_strength=bits)

    def get_public_key_modulus(self) -> bytes:
        """Get N modulus as bytes (for key exchange via CIDs)"""
        n = self.public_key.public_numbers().n
        return n.to_bytes(self.bit_strength // 8, byteorder=GLOBAL_BYTE_ORDER)

    @classmethod
    def from_public_key_modulus(
        cls, modulus_bytes: bytes, bit_strength: int = RSA_BIT_STRENGTH_4096
    ) -> rsa.RSAPublicKey:
        """Reconstruct public key from modulus bytes"""
        n = int.from_bytes(modulus_bytes, GLOBAL_BYTE_ORDER)
        public_key = rsa.RSAPublicNumbers(
            e=RSA_PUBLIC_EXPONENT,
            n=n,
        ).public_key()
        return public_key


class KeyManager:
    """Manages cryptographic keys for covert channel"""

    def __init__(self, key_type: str = "ecc"):
        """Initialize key manager

        Args:
            key_type: Either 'ecc', 'rsa2048', or 'rsa4096'
        """
        self.key_type = key_type
        self.ecc_keypair: Optional[ECCKeyPair] = None
        self.rsa_keypair: Optional[RSAKeyPair] = None
        self.peer_public_key: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None

        # Generate keys based on type
        if key_type == "ecc":
            self.ecc_keypair = ECCKeyPair.generate()
        elif key_type == "rsa2048":
            self.rsa_keypair = RSAKeyPair.generate(bits=RSA_BIT_STRENGTH_2048)
        elif key_type == "rsa4096":
            self.rsa_keypair = RSAKeyPair.generate(bits=RSA_BIT_STRENGTH_4096)
        else:
            msg = f"Unknown key type: {key_type}"
            raise ValueError(msg)

    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes for exchange"""
        if self.key_type == "ecc":
            return self.ecc_keypair.get_public_key_bytes()
        else:
            return self.rsa_keypair.get_public_key_modulus()

    def set_peer_public_key(self, peer_key_bytes: bytes) -> None:
        """Set peer's public key from bytes"""
        self.peer_public_key = peer_key_bytes

        # For ECC, derive shared secret immediately
        if self.key_type == "ecc":
            peer_pub = ECCKeyPair.from_public_key_bytes(peer_key_bytes)
            self.shared_secret = self.ecc_keypair.derive_shared_secret(peer_pub)

    def derive_session_keys(
        self, salt: Optional[bytes] = None
    ) -> Tuple[bytes, bytes, bytes]:
        """Derive encryption, MAC, and nonce keys from shared secret

        Args:
            salt: Optional salt for HKDF

        Returns:
            Tuple of (encryption_key, mac_key, nonce_key)
        """
        if self.shared_secret is None:
            msg = "Shared secret not established"
            raise ValueError(msg)

        if salt is None:
            salt = secrets.token_bytes(32)

        # Derive 96 bytes total: 32 for encryption, 32 for MAC, 32 for nonce
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=96,
            salt=salt,
            info=b"covert-channel-session-keys",
        )
        key_material = hkdf.derive(self.shared_secret)

        encryption_key = key_material[:32]
        mac_key = key_material[32:64]
        nonce_key = key_material[64:96]

        return encryption_key, mac_key, nonce_key

    def get_key_exchange_size(self) -> int:
        """Get size of public key for exchange"""
        if self.key_type == "ecc":
            return ECC_CURVE25519_KEY_SIZE
        elif self.key_type == "rsa2048":
            return RSA_BIT_STRENGTH_2048 // 8
        else:  # rsa4096
            return RSA_BIT_STRENGTH_4096 // 8
