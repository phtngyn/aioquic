"""Stealth and anti-detection utilities for covert channel"""

import random
import secrets
import time
from typing import Optional


class TimingObfuscator:
    """Randomizes timing to avoid detection via traffic analysis"""

    def __init__(
        self,
        base_delay_ms: int = 0,
        jitter_ms: int = 100,
        enable_mimicry: bool = True,
    ):
        """Initialize timing obfuscator

        Args:
            base_delay_ms: Base delay in milliseconds
            jitter_ms: Maximum random jitter in milliseconds
            enable_mimicry: Enable traffic mimicry patterns
        """
        self.base_delay_ms = base_delay_ms
        self.jitter_ms = jitter_ms
        self.enable_mimicry = enable_mimicry
        self._last_send_time = 0.0

        # Mimicry patterns (simulating human/application behavior)
        self._patterns = [
            self._pattern_constant_rate,
            self._pattern_bursty,
            self._pattern_exponential_backoff,
        ]
        self._current_pattern = random.choice(self._patterns)

    def get_delay(self) -> float:
        """Get delay before next transmission

        Returns:
            Delay in seconds
        """
        if not self.enable_mimicry:
            # Simple random jitter
            delay_ms = self.base_delay_ms + random.randint(0, self.jitter_ms)
            return delay_ms / 1000.0

        # Use mimicry pattern
        return self._current_pattern()

    def _pattern_constant_rate(self) -> float:
        """Constant rate with small jitter"""
        delay_ms = self.base_delay_ms + random.randint(-10, 10)
        return max(0, delay_ms) / 1000.0

    def _pattern_bursty(self) -> float:
        """Bursty traffic pattern (fast bursts, then pause)"""
        if random.random() < 0.3:  # 30% chance of burst
            return random.uniform(0.001, 0.01)  # Fast (1-10ms)
        else:
            return random.uniform(0.1, 0.5)  # Slower (100-500ms)

    def _pattern_exponential_backoff(self) -> float:
        """Exponential backoff pattern"""
        current_time = time.time()
        time_since_last = current_time - self._last_send_time
        self._last_send_time = current_time

        # Increase delay exponentially, then reset
        if time_since_last < 0.1:
            return random.uniform(0.1, 0.2)
        elif time_since_last < 0.5:
            return random.uniform(0.2, 0.5)
        else:
            return random.uniform(0.01, 0.05)  # Reset

    def wait(self) -> None:
        """Sleep for calculated delay"""
        delay = self.get_delay()
        if delay > 0:
            time.sleep(delay)


class EntropyMixer:
    """Mixes data with high-entropy sources for statistical uniformity"""

    def __init__(self, mix_strength: float = 1.0):
        """Initialize entropy mixer

        Args:
            mix_strength: Mixing strength (0.0 = no mixing, 1.0 = full mixing)
        """
        self.mix_strength = min(1.0, max(0.0, mix_strength))

    def mix(self, data: bytes) -> tuple[bytes, bytes]:
        """Mix data with random entropy

        Args:
            data: Data to mix

        Returns:
            Tuple of (mixed_data, mixing_key)
        """
        if self.mix_strength == 0.0:
            return data, b""

        # Generate mixing key
        key_length = len(data)
        mixing_key = secrets.token_bytes(key_length)

        # Apply XOR mixing with strength control
        mixed_data = bytearray(data)
        for i in range(key_length):
            # Partial mixing based on strength
            if random.random() < self.mix_strength:
                mixed_data[i] ^= mixing_key[i]

        return bytes(mixed_data), mixing_key

    def unmix(self, mixed_data: bytes, mixing_key: bytes) -> bytes:
        """Unmix data using mixing key

        Args:
            mixed_data: Mixed data
            mixing_key: Mixing key used

        Returns:
            Original data
        """
        if not mixing_key:
            return mixed_data

        # XOR is reversible
        unmixed_data = bytearray(mixed_data)
        for i in range(min(len(mixed_data), len(mixing_key))):
            unmixed_data[i] ^= mixing_key[i]

        return bytes(unmixed_data)

    @staticmethod
    def whiten(data: bytes) -> bytes:
        """Apply whitening transformation for uniform distribution

        Args:
            data: Data to whiten

        Returns:
            Whitened data
        """
        # Simple whitening: XOR with rotated version of itself
        whitened = bytearray(data)
        data_len = len(data)

        for i in range(data_len):
            # XOR with byte at rotated position
            whitened[i] ^= data[(i + 1) % data_len]

        return bytes(whitened)


class RSAModulusPadding:
    """Adds even-padding to RSA modulus to defeat statistical analysis"""

    @staticmethod
    def pad_modulus_for_stealth(modulus_bytes: bytes) -> tuple[bytes, int]:
        """Pad RSA modulus to make it statistically indistinguishable

        RSA modulus N is always odd. This is detectable via statistical
        analysis. We pad with random even byte and mark position.

        Args:
            modulus_bytes: Original N modulus bytes

        Returns:
            Tuple of (padded_bytes, padding_position)
        """
        # Generate random even byte (LSB = 0)
        even_byte = secrets.randbits(7) << 1

        # Random position to insert (not at start/end to avoid detection)
        if len(modulus_bytes) > 2:
            position = random.randint(1, len(modulus_bytes) - 1)
        else:
            position = 0

        # Insert padding
        padded = bytearray(modulus_bytes)
        padded.insert(position, even_byte)

        return bytes(padded), position

    @staticmethod
    def remove_padding(padded_bytes: bytes, position: int) -> bytes:
        """Remove padding from modulus

        Args:
            padded_bytes: Padded modulus
            position: Position where padding was inserted

        Returns:
            Original modulus
        """
        unpadded = bytearray(padded_bytes)
        if 0 <= position < len(unpadded):
            unpadded.pop(position)
        return bytes(unpadded)


class TrafficMimicry:
    """Mimics legitimate traffic patterns"""

    def __init__(self, pattern_type: str = "http3"):
        """Initialize traffic mimicry

        Args:
            pattern_type: Type of traffic to mimic (http3, video, etc.)
        """
        self.pattern_type = pattern_type
        self._request_count = 0

    def should_send_decoy(self, decoy_ratio: float = 0.1) -> bool:
        """Determine if a decoy packet should be sent

        Args:
            decoy_ratio: Ratio of decoy traffic (0.0-1.0)

        Returns:
            True if decoy should be sent
        """
        return random.random() < decoy_ratio

    def generate_decoy_cid(self, length: int = 20) -> bytes:
        """Generate a decoy connection ID

        Args:
            length: CID length

        Returns:
            Random CID bytes
        """
        return secrets.token_bytes(length)

    def get_http3_pattern_delay(self) -> float:
        """Get delay that mimics HTTP/3 request pattern

        Returns:
            Delay in seconds
        """
        self._request_count += 1

        # Mimic browser request patterns
        if self._request_count == 1:
            # Initial request
            return 0.0
        elif self._request_count < 5:
            # Quick follow-up requests (CSS, JS, images)
            return random.uniform(0.01, 0.05)
        elif self._request_count < 10:
            # Secondary resources
            return random.uniform(0.1, 0.3)
        else:
            # Periodic updates
            self._request_count = 0
            return random.uniform(1.0, 5.0)

    def get_video_pattern_delay(self) -> float:
        """Get delay that mimics video streaming pattern

        Returns:
            Delay in seconds
        """
        # Mimic video chunk requests (typically every 2-6 seconds)
        return random.uniform(2.0, 6.0)


class StatisticalUniformity:
    """Ensures data has uniform statistical properties"""

    @staticmethod
    def test_uniformity(data: bytes) -> dict:
        """Test data for statistical uniformity

        Args:
            data: Data to test

        Returns:
            Dictionary with uniformity metrics
        """
        if not data:
            return {"uniform": True, "entropy": 0.0, "bias": 0.0}

        # Count byte frequencies
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1

        # Calculate entropy
        import math

        data_len = len(data)
        entropy = 0.0
        for count in freq:
            if count > 0:
                p = count / data_len
                entropy -= p * math.log2(p)

        # Perfect entropy is 8.0 bits (uniform distribution)
        entropy_ratio = entropy / 8.0

        # Calculate bias (deviation from uniform)
        expected_count = data_len / 256
        bias = sum(abs(count - expected_count) for count in freq) / data_len

        return {
            "uniform": entropy_ratio > 0.95,  # Consider uniform if > 95%
            "entropy": entropy,
            "entropy_ratio": entropy_ratio,
            "bias": bias,
        }

    @staticmethod
    def ensure_uniformity(data: bytes) -> bytes:
        """Ensure data has uniform distribution

        Args:
            data: Input data

        Returns:
            Data with uniform distribution
        """
        # Already encrypted data should be uniform
        # This is a placeholder for additional uniformity guarantees
        stats = StatisticalUniformity.test_uniformity(data)

        if stats["uniform"]:
            return data

        # If not uniform, XOR with high-entropy source
        uniform_data = secrets.token_bytes(len(data))
        return bytes(a ^ b for a, b in zip(data, uniform_data))


class StealthManager:
    """Manages all stealth features"""

    def __init__(
        self,
        enable_timing_randomization: bool = True,
        enable_entropy_mixing: bool = True,
        enable_traffic_mimicry: bool = True,
        timing_jitter_ms: int = 100,
        decoy_ratio: float = 0.0,
    ):
        """Initialize stealth manager

        Args:
            enable_timing_randomization: Enable timing obfuscation
            enable_entropy_mixing: Enable entropy mixing
            enable_traffic_mimicry: Enable traffic mimicry
            timing_jitter_ms: Timing jitter in milliseconds
            decoy_ratio: Ratio of decoy traffic
        """
        self.timing_obfuscator = (
            TimingObfuscator(
                jitter_ms=timing_jitter_ms, enable_mimicry=enable_traffic_mimicry
            )
            if enable_timing_randomization
            else None
        )

        self.entropy_mixer = EntropyMixer() if enable_entropy_mixing else None

        self.traffic_mimicry = TrafficMimicry() if enable_traffic_mimicry else None

        self.decoy_ratio = decoy_ratio

    def apply_timing_delay(self) -> None:
        """Apply timing randomization delay"""
        if self.timing_obfuscator:
            self.timing_obfuscator.wait()

    def should_send_decoy(self) -> bool:
        """Check if decoy should be sent"""
        if self.traffic_mimicry and self.decoy_ratio > 0:
            return self.traffic_mimicry.should_send_decoy(self.decoy_ratio)
        return False

    def generate_decoy_cid(self, length: int = 20) -> Optional[bytes]:
        """Generate decoy CID"""
        if self.traffic_mimicry:
            return self.traffic_mimicry.generate_decoy_cid(length)
        return None
