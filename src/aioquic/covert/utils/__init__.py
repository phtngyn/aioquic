"""Utility functions for covert channel"""

import secrets
from typing import List


def generate_ordered_bytes(n: int, size: int = 4) -> List[bytes]:
    """Generate list of high-entropy ordered bytes

    Args:
        n: Number of ordered bytes to generate
        size: Size of each byte sequence

    Returns:
        Sorted list of n high-entropy bytes of length size
    """
    prefixes = set()
    while len(prefixes) < n:
        prefixes.add(secrets.token_bytes(size))
    return sorted(list(prefixes))


def chunks(data: bytes, size: int) -> List[bytes]:
    """Split data into chunks of given size

    Args:
        data: Data to chunk
        size: Size of each chunk

    Returns:
        List of chunks
    """
    return [data[i : i + size] for i in range(0, len(data), size)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences

    Args:
        a: First byte sequence
        b: Second byte sequence

    Returns:
        XOR result
    """
    return bytes(x ^ y for x, y in zip(a, b))


def pad_to_length(data: bytes, length: int, padding_byte: int = 0) -> bytes:
    """Pad data to specified length

    Args:
        data: Data to pad
        length: Target length
        padding_byte: Byte to use for padding

    Returns:
        Padded data
    """
    if len(data) >= length:
        return data
    return data + bytes([padding_byte] * (length - len(data)))


def entropy_mix(data: bytes, mix_key: bytes) -> bytes:
    """Mix data with high-entropy key for statistical uniformity

    Args:
        data: Data to mix
        mix_key: High-entropy mixing key

    Returns:
        Mixed data
    """
    # Extend mix_key to match data length if needed
    if len(mix_key) < len(data):
        mix_key = (mix_key * ((len(data) // len(mix_key)) + 1))[: len(data)]
    return xor_bytes(data, mix_key[: len(data)])
