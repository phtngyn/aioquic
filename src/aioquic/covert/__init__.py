"""
QUIC Covert Channel Implementation

Advanced covert channel using QUIC connection IDs with improved:
- Cryptography (ECC Curve25519 + ChaCha20-Poly1305)
- Synchronization (ACK/NACK + retransmission protocol)
- Stealth (statistical uniformity, traffic mimicry)
- Reliability (sliding window, flow control)

Quick Start:
    from aioquic.covert.core.config import CovertConfig
    from aioquic.covert.core.enums import CovertKeyType
    from aioquic.covert.state.manager import SessionManager

    # Create config
    config = CovertConfig(key_type=CovertKeyType.ECC_CURVE25519)

    # Create session manager
    manager = SessionManager(config=config, is_client=True)

    # Queue message
    manager.queue_message(peer_ip, CovertMessageType.TEXT, b"secret")

    # Get CID to send
    cid = manager.get_next_cid(peer_ip)

    # Handle received CID
    messages = manager.handle_received_cid(peer_ip, received_cid)
"""

__version__ = "0.1.0"

# Export main components for easy access
from .core.config import CovertConfig
from .core.enums import CovertKeyType, CovertMessageType, CovertState
from .state.manager import SessionManager

__all__ = [
    "CovertConfig",
    "CovertKeyType",
    "CovertMessageType",
    "CovertState",
    "SessionManager",
]
