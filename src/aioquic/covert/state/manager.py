"""Session management for covert channel"""

import logging
import threading
import time
from typing import Dict, List, Optional

from ..core.config import CovertConfig
from ..core.enums import CovertMessageType, CovertState
from ..core.types import CovertMessage, CovertSession
from ..crypto.exchange import KeyExchange
from ..crypto.keys import KeyManager
from ..protocol.encoder import CIDBuffer, CIDEncoder
from ..protocol.synchronizer import Synchronizer
from ..utils.stealth import StealthManager

logger = logging.getLogger(__name__)


class SessionManager:
    """Thread-safe manager for covert channel sessions"""

    def __init__(self, config: CovertConfig, is_client: bool = False):
        """Initialize session manager

        Args:
            config: Covert channel configuration
            is_client: Whether this is client-side
        """
        self.config = config
        self.is_client = is_client

        # Thread-safe session storage
        self._sessions: Dict[str, CovertSession] = {}
        self._lock = threading.RLock()

        # Message queues (peer_ip -> list of CIDs to send)
        self._outgoing_cids: Dict[str, List[bytes]] = {}

        # Stealth manager for anti-detection
        self.stealth = StealthManager(
            enable_timing_randomization=config.enable_timing_randomization,
            enable_entropy_mixing=True,
            enable_traffic_mimicry=config.enable_traffic_mimicry,
            timing_jitter_ms=config.timing_jitter_ms,
            decoy_ratio=config.decoy_traffic_ratio,
        )

        logger.info(
            "SessionManager initialized (client=%s, key_type=%s)",
            is_client,
            config.key_type.name,
        )

    def get_or_create_session(self, peer_address: str) -> CovertSession:
        """Get existing session or create new one

        Args:
            peer_address: Peer IP address

        Returns:
            CovertSession for the peer
        """
        with self._lock:
            if peer_address not in self._sessions:
                session = self._create_new_session(peer_address)
                self._sessions[peer_address] = session
                logger.info("Created new session for peer %s", peer_address)
            else:
                session = self._sessions[peer_address]
                session.update_activity()

            return session

    def _create_new_session(self, peer_address: str) -> CovertSession:
        """Create a new covert session

        Args:
            peer_address: Peer IP address

        Returns:
            New CovertSession
        """
        # Create key manager based on config
        key_type_map = {
            1: "rsa2048",  # RSA_2048
            2: "rsa4096",  # RSA_4096
            3: "ecc",  # ECC_CURVE25519
        }
        key_type = key_type_map.get(self.config.key_type, "ecc")
        key_manager = KeyManager(key_type=key_type)

        # Create session with components
        session = CovertSession(
            peer_address=peer_address,
            state=CovertState.IDLE,
            key_type=self.config.key_type,
            private_key=key_manager,
            send_window=self.config.sliding_window_size,
            recv_window=self.config.sliding_window_size,
        )

        # Initialize protocol components (stored in session metadata)
        session.metadata = {
            "key_manager": key_manager,
            "key_exchange": KeyExchange(key_manager, cid_chunk_size=16),
            "synchronizer": Synchronizer(
                window_size=self.config.sliding_window_size,
                retransmission_timeout=self.config.retransmission_timeout,
                max_retransmissions=self.config.max_retransmissions,
            ),
            "cid_encoder": CIDEncoder(
                cid_length=self.config.cid_max_length,
                chunk_size=self.config.chunk_size,
                use_ordering=True,
            ),
            "cid_buffer": CIDBuffer(max_buffer_size=100),
        }

        # Initialize outgoing CID queue
        self._outgoing_cids[peer_address] = []

        return session

    def queue_message(
        self, peer_address: str, message_type: CovertMessageType, payload: bytes
    ) -> bool:
        """Queue a message for sending

        Args:
            peer_address: Peer IP address
            message_type: Type of message
            payload: Message payload

        Returns:
            True if queued successfully
        """
        with self._lock:
            session = self.get_or_create_session(peer_address)

            # Check if session is ready
            if session.state not in (
                CovertState.READY,
                CovertState.KEY_EXCHANGE_COMPLETE,
            ):
                logger.warning(
                    "Cannot queue message for %s: session not ready (state=%s)",
                    peer_address,
                    session.state.value,
                )
                return False

            # Get components
            synchronizer = session.metadata["synchronizer"]
            cid_encoder = session.metadata["cid_encoder"]
            key_manager = session.metadata["key_manager"]

            # Prepare message with sequence number
            message = synchronizer.prepare_message(message_type, payload)
            if message is None:
                logger.warning("Send window full for %s, cannot queue", peer_address)
                return False

            # Encode to CIDs
            try:
                encryption_key, _, _ = key_manager.derive_session_keys()
                cids = cid_encoder.encode_message_to_cids(
                    message,
                    encryption_key,
                    compression_type=self.config.compression_type,
                )

                # Add to outgoing queue
                self._outgoing_cids[peer_address].extend(cids)

                session.messages_sent += 1
                session.bytes_sent += len(payload)
                session.update_activity()

                logger.debug(
                    "Queued message for %s: %d bytes -> %d CIDs",
                    peer_address,
                    len(payload),
                    len(cids),
                )

                return True

            except Exception as e:
                logger.error("Failed to encode message for %s: %s", peer_address, e)
                session.errors += 1
                return False

    def get_next_cid(self, peer_address: str) -> Optional[bytes]:
        """Get next CID to send for a peer

        Args:
            peer_address: Peer IP address

        Returns:
            Next CID to send, or None if queue is empty
        """
        # Apply timing randomization
        self.stealth.apply_timing_delay()

        # Maybe send decoy
        if self.stealth.should_send_decoy():
            return self.stealth.generate_decoy_cid()

        with self._lock:
            if peer_address not in self._outgoing_cids:
                return None

            queue = self._outgoing_cids[peer_address]
            if not queue:
                # Check for retransmissions or keep-alive
                session = self._sessions.get(peer_address)
                if session:
                    return self._get_control_cid(session)
                return None

            # Pop next CID from queue
            return queue.pop(0)

    def _get_control_cid(self, session: CovertSession) -> Optional[bytes]:
        """Get control CID (retransmission, ACK, keep-alive)

        Args:
            session: Covert session

        Returns:
            Control CID or None
        """
        synchronizer = session.metadata["synchronizer"]
        cid_encoder = session.metadata["cid_encoder"]
        key_manager = session.metadata["key_manager"]

        # Check for retransmissions
        retransmit_messages = synchronizer.get_retransmission_list()
        if retransmit_messages:
            message = retransmit_messages[0]
            try:
                encryption_key, _, _ = key_manager.derive_session_keys()
                cids = cid_encoder.encode_message_to_cids(
                    message,
                    encryption_key,
                    compression_type=self.config.compression_type,
                )
                if cids:
                    # Queue remaining CIDs
                    self._outgoing_cids[session.peer_address].extend(cids[1:])
                    session.retransmissions += 1
                    return cids[0]
            except Exception as e:
                logger.error("Failed to encode retransmission: %s", e)

        # Check if we need to send keep-alive
        if session.state == CovertState.READY:
            time_since_activity = time.time() - session.last_activity
            if time_since_activity > self.config.keep_alive_interval:
                # Queue keep-alive message
                keep_alive_msg = CovertMessage(
                    message_type=CovertMessageType.KEEP_ALIVE,
                    payload=b"",
                    sequence_number=0,
                )
                try:
                    encryption_key, _, _ = key_manager.derive_session_keys()
                    cids = cid_encoder.encode_message_to_cids(
                        keep_alive_msg,
                        encryption_key,
                        compression_type=self.config.compression_type,
                    )
                    if cids:
                        self._outgoing_cids[session.peer_address].extend(cids[1:])
                        session.update_activity()
                        return cids[0]
                except Exception as e:
                    logger.error("Failed to encode keep-alive: %s", e)

        return None

    def handle_received_cid(self, peer_address: str, cid: bytes) -> List[CovertMessage]:
        """Handle received CID

        Args:
            peer_address: Peer IP address
            cid: Received connection ID

        Returns:
            List of deliverable messages (may be empty)
        """
        with self._lock:
            session = self.get_or_create_session(peer_address)
            session.update_activity()

            # Handle based on session state
            if session.state == CovertState.IDLE:
                return self._handle_key_exchange_cid(session, cid)
            elif session.state in (
                CovertState.KEY_EXCHANGE_INIT,
                CovertState.KEY_EXCHANGE_PROGRESS,
            ):
                return self._handle_key_exchange_cid(session, cid)
            elif session.state in (
                CovertState.KEY_EXCHANGE_COMPLETE,
                CovertState.READY,
            ):
                return self._handle_data_cid(session, cid)
            else:
                logger.warning("Unexpected session state: %s", session.state.value)
                return []

    def _handle_key_exchange_cid(
        self, session: CovertSession, cid: bytes
    ) -> List[CovertMessage]:
        """Handle CID during key exchange

        Args:
            session: Covert session
            cid: Connection ID

        Returns:
            Empty list (no messages during key exchange)
        """
        key_exchange = session.metadata["key_exchange"]

        # Add CID to key exchange buffer
        is_complete = key_exchange.add_key_exchange_chunk(
            cid, invert=not self.is_client
        )

        if session.state == CovertState.IDLE:
            session.state = CovertState.KEY_EXCHANGE_INIT

        if not is_complete:
            session.state = CovertState.KEY_EXCHANGE_PROGRESS
            return []

        # Try to reconstruct peer key
        success = key_exchange.reconstruct_peer_key(invert=not self.is_client)
        if success:
            key_manager = session.metadata["key_manager"]
            session.peer_public_key = key_manager.peer_public_key
            session.shared_secret = key_manager.shared_secret
            session.state = CovertState.KEY_EXCHANGE_COMPLETE

            logger.info("Key exchange complete for %s", session.peer_address)

            # Send keep-alive to confirm
            self.queue_message(
                session.peer_address,
                CovertMessageType.KEEP_ALIVE,
                b"",
            )

            # Transition to READY
            session.state = CovertState.READY

        return []

    def _handle_data_cid(
        self, session: CovertSession, cid: bytes
    ) -> List[CovertMessage]:
        """Handle CID with data

        Args:
            session: Covert session
            cid: Connection ID

        Returns:
            List of deliverable messages
        """
        cid_buffer = session.metadata["cid_buffer"]
        cid_encoder = session.metadata["cid_encoder"]
        key_manager = session.metadata["key_manager"]
        synchronizer = session.metadata["synchronizer"]

        # Add to buffer
        cid_buffer.add_cid(cid)

        # Try to decode
        try:
            encryption_key, _, _ = key_manager.derive_session_keys()
            result = cid_buffer.try_decode(
                cid_encoder,
                encryption_key,
                compression_type=self.config.compression_type,
            )

            if result is None:
                return []

            message, cids_used = result

            # Handle message with synchronizer
            should_ack, deliverable_messages = synchronizer.handle_received_message(
                message
            )

            # Send ACK if needed
            if should_ack and message.message_type != CovertMessageType.KEEP_ALIVE:
                ack_msg = synchronizer.create_ack_message(message.sequence_number)
                try:
                    ack_cids = cid_encoder.encode_message_to_cids(
                        ack_msg,
                        encryption_key,
                        compression_type=self.config.compression_type,
                    )
                    self._outgoing_cids[session.peer_address].extend(ack_cids)
                except Exception as e:
                    logger.error("Failed to encode ACK: %s", e)

            # Update stats
            session.messages_received += len(deliverable_messages)
            for msg in deliverable_messages:
                session.bytes_received += len(msg.payload)

            return deliverable_messages

        except Exception as e:
            logger.error(
                "Failed to handle data CID for %s: %s", session.peer_address, e
            )
            session.errors += 1
            return []

    def prepare_key_exchange_cids(self, peer_address: str) -> List[bytes]:
        """Prepare CIDs for key exchange

        Args:
            peer_address: Peer IP address

        Returns:
            List of CIDs for key exchange
        """
        with self._lock:
            session = self.get_or_create_session(peer_address)
            key_exchange = session.metadata["key_exchange"]

            cids = key_exchange.prepare_key_exchange_cids(invert=self.is_client)
            session.state = CovertState.KEY_EXCHANGE_INIT

            logger.info(
                "Prepared %d CIDs for key exchange with %s",
                len(cids),
                peer_address,
            )

            return cids

    def get_session_stats(self, peer_address: str) -> Optional[dict]:
        """Get statistics for a session

        Args:
            peer_address: Peer IP address

        Returns:
            Statistics dictionary or None
        """
        with self._lock:
            session = self._sessions.get(peer_address)
            if not session:
                return None

            synchronizer = session.metadata["synchronizer"]
            sync_stats = synchronizer.get_stats()

            return {
                "peer_address": session.peer_address,
                "state": session.state.value,
                "messages_sent": session.messages_sent,
                "messages_received": session.messages_received,
                "bytes_sent": session.bytes_sent,
                "bytes_received": session.bytes_received,
                "errors": session.errors,
                "retransmissions": session.retransmissions,
                "last_activity": session.last_activity,
                "uptime": time.time() - session.created_at,
                "sync": sync_stats,
                "outgoing_queue_size": len(self._outgoing_cids.get(peer_address, [])),
            }

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions

        Returns:
            Number of sessions cleaned up
        """
        with self._lock:
            current_time = time.time()
            expired = []

            for peer_address, session in self._sessions.items():
                time_since_activity = current_time - session.last_activity
                if time_since_activity > self.config.session_timeout:
                    expired.append(peer_address)

            for peer_address in expired:
                del self._sessions[peer_address]
                if peer_address in self._outgoing_cids:
                    del self._outgoing_cids[peer_address]
                logger.info("Cleaned up expired session for %s", peer_address)

            return len(expired)

    def close_session(self, peer_address: str) -> None:
        """Close a session

        Args:
            peer_address: Peer IP address
        """
        with self._lock:
            if peer_address in self._sessions:
                session = self._sessions[peer_address]
                session.state = CovertState.CLOSED
                logger.info("Closed session for %s", peer_address)

    def get_all_sessions(self) -> List[str]:
        """Get list of all active peer addresses

        Returns:
            List of peer addresses
        """
        with self._lock:
            return list(self._sessions.keys())
