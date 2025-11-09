"""Integration point for covert channel with QUIC connection"""

import logging
import os
from typing import Optional

from ..core.config import CovertConfig
from ..core.enums import CovertMessageType
from ..state.manager import SessionManager

logger = logging.getLogger(__name__)


class CovertChannelMixin:
    """Mixin to add covert channel capabilities to QuicConnection

    Usage:
        Add to QuicConnection.__init__:
            self._covert_enabled = configuration.covert_channel_enabled
            if self._covert_enabled:
                self._covert_manager = SessionManager(
                    config=configuration.covert_config,
                    is_client=self._is_client
                )
    """

    def _init_covert_channel(
        self,
        enabled: bool = False,
        config: Optional[CovertConfig] = None,
        is_client: bool = True,
    ) -> None:
        """Initialize covert channel

        Args:
            enabled: Whether covert channel is enabled
            config: Covert channel configuration
            is_client: Whether this is client side
        """
        self._covert_enabled = enabled
        self._covert_manager: Optional[SessionManager] = None

        if enabled:
            if config is None:
                config = CovertConfig()

            self._covert_manager = SessionManager(config=config, is_client=is_client)
            logger.info("Covert channel initialized (client=%s)", is_client)

    def covert_send_message(self, peer_address: str, message: str) -> bool:
        """Send a text message via covert channel

        Args:
            peer_address: Peer IP address
            message: Text message to send

        Returns:
            True if queued successfully
        """
        if not self._covert_enabled or self._covert_manager is None:
            logger.warning("Covert channel not enabled")
            return False

        payload = message.encode("utf-8")
        return self._covert_manager.queue_message(
            peer_address,
            CovertMessageType.TEXT,
            payload,
        )

    def covert_get_received_messages(self, peer_address: str) -> list[str]:
        """Get received covert messages (placeholder for event delivery)

        This is a placeholder - in practice, messages should be delivered
        via events through the normal QUIC event system.

        Args:
            peer_address: Peer IP address

        Returns:
            List of received messages
        """
        # In real implementation, messages would be delivered via events
        # This is just a helper for testing
        return []

    def covert_get_stats(self, peer_address: str) -> Optional[dict]:
        """Get covert channel statistics

        Args:
            peer_address: Peer IP address

        Returns:
            Statistics dictionary or None
        """
        if not self._covert_enabled or self._covert_manager is None:
            return None

        return self._covert_manager.get_session_stats(peer_address)

    def _covert_handle_received_cid(
        self, peer_address: str, connection_id: bytes
    ) -> None:
        """Handle received connection ID (covert channel extraction)

        Args:
            peer_address: Peer IP address
            connection_id: Received connection ID
        """
        if not self._covert_enabled or self._covert_manager is None:
            return

        # Process CID through covert channel
        messages = self._covert_manager.handle_received_cid(peer_address, connection_id)

        # Deliver messages as events
        for message in messages:
            if message.message_type == CovertMessageType.TEXT:
                # Create covert message event
                text = message.payload.decode("utf-8", errors="replace")
                logger.info("Covert message from %s: %s", peer_address, text)
                # TODO: Add to self._events queue with custom event type

    def _covert_get_next_cid(self, peer_address: str) -> Optional[bytes]:
        """Get next covert CID to send

        Args:
            peer_address: Peer IP address

        Returns:
            Connection ID bytes or None
        """
        if not self._covert_enabled or self._covert_manager is None:
            return None

        return self._covert_manager.get_next_cid(peer_address)

    def _covert_prepare_key_exchange(self, peer_address: str) -> list[bytes]:
        """Prepare CIDs for key exchange

        Args:
            peer_address: Peer IP address

        Returns:
            List of CIDs for key exchange
        """
        if not self._covert_enabled or self._covert_manager is None:
            return []

        return self._covert_manager.prepare_key_exchange_cids(peer_address)

    def covert_cleanup_sessions(self) -> int:
        """Cleanup expired covert sessions

        Returns:
            Number of sessions cleaned up
        """
        if not self._covert_enabled or self._covert_manager is None:
            return 0

        return self._covert_manager.cleanup_expired_sessions()


# Patch functions to integrate with QuicConnection


def patch_handle_new_connection_id_frame(original_method):
    """Decorator to patch _handle_new_connection_id_frame

    Usage:
        In connection.py, wrap the method:
        @patch_handle_new_connection_id_frame
        def _handle_new_connection_id_frame(self, context, frame_type, buf):
            ...
    """

    def wrapper(self, context, frame_type, buf):
        # Extract CID before processing
        current_pos = buf.tell()
        try:
            buf.pull_uint_var()  # sequence_number
            buf.pull_uint_var()  # retire_prior_to
            length = buf.pull_uint8()
            connection_id = buf.pull_bytes(length)

            # Process through covert channel
            peer_address = context.addr[0] if hasattr(context, "addr") else None
            if peer_address and hasattr(self, "_covert_handle_received_cid"):
                self._covert_handle_received_cid(peer_address, connection_id)

        except Exception as e:
            logger.debug("Covert channel extraction failed: %s", e)
        finally:
            # Reset buffer position for original processing
            buf.seek(current_pos)

        # Call original method
        return original_method(self, context, frame_type, buf)

    return wrapper


def patch_replenish_connection_ids(original_method):
    """Decorator to patch _replenish_connection_ids

    Usage:
        In connection.py, wrap the method:
        @patch_replenish_connection_ids
        def _replenish_connection_ids(self):
            ...
    """

    def wrapper(self, peer_address: Optional[str] = None):
        # Try to get covert CID first
        covert_cid = None
        if peer_address and hasattr(self, "_covert_get_next_cid"):
            covert_cid = self._covert_get_next_cid(peer_address)

        if covert_cid:
            # Use covert CID instead of random
            # Note: QuicConnectionId import happens at runtime from quic.packet
            from ...quic.packet import QuicConnectionId

            self._host_cids.append(
                QuicConnectionId(
                    cid=covert_cid,
                    sequence_number=self._host_cid_seq,
                    stateless_reset_token=os.urandom(16),
                )
            )
            self._host_cid_seq += 1
            logger.debug("Added covert CID (seq=%d)", self._host_cid_seq - 1)
        else:
            # Call original method to add normal CIDs
            return original_method(self)

    return wrapper
