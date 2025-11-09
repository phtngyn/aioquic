"""Synchronization protocol for reliable covert channel communication"""

import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ..core.enums import CovertMessageType
from ..core.types import CovertMessage

logger = logging.getLogger(__name__)


@dataclass
class PacketInfo:
    """Information about a sent packet for retransmission"""

    message: CovertMessage
    sent_time: float
    retransmit_count: int = 0
    acked: bool = False


@dataclass
class SlidingWindow:
    """Sliding window for flow control"""

    window_size: int = 16
    base_sequence: int = 0  # Oldest unacknowledged sequence number
    next_sequence: int = 0  # Next sequence number to use
    acked: Set[int] = field(default_factory=set)
    sent_packets: Dict[int, PacketInfo] = field(default_factory=dict)

    def can_send(self) -> bool:
        """Check if we can send more packets within window"""
        unacked_count = self.next_sequence - self.base_sequence
        return unacked_count < self.window_size

    def get_next_sequence(self) -> int:
        """Get next sequence number"""
        if not self.can_send():
            return -1
        seq = self.next_sequence
        self.next_sequence = (self.next_sequence + 1) & 0xFFFFFFFF
        return seq

    def mark_sent(self, seq: int, message: CovertMessage) -> None:
        """Mark packet as sent"""
        self.sent_packets[seq] = PacketInfo(
            message=message,
            sent_time=time.time(),
            retransmit_count=0,
            acked=False,
        )

    def mark_acked(self, seq: int) -> bool:
        """Mark packet as acknowledged

        Returns:
            True if this was a new ACK, False if already acked
        """
        if seq in self.acked:
            return False

        self.acked.add(seq)

        # Update sent_packets
        if seq in self.sent_packets:
            self.sent_packets[seq].acked = True

        # Slide window forward if base is acked
        while self.base_sequence in self.acked:
            self.acked.remove(self.base_sequence)
            if self.base_sequence in self.sent_packets:
                del self.sent_packets[self.base_sequence]
            self.base_sequence = (self.base_sequence + 1) & 0xFFFFFFFF

        return True

    def get_unacked_packets(
        self, timeout: float, max_retransmits: int
    ) -> List[PacketInfo]:
        """Get packets that need retransmission

        Args:
            timeout: Retransmission timeout in seconds
            max_retransmits: Maximum retransmission attempts

        Returns:
            List of packets to retransmit
        """
        current_time = time.time()
        retransmit_list = []

        for seq, packet_info in self.sent_packets.items():
            if packet_info.acked:
                continue

            # Check timeout
            if current_time - packet_info.sent_time < timeout:
                continue

            # Check max retransmits
            if packet_info.retransmit_count >= max_retransmits:
                logger.warning(
                    "Packet %d exceeded max retransmissions (%d)",
                    seq,
                    max_retransmits,
                )
                continue

            retransmit_list.append(packet_info)

        return retransmit_list

    def mark_retransmitted(self, seq: int) -> None:
        """Mark packet as retransmitted"""
        if seq in self.sent_packets:
            packet_info = self.sent_packets[seq]
            packet_info.sent_time = time.time()
            packet_info.retransmit_count += 1


@dataclass
class ReceiveWindow:
    """Receive window for out-of-order packet handling"""

    window_size: int = 16
    expected_sequence: int = 0  # Next expected sequence number
    received_packets: Dict[int, CovertMessage] = field(default_factory=dict)
    received_set: Set[int] = field(default_factory=set)

    def can_accept(self, seq: int) -> bool:
        """Check if sequence number is within receive window"""
        # Accept if within window ahead of expected
        max_seq = (self.expected_sequence + self.window_size) & 0xFFFFFFFF
        return seq >= self.expected_sequence and seq < max_seq

    def add_packet(self, seq: int, message: CovertMessage) -> bool:
        """Add packet to receive buffer

        Returns:
            True if packet was added, False if duplicate or out of window
        """
        if seq in self.received_set:
            return False  # Duplicate

        if not self.can_accept(seq):
            logger.warning("Packet %d outside receive window", seq)
            return False

        self.received_packets[seq] = message
        self.received_set.add(seq)
        return True

    def get_deliverable_messages(self) -> List[CovertMessage]:
        """Get messages that can be delivered in order

        Returns:
            List of messages ready for delivery
        """
        deliverable = []

        while self.expected_sequence in self.received_packets:
            message = self.received_packets[self.expected_sequence]
            deliverable.append(message)

            # Remove from buffers
            del self.received_packets[self.expected_sequence]
            self.received_set.remove(self.expected_sequence)

            # Advance expected sequence
            self.expected_sequence = (self.expected_sequence + 1) & 0xFFFFFFFF

        return deliverable

    def get_missing_sequences(self) -> List[int]:
        """Get sequence numbers of missing packets (for NACK)

        Returns:
            List of missing sequence numbers within window
        """
        missing = []
        for i in range(min(self.window_size, len(self.received_set))):
            seq = (self.expected_sequence + i) & 0xFFFFFFFF
            if seq not in self.received_set:
                missing.append(seq)
        return missing


class Synchronizer:
    """Manages synchronization protocol for reliable delivery"""

    def __init__(
        self,
        window_size: int = 16,
        retransmission_timeout: float = 2.0,
        max_retransmissions: int = 5,
    ):
        """Initialize synchronizer

        Args:
            window_size: Size of sliding window
            retransmission_timeout: Timeout for retransmission in seconds
            max_retransmissions: Maximum retransmission attempts
        """
        self.window_size = window_size
        self.retransmission_timeout = retransmission_timeout
        self.max_retransmissions = max_retransmissions

        # Send state
        self.send_window = SlidingWindow(window_size=window_size)

        # Receive state
        self.recv_window = ReceiveWindow(window_size=window_size)

        # Statistics
        self.stats = {
            "sent": 0,
            "received": 0,
            "acks_sent": 0,
            "acks_received": 0,
            "nacks_sent": 0,
            "nacks_received": 0,
            "retransmissions": 0,
            "duplicates": 0,
            "out_of_window": 0,
        }

    def prepare_message(
        self, message_type: CovertMessageType, payload: bytes
    ) -> Optional[CovertMessage]:
        """Prepare a message for sending with sequence number

        Args:
            message_type: Type of message
            payload: Message payload

        Returns:
            CovertMessage with sequence number, or None if window is full
        """
        if not self.send_window.can_send():
            logger.debug("Send window full, cannot send message")
            return None

        seq = self.send_window.get_next_sequence()
        if seq == -1:
            return None

        message = CovertMessage(
            message_type=message_type,
            payload=payload,
            sequence_number=seq,
        )

        self.send_window.mark_sent(seq, message)
        self.stats["sent"] += 1

        return message

    def handle_received_message(
        self, message: CovertMessage
    ) -> tuple[bool, List[CovertMessage]]:
        """Handle received message

        Args:
            message: Received message

        Returns:
            Tuple of (should_ack, deliverable_messages)
        """
        seq = message.sequence_number

        # Handle control messages
        if message.message_type == CovertMessageType.ACK:
            return self._handle_ack(message)
        elif message.message_type == CovertMessageType.NACK:
            return self._handle_nack(message)

        # Handle data message
        if seq in self.recv_window.received_set:
            self.stats["duplicates"] += 1
            return True, []  # ACK duplicate but don't deliver

        added = self.recv_window.add_packet(seq, message)
        if not added:
            self.stats["out_of_window"] += 1
            return False, []

        self.stats["received"] += 1

        # Get messages ready for delivery
        deliverable = self.recv_window.get_deliverable_messages()

        return True, deliverable

    def _handle_ack(self, message: CovertMessage) -> tuple[bool, List[CovertMessage]]:
        """Handle ACK message"""
        # Payload contains acked sequence number (4 bytes)
        if len(message.payload) < 4:
            return False, []

        acked_seq = int.from_bytes(message.payload[:4], byteorder="big")
        was_new = self.send_window.mark_acked(acked_seq)

        if was_new:
            self.stats["acks_received"] += 1
            logger.debug("Received ACK for sequence %d", acked_seq)

        return False, []  # Don't ACK the ACK

    def _handle_nack(self, message: CovertMessage) -> tuple[bool, List[CovertMessage]]:
        """Handle NACK message"""
        # Payload contains list of missing sequence numbers
        if len(message.payload) % 4 != 0:
            return False, []

        missing_seqs = []
        for i in range(0, len(message.payload), 4):
            seq = int.from_bytes(message.payload[i : i + 4], byteorder="big")
            missing_seqs.append(seq)

        if missing_seqs:
            self.stats["nacks_received"] += 1
            logger.debug("Received NACK for sequences: %s", missing_seqs)

        # Mark for retransmission by resetting sent_time
        for seq in missing_seqs:
            if seq in self.send_window.sent_packets:
                packet_info = self.send_window.sent_packets[seq]
                packet_info.sent_time = 0  # Force immediate retransmit

        return False, []

    def create_ack_message(self, acked_seq: int) -> CovertMessage:
        """Create ACK message

        Args:
            acked_seq: Sequence number to acknowledge

        Returns:
            ACK message
        """
        payload = acked_seq.to_bytes(4, byteorder="big")
        self.stats["acks_sent"] += 1

        return CovertMessage(
            message_type=CovertMessageType.ACK,
            payload=payload,
            sequence_number=0,  # Control messages don't use sequence
        )

    def create_nack_message(self) -> Optional[CovertMessage]:
        """Create NACK message for missing packets

        Returns:
            NACK message if there are missing packets, None otherwise
        """
        missing = self.recv_window.get_missing_sequences()
        if not missing:
            return None

        # Pack missing sequence numbers
        payload = b"".join(seq.to_bytes(4, byteorder="big") for seq in missing)
        self.stats["nacks_sent"] += 1

        return CovertMessage(
            message_type=CovertMessageType.NACK,
            payload=payload,
            sequence_number=0,
        )

    def get_retransmission_list(self) -> List[CovertMessage]:
        """Get list of messages that need retransmission

        Returns:
            List of messages to retransmit
        """
        packets_to_retransmit = self.send_window.get_unacked_packets(
            self.retransmission_timeout,
            self.max_retransmissions,
        )

        messages = []
        for packet_info in packets_to_retransmit:
            seq = packet_info.message.sequence_number
            self.send_window.mark_retransmitted(seq)
            self.stats["retransmissions"] += 1
            messages.append(packet_info.message)
            logger.debug(
                "Retransmitting sequence %d (attempt %d)",
                seq,
                packet_info.retransmit_count,
            )

        return messages

    def get_stats(self) -> dict:
        """Get synchronization statistics"""
        return {
            **self.stats,
            "send_window_base": self.send_window.base_sequence,
            "send_window_next": self.send_window.next_sequence,
            "recv_window_expected": self.recv_window.expected_sequence,
            "unacked_packets": len(self.send_window.sent_packets),
            "buffered_packets": len(self.recv_window.received_packets),
        }

    def reset(self) -> None:
        """Reset synchronizer state"""
        self.send_window = SlidingWindow(window_size=self.window_size)
        self.recv_window = ReceiveWindow(window_size=self.window_size)
        self.stats = {k: 0 for k in self.stats}
