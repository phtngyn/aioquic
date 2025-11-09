"""Tests for covert channel protocol"""

import unittest

from aioquic.covert.core.enums import CovertMessageType
from aioquic.covert.core.types import CovertMessage
from aioquic.covert.protocol.encoder import CIDBuffer, CIDEncoder
from aioquic.covert.protocol.synchronizer import (
    ReceiveWindow,
    SlidingWindow,
    Synchronizer,
)


class TestSlidingWindow(unittest.TestCase):
    """Test sliding window for flow control"""

    def test_initialization(self):
        """Test window initialization"""
        window = SlidingWindow(window_size=8)
        self.assertEqual(window.window_size, 8)
        self.assertEqual(window.next_seq, 0)
        self.assertEqual(window.window_start, 0)

    def test_can_send(self):
        """Test send window check"""
        window = SlidingWindow(window_size=4)

        # Can send up to window size
        for i in range(4):
            self.assertTrue(window.can_send())
            window.add_sent_message(i, CovertMessage(0, i, 0, b"test"))

        # Window full
        self.assertFalse(window.can_send())

    def test_ack_message(self):
        """Test message acknowledgment"""
        window = SlidingWindow(window_size=4)

        # Send messages
        for i in range(3):
            window.add_sent_message(i, CovertMessage(0, i, 0, b"test"))

        # ACK message 0
        window.ack_message(0)
        self.assertEqual(window.window_start, 1)

        # ACK out of order
        window.ack_message(2)
        self.assertEqual(window.window_start, 1)  # Still waiting for 1

        window.ack_message(1)
        self.assertEqual(window.window_start, 3)  # Slides to 3


class TestReceiveWindow(unittest.TestCase):
    """Test receive window for out-of-order handling"""

    def test_initialization(self):
        """Test window initialization"""
        window = ReceiveWindow(window_size=8)
        self.assertEqual(window.window_size, 8)
        self.assertEqual(window.next_expected, 0)

    def test_in_order_receive(self):
        """Test in-order message reception"""
        window = ReceiveWindow(window_size=8)

        msg0 = CovertMessage(0, 0, 0, b"msg0")
        msg1 = CovertMessage(0, 1, 0, b"msg1")

        result0 = window.add_message(msg0)
        self.assertEqual(result0, [msg0])
        self.assertEqual(window.next_expected, 1)

        result1 = window.add_message(msg1)
        self.assertEqual(result1, [msg1])
        self.assertEqual(window.next_expected, 2)

    def test_out_of_order_receive(self):
        """Test out-of-order message reception"""
        window = ReceiveWindow(window_size=8)

        msg2 = CovertMessage(0, 2, 0, b"msg2")
        msg0 = CovertMessage(0, 0, 0, b"msg0")
        msg1 = CovertMessage(0, 1, 0, b"msg1")

        # Receive out of order
        result2 = window.add_message(msg2)
        self.assertEqual(result2, [])  # Buffered
        self.assertEqual(window.next_expected, 0)

        # Receive first
        result0 = window.add_message(msg0)
        self.assertEqual(result0, [msg0])
        self.assertEqual(window.next_expected, 1)

        # Receive second - triggers buffer flush
        result1 = window.add_message(msg1)
        self.assertEqual(result1, [msg1, msg2])
        self.assertEqual(window.next_expected, 3)


class TestSynchronizer(unittest.TestCase):
    """Test synchronization protocol"""

    def test_initialization(self):
        """Test synchronizer initialization"""
        sync = Synchronizer(window_size=16, retransmission_timeout=2.0)
        self.assertEqual(sync.send_window.window_size, 16)

    def test_prepare_message(self):
        """Test message preparation"""
        sync = Synchronizer(window_size=4)

        # Prepare message
        msg = sync.prepare_message(CovertMessageType.TEXT, b"Hello")
        self.assertIsNotNone(msg)
        self.assertEqual(msg.message_type, CovertMessageType.TEXT.value)
        self.assertEqual(msg.sequence_num, 0)
        self.assertEqual(msg.payload, b"Hello")

        # Next sequence number
        msg2 = sync.prepare_message(CovertMessageType.TEXT, b"World")
        self.assertEqual(msg2.sequence_num, 1)

    def test_handle_received_message(self):
        """Test received message handling"""
        sync = Synchronizer(window_size=8)

        msg = CovertMessage(
            message_type=CovertMessageType.TEXT.value,
            sequence_num=0,
            flags=0,
            payload=b"Test",
        )

        result = sync.handle_received_message(msg)
        self.assertEqual(result, [msg])


class TestCIDEncoder(unittest.TestCase):
    """Test CID encoding/decoding"""

    def test_encode_decode(self):
        """Test message encoding to CIDs"""
        encoder = CIDEncoder(chunk_size=16)
        key = b"0" * 32

        msg = CovertMessage(
            message_type=CovertMessageType.TEXT.value,
            sequence_num=42,
            flags=0,
            payload=b"Secret data",
        )

        # Encode
        cids = encoder.encode_message_to_cids(msg, key)
        self.assertGreater(len(cids), 0)

        # All CIDs should be 8-20 bytes
        for cid in cids:
            self.assertGreaterEqual(len(cid), 8)
            self.assertLessEqual(len(cid), 20)


class TestCIDBuffer(unittest.TestCase):
    """Test CID buffering and decoding"""

    def test_single_cid_message(self):
        """Test short message in single CID"""
        buffer = CIDBuffer()
        encoder = CIDEncoder(chunk_size=16)
        key = b"0" * 32

        msg = CovertMessage(
            message_type=CovertMessageType.TEXT.value,
            sequence_num=0,
            flags=0,
            payload=b"Hi",
        )

        cids = encoder.encode_message_to_cids(msg, key)

        # Process CIDs
        for cid in cids:
            result = buffer.try_decode(cid, key)
            if result:
                self.assertEqual(result.message_type, msg.message_type)
                self.assertEqual(result.sequence_num, msg.sequence_num)
                self.assertEqual(result.payload, msg.payload)
                break

    def test_multi_cid_message(self):
        """Test longer message across multiple CIDs"""
        buffer = CIDBuffer()
        encoder = CIDEncoder(chunk_size=8)
        key = b"1" * 32

        msg = CovertMessage(
            message_type=CovertMessageType.TEXT.value,
            sequence_num=1,
            flags=0,
            payload=b"A" * 100,
        )

        cids = encoder.encode_message_to_cids(msg, key)
        self.assertGreater(len(cids), 1)

        # Process all CIDs
        result = None
        for cid in cids:
            result = buffer.try_decode(cid, key)
            if result:
                break

        self.assertIsNotNone(result)
        self.assertEqual(result.payload, msg.payload)


if __name__ == "__main__":
    unittest.main()
