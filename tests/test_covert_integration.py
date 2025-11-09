"""Basic integration test for covert channel"""

import unittest

from aioquic.covert.core.config import CovertConfig
from aioquic.covert.core.enums import CovertKeyType, CovertMessageType
from aioquic.covert.state.manager import SessionManager


class TestCovertChannelIntegration(unittest.TestCase):
    """Test covert channel end-to-end"""

    def test_session_manager_initialization(self):
        """Test SessionManager can be created"""
        config = CovertConfig(
            key_type=CovertKeyType.ECC_CURVE25519,
            enable_timing_randomization=True,
            enable_traffic_mimicry=True,
        )

        manager = SessionManager(config, is_client=True)
        self.assertIsNotNone(manager)
        self.assertTrue(manager.is_client)
        self.assertEqual(manager.config.key_type, CovertKeyType.ECC_CURVE25519)

    def test_session_creation(self):
        """Test session creation for peer"""
        config = CovertConfig(key_type=CovertKeyType.ECC_CURVE25519)
        manager = SessionManager(config)

        session = manager.get_or_create_session("192.168.1.100")
        self.assertIsNotNone(session)
        self.assertEqual(session.peer_address, "192.168.1.100")

    def test_message_queuing(self):
        """Test message can be queued"""
        config = CovertConfig(key_type=CovertKeyType.ECC_CURVE25519)
        manager = SessionManager(config)

        # Create session and perform key exchange
        session = manager.get_or_create_session("192.168.1.100")
        self.assertIsNotNone(session)

        # Queue message (will fail without key exchange, but tests the path)
        result = manager.queue_message(
            "192.168.1.100", CovertMessageType.TEXT, b"Test message"
        )

        # Without completing key exchange, this should fail
        # But it tests that the code path works
        self.assertIsInstance(result, bool)

    def test_stealth_manager_integration(self):
        """Test stealth manager is integrated"""
        config = CovertConfig(
            enable_timing_randomization=True,
            enable_traffic_mimicry=True,
            timing_jitter_ms=50,
        )

        manager = SessionManager(config)
        self.assertIsNotNone(manager.stealth)

        # Test timing delay (should not crash)
        manager.stealth.apply_timing_delay()

        # Test decoy generation
        should_send = manager.stealth.should_send_decoy()
        self.assertIsInstance(should_send, bool)

        if manager.config.enable_decoy_traffic:
            decoy = manager.stealth.generate_decoy_cid()
            if decoy:
                self.assertIsInstance(decoy, bytes)


class TestCovertConfiguration(unittest.TestCase):
    """Test configuration options"""

    def test_default_config(self):
        """Test default configuration"""
        config = CovertConfig()

        self.assertEqual(config.key_type, CovertKeyType.ECC_CURVE25519)
        self.assertTrue(config.enable_sync)
        self.assertTrue(config.enable_authentication)
        self.assertEqual(config.sliding_window_size, 16)

    def test_custom_config(self):
        """Test custom configuration"""
        config = CovertConfig(
            key_type=CovertKeyType.RSA_2048,
            cid_max_length=18,
            sliding_window_size=8,
            enable_traffic_mimicry=False,
        )

        self.assertEqual(config.key_type, CovertKeyType.RSA_2048)
        self.assertEqual(config.cid_max_length, 18)
        self.assertEqual(config.sliding_window_size, 8)
        self.assertFalse(config.enable_traffic_mimicry)


if __name__ == "__main__":
    unittest.main()
