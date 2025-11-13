import argparse
import asyncio
import logging
import ssl
from datetime import datetime

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.covert.core.config import CovertConfig
from aioquic.covert.core.enums import CovertKeyType, CovertMessageType
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class CovertClientProtocol(QuicConnectionProtocol):
    """Client protocol that sends covert messages"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._server_address = None
        self._message_count = 0
        self._ready = False

    def quic_event_received(self, event: events.QuicEvent):
        """Handle QUIC events"""
        if isinstance(event, events.ConnectionTerminated):
            logger.info(
                "Connection terminated (error_code=%d, reason=%s)",
                event.error_code,
                event.reason_phrase,
            )
        elif isinstance(event, events.HandshakeCompleted):
            logger.info("Handshake completed, protocol: %s", event.alpn_protocol)
            self._server_address = self._quic._network_paths[0].addr[0]
            
            # Trigger key exchange
            if self._quic._covert_enabled and self._quic._covert_manager:
                logger.info("Initiating key exchange with %s", self._server_address)
                key_exchange_cids = self._quic._covert_manager.prepare_key_exchange_cids(self._server_address)
                # Queue key exchange CIDs
                for cid in key_exchange_cids:
                    if self._server_address not in self._quic._covert_manager._outgoing_cids:
                        self._quic._covert_manager._outgoing_cids[self._server_address] = []
                    self._quic._covert_manager._outgoing_cids[self._server_address].append(cid)
                self._quic._replenish_connection_ids(self._server_address)
                logger.info("Queued %d key exchange CIDs", len(key_exchange_cids))
            
            self._ready = True
            logger.info("✅ Covert channel ready!")

        # Check for covert message event
        if hasattr(events, "CovertMessageReceived") and isinstance(
            event, events.CovertMessageReceived
        ):
            self._handle_covert_message(event)

        super().quic_event_received(event)

    def _handle_covert_message(self, event):
        """Handle received covert message"""
        try:
            text = event.payload.decode("utf-8", errors="replace")
            timestamp = datetime.now().strftime("%H:%M:%S")

            logger.info(
                "\n" + "=" * 60 + "\n"
                "📨 RECEIVED FROM SERVER\n"
                "Time: %s\n"
                "Content: %s\n" + "=" * 60,
                timestamp,
                text,
            )
        except Exception as e:
            logger.error("Failed to handle covert message: %s", e)

    async def send_covert_message(self, message: str) -> bool:
        """Send a covert message"""
        if not self._ready or not self._server_address:
            logger.warning("Not ready to send messages yet")
            return False

        self._message_count += 1
        timestamp = datetime.now().strftime("%H:%M:%S")

        logger.info(
            "\n" + "=" * 60 + "\n"
            "📤 SENDING COVERT MESSAGE #%d\n"
            "To: %s\n"
            "Time: %s\n"
            "Content: %s\n" + "=" * 60,
            self._message_count,
            self._server_address,
            timestamp,
            message,
        )

        success = self._quic.covert_send_message(self._server_address, message)

        if success:
            logger.info("✅ Message queued successfully")
        else:
            logger.error("❌ Failed to queue message")

        return success


async def main(
    host: str, port: int, messages: list, interval: float, interactive: bool
):
    """Run covert channel client"""
    logger.info("=" * 60)
    logger.info("🔒 Covert Channel Client")
    logger.info("=" * 60)

    # Create configuration
    covert_config = CovertConfig(
        key_type=CovertKeyType.ECC_CURVE25519,
        compression_type=CovertConfig().compression_type,
        enable_timing_randomization=True,
        timing_jitter_ms=100,
    )

    configuration = QuicConfiguration(
        is_client=True,
        covert_channel_enabled=True,
        covert_config=covert_config,
        connection_id_length=20,
        alpn_protocols=["h3", "http/0.9"],
        verify_mode=ssl.CERT_NONE,  # Accept self-signed cert
    )

    logger.info("Connecting to %s:%d", host, port)
    logger.info("Covert channel: ENABLED")
    logger.info("Key type: %s", covert_config.key_type.name)
    logger.info("Compression: %s", covert_config.compression_type.name)
    logger.info("")

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=CovertClientProtocol,
    ) as client:
        protocol = client

        # Wait for handshake
        logger.info("Waiting for handshake...")
        for _ in range(50):  # 5 seconds max
            if protocol._ready:
                break
            await asyncio.sleep(0.1)

        if not protocol._ready:
            logger.error("Handshake timeout")
            return

        # Wait a bit more for key exchange
        logger.info("Performing key exchange...")
        await asyncio.sleep(2)

        if interactive:
            # Interactive mode
            logger.info("\n" + "=" * 60)
            logger.info("Interactive mode - type messages to send")
            logger.info("Type 'quit' to exit")
            logger.info("=" * 60 + "\n")

            while True:
                try:
                    message = input("Message: ")
                    if message.lower() in ["quit", "exit", "q"]:
                        break
                    if message:
                        await protocol.send_covert_message(message)
                        await asyncio.sleep(0.5)
                except (EOFError, KeyboardInterrupt):
                    break
        else:
            # Send predefined messages
            for i, message in enumerate(messages, 1):
                await asyncio.sleep(interval)
                await protocol.send_covert_message(message)

            # Keep connection alive and pump CIDs to transmit queued messages
            logger.info("\nWaiting for responses (15 seconds)...")
            for _ in range(30):  # 15 seconds, check every 0.5s
                # Send PING to force packet generation
                protocol._quic._ping_pending.append((0, None))
                protocol.transmit()
                await asyncio.sleep(0.5)

        # Show statistics
        if protocol._server_address:
            stats = protocol._quic.covert_get_stats(protocol._server_address)
            if stats:
                logger.info("\n" + "=" * 60)
                logger.info("📊 Covert Channel Statistics")
                logger.info("=" * 60)
                for key, value in stats.items():
                    logger.info("  %s: %s", key, value)
                logger.info("=" * 60)

        logger.info("\nClosing connection...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel client")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Server host (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="Server port (default: 4433)",
    )
    parser.add_argument(
        "--message",
        "-m",
        type=str,
        action="append",
        help="Message to send (can be specified multiple times)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Interval between messages in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        help="Interactive mode - type messages to send",
    )
    args = parser.parse_args()

    # Default messages if none provided
    messages = args.message or [
        "Hello from covert client!",
    ]

    asyncio.run(main(args.host, args.port, messages, args.interval, args.interactive))
