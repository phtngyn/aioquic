#!/usr/bin/env python3
"""Covert channel client demo - sends hidden messages via QUIC CIDs"""

import argparse
import asyncio
import logging
import sys

from aioquic.asyncio.client import connect
from aioquic.covert.core.config import CovertConfig
from aioquic.covert.core.enums import CovertKeyType, CovertMessageType
from aioquic.quic.configuration import QuicConfiguration

logger = logging.getLogger(__name__)


class CovertClient:
    """Client for covert channel demo"""

    def __init__(self, config: QuicConfiguration):
        self.config = config
        self._protocol = None

    async def connect(self, host: str, port: int):
        """Establish QUIC connection with covert channel"""
        logger.info("Connecting to %s:%d...", host, port)
        async with connect(
            host,
            port,
            configuration=self.config,
        ) as protocol:
            self._protocol = protocol
            logger.info("Connected! Covert channel active.")

            # Wait for key exchange
            await asyncio.sleep(1)

            # Send covert message
            await self.send_message("Hello from covert channel!")

            # Keep connection alive
            await asyncio.sleep(5)

    async def send_message(self, text: str):
        """Send covert text message"""
        if not self._protocol:
            logger.error("Not connected")
            return

        logger.info("Sending covert message: %s", text)
        success = self._protocol.covert_send_message(
            CovertMessageType.TEXT, text.encode("utf-8")
        )

        if success:
            logger.info("Message queued for transmission")
        else:
            logger.error("Failed to queue message")

    def get_stats(self):
        """Get covert channel statistics"""
        if not self._protocol or not hasattr(self._protocol, "_covert_manager"):
            return {}

        manager = self._protocol._covert_manager
        stats = {}

        for peer, session in manager._sessions.items():
            stats[peer] = {
                "state": session.state.name,
                "messages_sent": session.messages_sent,
                "messages_received": session.messages_received,
                "bytes_sent": session.bytes_sent,
                "bytes_received": session.bytes_received,
                "errors": session.errors,
            }

        return stats


async def main():
    parser = argparse.ArgumentParser(description="Covert channel client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=4433, help="Server port")
    parser.add_argument("--message", default="Secret message", help="Message to send")
    parser.add_argument(
        "--key-type",
        choices=["ecc", "rsa"],
        default="ecc",
        help="Key exchange type",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument(
        "--ca-certs", help="CA certificates file for server verification"
    )
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create QUIC configuration
    quic_config = QuicConfiguration(is_client=True)
    if args.ca_certs:
        quic_config.load_verify_locations(args.ca_certs)
    else:
        quic_config.verify_mode = False  # Skip cert verification for demo

    # Enable covert channel
    quic_config.covert_channel_enabled = True

    # Create covert configuration
    covert_config = CovertConfig(
        key_type=(
            CovertKeyType.ECC_CURVE25519
            if args.key_type == "ecc"
            else CovertKeyType.RSA_2048
        ),
        enable_timing_randomization=True,
        enable_traffic_mimicry=True,
        debug=args.verbose,
    )
    quic_config.covert_config = covert_config

    # Run client
    client = CovertClient(quic_config)
    try:
        await client.connect(args.host, args.port)

        # Print stats
        stats = client.get_stats()
        if stats:
            logger.info("Covert channel statistics:")
            for peer, peer_stats in stats.items():
                logger.info("  %s: %s", peer, peer_stats)

    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    except Exception as e:
        logger.exception("Error: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
