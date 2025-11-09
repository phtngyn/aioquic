#!/usr/bin/env python3
"""Covert channel server demo - receives hidden messages via QUIC CIDs"""

import argparse
import asyncio
import logging
import sys

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.covert.core.config import CovertConfig
from aioquic.covert.core.enums import CovertKeyType
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent

logger = logging.getLogger(__name__)


class CovertServerProtocol(QuicConnectionProtocol):
    """Server protocol with covert message handler"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._covert_messages = []

    def quic_event_received(self, event: QuicEvent):
        """Handle QUIC events"""
        super().quic_event_received(event)

    def covert_message_received(self, peer: str, message_type: int, payload: bytes):
        """Handle received covert message"""
        try:
            text = payload.decode("utf-8")
            logger.info("Received covert message from %s: %s", peer, text)
            self._covert_messages.append((peer, text))
        except Exception as e:
            logger.error("Failed to decode message: %s", e)

    def get_received_messages(self):
        """Get all received messages"""
        return self._covert_messages


class CovertServer:
    """Server for covert channel demo"""

    def __init__(self, config: QuicConfiguration):
        self.config = config
        self._protocols = []

    async def start(self, host: str, port: int):
        """Start covert channel server"""
        logger.info("Starting covert server on %s:%d", host, port)

        # Create protocol factory
        def create_protocol(*args, **kwargs):
            protocol = CovertServerProtocol(*args, **kwargs)
            self._protocols.append(protocol)
            return protocol

        # Start server
        server = await serve(
            host,
            port,
            configuration=self.config,
            create_protocol=create_protocol,
        )

        logger.info("Server listening. Press Ctrl+C to stop.")

        # Run until interrupted
        try:
            await asyncio.Future()  # Run forever
        except asyncio.CancelledError:
            pass
        finally:
            server.close()
            logger.info("Server stopped")

    def get_stats(self):
        """Get statistics from all connections"""
        stats = {}

        for protocol in self._protocols:
            if not hasattr(protocol, "_covert_manager"):
                continue

            manager = protocol._covert_manager
            for peer, session in manager._sessions.items():
                stats[peer] = {
                    "state": session.state.name,
                    "messages_sent": session.messages_sent,
                    "messages_received": session.messages_received,
                    "bytes_sent": session.bytes_sent,
                    "bytes_received": session.bytes_received,
                    "errors": session.errors,
                    "received_messages": [
                        msg[1] for msg in protocol.get_received_messages()
                    ],
                }

        return stats


async def main():
    parser = argparse.ArgumentParser(description="Covert channel server")
    parser.add_argument("--host", default="0.0.0.0", help="Listen host")
    parser.add_argument("--port", type=int, default=4433, help="Listen port")
    parser.add_argument(
        "--key-type",
        choices=["ecc", "rsa"],
        default="ecc",
        help="Key exchange type",
    )
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--cert", required=True, help="TLS certificate file")
    parser.add_argument("--key", required=True, help="TLS private key file")
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # Create QUIC configuration
    quic_config = QuicConfiguration(is_client=False)
    quic_config.load_cert_chain(args.cert, args.key)

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

    # Run server
    server = CovertServer(quic_config)
    try:
        await server.start(args.host, args.port)
    except KeyboardInterrupt:
        logger.info("Interrupted by user")

        # Print stats
        stats = server.get_stats()
        if stats:
            logger.info("Covert channel statistics:")
            for peer, peer_stats in stats.items():
                logger.info("  %s: %s", peer, peer_stats)

    except Exception as e:
        logger.exception("Error: %s", e)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
