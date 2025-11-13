import argparse
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import serve
from aioquic.covert.core.config import CovertConfig
from aioquic.covert.core.enums import CovertKeyType, CovertMessageType
from aioquic.quic import events
from aioquic.quic.configuration import QuicConfiguration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


class CovertServerProtocol(QuicConnectionProtocol):
    """Server protocol that handles covert messages"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._peer_address = None
        self._message_count = 0

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
            self._trigger_key_exchange()
        
        # Also trigger on ProtocolNegotiated (fires earlier on server)
        elif isinstance(event, events.ProtocolNegotiated) and not hasattr(self, '_key_exchange_initiated'):
            logger.info("Protocol negotiated: %s", event.alpn_protocol)
            self._trigger_key_exchange()

        # Check for covert message event
        if hasattr(events, "CovertMessageReceived") and isinstance(
            event, events.CovertMessageReceived
        ):
            self._handle_covert_message(event)

        super().quic_event_received(event)
    
    def _trigger_key_exchange(self):
        """Trigger key exchange CID generation"""
        if hasattr(self, '_key_exchange_initiated'):
            return
        self._key_exchange_initiated = True
        
        if not self._quic._network_paths:
            logger.warning("No network paths available for key exchange")
            return
            
        self._peer_address = self._quic._network_paths[0].addr[0]

        # Trigger key exchange
        if self._quic._covert_enabled and self._quic._covert_manager:
            logger.info("Initiating key exchange with %s", self._peer_address)
            key_exchange_cids = self._quic._covert_manager.prepare_key_exchange_cids(self._peer_address)
            # Queue key exchange CIDs
            for cid in key_exchange_cids:
                if self._peer_address not in self._quic._covert_manager._outgoing_cids:
                    self._quic._covert_manager._outgoing_cids[self._peer_address] = []
                self._quic._covert_manager._outgoing_cids[self._peer_address].append(cid)
            self._quic._replenish_connection_ids(self._peer_address)
            logger.info("Queued %d key exchange CIDs", len(key_exchange_cids))

    def _handle_covert_message(self, event):
        """Handle received covert message"""
        try:
            self._message_count += 1
            text = event.payload.decode("utf-8", errors="replace")
            timestamp = datetime.now().strftime("%H:%M:%S")

            logger.info(
                "\n" + "=" * 60 + "\n"
                "📨 COVERT MESSAGE #%d\n"
                "From: %s\n"
                "Time: %s\n"
                "Type: %s\n"
                "Content: %s\n" + "=" * 60,
                self._message_count,
                event.peer_address,
                timestamp,
                CovertMessageType(event.message_type).name,
                text,
            )

            # Echo back confirmation
            response = f"Server received: {text}"
            if self._quic.covert_send_message(event.peer_address, response):
                logger.info("📤 Sent echo: %s", response)

        except Exception as e:
            logger.error("Failed to handle covert message: %s", e, exc_info=True)


def generate_self_signed_cert():
    """Generate self-signed certificate for testing"""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Covert Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    return cert, key


async def main(host: str, port: int):
    """Run covert channel server"""
    logger.info("=" * 60)
    logger.info("🔒 Covert Channel Server")
    logger.info("=" * 60)

    # Generate certificate
    logger.info("Generating self-signed certificate...")
    cert, key = generate_self_signed_cert()

    # Create configuration
    covert_config = CovertConfig(
        key_type=CovertKeyType.ECC_CURVE25519,
        compression_type=CovertConfig().compression_type,
        enable_timing_randomization=True,
        timing_jitter_ms=100,
    )

    configuration = QuicConfiguration(
        is_client=False,
        covert_channel_enabled=True,
        covert_config=covert_config,
        connection_id_length=20,  # Match covert CID size
        alpn_protocols=["h3", "http/0.9"],
    )
    configuration.certificate = cert
    configuration.private_key = key

    logger.info("Starting server on %s:%d", host, port)
    logger.info("Covert channel: ENABLED")
    logger.info("Key type: %s", covert_config.key_type.name)
    logger.info("Compression: %s", covert_config.compression_type.name)
    logger.info("Waiting for connections...")
    logger.info("")

    # Start server
    server = await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=CovertServerProtocol,
    )

    try:
        await asyncio.Future()  # Run forever
    except KeyboardInterrupt:
        logger.info("\nShutting down server...")
    finally:
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert channel server")
    parser.add_argument(
        "--host",
        type=str,
        default="localhost",
        help="Host to bind to (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=4433,
        help="Port to bind to (default: 4433)",
    )
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port))
