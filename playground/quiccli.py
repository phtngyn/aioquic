import asyncio
import json
import logging
import os
import time

from aioquic.quic.ccrypto import get_compact_key, queue_message
from aioquic.quic.connection import (
    PEER_META,
    PEER_META_LOCK,
    RSA_BIT_STRENGTH,
    create_peer_meta,
    resolve_hostname_from_url,
)

logger = logging.getLogger(__name__)


def json_serializer(obj):
    return str(obj)


class QuiCCli:
    def __init__(
        self,
        send_function=None,
        configuration=None,
        urls=None,
        data=None,
        include=None,
        output_dir=None,
        local_port=0,
        zero_rtt=None,
        is_client=True,
    ):
        self.is_client = is_client
        self.send_function = send_function
        self.configuration = configuration
        self.urls = urls
        self.data = data
        self.include = include
        self.output_dir = output_dir
        self.local_port = local_port
        self.zero_rtt = (zero_rtt,)
        self.key_exchange_done = False
        # Connection pooling: reuse connections
        self.active_connection = None
        self.connection_cid_count = 0
        self.max_cids_per_connection = 50  # Reuse connection for up to 50 CIDs
        self.connection_created_at = None  # Track connection age
        self.connection_timeout = 30.0  # Seconds before connection considered stale
        if self.is_client:
            self.host, self.host_ip = resolve_hostname_from_url(self.urls[0])
            # For localhost, prefer IPv6 loopback to match server running on ::
            if self.host == "localhost" and self.host_ip == "127.0.0.1":
                self.host_ip = "::1"
            # Prepare peer meta but don't connect yet
            PEER_META_LOCK.acquire(timeout=5)
            peer_meta = create_peer_meta()
            key_bytes = get_compact_key(peer_meta["private_key"])
            open("client-public-key-client.bin", "wb").write(key_bytes)
            queue_message(
                host_ip=self.host_ip,
                payload=key_bytes,
                queue=peer_meta["cid_queue"],
                public_key=None,
                is_public_key=True,
            )
            # We need one final connection to get the last chunk of the
            # server's CID queue so add an extra random CID at the end
            peer_meta["cid_queue"].put(os.urandom(20))
            PEER_META[self.host_ip] = peer_meta
            PEER_META_LOCK.release()

    def send_message(self, count):
        print(f"SENDING {count} REQUESTS")
        send_urls = [self.urls[i % len(self.urls)] for i in range(count)]
        for i, url in enumerate(send_urls):
            # Connection pooling: health check
            now = time.time()
            connection_age = (
                now - self.connection_created_at
                if self.connection_created_at
                else float("inf")
            )
            is_connection_stale = connection_age > self.connection_timeout

            should_create_new = (
                self.active_connection is None
                or self.connection_cid_count >= self.max_cids_per_connection
                or is_connection_stale
            )

            if should_create_new:
                reason = (
                    "no connection"
                    if self.active_connection is None
                    else "stale"
                    if is_connection_stale
                    else "count limit"
                )
                print(f"SENDING REQUEST {i + 1}/{count} (new connection: {reason})")
                self.connection_cid_count = 0
                self.connection_created_at = now
                self.active_connection = url
            else:
                print(
                    f"SENDING REQUEST {i + 1}/{count} (reusing connection, age={connection_age:.1f}s)"
                )

            self.connection_cid_count += 1

            asyncio.run(
                self.send_function(
                    configuration=self.configuration,
                    urls=[url],
                    data=self.data,
                    include=self.include,
                    output_dir=self.output_dir,
                    local_port=self.local_port,
                    zero_rtt=self.zero_rtt,
                )
            )

    def process_message(self, command_input):
        command = command_input[0]
        payload = command_input[1:]
        if self.is_client:
            peer_meta = PEER_META.get(self.host_ip)
            # Do key exchange on first command
            if not self.key_exchange_done:
                print("Connecting to server and exchanging keys...")
                self.send_message((RSA_BIT_STRENGTH // 128) + 1)
                self.key_exchange_done = True
        try:
            if command == "m":
                if payload and payload[0] == ":":
                    count = queue_message(
                        host_ip=self.host_ip,
                        payload=(command + payload[1:]).encode("utf8"),
                        queue=peer_meta["cid_queue"],
                        public_key=peer_meta["public_key"],
                        session_key=peer_meta.get("session_key"),
                    )
                    if self.is_client:
                        self.send_message(count)
                else:
                    return False
            elif command == "f":
                if payload and payload[0] == ":":
                    payload_bytes = open(payload[1:], "rb").read()
                    count = queue_message(
                        host_ip=self.host_ip,
                        payload=b"f" + payload_bytes,
                        queue=peer_meta["cid_queue"],
                        public_key=peer_meta["public_key"],
                        session_key=peer_meta.get("session_key"),
                    )
                    if self.is_client:
                        self.send_message(count)
                else:
                    return False
            elif command == "q":
                os._exit(0)
            else:
                print(f"Unknown command '{command}'. Enter 'm', 'f', or 'q'.")
        except ValueError:
            logger.warning("Error queuing message for ip %s", self.host_ip)
            logger.warning(
                "Peer meta dump:\n%s",
                json.dumps(PEER_META, default=json_serializer, indent=True),
            )
        return True

    def run_cli(self):
        print("Welcome to the QuiCC console.")
        print("Enter 'm:[MESSAGE]' to send a message.")
        print("Enter 'f:[FILE]' to send a file.")
        print("Enter 'q' to quit.")

        while True:
            command_input = input("Enter your command: ").strip().lower()
            if len(command_input) >= 1:
                self.process_message(command_input)
            else:
                print("Invalid format. Use [COMMAND_CHAR]:[HOST]:[PAYLOAD]")
