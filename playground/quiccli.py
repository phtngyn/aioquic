import asyncio
import logging
import os
import random
import threading
import time
from urllib.parse import urlparse

from aioquic.quic.ccrypto import get_compact_key, queue_message
from aioquic.quic.connection import (
    PEER_META,
    PEER_META_LOCK,
    create_peer_meta,
    resolve_hostname_from_url,
)

logger = logging.getLogger(__name__)


class TrafficShaper:
    def __init__(self, mode="cloudflare"):
        if mode == "cloudflare":
            self.mu = -11.4994
            self.sigma = 2.8917
            self.min_interval = 0.000001

    def next_interval(self):
        interval = random.lognormvariate(self.mu, self.sigma)
        return max(interval, self.min_interval)


class QuiCCli:
    def __init__(self, send_function, configuration, urls, is_client=True):
        self.is_client = is_client
        self.send_function = send_function
        self.configuration = configuration
        self.urls = urls
        self.shaper = TrafficShaper(mode="cloudflare")

        if self.is_client:
            self.host, self.host_ip = resolve_hostname_from_url(self.urls[0])
            parsed = urlparse(self.urls[0])
            self.host_port = parsed.port or 443
            self.peer_key = (self.host_ip, self.host_port)

            PEER_META_LOCK.acquire(timeout=5)
            peer_meta = create_peer_meta()

            # Queue the public key handshake immediately
            key_bytes = get_compact_key(peer_meta["private_key"])
            queue_message(
                host_ip=self.host_ip,
                payload=key_bytes,
                queue=peer_meta["cid_queue"],
                public_key=None,
                is_public_key=True,
            )
            # Queue initial random CID for connection establishment
            peer_meta["cid_queue"].put(os.urandom(20))

            PEER_META[self.peer_key] = peer_meta
            PEER_META_LOCK.release()

            # Start the shaped traffic loop
            self._start_traffic_loop()

    def _next_sequence(self):
        peer_meta = PEER_META.get(self.peer_key)
        if peer_meta is None:
            return 0
        seq = peer_meta.get("next_sequence", 0)
        peer_meta["next_sequence"] = seq + 1
        return seq

    def _start_traffic_loop(self):
        def _loop():
            logger.info("Traffic shaper started (Mode: Cloudflare)")
            while True:
                # 1. Wait for the next "natural" packet time
                sleep_time = self.shaper.next_interval()
                if sleep_time > 0.001:
                    time.sleep(sleep_time)

                peer_meta = PEER_META.get(self.peer_key)
                if not peer_meta:
                    continue

                # 2. Check Queue State
                if peer_meta["cid_queue"].empty():
                    # Chaff: Send random CID to maintain cover
                    dummy_cid = os.urandom(20)
                    peer_meta["cid_queue"].put(dummy_cid)
                    self._next_sequence()

                # 3. Send exactly ONE packet (connection) per interval
                # This ensures the wire traffic matches the shaper's IAT exactly.
                self.send_message(1)

        threading.Thread(target=_loop, daemon=True).start()

    def send_message(self, count):
        """
        Triggers 'count' QUIC connections.
        Each connection consumes 1 CID from the queue.
        """
        for i in range(count):
            try:
                asyncio.run(
                    self.send_function(
                        configuration=self.configuration,
                        urls=self.urls,
                    )
                )
            except Exception as e:
                logger.debug(f"Send failed: {e}")

    def process_message(self, cmd):
        if not cmd:
            return

        peer_meta = PEER_META.get(self.peer_key) if self.is_client else None

        if cmd[0] == "m" and len(cmd) > 2 and cmd[1] == ":":
            fec_rate = (
                self.configuration.covert_fec_rate
                if self.configuration.covert_strategy == "fec"
                else None
            )
            # Just QUEUE the message. Do NOT send immediately.
            # The traffic loop will pick this up packet-by-packet.
            queue_message(
                host_ip=self.host_ip,
                payload=cmd.encode("utf8"),
                queue=peer_meta["cid_queue"],
                public_key=peer_meta["public_key"],
                sequence=self._next_sequence(),
                session_key=peer_meta.get("session_key"),
                fec_rate=fec_rate,
            )
            print("Message queued. Transmission will be shaped.")

        elif cmd == "q":
            os._exit(0)

    def run_cli(self):
        print("m:MSG | q")
        while True:
            cmd = input("> ").strip()
            self.process_message(cmd)
