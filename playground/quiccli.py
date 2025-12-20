import asyncio
import logging
import os
import random
import socket
import threading
import time
from urllib.parse import urlparse

from aioquic.quic.ccrypto import (
    SEQUENCE_BYTES,
    get_public_key_bytes,
    queue_message,
)
from aioquic.quic.connection import (
    PEER_META,
    PEER_META_LOCK,
    create_peer_meta,
    resolve_hostname_from_url,
)

logger = logging.getLogger(__name__)


class TrafficShaper:
    def __init__(self, mode="cloudflare"):
        self.mode = mode
        if mode == "cloudflare":
            self.mu = -11.2251
            self.sigma = 2.8571
            self.min_interval = 0.000001
        elif mode == "none":
            self.min_interval = 0

    def next_interval(self):
        if self.mode == "none":
            return 0
        interval = random.lognormvariate(self.mu, self.sigma)
        return max(interval, self.min_interval)


class QuiCCli:
    def __init__(self, send_function, configuration, urls, is_client=True):
        self.is_client = is_client
        self.send_function = send_function
        self.configuration = configuration
        self.urls = urls

        self.shaper_mode = getattr(configuration, "traffic_shaper_mode", "none")
        self.shaper = TrafficShaper(mode=self.shaper_mode)

        self._stop_event = threading.Event()
        self._handshake_queue = []
        self._traffic_thread = None
        self.peer_key = None

        if self.is_client:
            self.host, self.host_ip = resolve_hostname_from_url(self.urls[0])
            parsed = urlparse(self.urls[0])
            self.host_port = parsed.port or 443
            self.peer_key = (self.host_ip, self.host_port)

            PEER_META_LOCK.acquire(timeout=5)
            peer_meta = create_peer_meta()

            # Queue the public key handshake immediately
            key_bytes = peer_meta.get("local_public_key")
            if key_bytes is None:
                key_bytes = get_public_key_bytes(peer_meta["private_key"])
            queue_message(
                host_ip=self.host_ip,
                payload=key_bytes,
                queue=peer_meta["cid_queue"],
                public_key=None,
                is_public_key=True,
            )
            peer_meta["public_key_sent"] = True
            # Queue initial random CID for connection establishment
            peer_meta["cid_queue"].put(os.urandom(20))

            PEER_META[self.peer_key] = peer_meta
            PEER_META_LOCK.release()

            if self.shaper_mode != "none":
                self._start_traffic_loop()
            else:
                qsize = peer_meta["cid_queue"].qsize()
                if qsize > 0:
                    self.send_message(qsize)

    def _next_sequence(self):
        peer_meta = PEER_META.get(self.peer_key)
        if peer_meta is None:
            return 0
        seq = peer_meta.get("next_sequence", 0)
        modulo = 1 << (SEQUENCE_BYTES * 8)
        peer_meta["next_sequence"] = (seq + 1) % modulo
        return seq

    def make_fake_quic_packet(self):
        header = b"\xc0\x00\x00\x00\x01"  # Type + Version
        dcid = os.urandom(20)
        header += b"\x14" + dcid  # DCID Len + DCID
        header += b"\x00"  # SCID Len
        header += b"\x00"  # Token Len
        header += b"\x44\xb0"  # Length (~1200 encoded as 2-byte varint)

        # Fill the rest with random noise
        payload = os.urandom(1200 - len(header))
        return header + payload

    def _start_traffic_loop(self):
        # Prepare a raw socket for "Fast Chaff" injection
        raw_sock = None
        try:
            addr_info = socket.getaddrinfo(
                self.host_ip, self.host_port, type=socket.SOCK_DGRAM
            )
            family, socktype, proto, _, sockaddr = addr_info[0]
            raw_sock = socket.socket(family, socktype, proto)
        except Exception as e:
            if self.shaper_mode != "none":
                logger.error(f"Failed to create raw socket for shaper: {e}")
                return

        def _loop():
            logger.info(f"Traffic shaper started (Mode: {self.shaper_mode})")

            while not self._stop_event.is_set():
                # 1. Get the target interval
                sleep_time = self.shaper.next_interval()

                # 2. Precision Wait Logic
                if sleep_time > 0:
                    start = time.perf_counter()
                    target = start + sleep_time

                    while True:
                        now = time.perf_counter()
                        remaining = target - now
                        if remaining <= 0:
                            break
                        if remaining > 0.001:
                            time.sleep(remaining - 0.001)
                        else:
                            pass  # Busy wait

                peer_meta = PEER_META.get(self.peer_key)
                if not peer_meta:
                    time.sleep(0.1)
                    continue

                # 0. Check for pending handshake messages (Flush Buffer)
                if self._handshake_queue and peer_meta.get("session_key"):
                    logger.info(
                        "Handshake complete. Flushing %d queued messages.",
                        len(self._handshake_queue),
                    )
                    while self._handshake_queue:
                        cmd, fec_rate = self._handshake_queue.pop(0)
                        queue_message(
                            host_ip=self.host_ip,
                            payload=cmd.encode("utf8"),
                            queue=peer_meta["cid_queue"],
                            public_key=peer_meta["public_key"],
                            sequence=self._next_sequence(),
                            session_key=peer_meta.get("session_key"),
                            fec_rate=fec_rate,
                        )
                    # If not shaping, flush queue immediately
                    if self.shaper_mode == "none":
                        qsize = peer_meta["cid_queue"].qsize()
                        if qsize > 0:
                            self.send_message(qsize)

                # 3. Fast Chaff vs Real Message
                if peer_meta["cid_queue"].empty():
                    if self.shaper_mode != "none" and raw_sock:
                        try:
                            packet = self.make_fake_quic_packet()
                            raw_sock.sendto(packet, sockaddr)
                        except OSError:
                            pass
                    else:
                        time.sleep(0.05)  # Prevent busy loop in 'none' mode
                else:
                    self.send_message(1)

            logger.info("Traffic shaper stopped")
            if raw_sock:
                raw_sock.close()

        self._traffic_thread = threading.Thread(target=_loop, name="quic-shaper")
        self._traffic_thread.start()

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
            return True

        peer_meta = PEER_META.get(self.peer_key) if self.is_client else None

        if cmd[0] == "m" and len(cmd) > 2 and cmd[1] == ":":
            fec_rate = (
                self.configuration.covert_fec_rate
                if self.configuration.covert_strategy == "fec"
                else None
            )

            # --- FIX: Buffer message if handshake isn't ready ---
            if peer_meta.get("session_key") is None:
                print("Handshake pending... buffering message.")
                self._handshake_queue.append((cmd, fec_rate))
                # Ensure the loop is running to flush this later
                if self._traffic_thread is None or not self._traffic_thread.is_alive():
                    self._start_traffic_loop()
                return True
            # ----------------------------------------------------

            # Just QUEUE the message.
            count = queue_message(
                host_ip=self.host_ip,
                payload=cmd.encode("utf8"),
                queue=peer_meta["cid_queue"],
                public_key=peer_meta["public_key"],
                sequence=self._next_sequence(),
                session_key=peer_meta.get("session_key"),
                fec_rate=fec_rate,
            )

            if self.shaper_mode != "none":
                print("Message queued. Transmission will be shaped.")
            else:
                # Immediate Send Mode
                print(f"Message queued. Sending {count} packets immediately...")
                self.send_message(count)

        elif cmd == "q":
            self.stop()
            return False

        return True

    def stop(self):
        """Signal background loop to exit and wait briefly for shutdown."""
        if self._stop_event.is_set():
            return

        self._stop_event.set()
        if self._traffic_thread and self._traffic_thread.is_alive():
            self._traffic_thread.join(timeout=2.0)
        logger.info("QuiCCli stopped")

    def run_cli(self):
        print("m:MSG | q")
        while not self._stop_event.is_set():
            try:
                cmd = input("> ").strip()
            except EOFError:
                self.stop()
                break
            if not self.process_message(cmd):
                break
