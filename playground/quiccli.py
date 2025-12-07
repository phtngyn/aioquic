import asyncio
import os

from aioquic.quic.ccrypto import get_compact_key, queue_message
from aioquic.quic.connection import (
    PEER_META,
    PEER_META_LOCK,
    RSA_BIT_STRENGTH,
    create_peer_meta,
    resolve_hostname_from_url,
)


class QuiCCli:
    def __init__(self, send_function, configuration, urls, is_client=True):
        self.is_client = is_client
        self.send_function = send_function
        self.configuration = configuration
        self.urls = urls
        self.key_exchange_done = False
        if self.is_client:
            self.host, self.host_ip = resolve_hostname_from_url(self.urls[0])
            PEER_META_LOCK.acquire(timeout=5)
            peer_meta = create_peer_meta()
            key_bytes = get_compact_key(peer_meta["private_key"])
            queue_message(
                host_ip=self.host_ip,
                payload=key_bytes,
                queue=peer_meta["cid_queue"],
                public_key=None,
                is_public_key=True,
            )
            peer_meta["cid_queue"].put(os.urandom(20))
            PEER_META[self.host_ip] = peer_meta
            PEER_META_LOCK.release()

    def send_message(self, count):
        for i in range(count):
            asyncio.run(
                self.send_function(
                    configuration=self.configuration,
                    urls=self.urls,
                )
            )

    def process_message(self, cmd):
        if not cmd:
            return
        peer_meta = PEER_META.get(self.host_ip) if self.is_client else None
        if self.is_client and not self.key_exchange_done:
            self.send_message((RSA_BIT_STRENGTH // 128) + 1)
            self.key_exchange_done = True

        if cmd[0] == "m" and len(cmd) > 2 and cmd[1] == ":":
            count = queue_message(
                host_ip=self.host_ip,
                payload=cmd.encode("utf8"),
                queue=peer_meta["cid_queue"],
                public_key=peer_meta["public_key"],
                session_key=peer_meta.get("session_key"),
            )
            if self.is_client:
                self.send_message(count)
        elif cmd[0] == "f" and len(cmd) > 2 and cmd[1] == ":":
            data = open(cmd[2:], "rb").read()
            count = queue_message(
                host_ip=self.host_ip,
                payload=b"f" + data,
                queue=peer_meta["cid_queue"],
                public_key=peer_meta["public_key"],
                session_key=peer_meta.get("session_key"),
            )
            if self.is_client:
                self.send_message(count)
        elif cmd == "q":
            os._exit(0)

    def run_cli(self):
        print("m:MSG | f:FILE | q")
        while True:
            cmd = input("> ").strip()
            self.process_message(cmd)
