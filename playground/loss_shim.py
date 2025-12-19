import argparse
import asyncio
import logging
import random
import time

logger = logging.getLogger("loss_shim")


class UDPRelayProtocol(asyncio.DatagramProtocol):
    def __init__(
        self, target_addr, drop_rate_in, drop_rate_out, start_time, grace_period
    ):
        self.target_addr = target_addr  # (IP, Port)
        self.drop_rate_in = drop_rate_in
        self.drop_rate_out = drop_rate_out
        self.start_time = start_time
        self.grace_period = grace_period
        self.transport = None
        self.peer_addr = None  # Client Address

    def connection_made(self, transport):
        self.transport = transport

    def should_drop(self, rate):
        if time.time() - self.start_time < self.grace_period:
            return False
        return random.random() < rate

    def datagram_received(self, data, addr):
        # Determine direction based on whether the Sender matches the TARGET SERVER
        # Note: addr can be (host, port) or (host, port, flow, scope) for IPv6.
        # We compare the first two elements (IP and Port).
        is_from_server = (
            addr[0] == self.target_addr[0] and addr[1] == self.target_addr[1]
        )

        if is_from_server:
            # -----------------------------
            # Direction: Server -> Client
            # -----------------------------
            if self.should_drop(self.drop_rate_out):
                logger.debug(f"Dropped packet (Server -> Client) [{len(data)} bytes]")
                return

            # Forward to the LAST KNOWN client address
            if self.peer_addr:
                self.transport.sendto(data, self.peer_addr)

        else:
            # -----------------------------
            # Direction: Client -> Server
            # -----------------------------
            # Always update peer_addr to the current client port
            if self.peer_addr != addr:
                self.peer_addr = addr
                logger.info(f"Client port update: {addr}")

            if self.should_drop(self.drop_rate_in):
                logger.debug(f"Dropped packet (Client -> Server) [{len(data)} bytes]")
                return

            self.transport.sendto(data, self.target_addr)


async def main(args):
    loop = asyncio.get_running_loop()
    start_time = time.time()

    logger.info(f"Starting Loss Shim on {args.listen_host}:{args.listen_port}")
    logger.info(f"Forwarding to {args.target_host}:{args.target_port}")
    logger.info(f"Grace Period: {args.grace_period} seconds (No drops)")
    logger.info(
        f"Drop Rates after grace: In={args.drop_in * 100:.1f}% | Out={args.drop_out * 100:.1f}%"
    )

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: UDPRelayProtocol(
            target_addr=(args.target_host, args.target_port),
            drop_rate_in=args.drop_in,
            drop_rate_out=args.drop_out,
            start_time=start_time,
            grace_period=args.grace_period,
        ),
        local_addr=(args.listen_host, args.listen_port),
    )

    try:
        await asyncio.Future()
    finally:
        transport.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="UDP Packet Loss Shim")
    parser.add_argument("--listen-host", default="::1", help="Shim listen address")
    parser.add_argument(
        "--listen-port", type=int, default=4434, help="Shim listen port"
    )
    parser.add_argument("--target-host", default="::1", help="Real Server address")
    parser.add_argument(
        "--target-port", type=int, default=4433, help="Real Server port"
    )
    parser.add_argument(
        "--drop-in",
        type=float,
        default=0.05,
        help="Client->Server drop rate (0.0 - 1.0)",
    )
    parser.add_argument(
        "--drop-out",
        type=float,
        default=0.00,
        help="Server->Client drop rate (0.0 - 1.0)",
    )
    parser.add_argument(
        "--grace-period",
        type=float,
        default=5.0,
        help="Seconds to wait before dropping packets",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Log dropped packets"
    )

    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
    )

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        pass
