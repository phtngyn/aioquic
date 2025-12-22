import math
import os
from collections import Counter
from queue import Empty, Queue

from aioquic.quic.ccrypto import CHACHA20_KEY_SIZE, SEQUENCE_BYTES, queue_message


def shannon_entropy(samples):
    counts = Counter(samples)
    total = len(samples)
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def generate_cids(request_count):
    queue = Queue()
    session_key = os.urandom(CHACHA20_KEY_SIZE)
    modulo = 1 << (SEQUENCE_BYTES * 8)
    cids = []

    for seq in range(request_count):
        produced = queue_message(
            host_ip="127.0.0.1",
            payload=b"entropy-check",
            queue=queue,
            public_key=None,
            sequence=seq % modulo,
            session_key=session_key,
        )

        if not produced:
            raise RuntimeError("queue_message emitted no CIDs")

        for _ in range(produced):
            try:
                cids.append(queue.get(timeout=1.0))
            except Empty:
                raise RuntimeError("CID queue drained unexpectedly")

    return cids


def entropy_by_byte(cids, min_samples=100):
    max_length = max(len(cid) for cid in cids)
    entropies = []

    # We loop over all potential byte positions
    for index in range(max_length):
        byte_samples = [cid[index] for cid in cids if len(cid) > index]

        # If we don't have enough samples for a valid stat, stop or mark as None
        if len(byte_samples) < min_samples:
            entropies.append(None)  # Or break
        else:
            entropies.append(shannon_entropy(byte_samples))

    return entropies


def main():
    sample_requests = 2048
    cids = generate_cids(sample_requests)
    entropies = entropy_by_byte(cids)

    valid_entropies = [e for e in entropies if e is not None]

    print(f"sampled_cids={len(cids)}")
    print(f"mean_entropy={sum(valid_entropies) / len(valid_entropies):.3f} bits")

    min_ent = min(valid_entropies)
    if min_ent < 7.5:
        print(f"WARNING: Low entropy detected: {min_ent:.3f} bits")

    for idx, value in enumerate(entropies):
        if value is not None:
            print(f"byte[{idx}]={value:.3f} bits")
        else:
            print(f"byte[{idx}]= (insufficient samples)")


if __name__ == "__main__":
    main()
