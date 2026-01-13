#!/usr/bin/env python3
"""Simple HaLow-like benchmark for thingdb export/import with simulated bandwidth/latency.

This script creates two temporary ThingDB nodes, writes N small entries to the source node,
then transfers the ledger stream to the target node using a simulated limited-bandwidth
link (sleep between chunk sends). It reports elapsed wall time and throughput.
"""
import time
import tempfile
import shutil
import os
from pathlib import Path

from thingdb.db import ThingDB
from thingdb.db import Ed25519PrivateKey
import base64
import json
import secrets


def simulate_transfer(chunks_iter, bandwidth_bytes_per_sec: int = 1024, latency_sec: float = 0.05):
    """Simulate a constrained link by sleeping to maintain bandwidth and latency.

    Yields the same chunks but with sleeps between them to simulate throughput.
    """
    bytes_sent = 0
    start = time.time()
    for c in chunks_iter:
        # enforce per-chunk latency
        time.sleep(latency_sec)
        yield c
        bytes_sent += len(c)
        # throttle to bandwidth
        elapsed = time.time() - start
        if elapsed > 0:
            expected = bytes_sent / bandwidth_bytes_per_sec
            if expected > elapsed:
                time.sleep(expected - elapsed)


def make_actor_key():
    return ThingDB.generate_actor_keypair()


def run_demo(num_entries: int = 200, bandwidth: int = 1024, latency: float = 0.05):
    tmpdir = Path(tempfile.mkdtemp(prefix="thingdb-halow-"))
    src_dir = tmpdir / "nodeA"
    dst_dir = tmpdir / "nodeB"
    try:
        src_dir.mkdir()
        dst_dir.mkdir()
        src = ThingDB(str(src_dir), password="node-pass")
        dst = ThingDB(str(dst_dir), password="node-pass")

        # generate and load node keys so recipients include node
        a_priv = ThingDB.generate_node_x25519()
        src.save_node_x25519_encrypted(a_priv, str(src_dir / "node_x25519.enc"), passphrase="node-pass")
        src.load_node_x25519_encrypted(str(src_dir / "node_x25519.enc"), passphrase="node-pass")
        b_priv = ThingDB.generate_node_x25519()
        dst.save_node_x25519_encrypted(b_priv, str(dst_dir / "node_x25519.enc"), passphrase="node-pass")
        dst.load_node_x25519_encrypted(str(dst_dir / "node_x25519.enc"), passphrase="node-pass")

        # register each node as a peer of the other so CEK envelopes include both recipients
        # extract public bytes and register
        src_pub = a_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        dst_pub = b_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        src.register_peer("nodeB", base64.b64encode(dst_pub).decode())
        dst.register_peer("nodeA", base64.b64encode(src_pub).decode())

        # create an actor key
        actor = ThingDB.generate_actor_keypair()

        print(f"Writing {num_entries} entries to source node...")
        for i in range(num_entries):
            data = {"i": i, "payload": secrets.token_hex(16)}
            src.put(f"thing-{i}", data, actor_priv=actor, actor_name="bench")

        print("Exporting ledger as compressed chunks and transferring over simulated link...")
        chunks = src.export_ledger_stream(chunk_size=1024, compress=True)
        start = time.time()
        transferred = 0
        # perform simulated transfer
        received_chunks = []
        for c in simulate_transfer(chunks, bandwidth_bytes_per_sec=bandwidth, latency_sec=latency):
            received_chunks.append(c)
            transferred += len(c)
        duration = time.time() - start

        print(f"Transfer completed: {transferred} bytes in {duration:.2f}s ({transferred/duration:.1f} B/s)")

        # import into dst
        print("Importing into destination node...")
        start = time.time()
        res = dst.import_ledger_stream(iter(received_chunks))
        dur2 = time.time() - start
        print(f"Import result: {res}, import time {dur2:.2f}s")

    finally:
        # cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("-n", "--num", type=int, default=200)
    p.add_argument("-b", "--bandwidth", type=int, default=1024)
    p.add_argument("-l", "--latency", type=float, default=0.05)
    args = p.parse_args()
    run_demo(num_entries=args.num, bandwidth=args.bandwidth, latency=args.latency)
