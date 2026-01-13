#!/usr/bin/env python3
import sys
import tempfile
from pathlib import Path
from thingdb.db import ThingDB
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def demo(db_path: str, password: str):
    db = ThingDB(db_path, password)

    # generate an actor key and save to temp file
    actor = ThingDB.generate_actor_keypair()
    priv_pem = Path(db_path) / "actor_key.pem"
    ThingDB.save_private_key_to_pem(actor, str(priv_pem))

    # load private key (demo of utility)
    actor_priv = ThingDB.load_private_key_from_pem(str(priv_pem))

    thing_id = "thing-123"
    print("Writing first version...")
    db.put(thing_id, {"value": 42, "note": "initial"}, actor_priv, "alice", action="create")

    print("Updating value...")
    db.put(thing_id, {"value": 43, "note": "increment"}, actor_priv, "alice", action="update")

    latest = db.get_latest(thing_id)
    print("Latest payload:", latest)

    chain = db.provenance_chain(thing_id)
    print("Provenance entries:")
    for i, rec in enumerate(chain):
        p = rec["payload"]
        print(f"[{i}] ts={p['timestamp']} actor={p['actor']} action={p['action']} data={p['data']}")

    print("Verifying chain:", db.verify_chain(thing_id))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: run_demo.py <db_path> <passphrase>")
        sys.exit(2)
    demo(sys.argv[1], sys.argv[2])
