ThingDB — Encrypted thing-based database with provenance

Prototype overview

- Stores append-only ledger entries for "things".
- Each entry contains: thing id, timestamp, actor, data, data hash, prev hash, signature, and actor public key.
- Each entry payload is encrypted with an AES-GCM key derived from a passphrase.
- Entries are chained via SHA256(prev ciphertext) to provide tamper-evident provenance.

Quick start

1. Create a virtualenv and install deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the demo:

```bash
python examples/run_demo.py /tmp/mydb "my strong passphrase"
```

The demo creates an actor keypair, writes a couple of updates for a thing, prints the latest value and verifies the provenance chain.

**Decentralized workflow (TLS + token example)**

- Generate node keys for each node and register peers' X25519 public keys.
- Start a peer server with TLS:

```bash
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/peer_server.py /tmp/thingdb/nodeA node-pass 5443 cert.pem key.pem
```

- Add an API token to the node (so imports are authenticated):

```bash
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py /tmp/thingdb/nodeA node-pass add-token mytoken '{"name":"peer"}'
```

- From a peer, fetch exported lines and import (example using the CLI):

```bash
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py /tmp/thingdb/nodeB node-pass import-url https://nodeA:5443 mytoken
```

The repository contains `tests/test_decentralized_sync.py` which runs an automated two-node TLS sync demonstration.
