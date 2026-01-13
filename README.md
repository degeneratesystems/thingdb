ThingDB — Encrypted thing-based database with provenance

Prototype overview

- Stores append-only ledger entries for "things".
- Each entry contains: thing id, timestamp, actor, data, data hash, prev hash, signature, and actor public key.
- Each entry payload is encrypted with an AES-GCM key derived from a passphrase.
- Entries are chained via SHA256(prev ciphertext) to provide tamper-evident provenance.

Features

- Append-only ndjson ledger per node
- AES-GCM payload encryption with per-entry CEK
- Ed25519 signatures for provenance
- Optional envelope mode: per-peer CEK wrapping via X25519/HKDF
- Flask peer server with token auth and TLS support

Quick start

1. Create a virtualenv and install deps:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the single-node demo:

```bash
PYTHONPATH=. python3 examples/run_demo.py /tmp/mydb "my strong passphrase"
```

Two-node TLS demo (local)

1. Prepare node directories and certs:

```bash
./scripts/setup_nodes.sh
```

2. Start peer servers (example):

```bash
# start nodeA
PYTHONPATH=. python3 examples/peer_server.py ./nodeA node-pass 5001 ./nodeA/cert.pem ./nodeA/key.pem &
# start nodeB
PYTHONPATH=. python3 examples/peer_server.py ./nodeB node-pass 5002 ./nodeB/cert.pem ./nodeB/key.pem &
```

3. Add an API token on nodeA (imports require a token with `import` scope):

```bash
PYTHONPATH=. python3 examples/cli.py ./nodeA node-pass add-token demo-import-token '{"name": "demo"}'
```

4. Create an entry on nodeB and push to nodeA (example):

```bash
# on host, write an entry to nodeB
PYTHONPATH=. python3 examples/cli.py ./nodeB node-pass put thing-online '{"value":999}'

# export nodeB lines and POST only those addressed to nodeA
python3 - <<'PY'
from thingdb.db import ThingDB
import json
db = ThingDB('./nodeB','node-pass')
lines = db.export_ledger_lines()
print(json.dumps(lines))
PY

# then POST to nodeA import endpoint with demo token (skip TLS verify for self-signed cert)
curl -k -H "Authorization: Bearer demo-import-token" -X POST https://127.0.0.1:5001/import -H "Content-Type: application/json" --data-binary @lines.json
```

Docker Compose demo

Use the provided `docker-compose.yml` to run both nodes in containers. Example:

```bash
docker compose build
docker compose up -d
```

Development

- Run tests locally: `python -m pytest -q`

See `examples/` for CLI and server usage, and `scripts/setup_nodes.sh` for an automated local setup.

CI: Docker demo

The repository includes a second CI job that attempts to run the Docker Compose demo on `ubuntu-latest` runners. It:

- checks out the code
- installs Python deps
- runs `scripts/setup_nodes.sh` to generate `nodeA`/`nodeB` directories and certs
- runs `docker compose build` and `docker compose up -d`
- performs a quick smoke test against nodeA `/export`
- tears down the compose stack

Note: this attempts to run the demo on GitHub-hosted runners and may work for most cases. If you require more control (custom networking, privileged mounts, long-lived volumes), use a self-hosted runner.

Self-hosted runner setup

If you want the CI to run the full Docker Compose demo on your own hardware (recommended for repeatable demos), register a self-hosted runner for this repo and run the `./.github/self-hosted/runner-setup.sh` helper on that host.

1. Create a registration token: go to the repo Settings → Actions → Runners → New self-hosted runner → Follow instructions, copy the registration token.
2. Edit `./.github/self-hosted/runner-setup.sh`: set `REPO="OWNER/thingdb"` and `TOKEN="<REGISTRATION_TOKEN>"`.
3. Run the script as root on the runner host:

```bash
sudo bash ./.github/self-hosted/runner-setup.sh
```

After the runner is online, GitHub Actions will be able to schedule the `docker_demo` job on it.
