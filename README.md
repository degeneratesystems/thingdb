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

If you require more control (custom networking, privileged mounts, long-lived volumes), use a self-hosted runner.

Self-hosted runner setup
------------------------

If you want the CI to run the full Docker Compose demo on your own hardware (recommended for repeatable demos), register a self-hosted runner for this repo and run the `./.github/self-hosted/runner-setup.sh` helper on that host.

1. Create a registration token: go to the repo Settings → Actions → Runners → New self-hosted runner → Follow instructions, copy the registration token.
2. Edit `./.github/self-hosted/runner-setup.sh`: set `REPO="OWNER/thingdb"` and `TOKEN="<REGISTRATION_TOKEN>"`.
3. Run the script as root on the runner host:

```bash
sudo bash ./.github/self-hosted/runner-setup.sh
```

After the runner is online, GitHub Actions will be able to schedule the `docker_demo` job on it.

**Self-hosted Runner / docker_demo**

- **Purpose:** The `docker_demo` job in `.github/workflows/ci.yml` runs the two-node Docker Compose demo. For security and resource reasons it is configured to run on a self-hosted runner.
- **Register a runner:** On the machine that will host the runner, run:

```bash
# replace <PAT> with a short-lived personal access token (revoke/rotate afterwards)
GITHUB_TOKEN=<PAT> REPO=degeneratesystems/thingdb bash scripts/register-runner-auto.sh
```

- **Start the runner:** The register script creates an install directory and helper scripts; then either install and start the system service or run the runner directly from that directory:

```bash
# if the script created a systemd unit
sudo systemctl start actions.runner.degeneratesystems-thingdb.runner
sudo systemctl status actions.runner.degeneratesystems-thingdb.runner
# or from the runner dir
./svc.sh install
./svc.sh start
```

- **Add CI secrets:** Use the helper or `gh` to add secrets required by the workflow (example shown in `scripts/gh-set-secret.sh`).

- **Trigger the demo:** Push an empty commit or use the Actions UI to trigger the workflow. The `docker_demo` job will be picked up by your self-hosted runner when it is online and labeled correctly.

- **Security:** Revoke or rotate the PAT after registering the runner and updating secrets.

**Offline & Low-bandwidth / HaLow guidance**

This project is transport-agnostic: the ledger is stored as ndjson and can be transferred as files or streamed over any byte-oriented link. For operation over constrained networks (e.g., IEEE 802.11ah / HaLow) follow these recommendations:

- **Batch and compress:** Use the `export_ledger_stream(chunk_size, compress=True)` helper which streams a zlib-compressed byte stream. Consume it on the peer and call `import_ledger_stream()` to reconstitute and import entries.
- **Persistent connection:** Keep a single TCP/TLS session open when possible to avoid repeated TLS handshakes. If TCP isn't available, consider DTLS or a store-and-forward gateway.
- **Chunking & resume:** Transfer in reasonably sized chunks (1KiB–16KiB) to limit retransmit cost and support partial resume on failure.
- **Throttle & backoff:** On lossy/low-bandwidth links, limit sender throughput and back off on repeated failures. Our included `scripts/benchmark_halow.py` demonstrates simulated throttling.
- **MTU & fragmentation:** Split blobs to stay within the MTU of the link and reassemble on the receiver.
- **CPU & crypto:** AES-GCM + X25519 + Ed25519 are efficient but test on target devices. Reduce PBKDF2 iterations on constrained devices or use hardware crypto where available.

Example: use the included benchmark to simulate a 1KiB/s link with 50ms latency:

```bash
python3 scripts/benchmark_halow.py -n 200 -b 1024 -l 0.05
```

If you'd like, I can add a persistent TLS streaming endpoint to the peer server and a resumable transfer protocol (simple indexed-chunk upload) next.
Detailed usage
--------------

This section gives step-by-step commands and examples to run the project locally, run the two-node TLS demo, and run the Docker Compose demo.

Prerequisites
- Python 3.10+
- pip
- (For Docker/demo) Docker and Docker Compose installed locally

Install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

Run tests

```bash
python -m pytest -q
```

Single-node demo (quick)

```bash
# Run the demo which creates keys and writes a sample thing
PYTHONPATH=. python3 examples/run_demo.py /tmp/mydb "my strong passphrase"
```

Two-node TLS demo (local, step-by-step)

1) Prepare nodes (creates `nodeA` and `nodeB` directories with keys and self-signed TLS certs):

```bash
./scripts/setup_nodes.sh
```

2) Start peer servers (each in its own terminal or background):

```bash
# nodeA
PYTHONPATH=. python3 examples/peer_server.py ./nodeA node-pass 5001 ./nodeA/cert.pem ./nodeA/key.pem &
# nodeB
PYTHONPATH=. python3 examples/peer_server.py ./nodeB node-pass 5002 ./nodeB/cert.pem ./nodeB/key.pem &
```

3) Add API token to nodeA (imports require token with `import` scope):

```bash
PYTHONPATH=. python3 examples/cli.py ./nodeA node-pass add-token demo-import-token '{"name":"demo","scopes":["import"]}'
```

4) Register peers (so CEK is wrapped to recipients when writing entries):

```bash
# from nodeB register nodeA's X25519 public key (copy from ./nodeA/node_x25519.pub created by setup script)
PYTHONPATH=. python3 examples/cli.py ./nodeB node-pass register-peer nodeA $(cat ./nodeA/node_x25519.pub)
```

5) Create an entry on nodeB and push to nodeA:

```bash
# write entry to nodeB
PYTHONPATH=. python3 examples/cli.py ./nodeB node-pass put thing-online '{"value":999}'

# export nodeB ledger lines (JSON array) and POST to nodeA import endpoint
PYTHONPATH=. python3 - <<'PY' > /tmp/lines.json
from thingdb.db import ThingDB
import json
db = ThingDB('./nodeB','node-pass')
print(json.dumps(db.export_ledger_lines()))
PY

curl -k -H "Authorization: Bearer demo-import-token" -X POST https://127.0.0.1:5001/import -H "Content-Type: application/json" --data-binary @/tmp/lines.json
```

Docker Compose demo (local)

1) Ensure Docker and Docker Compose are installed locally.

2) Run the compose demo from repository root:

```bash
docker compose build
docker compose up -d
```

3) Once finished, tear down:

```bash
docker compose down --volumes
```

CI and runners
--------------
- The GitHub Actions workflow `ci.yml` runs unit tests on GitHub-hosted `ubuntu-latest` runners.
- The `docker_demo` job is configured to use `self-hosted` runners because Docker Compose and persistent resources are best run on your own host.
- To register a self-hosted runner, follow the README earlier steps or run `scripts/register-runner-auto.sh` on the host (requires a repo admin PAT / registration token).

Security and secrets
--------------------
- Do not commit private keys, tokens, or the `nodeA/` or `nodeB/` runtime directories — `.gitignore` excludes these.
- Revoke the PAT you provided after today's session if you want to rotate credentials. Create a new PAT for future automation with the minimum required scopes (`repo`, `workflow` if needed).

Support and contribution
------------------------
- See `CONTRIBUTING.md` for workflow and PR guidance.
- For security reports, use `SECURITY.md` guidelines.

Adding CI secrets
------------------

Most CI/automation credentials (docker registries, cloud API keys, deploy tokens) should be stored as GitHub Actions Secrets rather than embedded in the repository. You can add secrets via the GitHub web UI or using the `gh` CLI.

Web UI:

1. Go to your repository on GitHub: Settings → Secrets and variables → Actions → New repository secret.
2. Enter the secret name (e.g. `DOCKERHUB_USERNAME`) and its value, then Save.

Using the `gh` CLI (recommended for automation):

1. Install and authenticate `gh` (https://cli.github.com/).
2. Use the helper script included in this repo to set a secret:

```bash
# interactive: will prompt for value
./scripts/gh-set-secret.sh degeneratesystems thingdb MY_SECRET

# non-interactive (read value from env variable)
export SECRET_VALUE='sensitive-value'
./scripts/gh-set-secret.sh degeneratesystems thingdb MY_SECRET --env SECRET_VALUE

# or read from file
./scripts/gh-set-secret.sh degeneratesystems thingdb MY_SECRET --file /path/to/value.txt
```

Notes:
- Do not store long-lived PATs with excessive scopes. Create tokens with minimum privileges.
- If you need to store a Docker registry credential, use `DOCKERHUB_USERNAME` and `DOCKERHUB_PASSWORD` (or the equivalent for your registry) and reference them in workflows as `secrets.DOCKERHUB_USERNAME`.

