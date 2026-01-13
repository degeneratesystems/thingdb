#!/usr/bin/env bash
set -euo pipefail
BASE=/tmp/thingdb
NODEA=$BASE/nodeA
NODEB=$BASE/nodeB
mkdir -p "$NODEA" "$NODEB"

echo "Generating node X25519 keys..."
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py "$NODEA" node-pass gen-node-key
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py "$NODEB" node-pass gen-node-key

echo "Extracting public keys..."
PUBA=$(PYTHONPATH=/tmp/thingdb python3 - <<PY
from thingdb.db import ThingDB
import base64

db=ThingDB('$NODEA','node-pass')
db.load_node_x25519_encrypted('$NODEA/node_x25519.enc')
print(base64.b64encode(db._node_x25519.public_key().public_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)).decode())
PY
)

PUBB=$(PYTHONPATH=/tmp/thingdb python3 - <<PY
from thingdb.db import ThingDB
import base64

db=ThingDB('$NODEB','node-pass')
db.load_node_x25519_encrypted('$NODEB/node_x25519.enc')
print(base64.b64encode(db._node_x25519.public_key().public_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)).decode())
PY
)

echo "Registering peers..."
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py "$NODEA" node-pass register-peer nodeB "$PUBB"
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py "$NODEB" node-pass register-peer nodeA "$PUBA"

echo "Generating self-signed TLS certs for nodeA and nodeB..."
# nodeA cert
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$NODEA/key.pem" -out "$NODEA/cert.pem" -days 365 -subj "/CN=localhost"
# nodeB cert
openssl req -x509 -nodes -newkey rsa:2048 -keyout "$NODEB/key.pem" -out "$NODEB/cert.pem" -days 365 -subj "/CN=localhost"

echo "Adding API token with 'import' scope to nodeA..."
TOK="demo-import-token"
PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/cli.py "$NODEA" node-pass add-token "$TOK" '{"name":"demo-client","scopes":["import"],"expires_in":3600}'

echo "Setup complete. NodeA and NodeB prepared under $BASE/nodeA and $BASE/nodeB"

echo "To run with docker-compose (from /tmp/thingdb):"
echo "  docker-compose up --build"

echo "Or run servers manually (example):"
echo "  PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/peer_server.py $NODEA node-pass 5001 $NODEA/cert.pem $NODEA/key.pem &"
echo "  PYTHONPATH=/tmp/thingdb python3 /tmp/thingdb/examples/peer_server.py $NODEB node-pass 5002 $NODEB/cert.pem $NODEB/key.pem &"
