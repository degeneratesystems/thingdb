import os
import time
import json
import base64
import tempfile
import subprocess
import requests
from pathlib import Path
from thingdb.db import ThingDB


def run_server_in_bg(db_path, netpw, port, cert=None, key=None):
    repo = Path('/tmp/thingdb')
    script = str(repo / 'examples' / 'peer_server.py')
    args = ["python3", script, db_path, netpw, str(port)]
    if cert and key:
        args += [cert, key]
    env = os.environ.copy()
    env['PYTHONPATH'] = str(repo)
    p = subprocess.Popen(args, env=env)
    return p


def test_decentralized_sync(tmp_path):
    # setup node A and node B directories
    base = Path(str(tmp_path))
    nodeA = base / "nodeA"
    nodeB = base / "nodeB"
    nodeA.mkdir()
    nodeB.mkdir()

    # create ThingDB instances and generate node keys
    dbA = ThingDB(str(nodeA), "node-pass")
    dbB = ThingDB(str(nodeB), "node-pass")

    a_key = dbA.generate_node_x25519()
    dbA.save_node_x25519_encrypted(a_key, str(nodeA / "node_x25519.enc"))
    b_key = dbB.generate_node_x25519()
    dbB.save_node_x25519_encrypted(b_key, str(nodeB / "node_x25519.enc"))

    # exchange public keys
    pubA = base64.b64encode(a_key.public_key().public_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)).decode()
    pubB = base64.b64encode(b_key.public_key().public_bytes(encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.Raw, format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.Raw)).decode()
    dbA.register_peer('nodeB', pubB)
    dbB.register_peer('nodeA', pubA)

    # generate temporary self-signed cert for server A
    cert = str(nodeA / 'cert.pem')
    key = str(nodeA / 'key.pem')
    subprocess.run(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"], check=True)

    # add an API token on nodeA
    token = 'testtoken'
    dbA.add_token(token, {"name": "test-client"})

    # start server A with TLS
    p = run_server_in_bg(str(nodeA), "node-pass", 5443, cert, key)
    try:
        time.sleep(1.0)
        # create actor key for nodeA and write an entry using the library
        actor = ThingDB.generate_actor_keypair()
        dbA.save_private_key_encrypted(actor, str(nodeA / 'actor_key.enc'))
        actor_priv = dbA.load_private_key_encrypted(str(nodeA / 'actor_key.enc'))
        dbA.load_node_x25519_encrypted(str(nodeA / 'node_x25519.enc'))
        dbA.put('thing-sync', {'value': 123}, actor_priv, 'alice', action='create')

        # fetch exported lines (allow self-signed cert: verify=False)
        r = requests.get('https://127.0.0.1:5443/export', verify=False)
        assert r.status_code == 200
        lines = r.json()

        # try to import into nodeB using token (simulate sending token header)
        # but import endpoint on nodeA requires token; instead import locally using dbB.import_remote_lines
        dbB.load_node_x25519_encrypted(str(nodeB / 'node_x25519.enc'))
        res = dbB.import_remote_lines(lines)
        assert res['added'] >= 1
        assert dbB.verify_chain('thing-sync')
    finally:
        p.terminate()
        p.wait()
