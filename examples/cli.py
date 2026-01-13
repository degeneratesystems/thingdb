#!/usr/bin/env python3
import sys
import json
import requests
import secrets
from thingdb.db import ThingDB
from thingdb.db import Ed25519PrivateKey
from pathlib import Path

USAGE = """
Usage: cli.py <db_path> <passphrase> <command> [args...]

Commands:
  put <thing_id> <json_data>                  Store/update a thing
  get <thing_id>                              Show latest thing
  export                                      Print ledger lines (JSON lines)
  import-url <http://peer> [token]            Fetch ledger from peer and import (use token for auth)
    upload-file <url> <file> [token]             Upload a file to peer in resumable chunks
  serve <network_passphrase> [port] [cert key] Run peer HTTP server
  gen-node-key                                 Generate and save node X25519 key (encrypted)
  register-peer <peer_id> <x25519_pub_b64>     Add a peer's X25519 public key
  add-token <token> <json_info>                Add API token
"""


def main(argv):
    if len(argv) < 4:
        print(USAGE)
        return
    db_path = argv[1]
    passphrase = argv[2]
    cmd = argv[3]

    db = ThingDB(db_path, passphrase, network_passphrase=passphrase)
    # try to load node encryption key if present so import can verify/decrypt
    try:
        db.load_node_x25519_encrypted(str(Path(db_path) / "node_x25519.enc"))
    except Exception:
        pass

    if cmd == "put":
        if len(argv) < 6:
            print("put requires thing_id and json_data")
            return
        thing_id = argv[4]
        data = json.loads(argv[5])
        # use or create an actor key
        keypath = Path(db_path) / "actor_key.enc"
        if not keypath.exists():
            actor = db.generate_actor_keypair()
            db.save_private_key_encrypted(actor, str(keypath))
            actor_priv = actor
        else:
            actor_priv = db.load_private_key_encrypted(str(keypath))
        h = db.put(thing_id, data, actor_priv, "cli-user")
        print("written", h)

    elif cmd == "get":
        thing_id = argv[4]
        print(db.get_latest(thing_id))

    elif cmd == "export":
        for l in db.export_ledger_lines():
            print(l)

    elif cmd == "import-url":
        if len(argv) < 5:
            print("import-url requires a URL")
            return
        url = argv[4].rstrip("/") + "/export"
        token = argv[5] if len(argv) > 5 else None
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        r = requests.get(url, headers=headers)
        lines = r.json()
        res = db.import_remote_lines(lines)
        print(res)

    elif cmd == "serve":
        netpw = argv[4] if len(argv) > 4 else passphrase
        port = int(argv[5]) if len(argv) > 5 else 5000
        cert = argv[6] if len(argv) > 6 else None
        key = argv[7] if len(argv) > 7 else None
        print("Starting server...")
        import subprocess
        args = [sys.executable, "examples/peer_server.py", db_path, netpw, str(port)]
        if cert and key:
            args += [cert, key]
        subprocess.run(args)

    elif cmd == "gen-node-key":
        priv = db.generate_node_x25519()
        db.save_node_x25519_encrypted(priv, str(Path(db_path) / "node_x25519.enc"))
        print("generated and saved node X25519 key")

    elif cmd == "register-peer":
        if len(argv) < 6:
            print("register-peer requires peer_id and x25519_pub_b64")
            return
        pid = argv[4]
        pubb = argv[5]
        db.register_peer(pid, pubb)
        print("registered peer", pid)

    elif cmd == "add-token":
        elif cmd == "upload-file":
            if len(argv) < 6:
                print("upload-file requires url and file path")
                return
            url = argv[4].rstrip("/")
            filepath = argv[5]
            token = argv[6] if len(argv) > 6 else None
            headers = {"Authorization": f"Bearer {token}"} if token else {}
            # start upload
            r = requests.post(f"{url}/upload_start", headers=headers)
            if r.status_code != 200:
                print("failed to start upload", r.text)
                return
            upload_id = r.json().get("upload_id")
            # send chunks
            with open(filepath, "rb") as f:
                idx = 0
                while True:
                    b = f.read(4096)
                    if not b:
                        break
                    h = dict(headers)
                    h.update({"Upload-Id": upload_id, "Chunk-Index": str(idx)})
                    rr = requests.post(f"{url}/upload_chunk", headers=h, data=b)
                    if rr.status_code != 200:
                        print("chunk upload failed", rr.status_code, rr.text)
                        return
                    idx += 1
            # finish
            h = dict(headers)
            h.update({"Upload-Id": upload_id})
            rf = requests.post(f"{url}/upload_finish", headers=h)
            print(rf.status_code, rf.text)
        if len(argv) < 6:
            print("add-token requires token and json_info")
            return
        token = argv[4]
        info = json.loads(argv[5])
        db.add_token(token, info)
        print("added token")

    else:
        print("unknown command")


if __name__ == "__main__":
    main(sys.argv)
