#!/usr/bin/env python3
from flask import Flask, request, jsonify
import sys
import json
import base64
import hashlib
from thingdb.db import ThingDB
from typing import List

app = Flask(__name__)
_db: ThingDB = None


def _line_cipher_hash(line: str) -> str:
    try:
        obj = json.loads(line)
        if "payload" in obj and "ciphertext" in obj["payload"]:
            b = base64.b64decode(obj["payload"]["ciphertext"])
        elif "ciphertext" in obj:
            b = base64.b64decode(obj["ciphertext"])
        else:
            return ""
        return hashlib.sha256(b).hexdigest()
    except Exception:
        return ""


@app.route("/export", methods=["GET"])
def export_ledger():
    since = request.args.get("since")
    lines = _db.export_ledger_lines()
    if since:
        # find index of line matching since hash and return following lines
        out: List[str] = []
        seen = False
        for l in lines:
            h = _line_cipher_hash(l)
            if seen:
                out.append(l)
            if h == since:
                seen = True
        return jsonify(out)
    return jsonify(lines)


@app.route("/export_stream", methods=["GET"])
def export_stream():
    # stream compressed ledger bytes (zlib) to client
    compress = request.args.get("compress", "1") != "0"

    def generate():
        for chunk in _db.export_ledger_stream(chunk_size=4096, compress=compress):
            yield chunk

    # application/octet-stream is fine; consumer should know whether it's compressed
    return app.response_class(generate(), mimetype="application/octet-stream")


@app.route("/import", methods=["POST"])
def import_ledger():
    # simple token auth
    auth = request.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    info = _db.verify_token(token) if token else None
    # require token to have import scope
    if not info or "import" not in info.get("scopes", []):
        return jsonify({"error": "unauthorized or insufficient scope"}), 401

    payload = request.get_json()
    if not isinstance(payload, list):
        return jsonify({"error": "expected list of lines"}), 400
    res = _db.import_remote_lines(payload)
    return jsonify(res)


@app.route("/import_stream", methods=["POST"])
def import_stream():
    # simple token auth
    auth = request.headers.get("Authorization", "")
    token = None
    if auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
    info = _db.verify_token(token) if token else None
    if not info or "import" not in info.get("scopes", []):
        return jsonify({"error": "unauthorized or insufficient scope"}), 401

    # stream the incoming bytes in chunks to the db importer
    def chunks():
        # Flask provides request.stream as a file-like
        while True:
            b = request.stream.read(4096)
            if not b:
                break
            yield b

    res = _db.import_ledger_stream(chunks())
    return jsonify(res)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: peer_server.py <db_path> <node_password> [network_passphrase] [port] [cert.pem key.pem]")
        sys.exit(2)
    db_path = sys.argv[1]
    node_password = sys.argv[2]
    # flexible arg parsing:
    # usage variants supported:
    # 1) db_path node_password
    # 2) db_path node_password network_passphrase
    # 3) db_path node_password port
    # 4) db_path node_password network_passphrase port
    # optional cert/key may follow (as last two args)
    netpw = node_password
    port = 5000
    cert = None
    key = None
    if len(sys.argv) > 3:
        a3 = sys.argv[3]
        if a3.isdigit():
            port = int(a3)
        else:
            netpw = a3
    if len(sys.argv) > 4:
        a4 = sys.argv[4]
        if a4.isdigit():
            port = int(a4)
        else:
            cert = a4
    if len(sys.argv) > 5:
        key = sys.argv[5]
    _db = ThingDB(db_path, node_password, network_passphrase=netpw)
    # try to load node encryption key if present
    try:
        _db.load_node_x25519_encrypted(str(_db.node_enc_path))
    except Exception:
        pass

    if cert and key:
        app.run(host="0.0.0.0", port=port, ssl_context=(cert, key))
    else:
        app.run(host="0.0.0.0", port=port)
