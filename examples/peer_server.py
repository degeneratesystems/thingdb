from flask import Flask, request, jsonify, Response, stream_with_context, send_file
from werkzeug.utils import secure_filename
from thingdb import ThingDB
from thingdb.db import load_node_keys
from pathlib import Path
import os, json, secrets, time, hashlib, shutil
from functools import wraps

app = Flask(__name__)

def _ensure_upload_dir(data_dir):
    up_dir = os.path.join(data_dir, "uploads")
    os.makedirs(up_dir, exist_ok=True)
    return up_dir

def _token_ok(db, token):
    if not token:
        return None
    return db.tokens.get(token)

def require_token(db):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token = None
            if auth.startswith("Bearer "):
                token = auth.split(None, 1)[1]
            t = _token_ok(db, token)
            if not t:
                return jsonify({"error": "unauthorized"}), 401
            request._token = t
            request._token_raw = token
            return f(*args, **kwargs)
        return wrapper
    return deco

def cleanup_expired_uploads(data_dir, expire_seconds=None):
    if expire_seconds is None:
        expire_seconds = int(os.environ.get('THINGDB_UPLOAD_EXPIRY', 24 * 3600))
    up_dir = _ensure_upload_dir(data_dir)
    now = time.time()
    removed = []
    for name in os.listdir(up_dir):
        d = os.path.join(up_dir, name)
        meta = os.path.join(d, 'meta.json')
        try:
            if not os.path.exists(meta):
                shutil.rmtree(d)
                removed.append(name)
                continue
            with open(meta, 'r') as f:
                m = json.load(f)
            if now - m.get('created_at', 0) > expire_seconds:
                shutil.rmtree(d)
                removed.append(name)
        except Exception:
            continue
    return removed

def create_app(data_dir, db_password):
    db = ThingDB(data_dir, db_password)
    token_deco = require_token(db)

    @app.route('/export', methods=['GET'])
    def export_all():
        out = []
        for line in db._read_ledger_records():
            out.append(line)
        return jsonify(out)

    @app.route('/export_stream', methods=['GET'])
    def export_stream():
        chunk_size = int(request.args.get('chunk', 65536))
        gen = db.export_ledger_stream(chunk_size=chunk_size, compress=True)
        return Response(stream_with_context(gen), mimetype='application/octet-stream')

    @app.route('/import', methods=['POST'])
    @token_deco
    def import_lines():
        payload = request.get_json() or []
        result = db.import_remote_lines(payload)
        return jsonify(result)

    @app.route('/import_stream', methods=['POST'])
    @token_deco
    def import_stream():
        def stream_iter():
            while True:
                chunk = request.stream.read(65536)
                if not chunk:
                    break
                yield chunk
        try:
            result = db.import_ledger_stream(stream_iter())
        except Exception as e:
            return jsonify({'error': 'import_failed', 'detail': str(e)}), 500
        return jsonify(result)

    @app.route('/upload_start', methods=['POST'])
    @token_deco
    def upload_start():
        cleanup_expired_uploads(data_dir)
        token_info = request._token
        max_uploads = token_info.get('max_uploads', 5)
        up_dir = _ensure_upload_dir(data_dir)
        active = 0
        for name in os.listdir(up_dir):
            p = os.path.join(up_dir, name, 'meta.json')
            if os.path.exists(p):
                try:
                    with open(p, 'r') as f:
                        m = json.load(f)
                    if m.get('token') == request._token_raw:
                        active += 1
                except Exception:
                    continue
        if active >= max_uploads:
            return jsonify({'error': 'too_many_concurrent_uploads'}), 429

        upload_id = secrets.token_hex(12)
        target_dir = os.path.join(up_dir, upload_id)
        os.makedirs(target_dir, exist_ok=False)
        meta = {
            'created_at': time.time(),
            'chunks': [],
            'token': request._token_raw,
            'total_bytes': 0,
        }
        with open(os.path.join(target_dir, 'meta.json'), 'w') as f:
            json.dump(meta, f)
        return jsonify({'upload_id': upload_id})

    @app.route('/upload_status/<upload_id>', methods=['GET'])
    @token_deco
    def upload_status(upload_id):
        up_dir = os.path.join(_ensure_upload_dir(data_dir), upload_id)
        if not os.path.exists(up_dir):
            return jsonify({'error': 'not_found'}), 404
        meta_path = os.path.join(up_dir, 'meta.json')
        if not os.path.exists(meta_path):
            return jsonify({'error': 'meta_missing'}), 500
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        if meta.get('token') != request._token_raw and 'admin' not in request._token.get('scopes', []):
            return jsonify({'error': 'forbidden'}), 403
        return jsonify(meta)

    @app.route('/upload_chunk/<upload_id>', methods=['POST'])
    @token_deco
    def upload_chunk(upload_id):
        up_dir = os.path.join(_ensure_upload_dir(data_dir), upload_id)
        if not os.path.exists(up_dir):
            return jsonify({'error': 'not_found'}), 404
        meta_path = os.path.join(up_dir, 'meta.json')
        if not os.path.exists(meta_path):
            return jsonify({'error': 'meta_missing'}), 500
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        if meta.get('token') != request._token_raw and 'admin' not in request._token.get('scopes', []):
            return jsonify({'error': 'forbidden'}), 403

        chunk = request.get_data()
        max_chunk = request._token.get('max_chunk_size', 64 * 1024)
        if len(chunk) > max_chunk:
            return jsonify({'error': 'chunk_too_large', 'max_chunk': max_chunk}), 413
        max_upload_size = request._token.get('max_upload_size', 10 * 1024 * 1024)
        if meta.get('total_bytes', 0) + len(chunk) > max_upload_size:
            return jsonify({'error': 'upload_too_large', 'max_upload_size': max_upload_size}), 413

        idx = len([n for n in os.listdir(up_dir) if n.startswith('chunk_')])
        fname = os.path.join(up_dir, f'chunk_{idx:06d}')
        with open(fname, 'wb') as f:
            f.write(chunk)
        s = hashlib.sha256(chunk).hexdigest()
        meta['chunks'].append({'idx': idx, 'sha256': s, 'len': len(chunk)})
        meta['total_bytes'] = meta.get('total_bytes', 0) + len(chunk)
        with open(meta_path, 'w') as f:
            json.dump(meta, f)
        return jsonify({'idx': idx, 'sha256': s, 'len': len(chunk)})

    @app.route('/upload_finish/<upload_id>', methods=['POST'])
    @token_deco
    def upload_finish(upload_id):
        up_dir = os.path.join(_ensure_upload_dir(data_dir), upload_id)
        if not os.path.exists(up_dir):
            return jsonify({'error': 'not_found'}), 404
        meta_path = os.path.join(up_dir, 'meta.json')
        if not os.path.exists(meta_path):
            return jsonify({'error': 'meta_missing'}), 500
        with open(meta_path, 'r') as f:
            meta = json.load(f)
        if meta.get('token') != request._token_raw and 'admin' not in request._token.get('scopes', []):
            return jsonify({'error': 'forbidden'}), 403

        parts = []
        for n in sorted([n for n in os.listdir(up_dir) if n.startswith('chunk_')]):
            with open(os.path.join(up_dir, n), 'rb') as f:
                parts.append(f.read())
        data = b"".join(parts)
        try:
            result = db.import_ledger_stream([data])
        except Exception as e:
            return jsonify({'error': 'import_failed', 'detail': str(e)}), 500
        shutil.rmtree(up_dir)
        return jsonify(result)

    @app.route('/admin/cleanup_uploads', methods=['POST'])
    @token_deco
    def admin_cleanup():
        if 'admin' not in request._token.get('scopes', []):
            return jsonify({'error': 'forbidden'}), 403
        expire = request.get_json() or {}
        secs = expire.get('expire_seconds')
        removed = cleanup_expired_uploads(data_dir, secs)
        return jsonify({'removed': removed})

    return app, db

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print("Usage: peer_server.py <data_dir> <db_pass> [port] [cert] [key]")
        raise SystemExit(2)
    data_dir = sys.argv[1]
    db_pass = sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else 5443
    cert = sys.argv[4] if len(sys.argv) > 4 else None
    key = sys.argv[5] if len(sys.argv) > 5 else None
    app, db = create_app(data_dir, db_pass)
    if cert and key:
        app.run(host='0.0.0.0', port=port, ssl_context=(cert, key))
    else:
        app.run(host='0.0.0.0', port=port)
