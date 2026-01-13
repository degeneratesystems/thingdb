import os
import json
import base64
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time


def _derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(password)


def _hkdf_shared(secret: bytes, info: bytes = b"thingdb-enc") -> bytes:
    hk = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info, backend=default_backend())
    return hk.derive(secret)


class ThingDB:
    """A small prototype: append-only encrypted ledger with cryptographic provenance.

    Each ledger line is a JSON object: {"nonce": <b64>, "ciphertext": <b64>}\n
    The decrypted payload contains a JSON object with fields:
      - thing_id, timestamp, actor, action, data, data_hash, prev_hash, signature (b64), pubkey (b64)

    prev_hash is computed as SHA256(ciphertext_bytes) of the previous entry for the same thing (or None).
    """

    def __init__(self, path: str, password: str, network_passphrase: Optional[str] = None):
        self.dir = Path(path)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ledger_path = self.dir / "ledger.ndjson"
        self.salt_path = self.dir / "salt.bin"
        self.peers_path = self.dir / "peers.json"
        self.node_enc_path = self.dir / "node_x25519.enc"
        self.tokens_path = self.dir / "tokens.json"

        if not self.salt_path.exists():
            salt = secrets.token_bytes(16)
            self.salt_path.write_bytes(salt)
        else:
            salt = self.salt_path.read_bytes()

        # If a network_passphrase is provided, use it as the ledger encryption key
        # so multiple peers that share the passphrase can decrypt each other's entries.
        if network_passphrase:
            self.network_mode = True
            self.key = _derive_key(network_passphrase.encode(), salt)
        else:
            self.network_mode = False
            self.key = _derive_key(password.encode(), salt)
        self.aesgcm = AESGCM(self.key)
        # load peers registry
        if self.peers_path.exists():
            try:
                self._peers = json.loads(self.peers_path.read_text())
            except Exception:
                self._peers = {}
        else:
            self._peers = {}

        # load tokens
        if self.tokens_path.exists():
            try:
                self._tokens = json.loads(self.tokens_path.read_text())
            except Exception:
                self._tokens = {}
        else:
            self._tokens = {}

        # node X25519 encryption key: if not exists, keep unset until user creates it
        self._node_x25519: Optional[X25519PrivateKey] = None
        if self.node_enc_path.exists():
            # leave encrypted on disk; use load_node_x25519_encrypted to decrypt when needed
            pass
        # keep the original node password for optional encrypted key storage
        self.node_password = password.encode()

    def _encrypt_payload(self, payload_bytes: bytes):
        # used to encrypt payload with a content encryption key (CEK)
        nonce = secrets.token_bytes(12)
        ct = self.aesgcm.encrypt(nonce, payload_bytes, None)
        return nonce, ct

    def _decrypt_entry(self, nonce: bytes, ciphertext: bytes) -> Dict[str, Any]:
        pt = self.aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(pt.decode())

    def _hash_bytes_hex(self, b: bytes) -> str:
        return hashlib.sha256(b).hexdigest()

    def _read_ledger_records(self) -> List[Dict[str, Any]]:
        # Returns list of dicts: supports both legacy lines {nonce,ciphertext} and
        # envelope lines {payload:{nonce,ciphertext}, recipients:[...], meta:{}}
        records = []
        if not self.ledger_path.exists():
            return records
        with self.ledger_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                # legacy format: direct nonce & ciphertext
                if "nonce" in obj and "ciphertext" in obj:
                    try:
                        nonce = base64.b64decode(obj["nonce"])
                        ciphertext = base64.b64decode(obj["ciphertext"])
                        decrypted = None
                        try:
                            pt = self.aesgcm.decrypt(nonce, ciphertext, None)
                            decrypted = json.loads(pt.decode())
                        except Exception:
                            decrypted = None
                        records.append({"payload": {"nonce": obj["nonce"], "ciphertext": obj["ciphertext"]}, "recipients": [], "meta": {}, "decrypted": decrypted, "raw": obj})
                        continue
                    except Exception:
                        # fallthrough
                        pass

                # envelope format
                payload = obj.get("payload")
                recipients = obj.get("recipients", [])
                meta = obj.get("meta", {})
                decrypted = None
                if recipients and self._node_x25519 is not None:
                    for r in recipients:
                        try:
                            eph_pub = base64.b64decode(r["ephemeral_pub"])
                            enc_cek = base64.b64decode(r["enc_cek"])
                            rnonce = base64.b64decode(r.get("nonce", "")) if r.get("nonce") else None
                            peer_pub = X25519PublicKey.from_public_bytes(eph_pub)
                            shared = self._node_x25519.exchange(peer_pub)
                            kek = _hkdf_shared(shared)
                            aes = AESGCM(kek)
                            cek = aes.decrypt(rnonce, enc_cek, None) if rnonce is not None else None
                            if cek is None:
                                continue
                            pnonce = base64.b64decode(payload["nonce"])
                            pct = base64.b64decode(payload["ciphertext"])
                            aes2 = AESGCM(cek)
                            pt = aes2.decrypt(pnonce, pct, None)
                            decrypted = json.loads(pt.decode())
                            break
                        except Exception:
                            continue
                records.append({"payload": payload, "recipients": recipients, "meta": meta, "decrypted": decrypted, "raw": obj})
        return records

    def export_ledger_lines(self) -> List[str]:
        if not self.ledger_path.exists():
            return []
        with self.ledger_path.open("r", encoding="utf-8") as f:
            return [l.strip() for l in f if l.strip()]

    def export_ledger_stream(self, chunk_size: int = 4096, compress: bool = True):
        """Stream the ledger as bytes in chunks. If `compress` is True the stream is zlib-compressed.

        Yields bytes chunks suitable for transfer over low-bandwidth links.
        """
        import zlib

        if not self.ledger_path.exists():
            return

        # Read the entire ledger as bytes, stream-compress it to avoid large memory spikes
        compressor = zlib.compressobj(level=6) if compress else None

        with self.ledger_path.open("rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                if compressor is not None:
                    out = compressor.compress(chunk)
                    if out:
                        yield out
                else:
                    yield chunk

        if compressor is not None:
            tail = compressor.flush()
            if tail:
                yield tail

    def import_ledger_stream(self, chunks_iter) -> Dict[str, Any]:
        """Consume an iterator of bytes chunks (optionally compressed) and import ledger lines.

        This function attempts to detect if incoming stream is zlib-compressed by trying
        to decompress; if that fails it will fall back to treating the stream as plain text.
        Returns the same dict as `import_remote_lines` (counts and conflicts).
        """
        import zlib

        # try to decompress using a decompressobj; if it fails, treat as plain
        decomp = zlib.decompressobj()
        buf = b""
        lines = []

        # We'll attempt to decompress and collect newline-terminated JSON lines
        def _process_buffer(b: bytes):
            nonlocal buf, lines
            buf += b
            while True:
                idx = buf.find(b"\n")
                if idx == -1:
                    break
                line = buf[:idx].strip()
                buf = buf[idx + 1 :]
                if line:
                    try:
                        lines.append(line.decode())
                    except Exception:
                        # ignore non-decodable parts
                        continue

        stream_failed = False
        for chunk in chunks_iter:
            if not isinstance(chunk, (bytes, bytearray)):
                # skip invalid chunks
                continue
            if not stream_failed:
                try:
                    out = decomp.decompress(chunk)
                    if out:
                        _process_buffer(out)
                except Exception:
                    # not compressed or corrupted; fallback to plain-text accumulation
                    stream_failed = True
                    # flush any decompressor output into buffer
                    try:
                        tail = decomp.flush()
                        if tail:
                            _process_buffer(tail)
                    except Exception:
                        pass
                    _process_buffer(chunk)
            else:
                _process_buffer(chunk)

        # final decompressor tail if not failed
        if not stream_failed:
            try:
                tail = decomp.flush()
                if tail:
                    _process_buffer(tail)
            except Exception:
                pass

        # if there's residual data in buf that doesn't end with newline, attempt to decode
        if buf.strip():
            try:
                lines.append(buf.strip().decode())
            except Exception:
                pass

        return self.import_remote_lines(lines)

    def _ciphertext_hashes_set(self) -> set:
        s = set()
        for rec in self._read_ledger_records():
            raw = rec.get("raw", {})
            try:
                if "payload" in raw and "ciphertext" in raw["payload"]:
                    pct_b64 = raw["payload"]["ciphertext"]
                elif "ciphertext" in raw:
                    pct_b64 = raw["ciphertext"]
                else:
                    continue
                s.add(self._hash_bytes_hex(base64.b64decode(pct_b64)))
            except Exception:
                continue
        return s

    def import_remote_lines(self, lines: List[str]) -> Dict[str, int]:
        """Import remote ledger lines (JSON lines with nonce & ciphertext). Only accepts
        entries that can be decrypted with this node's ledger key (i.e. same network passphrase)
        and that pass signature and data-hash verification. Returns counts: added/skipped/invalid.
        """
        added = 0
        skipped = 0
        invalid = 0
        existing_hashes = self._ciphertext_hashes_set()

        conflicts = []
        for line in lines:
            try:
                obj = json.loads(line)
                payload = obj.get("payload")
                recipients = obj.get("recipients", [])
                pct_b64 = payload["ciphertext"]
                ciphertext = base64.b64decode(pct_b64)
            except Exception:
                invalid += 1
                continue

            cth = self._hash_bytes_hex(ciphertext)
            if cth in existing_hashes:
                skipped += 1
                continue

            # try to decrypt CEK using this node's encryption key
            if self._node_x25519 is None:
                # cannot verify entries without node private key
                invalid += 1
                continue

            decrypted_payload = None
            for r in recipients:
                try:
                    eph_pub = base64.b64decode(r["ephemeral_pub"])
                    enc_cek = base64.b64decode(r["enc_cek"])
                    rnonce = base64.b64decode(r.get("nonce", "")) if r.get("nonce") else None
                    peer_pub = X25519PublicKey.from_public_bytes(eph_pub)
                    shared = self._node_x25519.exchange(peer_pub)
                    kek = _hkdf_shared(shared)
                    aes = AESGCM(kek)
                    cek = aes.decrypt(rnonce, enc_cek, None) if rnonce is not None else None
                    if cek is None:
                        continue
                    # decrypt payload
                    pnonce = base64.b64decode(payload["nonce"])
                    pct = base64.b64decode(payload["ciphertext"])
                    aes2 = AESGCM(cek)
                    pt = aes2.decrypt(pnonce, pct, None)
                    decrypted_payload = json.loads(pt.decode())
                    break
                except Exception:
                    continue

            if decrypted_payload is None:
                invalid += 1
                continue

            # verify signature and data hash
            try:
                sig = base64.b64decode(decrypted_payload["signature"])
                pub_raw = base64.b64decode(decrypted_payload["pubkey"])
                pub = Ed25519PublicKey.from_public_bytes(pub_raw)
                signed_entry = {k: decrypted_payload[k] for k in decrypted_payload.keys() if k not in ("signature", "pubkey")}
                signed_bytes = json.dumps(signed_entry, separators=(",", ":"), sort_keys=True).encode()
                pub.verify(sig, signed_bytes)
                data_bytes = json.dumps(decrypted_payload["data"], separators=(",", ":"), sort_keys=True).encode()
                if hashlib.sha256(data_bytes).hexdigest() != decrypted_payload.get("data_hash"):
                    raise ValueError("data hash mismatch")
            except Exception:
                invalid += 1
                continue

            # conflict detection: compare prev_hash against our last for thing
            thing_id = decrypted_payload.get("thing_id")
            last_ct = self._find_last_for_thing(thing_id)
            last_hash = self._hash_bytes_hex(last_ct) if last_ct is not None else None
            if decrypted_payload.get("prev_hash") != last_hash and decrypted_payload.get("prev_hash") is not None:
                conflicts.append({"thing_id": thing_id, "expected_prev": last_hash, "entry_prev": decrypted_payload.get("prev_hash")})

            # append the raw line to ledger
            with self.ledger_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
            existing_hashes.add(cth)
            added += 1

        return {"added": added, "skipped": skipped, "invalid": invalid, "conflicts": conflicts}

        return {"added": added, "skipped": skipped, "invalid": invalid}

    def _find_last_for_thing(self, thing_id: str) -> Optional[bytes]:
        # return ciphertext bytes of last entry for thing_id (from raw payload)
        records = self._read_ledger_records()
        for rec in reversed(records):
            p = rec["decrypted"]
            if p and p.get("thing_id") == thing_id:
                try:
                    pct_b64 = rec["raw"]["payload"]["ciphertext"]
                    return base64.b64decode(pct_b64)
                except Exception:
                    return None
        return None

    def put(self, thing_id: str, data: Any, actor_priv: Ed25519PrivateKey, actor_name: str, action: str = "update") -> str:
        # prepare entry
        data_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        data_hash = hashlib.sha256(data_bytes).hexdigest()

        prev_ct = self._find_last_for_thing(thing_id)
        prev_hash = self._hash_bytes_hex(prev_ct) if prev_ct is not None else None

        entry = {
            "thing_id": thing_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "actor": actor_name,
            "action": action,
            "data": data,
            "data_hash": data_hash,
            "prev_hash": prev_hash,
        }

        # sign canonical entry bytes
        entry_bytes = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
        signature = actor_priv.sign(entry_bytes)
        pub = actor_priv.public_key()
        pub_raw = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

        entry["signature"] = base64.b64encode(signature).decode()
        entry["pubkey"] = base64.b64encode(pub_raw).decode()

        payload_bytes = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()

        # generate CEK and encrypt payload
        cek = secrets.token_bytes(32)
        pnonce = secrets.token_bytes(12)
        aes = AESGCM(cek)
        pct = aes.encrypt(pnonce, payload_bytes, None)

        recipients = []

        def _add_recipient(rid: str, peer_pub_bytes: bytes):
            eph = X25519PrivateKey.generate()
            eph_pub = eph.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            shared = eph.exchange(X25519PublicKey.from_public_bytes(peer_pub_bytes))
            kek = _hkdf_shared(shared)
            aes2 = AESGCM(kek)
            rnonce = secrets.token_bytes(12)
            enc_cek = aes2.encrypt(rnonce, cek, None)
            recipients.append({"id": rid, "ephemeral_pub": base64.b64encode(eph_pub).decode(), "enc_cek": base64.b64encode(enc_cek).decode(), "nonce": base64.b64encode(rnonce).decode()})

        # include node key
        if self._node_x25519 is not None:
            my_pub = self._node_x25519.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
            _add_recipient("__node__", my_pub)

        # include peers
        for pid, info in self._peers.items():
            try:
                pubb = base64.b64decode(info["x25519_pub"])
                _add_recipient(pid, pubb)
            except Exception:
                continue

        # if no recipients were added (no node key and no peers), fall back to legacy
        if not recipients:
            # encrypt using node/network key (backward compatibility)
            nonce2 = secrets.token_bytes(12)
            ct2 = self.aesgcm.encrypt(nonce2, payload_bytes, None)
            line = json.dumps({"nonce": base64.b64encode(nonce2).decode(), "ciphertext": base64.b64encode(ct2).decode()})
            with self.ledger_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
            return self._hash_bytes_hex(ct2)

        line_obj = {"payload": {"nonce": base64.b64encode(pnonce).decode(), "ciphertext": base64.b64encode(pct).decode()}, "recipients": recipients, "meta": {"thing_id": thing_id, "timestamp": datetime.utcnow().isoformat()+"Z"}}
        with self.ledger_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(line_obj) + "\n")

        return self._hash_bytes_hex(pct)

    def get_latest(self, thing_id: str) -> Optional[Dict[str, Any]]:
        records = self._read_ledger_records()
        for rec in reversed(records):
            if rec["decrypted"] and rec["decrypted"].get("thing_id") == thing_id:
                return rec["decrypted"]
        return None

    def provenance_chain(self, thing_id: str) -> List[Dict[str, Any]]:
        records = self._read_ledger_records()
        chain = []
        for rec in records:
            p = rec["decrypted"]
            if p and p.get("thing_id") == thing_id:
                chain.append({"payload": p, "raw": rec["raw"]})
        return chain

    def verify_chain(self, thing_id: str) -> bool:
        chain = self.provenance_chain(thing_id)
        prev_cipher_hash = None
        for rec in chain:
            p = rec["payload"]
            # verify prev_hash matches previous ciphertext
            if p.get("prev_hash") != prev_cipher_hash:
                return False
            # verify signature
            sig = base64.b64decode(p["signature"])
            pub_raw = base64.b64decode(p["pubkey"])
            pub = Ed25519PublicKey.from_public_bytes(pub_raw)
            # reconstruct the signed entry (without signature and pubkey) using same canonical form
            signed_entry = {k: p[k] for k in p.keys() if k not in ("signature", "pubkey")}
            signed_bytes = json.dumps(signed_entry, separators=(",", ":"), sort_keys=True).encode()
            try:
                pub.verify(sig, signed_bytes)
            except Exception:
                return False
            # verify data hash
            data_bytes = json.dumps(p["data"], separators=(",", ":"), sort_keys=True).encode()
            if hashlib.sha256(data_bytes).hexdigest() != p.get("data_hash"):
                return False
            # compute prev_cipher_hash from raw.payload.ciphertext
            try:
                raw = rec["raw"]
                pct_b64 = raw["payload"]["ciphertext"]
                prev_cipher_hash = self._hash_bytes_hex(base64.b64decode(pct_b64))
            except Exception:
                prev_cipher_hash = None
        return True

    # Utility helpers for actor keys (not encrypted here; demo only)
    @staticmethod
    def generate_actor_keypair() -> Ed25519PrivateKey:
        return Ed25519PrivateKey.generate()

    @staticmethod
    def save_private_key_to_pem(priv: Ed25519PrivateKey, path: str):
        pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        Path(path).write_bytes(pem)

    @staticmethod
    def load_private_key_from_pem(path: str) -> Ed25519PrivateKey:
        data = Path(path).read_bytes()
        return serialization.load_pem_private_key(data, password=None, backend=default_backend())

    # Encrypted key storage utilities (use node password)
    def save_private_key_encrypted(self, priv: Ed25519PrivateKey, path: str, passphrase: Optional[str] = None):
        # passphrase defaults to node password if not provided
        pw = (passphrase.encode() if passphrase is not None else self.node_password)
        salt = secrets.token_bytes(16)
        key = _derive_key(pw, salt)
        aes = AESGCM(key)
        pem = priv.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, pem, None)
        # store as: salt + nonce + ciphertext (binary)
        Path(path).write_bytes(salt + nonce + ct)

    def load_private_key_encrypted(self, path: str, passphrase: Optional[str] = None) -> Ed25519PrivateKey:
        pw = (passphrase.encode() if passphrase is not None else self.node_password)
        data = Path(path).read_bytes()
        salt = data[:16]
        nonce = data[16:28]
        ct = data[28:]
        key = _derive_key(pw, salt)
        aes = AESGCM(key)
        pem = aes.decrypt(nonce, ct, None)
        return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

    # Node X25519 helpers
    @staticmethod
    def generate_node_x25519() -> X25519PrivateKey:
        return X25519PrivateKey.generate()

    def save_node_x25519_encrypted(self, priv: X25519PrivateKey, path: str, passphrase: Optional[str] = None):
        pw = (passphrase.encode() if passphrase is not None else self.node_password)
        salt = secrets.token_bytes(16)
        key = _derive_key(pw, salt)
        aes = AESGCM(key)
        raw = priv.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())
        nonce = secrets.token_bytes(12)
        ct = aes.encrypt(nonce, raw, None)
        Path(path).write_bytes(salt + nonce + ct)

    def load_node_x25519_encrypted(self, path: str, passphrase: Optional[str] = None) -> X25519PrivateKey:
        pw = (passphrase.encode() if passphrase is not None else self.node_password)
        data = Path(path).read_bytes()
        salt = data[:16]
        nonce = data[16:28]
        ct = data[28:]
        key = _derive_key(pw, salt)
        aes = AESGCM(key)
        raw = aes.decrypt(nonce, ct, None)
        priv = X25519PrivateKey.from_private_bytes(raw)
        self._node_x25519 = priv
        return priv

    # Peer registry
    def register_peer(self, peer_id: str, x25519_pub_b64: str, meta: Optional[Dict[str, Any]] = None):
        self._peers[peer_id] = {"x25519_pub": x25519_pub_b64, "meta": meta or {}}
        self.peers_path.write_text(json.dumps(self._peers))

    def list_peers(self) -> Dict[str, Any]:
        return self._peers

    # Token management (simple)
    def add_token(self, token: str, info: Dict[str, Any]):
        # normalize token info: allow 'scopes' list and 'expires_in' seconds
        info = dict(info)
        scopes = info.get("scopes") or info.get("scope") or []
        if isinstance(scopes, str):
            scopes = [s.strip() for s in scopes.split() if s.strip()]
        info["scopes"] = scopes
        # support human-friendly expires_in (seconds)
        if "expires_in" in info and "expires_at" not in info:
            try:
                expires_in = int(info["expires_in"])
                info["expires_at"] = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat() + "Z"
            except Exception:
                pass
        self._tokens[token] = info
        self.tokens_path.write_text(json.dumps(self._tokens))

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        info = self._tokens.get(token)
        if not info:
            return None
        # check expiry
        exp = info.get("expires_at")
        if exp:
            try:
                exp_t = datetime.fromisoformat(exp.replace("Z", "+00:00"))
                if datetime.utcnow() > exp_t.replace(tzinfo=None):
                    return None
            except Exception:
                pass
        return info
