"""Second implementation of Hello, the ratchet, and the envelope.

Checks spec/vectors. Not Rust, no UI, no libp2p. A mismatch means this port
is wrong: do not rewrite the JSON.

    python second/check_vectors.py

Needs the `cryptography` package (X25519, Ed25519, HKDF, ChaCha20-Poly1305,
and ML-KEM-768 for envelope_opk_kem).
"""

from __future__ import annotations

import json
import sys
from hashlib import sha256, sha512
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "spec" / "vectors"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
HELLO_BIND_V3 = b"VOID_E2EE_HELLO_BIND_V3\0"
FRESHNESS = 600
DOMAIN = b"VOID_RATCHET_HDR_V1"
CT_LEN = 1088


def hx(data: bytes) -> str:
    return data.hex()


def uh(text: str) -> bytes:
    return bytes.fromhex(text)


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return ("1" * pad) + out


def b58decode(text: str) -> bytes:
    n = 0
    for c in text:
        n = n * 58 + B58.index(c)
    pad = 0
    for c in text:
        if c == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def seed32(tag: int) -> bytes:
    return bytes((tag * 17 + i) & 0xFF for i in range(32))


def lp(data: bytes) -> bytes:
    return len(data).to_bytes(4, "little") + data


def read_lp(buf: bytearray, limit: int) -> bytes:
    if len(buf) < 4:
        raise ValueError("lp")
    n = int.from_bytes(buf[:4], "little")
    if n > limit or len(buf) < 4 + n:
        raise ValueError("lp")
    out = bytes(buf[4 : 4 + n])
    del buf[: 4 + n]
    return out


def peer_bytes(seed: bytes) -> bytes:
    pk = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return b"\x00\x24\x08\x01\x12\x20" + pk


def ed_pub(peer: bytes) -> Ed25519PublicKey:
    digest = peer[2:]
    if not digest.startswith(b"\x08\x01\x12\x20") or len(digest) != 36:
        raise ValueError("peer id is not an ed25519 identity multihash")
    return Ed25519PublicKey.from_public_bytes(digest[4:])


def x_pub(sk: bytes) -> bytes:
    return (
        X25519PrivateKey.from_private_bytes(sk)
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def x_dh(sk: bytes, pk: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(sk).exchange(X25519PublicKey.from_public_bytes(pk))


def hkdf(salt: bytes, ikm: bytes, info: bytes, n: int) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=n, salt=salt, info=info).derive(ikm)


def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def quarter(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = rotl(s[b] ^ s[c], 7)


def chacha12_block(key: bytes, counter: int) -> bytes:
    def u32(off: int) -> int:
        return int.from_bytes(key[off : off + 4], "little")

    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        u32(0),
        u32(4),
        u32(8),
        u32(12),
        u32(16),
        u32(20),
        u32(24),
        u32(28),
        counter & 0xFFFFFFFF,
        (counter >> 32) & 0xFFFFFFFF,
        0,
        0,
    ]
    w = state[:]
    for _ in range(6):
        quarter(w, 0, 4, 8, 12)
        quarter(w, 1, 5, 9, 13)
        quarter(w, 2, 6, 10, 14)
        quarter(w, 3, 7, 11, 15)
        quarter(w, 0, 5, 10, 15)
        quarter(w, 1, 6, 11, 12)
        quarter(w, 2, 7, 8, 13)
        quarter(w, 3, 4, 9, 14)
    out = bytearray()
    for i in range(16):
        out += ((w[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(out)


class ChaCha12:
    """rand 0.8 StdRng: ChaCha12, 64-bit counter, 64-bit nonce of zeros."""

    def __init__(self, seed: bytes) -> None:
        self.key = seed
        self.counter = 0
        self.buf = b""
        self.off = 0

    def bytes(self, n: int) -> bytes:
        out = bytearray()
        while len(out) < n:
            if self.off >= len(self.buf):
                self.buf = chacha12_block(self.key, self.counter)
                self.counter += 1
                self.off = 0
            take = min(n - len(out), len(self.buf) - self.off)
            out += self.buf[self.off : self.off + take]
            self.off += take
        return bytes(out)


def hello_bind_v3(signer: bytes, recipient: bytes, static: bytes, eph: bytes, ts: int, nonce: bytes, caps: int) -> bytes:
    return (
        HELLO_BIND_V3
        + signer
        + recipient
        + static
        + eph
        + ts.to_bytes(8, "little")
        + nonce
        + caps.to_bytes(4, "little")
    )


def check_hello(name: str) -> None:
    doc = load(name)
    signer = peer_bytes(uh(doc["signer_seed"]))
    recipient = peer_bytes(uh(doc["recipient_seed"]))
    assert b58encode(signer) == doc["signer_peer_id"], name
    assert b58encode(recipient) == doc["recipient_peer_id"], name
    msg = hello_bind_v3(
        signer,
        recipient,
        uh(doc["x25519_static"]),
        uh(doc["x25519_ephemeral"]),
        doc["ts"],
        uh(doc["nonce"]),
        doc["caps"],
    )
    ed_pub(signer).verify(uh(doc["signature"]), msg)
    fresh = abs(doc["now"] - doc["ts"]) <= FRESHNESS and any(uh(doc["nonce"]))
    assert fresh == doc["accepted"], name
    if "bind" in doc:
        assert doc["accepted"] and doc["bind"] == "V3"


def check_replay() -> None:
    doc = load("hello_replay_eph.json")
    seen: dict[str, list[bytes]] = {}

    def accept(peer: str, eph: bytes) -> bool:
        slot = seen.setdefault(peer, [])
        if eph in slot:
            return False
        if len(slot) >= 256:
            slot.pop(0)
        slot.append(eph)
        return True

    for step in doc["steps"]:
        assert accept(step["peer"], uh(step["ephemeral"])) == step["accept"]
    window: dict[str, list[bytes]] = {}

    def take(eph: bytes) -> bool:
        return accept_into(window, "A", eph)

    def accept_into(store: dict[str, list[bytes]], peer: str, eph: bytes) -> bool:
        slot = store.setdefault(peer, [])
        if eph in slot:
            return False
        if len(slot) >= 256:
            slot.pop(0)
        slot.append(eph)
        return True

    keys = [i.to_bytes(2, "little") + b"\x00" * 30 for i in range(257)]
    for i in range(256):
        assert take(keys[i])
    assert take(keys[0]) is doc["window"]["repeat_oldest_while_full"]
    assert take(keys[256])
    assert take(keys[0]) is doc["window"]["after_one_new_key_oldest_again"]


class Chain:
    def __init__(self, key: bytes) -> None:
        self.key = key
        self.index = 0

    def step(self) -> bytes:
        mk = hkdf(self.key, b"message_key", self.index.to_bytes(4, "big"), 32)
        self.key = hkdf(self.key, b"chain_key", self.index.to_bytes(4, "big"), 32)
        self.index += 1
        return mk


class Session:
    def __init__(self, static: bytes, remote_static: bytes, eph: bytes, remote_eph: bytes, rng: ChaCha12, alice: bool) -> None:
        shared = x_dh(static, remote_static)
        self.rk = hkdf(b"VOID_SALT", shared, b"VOID_INIT_RK", 32)
        self.rng = rng
        self.dhs = eph
        self.ns = 0
        self.nr = 0
        self.pn = 0
        self.peer = b""
        self.require_aad = False
        if alice:
            self.dhr = remote_static
            self.rk, ck_send, _ = self.kdf(x_dh(self.dhs, remote_static))
            self.ck_send = Chain(ck_send)
            self.dhr = remote_eph
            self.rk, ck_recv, _ = self.kdf(x_dh(self.dhs, self.dhr))
            self.ck_recv = Chain(ck_recv)
            self.dhs = self.rng.bytes(32)
            self.rk, ck_send, _ = self.kdf(x_dh(self.dhs, self.dhr))
            self.ck_send = Chain(ck_send)
        else:
            self.dhr = remote_eph
            self.rk, ck_recv, _ = self.kdf(x_dh(static, remote_eph))
            self.ck_recv = Chain(ck_recv)
            self.rk, ck_send, _ = self.kdf(x_dh(self.dhs, remote_eph))
            self.ck_send = Chain(ck_send)

    def kdf(self, dh: bytes) -> tuple[bytes, bytes, bytes]:
        out = hkdf(self.rk, dh, b"dr_ratchet", 96)
        return out[:32], out[32:64], out[64:96]

    def bind(self, local: bytes, remote: bytes) -> None:
        self.peer = local + remote if local <= remote else remote + local

    def aad(self, dh: bytes, pn: int, n: int) -> bytes:
        return DOMAIN + dh + pn.to_bytes(4, "little") + n.to_bytes(4, "little") + self.peer

    def encrypt(self, plain: bytes) -> tuple[bytes, int, int, bytes]:
        mk = self.ck_send.step()
        n = self.ns
        pn = self.pn
        dh = x_pub(self.dhs)
        self.ns += 1
        nonce = n.to_bytes(4, "little") + b"\x00" * 8
        ct = ChaCha20Poly1305(mk).encrypt(nonce, plain, self.aad(dh, pn, n))
        return dh, pn, n, ct

    def decrypt(self, dh: bytes, pn: int, n: int, ct: bytes) -> bytes:
        saved = (
            self.rk,
            self.dhs,
            self.dhr,
            self.ck_send.key,
            self.ck_send.index,
            self.ck_recv.key,
            self.ck_recv.index,
            self.ns,
            self.nr,
            self.pn,
            self.rng.counter,
            self.rng.buf,
            self.rng.off,
        )
        try:
            if dh != x_pub(self.dhr):
                self.skip(pn)
                self.dh_ratchet(dh)
            self.skip(n)
            mk = self.ck_recv.step()
            self.nr += 1
            nonce = n.to_bytes(4, "little") + b"\x00" * 8
            if self.require_aad:
                return ChaCha20Poly1305(mk).decrypt(nonce, ct, self.aad(dh, pn, n))
            try:
                return ChaCha20Poly1305(mk).decrypt(nonce, ct, self.aad(dh, pn, n))
            except Exception:
                return ChaCha20Poly1305(mk).decrypt(nonce, ct, None)
        except Exception:
            (
                self.rk,
                self.dhs,
                self.dhr,
                self.ck_send.key,
                self.ck_send.index,
                self.ck_recv.key,
                self.ck_recv.index,
                self.ns,
                self.nr,
                self.pn,
                self.rng.counter,
                self.rng.buf,
                self.rng.off,
            ) = saved
            raise

    def skip(self, until: int) -> None:
        while self.ck_recv.index < until:
            self.ck_recv.step()

    def dh_ratchet(self, dh: bytes) -> None:
        self.pn = self.ns
        self.ns = 0
        self.nr = 0
        self.dhr = dh
        self.rk, ck_recv, _ = self.kdf(x_dh(self.dhs, self.dhr))
        self.ck_recv = Chain(ck_recv)
        self.dhs = self.rng.bytes(32)
        self.rk, ck_send, _ = self.kdf(x_dh(self.dhs, self.dhr))
        self.ck_send = Chain(ck_send)


def session_pair(doc: dict) -> tuple[Session, Session]:
    alice_peer = peer_bytes(seed32(10))
    bob_peer = peer_bytes(seed32(11))
    assert b58encode(alice_peer) == doc["alice_peer_id"]
    assert b58encode(bob_peer) == doc["bob_peer_id"]
    alice = Session(
        uh(doc["alice_static_sk"]),
        x_pub(uh(doc["bob_static_sk"])),
        uh(doc["alice_ephemeral_sk"]),
        x_pub(uh(doc["bob_ephemeral_sk"])),
        ChaCha12(uh(doc["alice_ratchet_seed"])),
        True,
    )
    bob = Session(
        uh(doc["bob_static_sk"]),
        x_pub(uh(doc["alice_static_sk"])),
        uh(doc["bob_ephemeral_sk"]),
        x_pub(uh(doc["alice_ephemeral_sk"])),
        ChaCha12(uh(doc["bob_ratchet_seed"])),
        False,
    )
    alice.bind(alice_peer, bob_peer)
    bob.bind(bob_peer, alice_peer)
    alice.require_aad = True
    bob.require_aad = True
    return alice, bob


def check_ratchet() -> None:
    doc = load("ratchet_dh_step.json")
    alice, bob = session_pair(doc)
    who = {"alice": (alice, bob), "bob": (bob, alice)}
    prev: dict[str, bytes] = {}
    for msg in doc["messages"]:
        send, recv = who[msg["from"]]
        dh, pn, n, ct = send.encrypt(msg["plaintext"].encode())
        assert hx(dh) == msg["dh_pub"], msg["plaintext"]
        assert pn == msg["pn"] and n == msg["n"]
        assert hx(ct) == msg["ct"]
        assert recv.decrypt(dh, pn, n, ct) == msg["plaintext"].encode()
        if msg["from"] in prev:
            assert prev[msg["from"]] != dh
        prev[msg["from"]] = dh


def check_bad_aad() -> None:
    step = load("ratchet_dh_step.json")
    doc = load("ratchet_bad_aad.json")
    step["alice_ratchet_seed"] = doc["alice_ratchet_seed"]
    step["bob_ratchet_seed"] = doc["bob_ratchet_seed"]
    alice, bob = session_pair(step)
    dh, pn, n, ct = alice.encrypt(b"keep")
    frame = doc["frame"]
    assert hx(dh) == frame["dh_pub"] and pn == frame["pn"] and n == frame["n"]
    assert hx(ct) == frame["ct"]
    try:
        bob.decrypt(dh, doc["tampered_pn"], n, ct)
        raise AssertionError("tampered pn opened")
    except Exception:
        assert doc["tampered_decrypt"] is False
    assert bob.decrypt(uh(frame["dh_pub"]), frame["pn"], frame["n"], uh(frame["ct"])) == doc["original_decrypt"].encode()
    dh2, pn2, n2, ct2 = bob.encrypt(b"next")
    follow = doc["following"]
    assert hx(dh2) == follow["dh_pub"] and pn2 == follow["pn"] and n2 == follow["n"]
    assert hx(ct2) == follow["ct"]
    assert alice.decrypt(dh2, pn2, n2, ct2) == b"next"


def identity_secret(seed: bytes) -> bytes:
    return sha512(seed).digest()[:32]


def outer_id(recipient: bytes, message_id: str) -> str:
    digest = sha256(b"VOID_OFFLINE_ID_V3\0" + recipient + message_id.encode()).digest()
    return digest[:16].hex()


def v3_aad(recipient: bytes, message_id: str, eph: bytes) -> bytes:
    return b"VOID_OFFLINE_AAD_V3\0" + bytes([3]) + lp(recipient) + lp(message_id.encode()) + eph


def header_v3(sender: bytes, recipient: bytes, sender_pk: bytes, message_id: str, kind: str, eph: bytes, extra: bytes = b"") -> bytes:
    return (
        b"VOID_OFFLINE_SIG_V3\0"
        + bytes([3])
        + lp(sender)
        + lp(recipient)
        + sender_pk
        + lp(message_id.encode())
        + lp(kind.encode())
        + eph
        + extra
    )


def open_signed(inner: bytes) -> tuple[bytes, bytes, bytearray]:
    if len(inner) < 2:
        raise ValueError("inner")
    n = int.from_bytes(inner[:2], "little")
    sig = inner[2 : 2 + n]
    rest = inner[2 + n :]
    m = int.from_bytes(rest[:2], "little")
    pb = rest[2 : 2 + m]
    return sig, pb, bytearray(rest[2 + m :])


def open_v3(env: dict, recipient_sk: bytes, recipient: bytes) -> tuple[str, str, bytes, str]:
    if env["v"] != 3:
        raise ValueError(f"envelope v{env['v']}")
    eph = uh(env["eph"])
    nonce = uh(env["nonce"])
    ct = uh(env["ct"])
    key = hkdf(b"VOID_OFFLINE_V2", x_dh(recipient_sk, eph), b"mail" + eph + x_pub(recipient_sk), 32)
    inner = ChaCha20Poly1305(key).decrypt(nonce, ct, v3_aad(recipient, env["message_id"], eph))
    sig, _pb, rest = open_signed(inner)
    sender = read_lp(rest, 128)
    sender_pk = bytes(rest[:32])
    del rest[:32]
    message_id = read_lp(rest, 1024).decode()
    kind = read_lp(rest, 64).decode()
    body = read_lp(rest, 2**32)
    assert env["message_id"] == outer_id(recipient, message_id)
    header = header_v3(sender, recipient, sender_pk, message_id, kind, eph)
    ed_pub(sender).verify(sig, header + sha256(body).digest())
    return message_id, kind, body, b58encode(sender)


def open_x3dh(env: dict, spk: bytes, opk: bytes, opk_id: bytes, recipient: bytes, kem_ss: bytes | None) -> tuple[str, str, bytes] | None:
    eph = uh(env["eph"])
    nonce = uh(env["nonce"])
    ct = uh(env["ct"])
    base = v3_aad(recipient, env["message_id"], eph) + opk_id
    ikm = x_dh(spk, eph) + x_dh(opk, eph)
    if kem_ss is None:
        if ct.startswith(b"VQK1"):
            return None
        key = hkdf(b"VOID_OFFLINE_X3DH", ikm, b"mail" + eph + x_pub(spk) + opk_id + x_pub(opk), 32)
        aad, aead = base, ct
    else:
        if not ct.startswith(b"VQK1") or len(ct) < 4 + CT_LEN:
            return None
        key = hkdf(b"VOID_OFFLINE_X3DH", ikm + kem_ss, b"mail" + eph + x_pub(spk) + opk_id + x_pub(opk), 32)
        aad = base + ct[: 4 + CT_LEN]
        aead = ct[4 + CT_LEN :]
    try:
        inner = ChaCha20Poly1305(key).decrypt(nonce, aead, aad)
    except Exception:
        return None
    sig, _pb, rest = open_signed(inner)
    sender = read_lp(rest, 128)
    sender_pk = bytes(rest[:32])
    del rest[:32]
    message_id = read_lp(rest, 1024).decode()
    kind = read_lp(rest, 64).decode()
    found = bytes(rest[:16])
    del rest[:16]
    if found != opk_id:
        return None
    body = read_lp(rest, 2**32)
    if env["message_id"] != outer_id(recipient, message_id):
        return None
    header = header_v3(sender, recipient, sender_pk, message_id, kind, eph, opk_id)
    ed_pub(sender).verify(sig, header + sha256(body).digest())
    return message_id, kind, body


def kem_decaps(dk: bytes, ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey

    key = None
    for name in ("from_seed", "from_seed_bytes"):
        factory = getattr(MLKEM768PrivateKey, name, None)
        if factory is not None:
            key = factory(dk)
            break
    if key is None:
        raise SystemExit("cryptography MLKEM768PrivateKey has no from_seed")
    return key.decapsulate(ct)


def check_envelope() -> None:
    doc = load("envelope_v3_roundtrip.json")
    recipient = peer_bytes(uh(doc["recipient_seed"]))
    sk = identity_secret(uh(doc["recipient_seed"]))
    message_id, kind, body, sender = open_v3(doc["envelope"], sk, recipient)
    assert message_id == doc["opened_message_id"]
    assert kind == doc["opened_kind"]
    assert hx(body) == doc["opened_body"]
    assert body == doc["plaintext"].encode()
    assert sender == doc["opened_sender"]

    reject = load("envelope_v2_reject.json")
    for part in (reject["v1"], reject["relabel_v3_as_v2"]):
        assert part["open"] is False
        try:
            open_v3(part["envelope"], sk, recipient)
        except Exception:
            continue
        raise AssertionError("v2/v1 envelope opened")


def check_opk() -> None:
    doc = load("envelope_opk_kem.json")
    recipient = peer_bytes(uh(doc["recipient_seed"]))
    opk_id = uh(doc["opk_id"])
    plain = open_x3dh(doc["without_kem"]["envelope"], uh(doc["spk_sk"]), uh(doc["opk_sk"]), opk_id, recipient, None)
    assert plain is not None
    assert plain[0] == doc["without_kem"]["inner_message_id"]
    assert hx(plain[2]) == doc["without_kem"]["opened_body"]
    assert doc["without_kem"]["starts_with_vqk1"] is False
    assert not uh(doc["without_kem"]["envelope"]["ct"]).startswith(b"VQK1")

    ct = uh(doc["with_kem"]["envelope"]["ct"])
    assert ct.startswith(b"VQK1")
    assert open_x3dh(doc["with_kem"]["envelope"], uh(doc["spk_sk"]), uh(doc["opk_sk"]), opk_id, recipient, None) is None
    assert doc["with_kem"]["open_without_kem_dk"] is False
    ss = kem_decaps(uh(doc["kem_dk"]), ct[4 : 4 + CT_LEN])
    opened = open_x3dh(doc["with_kem"]["envelope"], uh(doc["spk_sk"]), uh(doc["opk_sk"]), opk_id, recipient, ss)
    assert opened is not None
    assert opened[0] == doc["with_kem"]["inner_message_id"]
    assert hx(opened[2]) == doc["with_kem"]["opened_body"]
    assert opened[2] == doc["with_kem"]["plaintext"].encode()
    assert hx(opk_id) == doc["with_kem"]["spent_opk"]


def check_prekey() -> None:
    doc = load("prekey_expired.json")
    raw = uh(doc["dht_value"])
    pk = raw[:32]
    assert hx(pk) == doc["pk"]
    assert raw[32] == 2
    not_after = int.from_bytes(raw[33:41], "little")
    assert not_after == doc["not_after"]
    sig, _pb, rest = open_signed(raw[41:])
    assert bytes(rest) == b""
    owner = b58decode(doc["owner_peer_id"])
    assert b58encode(peer_bytes(uh(doc["owner_seed"]))) == doc["owner_peer_id"]
    msg = b"VOID_PREKEY_SIG_V2\0" + lp(owner) + pk + not_after.to_bytes(8, "little")
    ed_pub(owner).verify(sig, msg)
    assert doc["verify_ok"] is True
    assert doc["sealable"] == (not_after > doc["now"])


def main() -> int:
    check_hello("hello_v3_ok.json")
    check_hello("hello_v3_stale_ts.json")
    check_replay()
    check_ratchet()
    check_bad_aad()
    check_envelope()
    check_opk()
    check_prekey()
    print("second implementation matches spec/vectors (hello, ratchet, envelope, prekey)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print(f"vector mismatch: {exc}", file=sys.stderr)
        raise
