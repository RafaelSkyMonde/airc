# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""End-to-end encryption (spec §19).

Optional in the protocol, automatic in clients: an endpoint's keys are created
and published without a user step, and every message to a peer with a valid
key record is sealed to it.

    identity key   ed25519, long-lived; fingerprint = sha256(raw)[:32 hex]
    encryption key X25519, rotated (default 7 days, at most 30)
    key record     the public halves, signed by the identity key (§19.2)
    envelope       HPKE base mode, X25519 / HKDF-SHA256 / ChaCha20-Poly1305,
                   bound to id/from/to; the plaintext is signed by the
                   sender's identity key (§19.5)
    pins           per local endpoint: peer -> identity key, from a link, a
                   passport, or first use (§19.4); a change stops and asks

Private keys live in a Keystore (one JSON file per local endpoint, mode 0600)
under ~/.airc/e2e by default. Servers never see them.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import tempfile
import time

from . import address as A
from . import wire

from . import cryptolib

try:                                   # the reference is stdlib-only; E2E needs `cryptography`
    if not cryptolib.available():      # tried once, quietly: a broken install prints a pyo3 panic otherwise
        raise ImportError(cryptolib.HINT)
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    AVAILABLE = True
except ImportError:                    # pragma: no cover   not installed, or broken (cryptolib said so quietly)
    AVAILABLE = False

    class InvalidSignature(Exception):
        pass

    class InvalidTag(Exception):
        pass

MEDIA_TYPE = "application/airc-e2e+json"
SUITE = "hpke-x25519-sha256-chacha20poly1305"
KEY_LIFETIME = 7 * 86400          # default encryption key lifetime (§19.8)
KEY_LIFETIME_MAX = 30 * 86400
ROTATE_BEFORE = 2 * 86400         # publish the next key when the current one has less left
RETIRED_GRACE = 86400             # keep a retired private key this long past not_after
PIN_SOURCES = ("first-use", "link", "passport", "verified")   # weakest first

if AVAILABLE:
    _RAW = serialization.Encoding.Raw
    _PUB = serialization.PublicFormat.Raw
    _PRIV = serialization.PrivateFormat.Raw
    _NOENC = serialization.NoEncryption()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def fingerprint(ik_b64: str) -> str:
    """ifp: first 32 lower-case hex digits of sha256 over the raw identity key."""
    return hashlib.sha256(unb64(ik_b64)).hexdigest()[:32]


def show_fingerprint(ifp: str) -> str:
    return " ".join(ifp[i:i + 4] for i in range(0, len(ifp), 4))


def x_kid(pub_b64: str) -> str:
    return hashlib.sha256(unb64(pub_b64)).hexdigest()[:8]


# ---------------------------------------------------------------- HPKE base mode (RFC 9180)
_KEM_ID, _KDF_ID, _AEAD_ID = 0x0020, 0x0001, 0x0003
_SUITE_KEM = b"KEM" + struct.pack(">H", _KEM_ID)
_SUITE_HPKE = b"HPKE" + struct.pack(">HHH", _KEM_ID, _KDF_ID, _AEAD_ID)


def _extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()


def _expand(prk: bytes, info: bytes, n: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:n]


def _lextract(suite: bytes, salt: bytes, label: bytes, ikm: bytes) -> bytes:
    return _extract(salt, b"HPKE-v1" + suite + label + ikm)


def _lexpand(suite: bytes, prk: bytes, label: bytes, info: bytes, n: int) -> bytes:
    return _expand(prk, struct.pack(">H", n) + b"HPKE-v1" + suite + label + info, n)


def _x_pub(sk: bytes) -> bytes:
    return x25519.X25519PrivateKey.from_private_bytes(sk).public_key().public_bytes(_RAW, _PUB)


def derive_x25519(ikm: bytes) -> bytes:
    """DeriveKeyPair for DHKEM(X25519): the private key (RFC 9180 §7.1.3)."""
    prk = _lextract(_SUITE_KEM, b"", b"dkp_prk", ikm)
    return _lexpand(_SUITE_KEM, prk, b"sk", b"", 32)


def _shared_secret(dh: bytes, enc: bytes, pk_r: bytes) -> bytes:
    prk = _lextract(_SUITE_KEM, b"", b"eae_prk", dh)
    return _lexpand(_SUITE_KEM, prk, b"shared_secret", enc + pk_r, 32)


def _key_schedule(shared: bytes, info: bytes) -> tuple[bytes, bytes]:
    psk_id_hash = _lextract(_SUITE_HPKE, b"", b"psk_id_hash", b"")
    info_hash = _lextract(_SUITE_HPKE, b"", b"info_hash", info)
    ctx = b"\x00" + psk_id_hash + info_hash            # mode_base
    secret = _lextract(_SUITE_HPKE, shared, b"secret", b"")
    return (_lexpand(_SUITE_HPKE, secret, b"key", ctx, 32),
            _lexpand(_SUITE_HPKE, secret, b"base_nonce", ctx, 12))


def hpke_seal(pk_r: bytes, info: bytes, aad: bytes, pt: bytes, ikm_e: bytes | None = None) -> tuple[bytes, bytes]:
    """Single-shot base-mode seal: (enc, ct). ikm_e fixes the ephemeral key (test vectors only)."""
    sk_e = derive_x25519(ikm_e) if ikm_e is not None else x25519.X25519PrivateKey.generate().private_bytes(_RAW, _PRIV, _NOENC)
    enc = _x_pub(sk_e)
    dh = x25519.X25519PrivateKey.from_private_bytes(sk_e).exchange(x25519.X25519PublicKey.from_public_bytes(pk_r))
    key, nonce = _key_schedule(_shared_secret(dh, enc, pk_r), info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce, pt, aad)


def hpke_open(sk_r: bytes, enc: bytes, info: bytes, aad: bytes, ct: bytes) -> bytes:
    """Single-shot base-mode open; raises InvalidTag when it does not open."""
    pk_r = _x_pub(sk_r)
    dh = x25519.X25519PrivateKey.from_private_bytes(sk_r).exchange(x25519.X25519PublicKey.from_public_bytes(enc))
    key, nonce = _key_schedule(_shared_secret(dh, enc, pk_r), info)
    return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)


def looks_sealed(msg: dict) -> tuple[bool, str]:
    """Whether msg is a well-formed end-to-end envelope (§19.5), by shape only: servers cannot open
    it. (sealed, reason). Needs no crypto library, so every server can enforce §19.7."""
    if msg.get("type") != MEDIA_TYPE:
        return False, "plaintext"
    try:
        env = json.loads(msg.get("body") or "")
        ok = (isinstance(env, dict) and env.get("v") in (1, 2) and env.get("suite") == SUITE
              and isinstance(env.get("kid"), str) and len(env["kid"]) == 8
              and len(unb64(env.get("enc", ""))) == 32
              and (len(unb64(env.get("ct", ""))) >= 16 if env["v"] == 1 else int(msg.get("bin") or 0) >= 16))   # v 2: ct is the binary section
    except (ValueError, TypeError):
        ok = False
    return (True, "") if ok else (False, "not a valid end-to-end envelope")


# ---------------------------------------------------------------- key records (§19.2)
def canonical_record(rec: dict) -> bytes:
    lines = ["airc-e2e-keys", str(rec["endpoint"]), str(rec["ik"]), str(int(rec["ts"]))]
    for k in rec.get("keys") or []:
        lines += [str(k["kid"]), str(k["x25519"]), str(int(k["not_after"]))]
    return "\n".join(lines).encode()


def verify_record(rec: dict, endpoint: str | None = None, now: float | None = None) -> tuple[bool, str]:
    """(valid, reason). Valid: signature under ik, endpoint as expected, one unexpired key."""
    now = time.time() if now is None else now
    if not AVAILABLE:
        return False, "this server cannot check key records (python package cryptography missing)"
    try:
        if rec.get("t") != "e2e-keys":
            return False, "not a key record"
        if endpoint is not None and rec.get("endpoint") != endpoint:
            return False, f"record is for {rec.get('endpoint')}, not {endpoint}"
        ik = ed25519.Ed25519PublicKey.from_public_bytes(unb64(rec["ik"]))
        ik.verify(unb64(rec["sig"]), canonical_record(rec))
        for k in rec.get("keys") or []:
            if x_kid(k["x25519"]) != k["kid"]:
                return False, f"key {k['kid']} does not match its kid"
        if not any(float(k["not_after"]) > now for k in rec.get("keys") or []):
            return False, "every encryption key has expired"
        succ = rec.get("succession")
        if succ:
            old = ed25519.Ed25519PublicKey.from_public_bytes(unb64(succ["ik_old"]))
            old.verify(unb64(succ["sig_old"]), canonical_record(rec))
        return True, ""
    except (InvalidSignature, KeyError, ValueError, TypeError) as e:
        return False, f"bad key record ({e.__class__.__name__}: {e})" if not isinstance(e, InvalidSignature) else "key record signature did not verify"


def current_key(rec: dict, now: float | None = None) -> dict | None:
    now = time.time() if now is None else now
    live = [k for k in rec.get("keys") or [] if float(k["not_after"]) > now]
    return max(live, key=lambda k: float(k["not_after"])) if live else None


# ---------------------------------------------------------------- canonical strings (§19.5)
def envelope_info(msg_id: str, frm: str, to: str) -> bytes:
    return f"airc-e2e/1\n{msg_id}\n{frm}\n{to}".encode()


def canonical_plain(msg_id: str, frm: str, to: str, mtype: str, re_id: str, body: str) -> bytes:
    return f"airc-e2e-msg\n{msg_id}\n{frm}\n{to}\n{mtype}\n{re_id or ''}\n{body}".encode()


# ---------------------------------------------------------------- signed link controls (§19.9) and passport auth (§12.4)
def ts_ms(ts) -> int:
    """A message ts in milliseconds, as in §9.3: round(ts x 1000), half to even."""
    return int(round(float(ts) * 1000))


def _secs(v) -> str:
    """Unix seconds for a canonical string: the integer part; empty for none."""
    return "" if v in (None, "") else str(int(float(v)))


def canonical_link_control(action: str, link_id: str, a: str, b: str, direction: str, expires, ts) -> bytes:
    """The string an acting endpoint signs for a link control (§19.9)."""
    return canonical_link_control_ms(action, link_id, a, b, direction, None if expires in (None, "") else int(float(expires)), ts_ms(ts))


def canonical_link_control_ms(action: str, link_id: str, a: str, b: str, direction: str, expires_s, ts_ms_: int) -> bytes:
    """The same string from the integers that were signed: expires in Unix seconds (None for none), ts in ms.
    These are what a notice's airc-peer-control carries."""
    return "\n".join(["airc-link-control", str(action), str(link_id), str(a), str(b), str(direction),
                      "" if expires_s is None else str(int(expires_s)), str(int(ts_ms_))]).encode()


def canonical_passport_auth(scope: str, token_sha256: str, direction: str, expires, uses, bind_to, link_ttl,
                            offer=None) -> bytes:
    """The string every authorizing key signs (§12.4); see passports.canonical."""
    from . import passports as P
    return P.canonical(scope, token_sha256, direction, expires, uses, bind_to, link_ttl, offer)


def verify_sig(ik_b64: str, sig_b64: str, data: bytes) -> bool:
    """Whether sig_b64 is ik_b64's ed25519 signature over data. False when unreadable or without the crypto library."""
    if not AVAILABLE or not isinstance(ik_b64, str) or not isinstance(sig_b64, str):
        return False
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(ik_b64)).verify(unb64(sig_b64), data)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def link_control_fields(rec: dict, action: str, ts) -> bytes:
    """canonical_link_control over a link record's own fields."""
    return canonical_link_control(action, rec.get("id"), rec.get("a"), rec.get("b"), rec.get("direction") or "both",
                                  rec.get("expires"), ts)


def _names(ctl: dict, key: str) -> bool:
    """Whether a link's a or b is key, or a namespace (trailing /) above it."""
    for side in (str(ctl.get("a") or ""), str(ctl.get("b") or "")):
        s = _ep(side)
        if s == key or (s.endswith("/") and key.startswith(s)):
            return True
    return False


def check_link_notice(ks, hdr: dict, to_key: str) -> tuple[str | None, str]:
    """What an endpoint does with its own realm's link notice (§19.9): verify a signed control, pin the
    acting endpoint's key, and flag an accept/decline/revoke that the pinned key did not sign.
    Returns (pin result or None, warning text or "")."""
    peer_raw, action = hdr.get("airc-peer"), hdr.get("airc-link-action")
    ik, sig, ctl = hdr.get("airc-peer-ik"), hdr.get("airc-peer-sig"), hdr.get("airc-peer-control")
    if not peer_raw:
        return None, ""
    peer = _ep(peer_raw)
    verified, why = False, ""
    if sig:
        if not (isinstance(ctl, dict) and isinstance(ik, str)):
            why = "its signature cannot be checked (the notice lacks the signed fields)"
        elif not (_names(ctl, peer) and _names(ctl, _ep(to_key))):
            why = "its signed fields name other endpoints"
        elif not (isinstance(ctl.get("ts"), int) and (ctl.get("expires") is None or isinstance(ctl["expires"], int))):
            why = "its signed fields are not integers (ts in ms, expires in seconds)"
        elif not verify_sig(ik, sig, canonical_link_control_ms(action, hdr.get("airc-link"), ctl.get("a"), ctl.get("b"),
                                                               ctl.get("direction") or "both", ctl.get("expires"), ctl["ts"])):
            why = "its signature does not verify"
        else:
            verified = True
    pinned = ks.pin_of(peer)
    if action == "grant" or (action == "accept" and hdr.get("airc-passport-pins")):
        # §12.6, §19.9: a grant's key is an identity pin only when the scope is an endpoint and the key's pin is
        # among the passport's pins (the redeemer's server passes airc-peer-ik only then); never source "link"
        from . import passports as P
        pins = str(hdr.get("airc-passport-pins") or "").split(".")
        if sig and not verified:
            return None, f"[airc: WARNING the link {action} for {hdr.get('airc-link')} from {peer}: {why}; its key was not pinned]"
        if isinstance(ik, str) and len(ik) == 44 and not peer.endswith("/"):
            try:
                if P.pin(ik) in pins:
                    return ks.pin(peer, ik, "passport"), ""
            except ValueError:
                pass
        return None, ""
    if action in ("accept", "decline", "revoke") and pinned:
        if not verified:
            return None, (f"[airc: WARNING the link {action} for {hdr.get('airc-link')} from {peer} was not signed by its pinned "
                          f"end-to-end key ({why or 'unsigned'}); its server may be acting for it]")
        if ik != pinned["ik"]:
            return None, (f"[airc: WARNING the link {action} for {hdr.get('airc-link')} from {peer} is signed by a key other than "
                          f"the pinned one ({fingerprint(ik)} vs {fingerprint(pinned['ik'])}); treat it as unauthenticated]")
        return ks.pin(peer, ik, "link"), ""
    if sig and not verified:
        return None, f"[airc: WARNING the link {action} for {hdr.get('airc-link')} from {peer}: {why}; its key was not pinned]"
    if isinstance(ik, str) and len(ik) == 44:
        return ks.pin(peer, ik, "link"), ""
    return None, ""


# ---------------------------------------------------------------- keystore
def _ep(addr: str) -> str:
    """Pins and keystores are keyed by endpoint key (no fragment)."""
    try:
        return A.parse(addr).key
    except A.AddressError:
        return addr


class E2EError(Exception):
    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code, self.reason = code, reason


class Keystore:
    """One local endpoint's private keys and pins, in <dir>/<sha256(endpoint)[:16]>.json (0600)."""

    def __init__(self, endpoint: str, directory: str | None = None):
        if not AVAILABLE:
            raise E2EError("e2e_unavailable", "end-to-end encryption needs the python package cryptography")
        self.endpoint = endpoint
        self.dir = os.path.expanduser(directory or os.environ.get("AIRC_E2E_DIR") or "~/.airc/e2e")
        self.path = os.path.join(self.dir, hashlib.sha256(endpoint.encode()).hexdigest()[:16] + ".json")
        self.data = {"endpoint": endpoint, "identity": None, "keys": [], "pins": {}, "published": None}
        if os.path.exists(self.path):
            with open(self.path) as f:
                self.data.update(json.load(f))

    # -- storage
    def save(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".ks-")
        with os.fdopen(fd, "w") as f:
            json.dump(self.data, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- keys
    def ensure(self, now: float | None = None, lifetime: int = KEY_LIFETIME) -> bool:
        """Create the identity key and a current encryption key if needed, rotate, prune.
        Returns True when the public record changed (publish it again)."""
        now = time.time() if now is None else now
        changed = False
        if not self.data["identity"]:
            self.data["identity"] = b64(ed25519.Ed25519PrivateKey.generate().private_bytes(_RAW, _PRIV, _NOENC))
            changed = True
        keys = self.data["keys"]
        before = len(keys)
        keys[:] = [k for k in keys if float(k["not_after"]) + RETIRED_GRACE > now]   # destroy retired halves
        changed |= len(keys) != before
        newest = max((float(k["not_after"]) for k in keys), default=0)
        if newest - now < ROTATE_BEFORE:
            sk = x25519.X25519PrivateKey.generate()
            pub = b64(sk.public_key().public_bytes(_RAW, _PUB))
            keys.append({"kid": x_kid(pub), "x25519": pub, "sk": b64(sk.private_bytes(_RAW, _PRIV, _NOENC)),
                         "not_after": int(now + min(lifetime, KEY_LIFETIME_MAX))})
            changed = True
        if changed:
            self.save()
        return changed

    def _identity(self) -> ed25519.Ed25519PrivateKey:
        return ed25519.Ed25519PrivateKey.from_private_bytes(unb64(self.data["identity"]))

    @property
    def ik(self) -> str:
        return b64(self._identity().public_key().public_bytes(_RAW, _PUB))

    @property
    def ifp(self) -> str:
        return fingerprint(self.ik)

    def record(self, now: float | None = None, require: bool = False) -> dict:
        now = time.time() if now is None else now
        rec = {"t": "e2e-keys", "endpoint": self.endpoint, "ik": self.ik,
               "keys": [{"kid": k["kid"], "x25519": k["x25519"], "not_after": int(k["not_after"])}
                        for k in self.data["keys"] if float(k["not_after"]) > now],
               "ts": int(now)}
        if require:
            rec["require"] = True
        rec["sig"] = b64(self._identity().sign(canonical_record(rec)))
        return rec

    def sign(self, data: bytes) -> str:
        """The identity key's ed25519 signature over data, base64."""
        return b64(self._identity().sign(data))

    def private_for(self, kid: str) -> bytes | None:
        for k in self.data["keys"]:
            if k["kid"] == kid:
                return unb64(k["sk"])
        return None

    # -- pins (§19.4)
    def pin_of(self, peer: str) -> dict | None:
        return self.data["pins"].get(peer)

    def pin(self, peer: str, ik: str, source: str, succession_from: str | None = None) -> str:
        """Record peer's identity key. Returns 'new', 'same', 'upgraded', 'succeeded' or 'changed'
        (a different key without succession: not stored, the caller must stop and ask)."""
        cur = self.data["pins"].get(peer)
        if cur is None:
            self.data["pins"][peer] = {"ik": ik, "source": source, "first_seen": int(time.time())}
            self.save()
            return "new"
        if cur["ik"] == ik:
            if PIN_SOURCES.index(source) > PIN_SOURCES.index(cur["source"]):
                cur["source"] = source
                self.save()
                return "upgraded"
            return "same"
        if succession_from and succession_from == cur["ik"]:
            self.data["pins"][peer] = {"ik": ik, "source": cur["source"], "first_seen": int(time.time()),
                                       "succeeded": cur["ik"]}
            self.save()
            return "succeeded"
        return "changed"

    def repin(self, peer: str, ik: str, source: str = "verified"):
        """An operator's explicit decision after a key change."""
        self.data["pins"][peer] = {"ik": ik, "source": source, "first_seen": int(time.time())}
        self.save()

    def check_record(self, peer: str, rec: dict, source: str = "first-use") -> str:
        """Pin the record's ik (first use when nothing better exists); raise E2EError on a change."""
        succ = (rec.get("succession") or {}).get("ik_old")
        r = self.pin(peer, rec["ik"], source, succession_from=succ)
        if r == "changed":
            raise E2EError("e2e_sender", f"the identity key of {peer} changed (pinned {fingerprint(self.pin_of(peer)['ik'])}, "
                                         f"now {fingerprint(rec['ik'])}); verify it and re-pin before talking to it")
        return r

    # -- messages
    def seal(self, msg: dict, peer_record: dict) -> dict:
        """The encrypted form of msg (§19.5), sealed to peer_record's current key. msg needs id/from/to."""
        ok, why = verify_record(peer_record, _ep(msg["to"]))
        if not ok:
            raise E2EError("e2e_no_key", why)
        self.check_record(_ep(msg["to"]), peer_record)
        k = current_key(peer_record)
        mtype = msg.get("type") or "text/plain"
        body, binary = msg["body"], msg.get("_bin")
        # v 2 (§19.5): a binary section is sealed too. The plaintext is the JSON line, then the section's raw
        # bytes; the ciphertext becomes the outer message's binary section, so nothing is base64-encoded.
        signed = canonical_plain(msg["id"], msg["from"], msg["to"], mtype, msg.get("re") or "", body)
        if binary is not None:
            signed += b"\n" + hashlib.sha256(binary).hexdigest().encode()
        plain = {"type": mtype, "body": body, "re": msg.get("re") or "",
                 "sender": {"ik": self.ik, "sig": b64(self._identity().sign(signed))}}
        if binary is not None:
            plain["bin"] = len(binary)
        pt = json.dumps(plain, separators=(",", ":")).encode()
        if binary is not None:
            pt += b"\n" + binary
        info = envelope_info(msg["id"], msg["from"], msg["to"])
        enc, ct = hpke_seal(unb64(k["x25519"]), info, info, pt)
        out = {kk: v for kk, v in msg.items() if kk not in ("re", "body", "type", "_bin", "bin", "bin_sha256")}
        out["type"] = MEDIA_TYPE
        if binary is None:
            out["body"] = json.dumps({"v": 1, "suite": SUITE, "kid": k["kid"], "enc": b64(enc), "ct": b64(ct)}, separators=(",", ":"))
        else:
            out["body"] = json.dumps({"v": 2, "suite": SUITE, "kid": k["kid"], "enc": b64(enc)}, separators=(",", ":"))
            wire.attach_bin(out, ct)
        return out

    def open(self, msg: dict) -> dict:
        """The plaintext form of an encrypted msg addressed to this endpoint; raises E2EError with the
        ack code of §19.6. The result carries hdr['airc-e2e'] = {'ifp', 'pin'} for the reader."""
        try:
            env = wire.loads(msg["body"])
            if not isinstance(env, dict):
                raise ValueError("not an object")
            if env.get("v") not in (1, 2) or env.get("suite") != SUITE:
                raise E2EError("e2e_decrypt", f"unsupported envelope {env.get('v')}/{env.get('suite')}")
        except (ValueError, TypeError):
            raise E2EError("e2e_decrypt", "envelope is not JSON")
        sk = self.private_for(env.get("kid", ""))
        if sk is None:
            raise E2EError("e2e_no_key", f"no private key for kid {env.get('kid')}")
        info = envelope_info(msg["id"], msg["from"], msg["to"])
        try:
            ct = msg["_bin"] if env["v"] == 2 else unb64(env["ct"])   # v 2: the ciphertext is the binary section
            pt = hpke_open(sk, unb64(env["enc"]), info, info, ct)
            binary = None
            if env["v"] == 2:                           # a JSON line, then the raw bytes it counts in "bin"
                head, _, binary = pt.partition(b"\n")
                pt = head
            plain = wire.loads(pt)
        except (InvalidTag, ValueError, KeyError, TypeError):
            raise E2EError("e2e_decrypt", "the envelope did not open")
        # B4: whoever can read a published key can seal anything to it; the plaintext is checked for shape
        snd = plain.get("sender") if isinstance(plain, dict) else None
        if not (isinstance(snd, dict) and isinstance(snd.get("ik"), str) and isinstance(snd.get("sig"), str)
                and all(isinstance(plain.get(k), (str, type(None))) for k in ("type", "body", "re"))):
            raise E2EError("e2e_decrypt", "the sealed message is malformed")
        if plain.get("re") and not wire.valid_id(plain["re"]):          # §4.2 holds inside the envelope too
            raise E2EError("e2e_decrypt", "the sealed re does not fit the id grammar")
        if env["v"] == 2 and plain.get("bin") != len(binary):
            raise E2EError("e2e_decrypt", "the sealed binary section does not match its header")
        signed = canonical_plain(msg["id"], msg["from"], msg["to"], plain.get("type") or "text/plain",
                                 plain.get("re") or "", plain.get("body") or "")
        if binary is not None:
            signed += b"\n" + hashlib.sha256(binary).hexdigest().encode()
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(unb64(snd["ik"])).verify(unb64(snd["sig"]), signed)
        except (InvalidSignature, KeyError, ValueError):
            raise E2EError("e2e_sender", "the sender's signature did not verify")
        pin = self.check_record(_ep(msg["from"]), {"ik": snd["ik"]})
        out = {k: v for k, v in msg.items() if k not in ("body", "type", "_bin", "bin", "bin_sha256")}
        out["type"] = plain.get("type") or "text/plain"
        out["body"] = plain.get("body") or ""
        if binary is not None:
            wire.attach_bin(out, binary)
        if plain.get("re"):
            out["re"] = plain["re"]
        out.setdefault("hdr", {})
        out["hdr"] = dict(out["hdr"], **{"airc-e2e": {"ifp": fingerprint(snd["ik"]),
                                                       "pin": (self.pin_of(_ep(msg["from"])) or {}).get("source", pin)}})
        return out


REPUBLISH_EVERY = 6 * 3600


async def ensure_published(ks: Keystore, publish) -> bool:
    """Create or rotate ks's keys and publish its record when it changed or has not been published
    lately. publish(record) -> (ok, reason). Returns whether the record is published."""
    changed = ks.ensure()
    last = ks.data.get("published") or 0
    if changed or time.time() - last > REPUBLISH_EVERY:
        ok, _why = await publish(ks.record())
        if ok:
            ks.data["published"] = int(time.time())
            ks.save()
        return ok
    return True


async def auto_seal(msg: dict, get, publish, directory: str | None = None) -> tuple[dict, str]:
    """The automatic path (§19): msg must carry absolute from/to. Publishes the sender's keys, fetches
    the recipient's record with get(endpoint) -> record|None, seals when there is one.
    Returns (msg to send, note): note is "e2e <ifp>" or "plain: <why>". Raises E2EError on a key change."""
    if not AVAILABLE:
        return msg, "plain: cryptography missing"
    ks = Keystore(_ep(msg["from"]), directory)
    await ensure_published(ks, publish)
    rec = await get(_ep(msg["to"]))
    if not rec:
        return msg, "plain: the recipient publishes no keys"
    ok, why = verify_record(rec, _ep(msg["to"]))
    if not ok:
        return msg, f"plain: {why}"
    sealed = ks.seal(msg, rec)
    return sealed, f"e2e {fingerprint(rec['ik'])}"


def _sealed_kid(m: dict) -> str | None:
    try:
        return json.loads(m["body"]).get("kid") if m.get("type") == MEDIA_TYPE else None
    except (ValueError, AttributeError):
        return None


async def auto_send(msg: dict, get, publish, send, directory: str | None = None) -> tuple[dict, str]:
    """auto_seal, then send(msg) -> ack. On a failed ack with code e2e_no_key (§19.6: the recipient
    holds no private key for that kid, typically after rotating) the recipient's record is fetched
    again and, when its current key differs from the one used, the message is resealed and sent
    once more, under a new id (the first one is spent at the recipient)."""
    import uuid
    orig = dict(msg)
    m, note = await auto_seal(msg, get, publish, directory)
    a = await send(m)
    if not (isinstance(a, dict) and a.get("status") == "failed" and a.get("code") == "e2e_no_key" and _sealed_kid(m)):
        return a, note
    m2, note2 = await auto_seal({**orig, "id": str(uuid.uuid4())}, get, publish, directory)
    if _sealed_kid(m2) in (None, _sealed_kid(m)):
        return a, note                                  # same key (or none now): a retry cannot open either
    return await send(m2), note2 + " (resealed after e2e_no_key)"

