# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Realm signing keys and message signatures (transport spec §7.2).

Every realm holds one or more ed25519 keys and publishes the public halves in
DNS:   _airc.<realm>  TXT  "v=airc1 k=ed25519 p=<base64 public key>"
(one record per key; publishing two lets a realm rotate).

Algorithm agility without negotiation. Nothing is negotiated on the wire:
the published key names its algorithm (k=), every signature names its
algorithm as a prefix, and a verifier accepts only algorithms on its own
allowlist (config signing.accept_algs, default ["ed25519"]). To move to a
new algorithm a realm publishes a second key of the new type, signs each
message with both keys (hdr["sig"] may be a list), and drops the old one once
its peers have added the new algorithm to their allowlists. A message picks
nothing; a downgrade needs the verifier's cooperation.

What is signed:
  message   canonical string, placed in hdr["sig"] as "ed25519:<kid>:<base64>"
            (or a list of such strings, one per key, during a transition)
            airc-msg-2 \\n id \\n from \\n to \\n <ts in whole ms> \\n ttl \\n type \\n re \\n bin_sha256 \\n body (§9.3)
  hello     "airc-hello\\n<my realm>\\n<target realm>\\n<ts>\\n<nonce>"      (peer link, dialler)
  welcome   "airc-welcome\\n<my realm>\\n<peer realm>\\n<nonce>"            (peer link, acceptor)

kid is the first 8 hex digits of sha256(public key), so a verifier with
several published keys picks the right one without trying each.

Uses the `cryptography` package for ed25519; it is the reference
implementation's only dependency, and only federation needs it. A realm that
never opens its peer face runs without it.
"""
from __future__ import annotations

import base64
import hashlib
import os
import time

ALG = "ed25519"
ACCEPTED_ALGS = ("ed25519",)      # the verifier's allowlist; "none" can never be on it
HELLO_SKEW = 300


class SigningUnavailable(RuntimeError):
    pass


def _lib():
    from . import cryptolib
    if not cryptolib.available():
        raise SigningUnavailable("cannot sign: " + cryptolib.HINT)
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
        from cryptography.exceptions import InvalidSignature
    except BaseException as e:  # pragma: no cover   not installed, or broken (pyo3 panics are BaseException)
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        raise SigningUnavailable("signing needs the Python package 'cryptography': pip install cryptography "
                                 "(Debian/Ubuntu: apt install python3-cryptography; if that import fails, "
                                 "python3 -m venv v && v/bin/pip install cryptography)") from e
    return ed25519, serialization, InvalidSignature


def kid_of(pub_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(pub_b64)).hexdigest()[:8]


DEFAULT_MSG_TTL = 86400


def canonical_message(m: dict) -> bytes:
    """§9.3 airc-msg-2: every field on its own line, ttl and the binary section's hash always present, the
    body last, so the string is a bijection of the signed fields."""
    ts_ms = int(round(float(m.get("ts", 0)) * 1000))
    ttl = m.get("ttl")
    parts = ["airc-msg-2", str(m["id"]), str(m["from"]), str(m["to"]), str(ts_ms),
             str(int(ttl) if ttl is not None else DEFAULT_MSG_TTL), str(m.get("type") or "text/plain"),
             str(m.get("re") or ""), str(m.get("bin_sha256") or ""), str(m["body"])]
    return "\n".join(parts).encode()


def canonical_hello(realm: str, target: str, ts: int, nonce: str) -> bytes:
    return f"airc-hello\n{realm}\n{target}\n{ts}\n{nonce}".encode()


def canonical_welcome(realm: str, peer_realm: str, nonce: str) -> bytes:
    return f"airc-welcome\n{realm}\n{peer_realm}\n{nonce}".encode()


def canonical_capabilities(realm: str, nonce: str, ts: int) -> bytes:
    return f"airc-capabilities\n{realm}\n{nonce}\n{ts}".encode()


def canonical_client_request(realm: str, method: str, path: str, ts: int, nonce: str, body: bytes) -> bytes:
    return f"airc-client\n{realm}\n{method.upper()}\n{path}\n{ts}\n{nonce}\n{hashlib.sha256(body).hexdigest()}".encode()


def txt_record(realm: str, pub_b64: str) -> str:
    return f'_airc.{realm}. IN TXT "v=airc1 k=ed25519 p={pub_b64}"'


class Signer:
    """A realm's private key. Loads <path>; generates it (mode 0600) if absent."""

    def __init__(self, path: str):
        ed25519, serialization, _ = _lib()
        self.path = path
        if os.path.exists(path):
            with open(path, "rb") as f:
                seed = base64.b64decode(f.read().strip())
            self._key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        else:
            self._key = ed25519.Ed25519PrivateKey.generate()
            seed = self._key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                           serialization.NoEncryption())
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(base64.b64encode(seed) + b"\n")
        pub = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_b64 = base64.b64encode(pub).decode()
        self.kid = kid_of(self.public_b64)

    def sign(self, data: bytes) -> str:
        return base64.b64encode(self._key.sign(data)).decode()

    def sign_message(self, m: dict, extra_signers: list["Signer"] | None = None) -> dict:
        """Sign with this key, plus any transition keys; several signatures
        are carried as a list so peers on either algorithm can verify."""
        sigs = [f"{ALG}:{self.kid}:{self.sign(canonical_message(m))}"]
        for other in extra_signers or []:
            sigs.append(f"{ALG}:{other.kid}:{other.sign(canonical_message(m))}")
        m.setdefault("hdr", {})["sig"] = sigs[0] if len(sigs) == 1 else sigs
        return m

    def sign_hello(self, target_realm: str, my_realm: str, nonce: str) -> dict:
        ts = int(time.time())
        return {"ts": ts, "nonce": nonce, "sig": f"{ALG}:{self.kid}:{self.sign(canonical_hello(my_realm, target_realm, ts, nonce))}"}

    def sign_welcome(self, my_realm: str, peer_realm: str, nonce: str) -> str:
        return f"{ALG}:{self.kid}:{self.sign(canonical_welcome(my_realm, peer_realm, nonce))}"

    def sign_capabilities(self, my_realm: str, nonce: str, ts: int) -> str:
        return f"{ALG}:{self.kid}:{self.sign(canonical_capabilities(my_realm, nonce, ts))}"

    def sign_client_request(self, realm: str, method: str, path: str, body: bytes) -> str:
        """Value for the Authorization header: AIRC-Key <kid>:<ts>:<nonce>:<sig>."""
        ts = int(time.time())
        nonce = os.urandom(12).hex()
        sig = self.sign(canonical_client_request(realm, method, path, ts, nonce, body))
        return f"AIRC-Key {self.kid}:{ts}:{nonce}:{sig}"


def _parse_sig(sig: str, accept=ACCEPTED_ALGS):
    try:
        alg, kid, b64 = sig.split(":", 2)
        if alg not in accept:
            return None
        return alg, kid, base64.b64decode(b64)
    except (ValueError, TypeError, AttributeError):
        return None


def _verify_one(data: bytes, alg: str, raw: bytes, pub_b64: str) -> bool:
    ed25519, _, InvalidSignature = _lib()
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(raw, data)
            return True
    except (InvalidSignature, ValueError):
        return False
    return False   # an algorithm on the allowlist that this build cannot verify


def verify(data: bytes, sig, pubkeys_b64: list[str], accept=ACCEPTED_ALGS) -> bool:
    """True if any signature over data verifies with any given public key
    under an accepted algorithm. `sig` is one "alg:kid:base64" string or a
    list of them. The kid orders the candidates; every key is still tried."""
    sigs = sig if isinstance(sig, list) else [sig]
    for one in sigs:
        parsed = _parse_sig(one or "", accept)
        if not parsed or not pubkeys_b64:
            continue
        alg, kid, raw = parsed
        for pub in sorted(pubkeys_b64, key=lambda p: 0 if kid_of(p) == kid else 1):
            if _verify_one(data, alg, raw, pub):
                return True
    return False


def verify_message(m: dict, pubkeys_b64: list[str], accept=ACCEPTED_ALGS) -> bool:
    sig = (m.get("hdr") or {}).get("sig")
    return bool(sig) and verify(canonical_message(m), sig, pubkeys_b64, accept)


def verify_hello(hello: dict, target_realm: str, pubkeys_b64: list[str], skew: int = HELLO_SKEW, accept=ACCEPTED_ALGS) -> bool:
    try:
        ts = int(hello.get("ts"))
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > skew:
        return False
    nonce = str(hello.get("nonce") or "")
    return verify(canonical_hello(str(hello.get("realm", "")).lower(), target_realm, ts, nonce), hello.get("sig", ""), pubkeys_b64, accept)


def verify_welcome(welcome: dict, expected_realm: str, my_realm: str, nonce: str, pubkeys_b64: list[str], accept=ACCEPTED_ALGS) -> bool:
    return verify(canonical_welcome(expected_realm, my_realm, nonce), welcome.get("sig", ""), pubkeys_b64, accept)


def verify_capabilities(doc: dict, expected_realm: str, nonce: str, pubkeys_b64: list[str], skew: int = HELLO_SKEW, accept=ACCEPTED_ALGS) -> bool:
    try:
        ts = int(doc.get("ts"))
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts) > skew or str(doc.get("nonce")) != nonce or str(doc.get("realm", "")).lower() != expected_realm:
        return False
    return verify(canonical_capabilities(expected_realm, nonce, ts), doc.get("sig", ""), pubkeys_b64, accept)


def parse_client_auth(header: str):
    """'AIRC-Key kid:ts:nonce:sig' -> (kid, ts, nonce, sig) or None."""
    try:
        scheme, rest = header.strip().split(None, 1)
        if scheme != "AIRC-Key":
            return None
        kid, ts, nonce, sig = rest.split(":", 3)
        return kid, int(ts), nonce, sig
    except (ValueError, AttributeError):
        return None


def verify_client_request(header: str, realm: str, method: str, path: str, body: bytes, pub_b64: str,
                          skew: int = HELLO_SKEW) -> bool:
    parsed = parse_client_auth(header)
    if not parsed:
        return False
    kid, ts, nonce, sig = parsed
    if abs(time.time() - ts) > skew or kid != kid_of(pub_b64):
        return False
    return verify(canonical_client_request(realm, method, path, ts, nonce, body), f"{ALG}:{kid}:{sig}", [pub_b64])
