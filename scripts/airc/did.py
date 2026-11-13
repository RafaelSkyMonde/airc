"""
airc.did: DID documents (spec §24). Pure functions, stdlib only.

A realm's signing keys (§9.1) and an endpoint's key record (§19.2) exported in
W3C DID syntax: `did:web:<host>` for the realm, `did:web:<host>:<ns>:<agent>`
for an endpoint, and `did:key:z6Mk…` for an identity key. The documents mirror
the DNS record and the key record; nothing else in the protocol consults them.

Multikey: multibase base58-btc (prefix `z`) over multicodec prefix + raw key;
ed25519-pub is 0xed 0x01 (`z6Mk…`), x25519-pub is 0xec 0x01 (`z6LS…`).
"""
from __future__ import annotations

import base64
import datetime

CONTEXT = ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"]
ED25519_PREFIX = b"\xed\x01"
X25519_PREFIX = b"\xec\x01"

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58)}


def b58encode(data: bytes) -> str:
    """base58-btc (Bitcoin alphabet), leading zero bytes become leading '1's."""
    n = int.from_bytes(data, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(_B58[r])
    pad = len(data) - len(data.lstrip(b"\0"))
    return "1" * pad + "".join(reversed(out))


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise ValueError(f"not base58: {c!r}")
        n = n * 58 + _B58_INDEX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\0" * pad + body


def multikey(raw: bytes, prefix: bytes) -> str:
    """Multibase base58-btc of multicodec prefix + raw key."""
    return "z" + b58encode(prefix + raw)


def ed25519_multikey(pub_b64: str) -> str:
    return multikey(base64.b64decode(pub_b64), ED25519_PREFIX)


def x25519_multikey(pub_b64: str) -> str:
    return multikey(base64.b64decode(pub_b64), X25519_PREFIX)


def unmultikey(mk: str) -> tuple[bytes, bytes]:
    """A Multikey string -> (multicodec prefix, raw key). Raises ValueError when it is not one we know."""
    if not mk.startswith("z"):
        raise ValueError("multibase prefix is not 'z' (base58-btc)")
    b = b58decode(mk[1:])
    for p in (ED25519_PREFIX, X25519_PREFIX):
        if b.startswith(p) and len(b) == len(p) + 32:
            return p, b[len(p):]
    raise ValueError("unknown multicodec prefix or key length")


def did_key(pub_b64: str) -> str:
    """The identity key as did:key (§24.2)."""
    return "did:key:" + ed25519_multikey(pub_b64)


def web_did(host: str, *segments: str) -> str:
    """did:web for a host and path segments; a port in the host is written %3A (§24.1)."""
    return ":".join(["did:web:" + host.replace(":", "%3A"), *segments])


def rfc3339(ts: int | float) -> str:
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def realm_document(realm: str, host: str, keys: list[tuple[str, str]], current_kid: str, apex_too: bool = False) -> dict:
    """§24.1. `keys` are (kid, base64 public key) for every key in the _airc TXT record; `current_kid`
    names the one that signs now. `apex_too` adds did:web:<realm> to alsoKnownAs when the document is
    also served at the realm's apex (only meaningful when host != realm)."""
    did = web_did(host)
    address = f"airc://{realm}/"
    cur = next((p for k, p in keys if k == current_kid), None)
    vm, am = [], []
    if cur is not None:
        vm.append({"id": f"{did}#airc", "type": "Multikey", "controller": did, "publicKeyMultibase": ed25519_multikey(cur)})
        am.append(f"{did}#airc")
    for kid, pub in keys:
        vm.append({"id": f"{did}#airc-{kid}", "type": "Multikey", "controller": did, "publicKeyMultibase": ed25519_multikey(pub)})
        am.append(f"{did}#airc-{kid}")
    aka = [address]
    if apex_too and host != realm:
        aka.append(web_did(realm))
    return {"@context": list(CONTEXT), "id": did, "alsoKnownAs": aka, "verificationMethod": vm,
            "assertionMethod": am, "authentication": [f"{did}#airc"] if cur is not None else [],
            "service": [{"id": f"{did}#airc", "type": "AIRC", "serviceEndpoint": address}]}


def endpoint_document(realm: str, host: str, ns: str, agent: str, record: dict, now: float | None = None) -> dict:
    """§24.2 from the endpoint's current key record (§19.2). Expired encryption keys are left out."""
    import time
    now = time.time() if now is None else now
    did = web_did(host, ns, agent)
    controller = web_did(host)
    address = f"airc://{realm}/{ns}/{agent}"
    ik = record["ik"]
    vm = [{"id": f"{did}#ik", "type": "Multikey", "controller": did, "publicKeyMultibase": ed25519_multikey(ik)}]
    ka = []
    for k in record.get("keys") or []:
        if int(k.get("not_after", 0)) <= now:
            continue
        vm.append({"id": f"{did}#{k['kid']}", "type": "Multikey", "controller": did,
                   "publicKeyMultibase": x25519_multikey(k["x25519"]), "expires": rfc3339(k["not_after"])})
        ka.append(f"{did}#{k['kid']}")
    return {"@context": list(CONTEXT), "id": did, "alsoKnownAs": [address, did_key(ik)], "controller": controller,
            "verificationMethod": vm, "assertionMethod": [f"{did}#ik"], "keyAgreement": ka,
            "service": [{"id": f"{did}#airc", "type": "AIRC", "serviceEndpoint": address}]}
