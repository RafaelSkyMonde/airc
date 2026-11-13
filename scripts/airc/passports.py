# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Passports (spec §12): bearer invitations that create a link when redeemed.

A passport names a scope on the issuing realm (an endpoint, a namespace or the
whole realm), carries a secret token, and pins one or more authorizing keys,
every one of which signed the passport's terms (§12.4). There is one form:

    https://<host>/<scope-path>#passport=<token>.<pin>[.<pin>...][.r=<realm pin>]

host serves the issuing realm's signed capabilities document (§3.4.1); the
scope path is `alice/x` (endpoint), `alice/` (namespace) or empty (realm). The
pin is base62 (0-9A-Za-z) of the first 16 bytes of SHA-256 over the raw ed25519
public key, left-padded with '0' to 22 characters. The token is client-made
base62, 22 to 64 characters, and only its SHA-256 is stored by the issuer.

Records, and the keys entitled to authorize passports per scope (§4.7 key-*
operations), live in <state_dir>/passports.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import string
import time

from . import address as A
from .links import parse_side, side_kind

MEDIA_TYPE = "application/airc-passport+json"
ENDPOINT_NAME = "_passport"          # airc://<realm>/_passport receives redemptions
DEFAULT_TTL = 7 * 86400
DEFAULT_USES = 1
DEFAULT_LINK_TTL = 30 * 86400
LABEL_MAX = 200
MAX_PINS = 16                        # what the parser reads; issuance is capped by policy (default 4)
B62 = string.digits + string.ascii_uppercase + string.ascii_lowercase
OLD_FORMAT = "old or unknown passport format; ask the issuer for a new passport"
WITHDRAWN = "passport format withdrawn; ask for a new one"
DIRECTIONS = ("both", "a-initiates", "b-initiates")
_FORM = re.compile(r"^https://(?P<host>[^/#?\s]+)/(?P<path>[^#?\s]*)#passport=(?P<token>[0-9A-Za-z]{22,64})"
                   r"(?P<pins>(?:\.[0-9A-Za-z]{22})+)(?:\.r=(?P<rpin>[0-9A-Za-z]{22}))?(?P<layers>(?:~[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[0-9A-Za-z]{22})*)$")
_REF = re.compile(r"^[0-9a-f]{64}\Z")


class PassportFormatError(ValueError):
    pass


def b62(n: int, width: int = 0) -> str:
    out = []
    while n:
        n, r = divmod(n, 62)
        out.append(B62[r])
    return ("".join(reversed(out)) or "0").rjust(width, "0")


def pin_raw(raw: bytes) -> str:
    return b62(int.from_bytes(hashlib.sha256(raw).digest()[:16], "big"), 22)


def pin(key_b64: str) -> str:
    """§12.1: the pin of a base64 ed25519 public key (raises ValueError if it is not 32 bytes of base64)."""
    import base64
    raw = base64.b64decode(key_b64, validate=True)
    if len(raw) != 32:
        raise ValueError("a public key is 32 bytes")
    return pin_raw(raw)


def new_token(n: int = 32) -> str:
    """§12.2: a CSPRNG token, n base62 characters (32 -> about 190 bits)."""
    return "".join(secrets.choice(B62) for _ in range(n))


def valid_token(token) -> bool:
    return isinstance(token, str) and 22 <= len(token) <= 64 and all(c in B62 for c in token)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- scopes
def scope_of(text, realm: str | None = None, namespace: str = "") -> str:
    """A scope in any accepted form -> its URI key (airc://R/x/y, airc://R/ns/, airc://R/)."""
    return parse_side(text, realm, namespace).key


def scope_kind(scope: str) -> str:
    return side_kind(scope)


def scope_path(scope: str) -> str:
    """The scope-path of a passport URL: 'alice/x', 'alice/' or ''."""
    rest = scope.split("//", 1)[1]
    return rest.split("/", 1)[1]


def scope_realm(scope: str) -> str:
    return parse_side(scope).authority


def entitles(entitled_scope: str, scope: str) -> bool:
    """An entitled key at scope S covers S and everything beneath it: for a namespace or realm, anything
    under it; for an endpoint, itself and its sub-agents (S/...)."""
    if entitled_scope.endswith("/"):
        return scope.startswith(entitled_scope)
    return scope == entitled_scope or scope.startswith(entitled_scope + "/")


def scope_pattern_match(pattern: str, scope: str) -> bool:
    """A policy pattern (§2.7) against a scope. '*' matches all; a pattern ending in '/' matches the scope
    itself and everything beneath; otherwise the address pattern rules apply to endpoint scopes and to
    the namespace prefix of group scopes."""
    p = pattern.strip()
    if p == "*":
        return True
    try:
        if p.endswith("/"):
            return entitles(scope_of(p), scope)
        if scope.endswith("/"):
            return False
        return A.pattern_match(p, A.parse(scope))
    except A.AddressError:
        return False


# ---------------------------------------------------------------- canonical string and signatures
def _secs(v) -> str:
    return "" if v in (None, "") else str(int(float(v)))


def canonical(scope: str, token_sha256: str, direction: str, expires, uses, bind_to, link_ttl, offer=None) -> bytes:
    """§12.4: the string every authorizing key signs. offer: the offer hash (§12.9) for a passport that
    answers a link offer, else empty."""
    return "\n".join(["airc-passport-auth", str(scope), str(token_sha256).lower(), str(direction),
                      _secs(expires), "" if uses in (None, "") else str(int(uses)), str(bind_to or ""),
                      _secs(link_ttl), str(offer or "").lower()]).encode()


def offer_hash(link_id: str, offerer: str, offeree: str, direction: str, expires) -> str:
    """§12.9: the offer hash, lowercase hex SHA-256 of
    airc-offer\n<link id>\n<offerer URI>\n<offeree URI>\n<direction>\n<expires Unix seconds or empty>."""
    return hashlib.sha256("\n".join(["airc-offer", str(link_id), str(offerer), str(offeree), str(direction),
                                     _secs(expires)]).encode()).hexdigest()


def offer_hash_of(rec: dict) -> str:
    """The offer hash of a link offer record (offerer = offered_by, offeree = the other side)."""
    offerer = rec["offered_by"]
    offeree = rec["b"] if rec["a"] == offerer else rec["a"]
    return offer_hash(rec["id"], offerer, offeree, rec["direction"], rec.get("expires"))


def canonical_of(pa: dict) -> bytes:
    """canonical() over a record or a grant's passport_auth (fields scope/token_sha256 or token_hash...);
    canonical_delegate() for a delegation (§12.10)."""
    if pa.get("delegates"):
        return canonical_delegate(pa.get("scope", ""), pa.get("token_sha256") or pa.get("token_hash") or "",
                                  pa.get("direction", ""), pa.get("expires"), pa.get("uses"), pa.get("bind_to"),
                                  pa.get("link_ttl"), pa["delegates"], pa.get("rules"))
    return canonical(pa.get("scope", ""), pa.get("token_sha256") or pa.get("token_hash") or "", pa.get("direction", ""),
                     pa.get("expires"), pa.get("uses"), pa.get("bind_to"), pa.get("link_ttl"), pa.get("offer"))


def verify(key_b64: str, sig_b64: str, data: bytes) -> bool:
    from . import e2e as E2E
    return E2E.verify_sig(key_b64, sig_b64, data)


def auth_problem(auth, data: bytes) -> str | None:
    """Check a list of {key, sig}: well formed, distinct keys, every signature verifies over data."""
    if not isinstance(auth, list):
        return "auth must be a list of {key, sig}"
    seen = set()
    for a in auth:
        if not (isinstance(a, dict) and isinstance(a.get("key"), str) and isinstance(a.get("sig"), str)):
            return "auth must be a list of {key, sig}"
        try:
            p = pin(a["key"])
        except ValueError:
            return "an auth key is not a base64 ed25519 public key"
        if p in seen:
            return f"key {p} is listed twice"
        seen.add(p)
        if not verify(a["key"], a["sig"], data):
            return f"the signature of key {p} does not verify over these terms"
    return None


# ---------------------------------------------------------------- the passport string
def render(host: str, scope: str, token: str, pins: list[str], realm_pin: str | None = None) -> str:
    """§12.3; realm_pin: the pin of the issuing realm's signing key, appended as .r=<pin>."""
    return f"https://{host}/{scope_path(scope)}#passport={token}." + ".".join(pins) + (f".r={realm_pin}" if realm_pin else "")


def parse(text) -> dict:
    """The one passport form -> {"host", "path", "token", "pins", "realm_pin" (or None)}. Anything else raises
    PassportFormatError(OLD_FORMAT)."""
    t = text.strip() if isinstance(text, str) else ""
    m = _FORM.match(t)
    if not m:
        raise PassportFormatError(OLD_FORMAT)
    host, path = m.group("host").lower(), m.group("path")
    try:
        h, port = A._authority(host)
        if path:
            parse_side("//" + h + "/" + path)
    except A.AddressError:
        raise PassportFormatError(OLD_FORMAT)
    pins = m.group("pins")[1:].split(".")
    if len(pins) > MAX_PINS or len(set(pins)) != len(pins):
        raise PassportFormatError(OLD_FORMAT)
    out = {"host": host, "path": path, "token": m.group("token"), "pins": pins, "realm_pin": m.group("rpin")}
    layers = [x for x in m.group("layers").split("~") if x]
    if layers:                                   # §12.10: a delegated passport carries the reference, not a token
        if not _REF.match(m.group("token")):
            raise PassportFormatError(OLD_FORMAT)
        out["layers"] = layers
    return out


def render_delegated(host: str, scope: str, reference: str, pins: list[str], layers: list[str],
                     realm_pin: str | None = None) -> str:
    return render(host, scope, reference, pins, realm_pin) + "".join("~" + l for l in layers)


# ---------------------------------------------------------------- delegated passports (§12.10)
import base64 as _b64

DIR_ORDER = {"both": 2, "a-initiates": 1, "b-initiates": 1}


def cjson(obj) -> str:
    """Canonical JSON: keys sorted, no whitespace, UTF-8 (§12.10)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def b64u(b: bytes) -> str:
    return _b64.urlsafe_b64encode(b).decode().rstrip("=")


def unb64u(s: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", s or ""):
        raise ValueError("not base64url")
    return _b64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def norm_delegates(ds) -> list[dict]:
    """[{"realm", "pins"}] checked and normalized (realm lower case); raises ValueError."""
    if not isinstance(ds, list) or not ds:
        raise ValueError("delegates must be a non-empty list of {realm, pins}")
    out = []
    for d in ds:
        if not (isinstance(d, dict) and isinstance(d.get("realm"), str) and isinstance(d.get("pins"), list) and d["pins"]
                and all(isinstance(p, str) and re.fullmatch(r"[0-9A-Za-z]{22}", p) for p in d["pins"])):
            raise ValueError("each delegate is {realm, pins: [22-character pins]}")
        realm, port = A._authority(d["realm"].lower())
        out.append({"realm": realm if port is None else f"{realm}:{port}", "pins": list(d["pins"])})
    return out


def rules_line(rules) -> str:
    return cjson(rules) if isinstance(rules, dict) and rules else ""


def canonical_delegate(scope, token_sha256, direction, expires, uses, bind_to, link_ttl, delegates, rules) -> bytes:
    """§12.10: the string a delegation's authorizing keys sign."""
    return "\n".join(["airc-passport-delegate", str(scope), str(token_sha256).lower(), str(direction), _secs(expires),
                      "" if uses in (None, "") else str(int(uses)), str(bind_to or ""), _secs(link_ttl),
                      cjson(delegates), rules_line(rules)]).encode()


def canonical_layer(scope: str, reference: str, prev_hash: str, body_json: str) -> bytes:
    return "\n".join(["airc-passport-layer", scope, reference, prev_hash, body_json]).encode()


def layer_hash(enc: str) -> str:
    return hashlib.sha256(enc.encode()).hexdigest()


def decode_layer(enc: str) -> dict:
    """An encoded layer -> {"body", "json", "sig", "pin", "enc"}; raises ValueError."""
    parts = enc.split(".")
    if len(parts) != 3:
        raise ValueError("a layer is body.sig.pin")
    raw = unb64u(parts[0]).decode()
    try:
        body = json.loads(raw, parse_constant=lambda c: (_ for _ in ()).throw(ValueError(f"{c} is not JSON")))
    except RecursionError:
        raise ValueError("a layer body is nested too deeply")
    if not isinstance(body, dict) or cjson(body) != raw:
        raise ValueError("a layer body must be canonical JSON")
    if not (isinstance(body.get("id"), str) and re.fullmatch(r"[0-9A-Za-z]{11,64}", body["id"])):
        raise ValueError("a layer id is 11 to 64 base62 characters")
    if not isinstance(body.get("expires"), int) or isinstance(body["expires"], bool):
        raise ValueError("a layer needs expires (integer Unix seconds)")
    if not isinstance(body.get("key"), str) or pin(body["key"]) != parts[2]:
        raise ValueError("the layer's key does not match its pin")
    if body.get("direction") is not None and body["direction"] not in DIRECTIONS:
        raise ValueError("bad layer direction")
    for k in ("uses", "link_ttl"):
        if body.get(k) is not None and (not isinstance(body[k], int) or isinstance(body[k], bool) or body[k] < 1):
            raise ValueError(f"layer {k} must be a positive integer")
    if body.get("delegates") is not None:
        if norm_delegates(body["delegates"]) != body["delegates"]:
            raise ValueError("layer delegates must be normalized")
    if body.get("rules") is not None and not isinstance(body["rules"], dict):
        raise ValueError("layer rules must be an object")
    if body.get("offer") is not None and not (isinstance(body["offer"], str) and _REF.match(body["offer"])):
        raise ValueError("a layer's offer is an offer hash (64 lowercase hex digits)")
    return {"body": body, "json": raw, "sig": parts[1], "pin": parts[2], "enc": enc}


def layer_pins(layers: list[str]) -> list[str]:
    """The pins of encoded layers, in order (the last dot-separated part of each)."""
    return [l.rsplit(".", 1)[-1] for l in layers if isinstance(l, str) and "." in l]


def new_layer_id() -> str:
    return new_token(16)


def make_layer(signer, scope: str, reference: str, prev_enc: str | None, body: dict) -> str:
    """Sign a layer (pure client-side). signer: .ik (base64 public key) and .sign(bytes) -> standard base64."""
    body = dict(body, key=signer.ik)
    if body.get("delegates") is not None:
        body["delegates"] = norm_delegates(body["delegates"])
    raw = cjson(body)
    data = canonical_layer(scope, reference, layer_hash(prev_enc) if prev_enc else "", raw)
    sig = _b64.b64decode(signer.sign(data))
    return f"{b64u(raw.encode())}.{b64u(sig)}.{pin(signer.ik)}"


def narrower(child: str | None, parent: str) -> bool:
    return child is None or parent == "both" or child == parent


def _realm_of(pin_: str, delegates: list[dict]) -> str | None:
    return next((d["realm"] for d in delegates if pin_ in d["pins"]), None)


def _realm_allowed(patterns: list[str], realm: str) -> bool:
    for p in patterns:
        p = str(p).lower()
        if p == "*" or p == realm or (p.startswith("*.") and realm.endswith(p[1:])):
            return True
    return False


class ChainError(ValueError):
    pass


def check_chain(root: dict, layers: list[str], now: float | None = None, layer_state=None) -> dict:
    """§12.10 steps 2-3 (signatures, parents, terms, rules, finality) over a root's terms
    {scope, token_hash|token_sha256, direction, expires, link_ttl, bind_to, delegates, rules}.
    layer_state(realm, id) -> None or why the layer may not be used (revoked, no uses left).
    Returns {"chain": [{realm, id, pin}], "direction", "link_ttl", "bind_tos", "bodies"}; raises ChainError."""
    now = time.time() if now is None else now
    if not layers:
        raise ChainError("a delegation cannot be redeemed without a delegate layer")
    ref = root.get("token_sha256") or root.get("token_hash")
    parent = {"expires": root.get("expires"), "link_ttl": root.get("link_ttl"), "direction": root.get("direction") or "both",
              "delegates": root.get("delegates") or []}
    rules = []                                       # (index stated at, rules)
    if isinstance(root.get("rules"), dict) and root["rules"]:
        rules.append((-1, root["rules"]))
    chain, bind_tos, bodies = [], [root.get("bind_to")] if root.get("bind_to") else [], []
    direction, link_ttl, prev = parent["direction"], parent["link_ttl"], None
    for i, enc in enumerate(layers):
        try:
            L = decode_layer(enc)
        except (ValueError, UnicodeDecodeError) as e:
            raise ChainError(f"layer {i + 1} is malformed ({e})")
        b = L["body"]
        if not parent["delegates"]:
            raise ChainError(f"layer {i + 1} follows a final layer")
        realm = _realm_of(L["pin"], parent["delegates"])
        if realm is None:
            raise ChainError(f"layer {i + 1} is signed by a key its parent does not list")
        data = canonical_layer(root["scope"], ref, layer_hash(prev) if prev else "", L["json"])
        try:
            sig_b64 = _b64.b64encode(unb64u(L["sig"])).decode()
        except ValueError:
            raise ChainError(f"layer {i + 1} has an unreadable signature")
        if not verify(b["key"], sig_b64, data):
            raise ChainError(f"the signature of layer {i + 1} does not verify")
        if b["expires"] < now:
            raise ChainError(f"layer {i + 1} has expired")
        if parent["expires"] not in (None, "") and b["expires"] > int(float(parent["expires"])):
            raise ChainError(f"layer {i + 1} expires after its parent")
        lt = b.get("link_ttl")
        if lt is not None and parent["link_ttl"] not in (None, "") and lt > int(parent["link_ttl"]):
            raise ChainError(f"layer {i + 1} has a longer link_ttl than its parent")
        if not narrower(b.get("direction"), parent["direction"]):
            raise ChainError(f"layer {i + 1} has a wider direction than its parent")
        for at, r in rules:                         # rules stated above apply to the layers that follow
            if isinstance(r.get("depth"), int) and i - at > r["depth"]:
                raise ChainError(f"layer {i + 1} exceeds the depth allowed by {'the delegation' if at < 0 else f'layer {at + 1}'}")
            # "to" limits the realms the next layer may name as delegates (§12.10: with "to": ["b.example"]
            # stated for A, A→B→C is allowed and A→D→C is not)
            if isinstance(r.get("to"), list) and i == at + 1:
                for d in b.get("delegates") or []:
                    if not _realm_allowed(r["to"], d["realm"]):
                        raise ChainError(f"layer {i + 1} names {d['realm']} as a delegate, which the rules do not allow")
        if layer_state is not None:
            why = layer_state(realm, b["id"])
            if why:
                raise ChainError(f"layer {i + 1} ({realm} {b['id']}): {why}")
        if isinstance(b.get("rules"), dict) and b["rules"]:
            rules.append((i, b["rules"]))
        chain.append({"realm": realm, "id": b["id"], "pin": L["pin"]})
        if b.get("bind_to"):
            bind_tos.append(b["bind_to"])
        bodies.append(b)
        direction = b.get("direction") or direction
        if lt is not None:
            link_ttl = lt if link_ttl in (None, "") else min(int(link_ttl), lt)
        parent = {"expires": b["expires"], "link_ttl": link_ttl, "direction": direction,
                  "delegates": b.get("delegates") or []}
        prev = enc
    if parent["delegates"]:
        raise ChainError("the last layer is not final (it names delegates)")
    return {"chain": chain, "direction": direction, "link_ttl": link_ttl, "bind_tos": bind_tos, "bodies": bodies}


def looks_like_passport(text) -> bool:
    """For send paths: a passport is not an address (§12.3)."""
    return isinstance(text, str) and text.strip().lower().startswith("https://") and "#passport=" in text


# ---------------------------------------------------------------- the issuer's store
class PassportStore:
    def __init__(self, path: str):
        self.path = path
        self.recs: dict[str, dict] = {}
        self.keys: list[dict] = []           # entitled keys: {"scope", "key", "pin", "set_by", "at"}
        self._load()

    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {}
        self.recs = {}
        for r in data.get("passports", []):
            if isinstance(r, dict) and "id" in r:
                if "scope" not in r and isinstance(r.get("endpoint"), str):
                    r["scope"] = r["endpoint"]       # a record from before draft 0.10; refused at redemption (no auth list)
                self.recs[r["id"]] = r
        self.keys = [k for k in data.get("keys", []) if isinstance(k, dict) and "scope" in k and "key" in k]

    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"passports": list(self.recs.values()), "keys": self.keys}, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    # --- records -------------------------------------------------------------
    def issue(self, scope: str, token: str, *, label: str = "", expires: int, uses: int, direction: str,
              bind_to: str | None, link_ttl: int | None, issued_by: str, auth: list[dict],
              delegates: list[dict] | None = None, rules: dict | None = None, offer: str | None = None) -> dict:
        if direction not in DIRECTIONS:
            raise ValueError("bad direction")
        if not valid_token(token):
            raise ValueError("token must be base62, 22 to 64 characters (at least 128 bits)")
        if self.by_token(token) is not None:
            raise ValueError("that token is already in use")
        rec = {
            "id": "P" + secrets.token_hex(4),
            "token_hash": token_hash(token),
            "scope": scope,
            "label": (label or "")[:LABEL_MAX],
            "direction": direction,
            "created": round(time.time(), 3),
            "expires": int(expires),
            "uses": int(uses),
            "used": [],
            "bind_to": bind_to or None,
            "link_ttl": int(link_ttl) if link_ttl else None,
            "state": "active",
            "issued_by": issued_by,
            "auth": [{"key": a["key"], "sig": a["sig"]} for a in auth],
        }
        if offer:                                    # §12.4, §12.9: the offer hash it answers, a signed term
            rec["offer"] = offer
        if delegates:                                # §12.10: a delegation
            rec.update(delegates=delegates, rules=rules or {}, layer_uses={}, revoked_layers=[])
        self.recs[rec["id"]] = rec
        self._save()
        return rec

    def by_token(self, token: str) -> dict | None:
        h = token_hash(token)
        return next((r for r in self.recs.values() if r["token_hash"] == h), None)

    def use(self, rec: dict, redeemer_key: str, link_id: str) -> dict:
        rec["used"].append({"redeemer": redeemer_key, "at": round(time.time(), 3), "link": link_id})
        if len(rec["used"]) >= rec["uses"]:
            rec["state"] = "exhausted"
        self._save()
        return rec

    def revoke(self, rec: dict, by: str) -> dict:
        rec["state"] = "revoked"
        rec["revoked_by"] = by
        rec["revoked_at"] = round(time.time(), 3)
        self._save()
        return rec

    @staticmethod
    def public(r: dict) -> dict:
        return {k: v for k, v in r.items() if k != "token_hash"}

    def for_scopes(self, prefixes: list[str] | None) -> list[dict]:
        """Passports whose scope lies in one of the key prefixes (None = all)."""
        if prefixes is None:
            recs = self.recs.values()
        else:
            recs = (r for r in self.recs.values() if any(r["scope"].startswith(p) for p in prefixes))
        return sorted((self.public(r) for r in recs), key=lambda r: r["created"], reverse=True)

    def get(self, pid: str) -> dict | None:
        return self.recs.get(pid)

    # --- entitled keys (§4.7 key-add/key-list/key-remove, §12.8) --------------
    def key_add(self, scope: str, key: str, set_by: str) -> dict:
        p = pin(key)
        for k in self.keys:
            if k["scope"] == scope and k["key"] == key:
                return k
        k = {"scope": scope, "key": key, "pin": p, "set_by": set_by, "at": round(time.time(), 3)}
        self.keys.append(k)
        self._save()
        return k

    def key_remove(self, scope: str, key: str) -> bool:
        n = len(self.keys)
        self.keys = [k for k in self.keys if not (k["scope"] == scope and k["key"] == key)]
        if len(self.keys) != n:
            self._save()
            return True
        return False

    def keys_for(self, prefixes: list[str] | None) -> list[dict]:
        if prefixes is None:
            return list(self.keys)
        return [k for k in self.keys if any(k["scope"].startswith(p) for p in prefixes)]
