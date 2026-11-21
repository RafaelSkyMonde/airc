# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Links: standing grants between two endpoints.

A link joins endpoint a and endpoint b with terms; between two endpoints the
newest decisive record (active or revoked) is what policy sees. It is recorded at both
endpoints' servers (each keeps its own copy, each enforces its own) and is
what the policy engine consults before its rule list. Lifecycle:

    pending   offered by a, not yet answered by b
    active    accepted by b (or auto-accepted); traffic allowed per direction
    declined  b said no; no effect on policy
    revoked   either side cut it; traffic between a and b is DENIED, which is
              how an endpoint blocks a pest without an operator

direction:
    both          either side may initiate
    a-initiates   a may message b; b may only answer within the reply window
    b-initiates   the mirror

Records live in <state_dir>/links.json. Writes are atomic (tmp + rename).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import time

from . import address as A

DIRECTIONS = ("both", "a-initiates", "b-initiates")
STATES = ("pending", "active", "declined", "revoked")
MEDIA_TYPE = "application/airc-link+json"
DEFAULT_LABEL_MAX = 200
ID_RE = re.compile(r"^L[0-9a-f]{8}\Z")           # §11.1: L + 8 lower-case hex
# §11.1: states only move forward; a declined or revoked link never changes again
FORWARD = {"pending": ("active", "declined", "revoked"), "active": ("revoked",), "declined": (), "revoked": ()}


def can_move(cur: str, new: str) -> bool:
    return new in FORWARD.get(cur, ())


_REALM_SIDE = re.compile(r"^(?:airc:)?//([^/#\s]+)/$", re.I)


def parse_side(text, realm: str | None = None, namespace: str = "") -> A.Address:
    """A link side or passport scope (§11.1, §12.1): an endpoint, a namespace (trailing /) or a whole
    realm (airc://<realm>/, or "/" in local form). A realm side is returned as an Address with an empty
    path, whose key is airc://<realm>/ (§2.1 has no realm-only address; links and passports need one)."""
    if not isinstance(text, str):
        raise A.AddressError("address must be a string")
    t = text.strip()
    m = _REALM_SIDE.match(t)
    if m:
        host, port = A._authority(m.group(1))
        return A.Address(host, (), port, False)
    if t == "/" and realm is not None:
        host, port = A._authority(realm)
        return A.Address(host, (), port, False)
    return A.parse(t, realm, namespace)


def side_key(text) -> str:
    return parse_side(text).key


def side_kind(key: str) -> str:
    """endpoint | namespace | realm, for a side key."""
    if not key.endswith("/"):
        return "endpoint"
    return "realm" if key.count("/") == 3 else "namespace"


def side_matches(side: str, key: str) -> bool:
    """Whether a link side covers key (§11.3): equal; a namespace or realm side covers what lies beneath it;
    an endpoint side covers the endpoint and every endpoint beneath it (its sub-agents and tool tunnels)."""
    if side == key:
        return True
    return key.startswith(side if side.endswith("/") else side + "/")


def show_side(addr: A.Address, realm: str, namespace: str = "") -> str:
    """How a notice names a side: the realm for a realm side, else the address's shortest form."""
    if not addr.path:
        return f"the whole realm {addr.authority}"
    return addr.relative_to(realm, namespace)


def new_id() -> str:
    return "L" + secrets.token_hex(4)


def parse_duration(text) -> int | None:
    """'7d', '12h', '30m', '3600' -> seconds; None/'' -> None."""
    if text in (None, "", "never", "none"):
        return None
    if isinstance(text, (int, float)):
        return int(text)
    t = str(text).strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    if not t or not t.isascii():
        raise ValueError(f"bad duration {text!r}")
    if t[-1] in mult and t[:-1].isdigit():
        return int(t[:-1]) * mult[t[-1]]
    if t.isdigit():
        return int(t)
    raise ValueError(f"bad duration {text!r}")


class LinkStore:
    def __init__(self, path: str):
        self.path = path
        self.links: dict[str, dict] = {}
        # exempt(link, endpoint key) -> True where site policy requires the endpoint to accept the link
        # (links.must_accept, §12.8), which a rejection by key does not override (§12.7); set by the server
        self.exempt = None
        # link id -> {"last": ts, "from": ..., "to": ..., "count": n}: when a message last passed on the
        # link's strength and between which endpoints. Kept beside the store, written at most every few seconds.
        self.usage: dict[str, dict] = {}
        self._usage_saved = 0.0
        self._load()

    # --- persistence --------------------------------------------------------
    def _load(self):
        try:
            with open(self.path) as f:
                data = json.load(f)
            self.links = {l["id"]: l for l in data.get("links", []) if isinstance(l, dict) and "id" in l}
        except (OSError, ValueError):
            self.links = {}
        try:
            with open(self.path + ".usage") as f:
                u = json.load(f)
            self.usage = {k: v for k, v in u.items() if isinstance(v, dict)} if isinstance(u, dict) else {}
        except (OSError, ValueError):
            self.usage = {}

    def note_use(self, link_id: str, frm: str, to: str, *, sent: bool = True, now: float | None = None) -> None:
        """A message passed because of this link: remember when, and between which endpoints, overall and per
        direction (sent: it left from this realm's side of the link; otherwise it was received into it)."""
        now = time.time() if now is None else now
        u = self.usage.setdefault(link_id, {"count": 0})
        u["last"], u["from"], u["to"], u["count"] = now, frm, to, int(u.get("count", 0)) + 1
        d = u.setdefault("sent" if sent else "received", {"count": 0})
        d["last"], d["from"], d["to"], d["count"] = now, frm, to, int(d.get("count", 0)) + 1
        if now - self._usage_saved >= 5:
            self._usage_saved = now
            try:
                tmp = self.path + ".usage.tmp"
                with open(tmp, "w") as f:
                    json.dump(self.usage, f)
                os.replace(tmp, self.path + ".usage")
            except OSError:
                pass

    def _save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"links": list(self.links.values())}, f, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    # --- records ------------------------------------------------------------
    @staticmethod
    def make(a: str, b: str, *, direction: str = "both", label: str = "", expires_in: int | None = None,
             offered_by: str | None = None, origin: dict | None = None, link_id: str | None = None) -> dict:
        if direction not in DIRECTIONS:
            raise ValueError(f"direction must be one of {DIRECTIONS}")
        now = time.time()
        return {
            "id": link_id or new_id(),
            "a": a, "b": b,
            "direction": direction,
            "label": (label or "")[:DEFAULT_LABEL_MAX],
            "created": round(now, 3),
            "expires": round(now + expires_in, 3) if expires_in else None,
            "state": "pending",
            "offered_by": offered_by or a,
            "origin": origin or {},
        }

    @staticmethod
    def validate(link: dict) -> dict:
        """Check a record received from elsewhere; returns a clean copy."""
        out = {}
        for k in ("id", "a", "b", "direction", "state", "offered_by"):
            if not isinstance(link.get(k), str):
                raise ValueError(f"link.{k} missing")
            out[k] = link[k]
        if not ID_RE.match(out["id"]):
            raise ValueError("bad link id (L and 8 lower-case hex digits)")
        if out["direction"] not in DIRECTIONS or out["state"] not in STATES:
            raise ValueError("bad direction/state")
        out["a"], out["b"] = side_key(out["a"]), side_key(out["b"])
        out["label"] = str(link.get("label", ""))[:DEFAULT_LABEL_MAX]
        out["created"] = float(link.get("created") or time.time())
        out["expires"] = float(link["expires"]) if link.get("expires") else None
        out["origin"] = link.get("origin") if isinstance(link.get("origin"), dict) else {}
        for k in ("revoked_by", "revoked_at", "accepted_at", "declined_at"):
            if k in link:
                out[k] = link[k]
        return out

    def get(self, link_id: str) -> dict | None:
        return self.links.get(link_id)

    def put(self, link: dict) -> dict:
        """Upsert. States only move forward (FORWARD), so a stale or replayed control
        cannot reopen a revoked link or turn an active one into declined."""
        cur = self.links.get(link["id"])
        if cur and cur["state"] != link["state"] and not can_move(cur["state"], link["state"]):
            return cur
        if cur and cur["state"] == "revoked":
            return cur
        self.links[link["id"]] = link
        self._save()
        return link

    def set_state(self, link_id: str, state: str, by: str | None = None) -> dict:
        l = self.links[link_id]
        if not can_move(l["state"], state):              # forward only; the caller checks preconditions (§11.2)
            return l
        l["state"] = state
        stamp = {"active": "accepted_at", "declined": "declined_at", "revoked": "revoked_at"}.get(state)
        if stamp:
            l[stamp] = round(time.time(), 3)
        if state == "revoked" and by:
            l["revoked_by"] = by
        self._save()
        return l

    # --- queries ------------------------------------------------------------
    @staticmethod
    def _live(l: dict, now: float) -> bool:
        return not (l.get("expires") and l["expires"] < now)

    def between(self, x: str, y: str) -> list[dict]:
        """All records joining keys x and y, newest first. A side matches the keys it covers (§11.3,
        side_matches): an endpoint side its endpoint and everything beneath, a namespace or realm side
        what lies beneath it."""
        side = side_matches
        out = [l for l in self.links.values()
               if (side(l["a"], x) and side(l["b"], y)) or (side(l["a"], y) and side(l["b"], x))]
        return sorted(out, key=lambda l: l["created"], reverse=True)

    def rejections(self, endpoint: str) -> list[dict]:
        """§12.7: the endpoint's standing rejections by key, {a: endpoint, b: "*", state: revoked,
        origin: {reject_key: pin}}."""
        return [l for l in self.links.values() if l["a"] == endpoint and l["b"] == "*" and l["state"] == "revoked"
                and isinstance((l.get("origin") or {}).get("reject_key"), str)]

    def rejected_pin(self, endpoint: str, pins, link: dict | None = None) -> str | None:
        """The first of pins the endpoint rejects (§12.7), unless site policy makes it accept link; else None."""
        if not pins:
            return None
        rej = {l["origin"]["reject_key"] for l in self.rejections(endpoint)}
        hit = next((p for p in pins if p in rej), None)
        if hit is not None and link is not None and self.exempt is not None and self.exempt(link, endpoint):
            return None
        return hit

    def decision(self, frm: A.Address, to: A.Address, in_reply_window) -> tuple[str | None, str]:
        """('allow'|'deny'|None, reason). The newest DECISIVE record between
        the two wins: an active link allows (per direction), a revoked one
        denies. Pending, declined and expired records are skipped. So a
        revocation blocks until the two endpoints agree again (a new offer
        accepted, or a passport redeemed), and no longer than that."""
        now = time.time()
        recs = self.between(frm.key, to.key)          # newest first
        for l in recs:
            if l["state"] == "revoked":
                return "deny", f"link {l['id']} revoked"
            if l["state"] != "active" or not self._live(l, now):
                continue
            pins = (l.get("origin") or {}).get("pins")
            for k in (frm.key, to.key):                # §12.7: a link whose passport a key the endpoint rejects authorized
                hit = self.rejected_pin(k, pins, l) if pins else None
                if hit:
                    return "deny", f"link {l['id']} refused: key {hit} is rejected by {k}"
            frm_is_a = side_matches(l["a"], frm.key) and side_matches(l["b"], to.key)
            d = l["direction"]
            if d == "both" or (d == "a-initiates" and frm_is_a) or (d == "b-initiates" and not frm_is_a):
                return "allow", f"link {l['id']}"
            if in_reply_window(frm, to):
                return "allow", f"link {l['id']} (reply)"
            return "deny", f"link {l['id']} is {d}; {frm.key} may only reply"
        return None, ""

    def involving(self, prefixes: list[str] | None) -> list[dict]:
        """Links whose a or b lies under one of the given key prefixes (None = all)."""
        if prefixes is None:
            return sorted(self.links.values(), key=lambda l: l["created"], reverse=True)
        def under(v):
            return any(v == p or v.startswith(p.rstrip("/") + "/") or (v.endswith("/") and p.startswith(v)) for p in prefixes)
        return sorted((l for l in self.links.values() if under(l["a"]) or under(l["b"])),
                      key=lambda l: l["created"], reverse=True)

    def pending_from(self, offerer_key: str) -> int:
        return sum(1 for l in self.links.values() if l["state"] == "pending" and l["offered_by"] == offerer_key)
