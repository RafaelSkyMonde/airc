# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Client library: connect to a realm server, bind names, send and receive.

    async with Client.connect("/run/airc/airc.sock") as c:
        await c.bind(["alice/*"])
        ack = await c.send("carol/analyst", "hello")
        async for msg in c.messages():
            ...; await c.ack(msg["id"], "delivered")

The server address is a Unix socket path, or host:port for a TCP client face.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import OrderedDict
from typing import AsyncIterator, Callable, Awaitable

from . import PROTO, __version__
from . import address as A
from . import wire
from .wire import Conn, WireError

DEFAULT_SOCKET = os.environ.get("AIRC_SOCKET", "/run/airc/airc.sock")

log = logging.getLogger("airc.client")

# ---------------------------------------------------------------- receipts (spec §6.7)
RECEIPT_TYPE = "application/airc-receipt+json"
RECEIPT_STATES = ("seen", "done")


def receipts_asked(msg: dict) -> set[str]:
    """The receipt types a message asks for (hdr airc-receipt, comma-separated; unknown types ignored).
    A receipt itself asks for nothing: a receipt is never receipted."""
    if not isinstance(msg, dict) or msg.get("type") == RECEIPT_TYPE:
        return set()
    v = (msg.get("hdr") or {}).get("airc-receipt")
    if not isinstance(v, str):
        return set()
    return {t.strip().lower() for t in v.split(",") if t.strip()} & set(RECEIPT_STATES)


def receipt_state(msg: dict) -> str | None:
    """The state a receipt carries, or None when msg is not a well-formed receipt."""
    if not isinstance(msg, dict) or msg.get("type") != RECEIPT_TYPE or not msg.get("re"):
        return None
    try:
        body = json.loads(msg.get("body") or "")
    except ValueError:
        return None
    st = body.get("state") if isinstance(body, dict) else None
    return st if st in RECEIPT_STATES else None


def receipt_body(state: str) -> str:
    return json.dumps({"state": state, "ts": int(time.time())}, separators=(",", ":"))


class ReceiptSender:
    """Sends seen/done receipts for messages that asked for them, fire and forget: a receipt send never
    blocks or fails a delivery (a failed or refused receipt is logged at debug), and each (message id,
    state) goes out at most once per process (a bounded in-memory set).

    `client` needs send(to, body, *, frm, mtype, re_id) -> ack  (Client, HttpClient, HttpRelaySession).
    Receipts travel in plaintext like other control traffic: the recipient's server must see the type
    to apply the site's receipt policy on egress (§6.7), and a sealed envelope hides it (§19)."""

    LIMIT = 4096

    def __init__(self, client, index: "AskedIndex | None" = None, delay: float = 0.05):
        self.client = client
        self.index = index
        self.delay = delay                      # lets the delivery ack leave before the receipt follows
        self._sent: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._tasks: set[asyncio.Task] = set()

    def wants(self, msg: dict, state: str) -> bool:
        return state in receipts_asked(msg) and (msg.get("id"), state) not in self._sent

    def fire(self, msg: dict, state: str, frm: str | None = None) -> bool:
        """Schedule a receipt for msg if it asked for `state` and none went yet. True when scheduled."""
        if not self.wants(msg, state):
            return False
        self._sent[(msg["id"], state)] = None
        while len(self._sent) > self.LIMIT:
            self._sent.popitem(last=False)
        if frm is None:
            try:
                frm = A.parse(msg["to"]).key
            except (A.AddressError, KeyError):
                return False
        t = asyncio.get_running_loop().create_task(self._go(msg, state, frm))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return True

    async def _go(self, msg: dict, state: str, frm: str):
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            a = await self.client.send(msg["from"], receipt_body(state), frm=frm, mtype=RECEIPT_TYPE, re_id=msg["id"])
            if isinstance(a, tuple):
                a = a[0]
            if not isinstance(a, dict) or a.get("status") == "failed":
                log.debug("receipt %s for %s not sent: %s", state, msg.get("id"), (a or {}).get("reason") if isinstance(a, dict) else a)
            elif self.index is not None:
                self.index.mark(msg["id"], state)
        except Exception as e:  # noqa: BLE001
            log.debug("receipt %s for %s not sent: %s", state, msg.get("id"), e)

    async def drain(self, timeout: float = 5.0):
        """Wait for the receipts in flight (a short-lived command calls this before it exits)."""
        if self._tasks:
            await asyncio.wait(list(self._tasks), timeout=timeout)


class AskedIndex:
    """What recent messages asked for, so `airc done <id>` (a later process) can send the done receipt
    to the right sender, once. A small JSON file: id -> {"from", "to", "asked", "sent", "ts"}, bounded."""

    LIMIT = 1000

    def __init__(self, path: str | None = None):
        self.path = path or os.path.expanduser(os.environ.get("AIRC_RECEIPTS_INDEX") or "~/.airc/receipts.json")

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d: dict) -> None:
        if len(d) > self.LIMIT:
            for k in sorted(d, key=lambda k: d[k].get("ts", 0))[:len(d) - self.LIMIT]:
                d.pop(k, None)
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:
            log.debug("receipts index not written: %s", e)

    def remember(self, msg: dict) -> None:
        asked = receipts_asked(msg)
        if not asked or not wire.valid_id(msg.get("id")):
            return
        d = self._load()
        d[msg["id"]] = {"from": msg.get("from"), "to": msg.get("to"), "asked": sorted(asked),
                        "sent": (d.get(msg["id"]) or {}).get("sent", []), "ts": time.time()}
        self._save(d)

    def get(self, msg_id: str) -> dict | None:
        return self._load().get(msg_id)

    def mark(self, msg_id: str, state: str) -> None:
        d = self._load()
        rec = d.get(msg_id)
        if rec is not None and state not in rec.setdefault("sent", []):
            rec["sent"].append(state)
            self._save(d)



class Client:
    def __init__(self, conn: Conn, welcome: dict):
        self.conn = conn
        self.realm: str = welcome.get("realm", "")
        self.namespaces: list[str] = welcome.get("ns", [])
        # "keys": the server has an E2E key directory (§19.3). A server without it closes the
        # connection on a keys frame, so never send one unless the welcome says so.
        self.features: list[str] = welcome.get("features") or []
        # this fleet's local aliases (address.alias_expand): typed and shown short, never sent short
        self.aliases: dict[str, str] = dict(welcome.get("aliases") or {})
        self._pending: dict[str, asyncio.Future] = {}
        self._inbox: asyncio.Queue = asyncio.Queue()
        self._events: asyncio.Queue = asyncio.Queue()
        self._stats: asyncio.Queue = asyncio.Queue()
        self._reader: asyncio.Task | None = None
        self._closed = asyncio.Event()

    @classmethod
    async def connect(cls, where: str = DEFAULT_SOCKET, *, ns_claim: list[str] | None = None,
                      agent: str = f"airc-client/{__version__}", timeout: float = 10) -> "Client":
        if "/" in where or where.startswith("@"):
            r, w = await asyncio.wait_for(asyncio.open_unix_connection(where, limit=wire.STREAM_LIMIT), timeout)
        else:
            host, _, port = where.rpartition(":")
            r, w = await asyncio.wait_for(asyncio.open_connection(host or "127.0.0.1", int(port), limit=wire.STREAM_LIMIT), timeout)
        conn = Conn(r, w)
        hello = {"t": "hello", "proto": PROTO, "role": "client", "agent": agent, "features": ["bin", "aliases"]}
        if ns_claim:
            hello["ns"] = ns_claim
        await conn.send(hello)
        welcome = await asyncio.wait_for(conn.recv(), timeout)
        if not welcome or welcome.get("t") != "welcome":
            await conn.close()
            raise WireError("no_welcome", str(welcome))
        c = cls(conn, welcome)
        c._reader = asyncio.get_running_loop().create_task(c._read_loop())
        return c

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

    async def close(self):
        await self.conn.close()
        if self._reader:
            self._reader.cancel()
        self._closed.set()

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    async def _read_loop(self):
        try:
            while True:
                f = await self.conn.recv()
                if f is None:
                    break
                t = f.get("t")
                if t == "ack":
                    fut = self._pending.get(f.get("id"))
                    if fut and not fut.done():
                        fut.set_result(f)
                elif t == "msg":
                    try:                                  # B4: a malformed msg never reaches a handler
                        wire.validate_msg(f)
                    except WireError as e:
                        if wire.valid_id(f.get("id")):
                            await self.conn.send(wire.ack(f["id"], "failed", f"malformed message: {e.reason}", "bad_request"))
                        continue
                    await self._inbox.put(f)
                elif t == "ping":
                    await self.conn.send({"t": "pong", "n": f.get("n")})
                elif t == "event":
                    await self._events.put(f)
                elif t == "aliases":                      # the fleet's table changed (another client of the fleet edited it)
                    if isinstance(f.get("aliases"), dict):
                        self.aliases = dict(f["aliases"])
                elif t in ("bound", "stats", "pong", "linked", "passported", "subscribed", "keyed", "profiled", "aliased"):
                    await self._stats.put(f)
                elif t == "error":
                    await self._stats.put(f)
                    break
        except (WireError, OSError, asyncio.CancelledError):
            pass
        finally:
            self._closed.set()
            await self._inbox.put(None)
            await self._events.put(None)
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_result(wire.ack("?", "failed", "connection closed"))

    async def _expect(self, kind: str, timeout: float = 10) -> dict:
        while True:
            f = await asyncio.wait_for(self._stats.get(), timeout)
            if f.get("t") == kind:
                return f
            if f.get("t") == "error":
                raise WireError(f.get("code", "error"), f.get("reason", ""))

    async def bind(self, names: list[str], take_over: bool = False) -> list[str]:
        await self.conn.send({"t": "bind", "names": names, **({"take_over": True} if take_over else {})})
        r = await self._expect("bound")
        self.front = dict(r.get("front") or {})    # namespace -> its front-door agent (spec §20.3)
        return r["names"]

    async def send(self, to: str, body: str, *, frm: str | None = None, mtype: str = "text/plain",
                   re_id: str | None = None, ttl: int | None = None, hdr: dict | None = None,
                   timeout: float = 20, bin: bytes | None = None) -> dict:
        """Send and return the ack frame {"status": delivered|queued|failed, "reason"?}."""
        if frm is None:
            name = os.environ.get("CO_SESSION_NAME") or os.environ.get("USER") or "anon"
            frm = name
        to = A.alias_expand(to, self.aliases)          # an alias never reaches the server
        m = wire.new_msg(frm, to, body, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)
        if bin is not None:
            wire.attach_bin(m, bin)
        fut = asyncio.get_running_loop().create_future()
        self._pending[m["id"]] = fut
        try:
            await self.conn.send(m)
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return wire.ack(m["id"], "queued", "no ack from server within timeout")
        finally:
            self._pending.pop(m["id"], None)

    async def ack(self, msg_id: str, status: str = "delivered", reason: str = "") -> None:
        await self.conn.send(wire.ack(msg_id, status, reason))

    async def messages(self) -> AsyncIterator[dict]:
        while True:
            m = await self._inbox.get()
            if m is None:
                return
            yield m

    async def serve(self, handler: Callable[[dict], Awaitable[tuple[str, str] | str | None]]) -> None:
        """Run handler on each inbound message and ack with its result.

        handler returns None (= delivered), a status string, a tuple
        (status, reason[, code[, by]]) or a dict with those keys.
        An exception from the handler acks "failed" with the exception text.
        """
        async for m in self.messages():
            try:
                r = await handler(m)
            except Exception as e:  # noqa: BLE001
                r = ("failed", f"handler error: {e}")
            if r is None:
                a = wire.ack(m["id"], "delivered")
            elif isinstance(r, str):
                a = wire.ack(m["id"], r)
            elif isinstance(r, dict):
                a = wire.ack(m["id"], r.get("status", "delivered"), r.get("reason", ""), r.get("code"), r.get("by"))
            else:
                a = wire.ack(m["id"], r[0], r[1] if len(r) > 1 else "", r[2] if len(r) > 2 else None,
                             r[3] if len(r) > 3 else None)
            try:
                await self.conn.send(a)
            except Exception:
                return

    async def link(self, op: str, **fields) -> dict:
        """Link operations: offer(as, peer, direction, label, expires),
        accept/decline/revoke(as, id), list(all). Returns the `linked` frame."""
        fields = self._expand_aliases(fields)
        await self.conn.send({"t": "link", "op": op, **{k: v for k, v in fields.items() if v is not None}})
        return await self._expect("linked")

    async def keys(self, op: str, **fields) -> dict:
        """E2E key directory (§19.3): publish(record) or get(endpoint). Returns the `keyed` frame."""
        await self.conn.send({"t": "keys", "op": op, **{k: v for k, v in fields.items() if v is not None}})
        return await self._expect("keyed")

    async def keys_get(self, endpoint: str) -> dict | None:
        if "keys" not in self.features:
            return None
        r = await self.keys("get", endpoint=endpoint)
        return r.get("record") if r.get("ok") else None

    async def keys_publish(self, record: dict) -> tuple[bool, str]:
        if "keys" not in self.features:
            return False, "this server has no key directory"
        r = await self.keys("publish", record=record)
        return bool(r.get("ok")), r.get("reason", "")

    async def profile_publish(self, record: dict) -> tuple[bool, str]:
        """Publish an endpoint's public profile (§21.1), if the server offers profiles."""
        if "profile" not in self.features:
            return False, "this server has no profiles"
        await self.conn.send({"t": "profile", "op": "publish", "record": record})
        r = await self._expect("profiled")
        return bool(r.get("ok")), r.get("reason", "")

    async def profile_status(self, statuses: list[dict]) -> tuple[bool, str]:
        """Publish endpoints' status (§21.2): [{"endpoint", "status": push-active|push-inactive}]."""
        if "profile" not in self.features:
            return False, "this server has no profiles"
        await self.conn.send({"t": "profile", "op": "status", "statuses": statuses})
        r = await self._expect("profiled")
        return bool(r.get("ok")), r.get("reason", "")

    async def profile_delete(self, endpoint: str) -> tuple[bool, str]:
        return await self.profile_publish({"endpoint": endpoint, "delete": True})

    async def channel_close(self, endpoint: str) -> tuple[bool, str]:
        """Close a channel (§21.4): its profile, keys and status go, and a message to it fails path_gone."""
        return await self.profile_publish({"endpoint": endpoint, "close": True})

    async def profile_get(self, endpoint: str) -> dict | None:
        if "profile" not in self.features:
            return None
        await self.conn.send({"t": "profile", "op": "get", "endpoint": endpoint})
        r = await self._expect("profiled")
        return r.get("record") if r.get("ok") else None

    def absolute(self, addr: str) -> str:
        return str(A.parse(addr, self.realm, self.namespaces[0] if self.namespaces else "", self.aliases))

    def _expand_aliases(self, fields: dict) -> dict:
        """Peer addresses typed with an alias go to the server in full (the server never sees aliases)."""
        if not self.aliases:
            return fields
        return {k: (A.alias_expand(v, self.aliases) if k in ("peer", "to") and isinstance(v, str) else v) for k, v in fields.items()}

    def display(self, addr: str, namespace: str | None = None) -> str:
        """The short form of an address for people: this fleet's local forms, or an alias for another realm."""
        try:
            a = A.parse(addr)
        except A.AddressError:
            return addr
        ns = namespace if namespace is not None else (self.namespaces[0] if self.namespaces else "")
        return a.relative_to(self.realm, ns, self.aliases)

    async def alias(self, op: str, alias: str | None = None, prefix: str | None = None) -> dict:
        """Manage this fleet's aliases on the server: op list | add (alias, prefix) | remove (alias)."""
        if "aliases" not in self.features:
            return {"ok": False, "reason": "this server has no aliases (it predates them)", "aliases": {}}
        await self.conn.send({"t": "alias", "op": op, **({"alias": alias} if alias else {}), **({"prefix": prefix} if prefix else {})})
        r = await self._expect("aliased")
        if isinstance(r.get("aliases"), dict):
            self.aliases = dict(r["aliases"])
        return r

    async def send_msg(self, m: dict, timeout: float = 20) -> dict:
        fut = asyncio.get_running_loop().create_future()
        self._pending[m["id"]] = fut
        try:
            await self.conn.send(m)
            return await asyncio.wait_for(fut, timeout)
        except asyncio.TimeoutError:
            return wire.ack(m["id"], "queued", "no ack from server within timeout")
        finally:
            self._pending.pop(m["id"], None)

    async def send_e2e(self, to: str, body: str, *, frm: str | None = None, re_id: str | None = None,
                       ttl: int | None = None, timeout: float = 20, mtype: str = "text/plain", bin: bytes | None = None,
                       hdr: dict | None = None) -> tuple[dict, str]:
        """Send with automatic end-to-end encryption (§19): sealed when the recipient publishes keys.
        hdr (e.g. airc-receipt, §6.7) stays outside the sealed envelope, as every header does."""
        from . import e2e as E2E
        if frm is None:
            frm = os.environ.get("CO_SESSION_NAME") or os.environ.get("USER") or "anon"
        m = wire.new_msg(self.absolute(frm), self.absolute(to), body, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)
        if bin is not None:
            wire.attach_bin(m, bin)
        return await E2E.auto_send(m, self.keys_get, self.keys_publish, lambda x: self.send_msg(x, timeout))

    async def passport(self, op: str, **fields) -> dict:
        """Passport operations: new(as, label, expires, uses, direction, to, link_ttl),
        list(all), revoke(as, id, and_links), redeem(as, passport)."""
        fields = self._expand_aliases(fields)
        await self.conn.send({"t": "passport", "op": op, **{k: v for k, v in fields.items() if v is not None}})
        return await self._expect("passported")

    async def subscribe(self, kinds: list[str] | None = None) -> dict:
        await self.conn.send({"t": "subscribe", **({"kinds": kinds} if kinds else {})})
        return await self._expect("subscribed")

    async def events(self) -> AsyncIterator[dict]:
        while not self.closed:
            ev = await self._events.get()
            if ev is None:
                return
            yield ev

    async def stats(self) -> dict:
        await self.conn.send({"t": "stat"})
        return await self._expect("stats")
