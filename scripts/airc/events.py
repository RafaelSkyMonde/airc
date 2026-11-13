# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""aircd's audit stream: what happened to every message, link, passport and
peer link, without message bodies.

Two outlets for the same events:
  - <state_dir>/events.jsonl, append-only, one JSON object per line, rotated
    to events.jsonl.1 when it passes max_bytes. This is the durable record a
    site layer tails (message logs, indexers, dashboards).
  - live subscribers (client connections that sent a `subscribe` frame),
    each with a kind filter and a namespace filter.

Event shape:
  {"ts": 1790380000.123, "kind": "msg.delivered", "id": "...", "from": "airc://...",
   "to": "airc://...", "status": "delivered", "code": null, "reason": "", "by": "airc://.../_resolver",
   "hop": "client"|"peer"|"local"|"spool", "bytes": 42, "link": "L...", "passport": "P..."}
kinds:
  msg.delivered msg.queued msg.failed msg.flushed
  msg.receipt     a seen/done receipt (§6.7) passed: "state", "re" (the message it answers), from, to
  link.offer link.accept link.decline link.revoke link.grant
  passport.issue passport.redeem passport.revoke
  peer.up peer.down
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time

log = logging.getLogger("aircd.events")

KINDS = ("msg.delivered", "msg.queued", "msg.failed", "msg.flushed", "msg.receipt",
         "link.offer", "link.accept", "link.decline", "link.revoke", "link.grant",
         "passport.issue", "passport.redeem", "passport.revoke",
         "peer.up", "peer.down")


class Subscriber:
    def __init__(self, send, kinds: list[str] | None, prefixes: list[str] | None):
        self.send = send                  # async callable(frame)
        self.kinds = set(kinds) if kinds else None
        self.prefixes = prefixes          # None = everything (admin); else key prefixes
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self.dropped = 0

    def wants(self, ev: dict) -> bool:
        if self.kinds and ev["kind"] not in self.kinds and ev["kind"].split(".")[0] not in self.kinds:
            return False
        if self.prefixes is None:
            return True
        for k in ("from", "to", "endpoint", "realm"):
            v = ev.get(k)
            if isinstance(v, str) and any(v == p or v.startswith(p) for p in self.prefixes):
                return True
        return False


class EventLog:
    def __init__(self, path: str, max_bytes: int = 50 * 1024 * 1024):
        self.path = path
        self.max_bytes = max_bytes
        self.subscribers: list[Subscriber] = []
        self._tasks: set[asyncio.Task] = set()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def emit(self, kind: str, **fields) -> dict:
        ev = {"ts": round(time.time(), 3), "kind": kind}
        ev.update({k: v for k, v in fields.items() if v is not None})
        try:
            line = json.dumps(ev, separators=(",", ":"), ensure_ascii=False)
            # world-readable: metadata only, no bodies; site subscribers tail it as themselves
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            if os.path.getsize(self.path) > self.max_bytes:
                os.replace(self.path, self.path + ".1")
        except OSError as e:
            log.warning("event log write failed: %s", e)
        for sub in list(self.subscribers):
            if sub.wants(ev):
                try:
                    sub.queue.put_nowait(ev)
                except asyncio.QueueFull:
                    sub.dropped += 1
        return ev

    def subscribe(self, sub: Subscriber) -> None:
        self.subscribers.append(sub)
        loop = asyncio.get_running_loop()
        t = loop.create_task(self._pump(sub))
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)

    def unsubscribe(self, sub: Subscriber) -> None:
        if sub in self.subscribers:
            self.subscribers.remove(sub)
            try:
                sub.queue.put_nowait(None)
            except asyncio.QueueFull:               # a full queue: make room for the end marker
                try:
                    sub.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                sub.queue.put_nowait(None)

    async def _pump(self, sub: Subscriber) -> None:
        while True:
            ev = await sub.queue.get()
            if ev is None:
                return
            try:
                await sub.send({"t": "event", **ev, **({"dropped": sub.dropped} if sub.dropped else {})})
                sub.dropped = 0
            except Exception:
                self.unsubscribe(sub)
                return

    @staticmethod
    def tail(path: str, n: int = 50) -> list[dict]:
        out = []
        try:
            with open(path, encoding="utf-8") as f:
                lines = f.readlines()[-n:]
            for ln in lines:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    continue
        except OSError:
            pass
        return out
