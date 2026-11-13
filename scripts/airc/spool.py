# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Store-and-forward spool and duplicate suppression.

Layout: <dir>/queue/<urlquoted destination key>.jsonl  — one msg frame per line.
A destination key is either a realm ("example.com", messages waiting for a
peer link) or a local path ("carol/analyst", messages waiting for a client to
bind that name). Expired messages are dropped when the queue is read.

A message's binary section (spec §22) is kept beside it in <dir>/bin/<hash of its id>.

Dedupe: <dir>/seen.jsonl holds "id ts" lines; ids older than seen_keep (the
server's max_ttl plus its allowed clock skew, 8 days by default, §7.3 and §9.3)
are forgotten on compaction. A message whose id was seen is acked
"delivered" again and not re-delivered — so senders may retry freely.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse

from .wire import expired, strip


class Spool:
    def __init__(self, directory: str, seen_keep: float = 8 * 86400):
        self.dir = directory
        self.seen_keep = float(seen_keep)
        os.makedirs(os.path.join(directory, "queue"), exist_ok=True)
        os.makedirs(os.path.join(directory, "bin"), exist_ok=True)
        self._seen: dict[str, float] = {}
        self._seen_path = os.path.join(directory, "seen.jsonl")
        self._load_seen()

    # --- dedupe -----------------------------------------------------------
    def _load_seen(self):
        try:
            with open(self._seen_path) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) == 2:
                        self._seen[parts[0]] = float(parts[1])
        except OSError:
            pass
        self._compact_seen(write=False)

    def _compact_seen(self, write=True):
        cutoff = time.time() - self.seen_keep
        self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        if write:
            tmp = self._seen_path + ".tmp"
            with open(tmp, "w") as f:
                for k, v in self._seen.items():
                    f.write(f"{k} {v}\n")
            os.replace(tmp, self._seen_path)

    def seen(self, msg_id: str) -> bool:
        return msg_id in self._seen

    def mark_seen(self, msg_id: str) -> None:
        now = time.time()
        self._seen[msg_id] = now
        try:
            with open(self._seen_path, "a") as f:
                f.write(f"{msg_id} {now}\n")
        except OSError:
            pass
        if len(self._seen) > 200000:
            self._compact_seen()

    # --- queues -------------------------------------------------------------
    def _qpath(self, key: str) -> str:
        return os.path.join(self.dir, "queue", urllib.parse.quote(key.lower(), safe="") + ".jsonl")

    def _bpath(self, msg_id: str) -> str:
        return os.path.join(self.dir, "bin", hashlib.sha256(str(msg_id).encode()).hexdigest()[:32])

    def bin(self, msg_id: str) -> bytes | None:
        """A queued message's binary section."""
        try:
            with open(self._bpath(msg_id), "rb") as f:
                return f.read()
        except OSError:
            return None

    def _drop_bin(self, msg_id: str) -> None:
        try:
            os.remove(self._bpath(msg_id))
        except OSError:
            pass

    def enqueue(self, key: str, msg: dict) -> None:
        if "_bin" in msg:
            tmp = self._bpath(msg["id"]) + ".tmp"
            with open(tmp, "wb") as f:
                f.write(msg["_bin"])
            os.replace(tmp, self._bpath(msg["id"]))
        with open(self._qpath(key), "a") as f:
            f.write(json.dumps(strip(msg), separators=(",", ":")) + "\n")

    def drain(self, key: str) -> list[dict]:
        """Remove and return all live messages queued for key."""
        p = self._qpath(key)
        try:
            with open(p) as f:
                lines = f.readlines()
        except OSError:
            return []
        try:
            os.remove(p)
        except OSError:
            pass
        out = []
        for line in lines:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if "bin" in m:                             # its section travels with it; requeueing writes it back
                data = self.bin(m.get("id", ""))
                self._drop_bin(m.get("id", ""))
                if data is None:
                    continue
                m["_bin"] = data
            if not expired(m):
                out.append(m)
        return out

    def peek(self, key: str, limit: int = 50) -> list[dict]:
        """Live messages queued for key, oldest first, left in place."""
        try:
            with open(self._qpath(key)) as f:
                lines = f.readlines()
        except OSError:
            return []
        out = []
        for line in lines:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if not expired(m):
                out.append(m)
            if len(out) >= limit:
                break
        return out

    def remove(self, key: str, msg_id: str) -> bool:
        """Drop one message from a queue by id. Returns True if it was there."""
        p = self._qpath(key)
        try:
            with open(p) as f:
                lines = f.readlines()
        except OSError:
            return False
        keep, found = [], False
        for line in lines:
            try:
                if json.loads(line).get("id") == msg_id:
                    found = True
                    self._drop_bin(msg_id)
                    continue
            except ValueError:
                pass
            keep.append(line)
        if found:
            if keep:
                tmp = p + ".tmp"
                with open(tmp, "w") as f:
                    f.writelines(keep)
                os.replace(tmp, p)
            else:
                try:
                    os.remove(p)
                except OSError:
                    pass
        return found

    def requeue(self, key: str, msgs: list[dict]) -> None:
        for m in msgs:
            self.enqueue(key, m)

    def pending(self, key: str) -> int:
        try:
            with open(self._qpath(key)) as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    def backlog_keys(self) -> list[str]:
        try:
            names = os.listdir(os.path.join(self.dir, "queue"))
        except OSError:
            return []
        return [urllib.parse.unquote(n[:-6]) for n in names if n.endswith(".jsonl")]
