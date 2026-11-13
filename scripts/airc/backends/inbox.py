# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Last hop over Claude Code's per-session inbox socket (phase B of the
single-plane plan). Used by the co backend for allow-listed agents; kept in
its own module because it knows about Claude Code, not about co.

What the CLI gives us (measured on 2.1.280):
  - ~/.claude/sessions/<pid>.json per live session: name, cwd, sessionId,
    messagingSocketPath; a sibling <pid>.<hash>.key holds the auth token.
  - Posting one line {"type":"user","message":{"role":"user","content":...}}
    to the socket makes the text a message in that session. There is no
    sender field, so the first line of the content carries it.
  - The session's transcript, ~/.claude/projects/<cwd with / -> ->/<sessionId>.jsonl,
    records arrival ({"type":"queue-operation","operation":"enqueue",...})
    and then reading (an "operation":"remove", a queued_command attachment,
    or a peer user turn), all containing the text.
  - A session that dies between enqueue and read loses the message.

So delivery is confirmed by watching the transcript for the message's own
header: stage (a) enqueue within ACCEPT_WAIT seconds is what we ack as
delivered; stage (b) read is watched in the background, and if the session's
pid changes before it, the message is re-posted once to the new session.
One message in flight per agent until (a), so order holds and the CLI's
burst limits are never hit. No timeout-driven resends.
"""
from __future__ import annotations

import asyncio
import glob
import json
import logging
import os
import socket
import time

log = logging.getLogger("airc.inbox")

ACCEPT_WAIT = 12.0          # below aircd's 15 s next-hop ack timeout
POLL = 0.25
READ_POLL = 1.0
MAX_WATCHERS = 200


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Session:
    def __init__(self, rec: dict, key_path: str | None, projects_dir: str):
        self.pid = int(rec["pid"])
        self.name = rec.get("name")
        self.cwd = rec.get("cwd", "")
        self.session_id = rec.get("sessionId", "")
        self.socket_path = rec.get("messagingSocketPath", "")
        self.key_path = key_path
        self.transcript = os.path.join(projects_dir, self.cwd.replace("/", "-"), self.session_id + ".jsonl")

    def token(self) -> str | None:
        try:
            return open(self.key_path).read().strip() if self.key_path else None
        except OSError:
            return None

    def __repr__(self):
        return f"<session {self.name} pid={self.pid} sid={self.session_id[:8]}>"


class InboxHop:
    def __init__(self, agents_dir: str, sessions_dir: str | None = None, projects_dir: str | None = None):
        home = os.path.expanduser("~")
        self.agents_dir = agents_dir
        self.sessions_dir = sessions_dir or os.path.join(home, ".claude", "sessions")
        self.projects_dir = projects_dir or os.path.join(home, ".claude", "projects")
        self._locks: dict[str, asyncio.Lock] = {}
        self._watchers: set[asyncio.Task] = set()
        self.read_count = 0

    # --- resolve ------------------------------------------------------------
    def resolve(self, agent: str) -> Session | None:
        """The live session for an agent: by --name first, then by cwd. The
        pid must be alive and the socket must connect."""
        by_name, by_cwd = [], []
        want_cwd = os.path.join(self.agents_dir, agent)
        for p in glob.glob(os.path.join(self.sessions_dir, "*.json")):
            try:
                rec = json.load(open(p))
            except (OSError, ValueError):
                continue
            if not rec.get("messagingSocketPath") or not rec.get("sessionId") or not rec.get("pid"):
                continue
            keys = glob.glob(os.path.join(self.sessions_dir, f"{rec['pid']}.*.key"))
            s = Session(rec, keys[0] if keys else None, self.projects_dir)
            (by_name if rec.get("name") == agent else by_cwd if rec.get("cwd") == want_cwd else []).append(s)
        for s in by_name + by_cwd:
            if pid_alive(s.pid) and self._connects(s.socket_path):
                return s
        return None

    @staticmethod
    def _connects(path: str) -> bool:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sk:
                sk.settimeout(1.0)
                sk.connect(path)
            return True
        except OSError:
            return False

    def selftest(self, agents: list[str]) -> tuple[bool, str]:
        if not os.path.isdir(self.sessions_dir):
            return False, f"no sessions dir {self.sessions_dir}"
        recs = glob.glob(os.path.join(self.sessions_dir, "*.json"))
        if not recs:
            return False, "no live sessions registered"
        bad = [p for p in recs if not {"pid", "cwd", "sessionId", "messagingSocketPath"} <= set(json.load(open(p)).keys())]
        if len(bad) == len(recs):
            return False, "session records lack the expected fields (CLI too old?)"
        found = [a for a in agents if self.resolve(a)]
        if agents and not found:
            return False, f"none of {agents} resolves to a live session with a reachable inbox"
        return True, f"{len(recs)} sessions; resolvable now: {found or 'none of the allow-list (they may be stopped)'}"

    # --- post and confirm ---------------------------------------------------
    @staticmethod
    def header(sender: str, msg: dict) -> str:
        """The one header line: the sender (the socket carries none), the FULL id and re (a reply's
        re must match exactly, §4.2), the link, and how an encrypted message was opened."""
        from .. import wire
        from ..links import ID_RE as LINK_ID_RE
        hdr = msg.get("hdr") or {}
        # §16 item 4: ids only when they fit their grammar, everything else cleaned
        h = f"[airc from {wire.clean(sender, 300)}" + (f" id={msg['id']}" if wire.valid_id(msg.get("id")) else "")
        e2e = hdr.get("airc-e2e")
        if isinstance(e2e, dict):
            h += f" e2e={wire.clean(e2e.get('ifp', ''))[:8]}:{wire.clean(e2e.get('pin', ''), 20)}"
        if wire.valid_id(msg.get("re")):
            h += f" re={msg['re']}"
        if isinstance(hdr.get("airc-link"), str) and LINK_ID_RE.match(hdr["airc-link"]):
            h += f" link={hdr['airc-link']}"
        return h + "]"

    @staticmethod
    def compose(sender: str, msg: dict, relay_text: str) -> str:
        """Replace the relay's [airc id=...] line (if any) with the inbox header, which carries the
        same ids and e2e marker and adds the sender, since the socket carries none."""
        lines = relay_text.split("\n")
        hdr = InboxHop.header(sender, msg)
        for i in range(min(2, len(lines))):
            if lines[i].startswith("[airc id="):
                lines[i] = hdr
                break
        else:
            at = 1 if lines and lines[0].startswith("[airc: message from") else 0
            lines.insert(at, hdr)
        return "\n".join(lines)

    async def _post(self, s: Session, content: str) -> None:
        loop = asyncio.get_running_loop()

        def go():
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sk:
                sk.settimeout(5.0)
                sk.connect(s.socket_path)
                tok = s.token()
                if tok:
                    sk.sendall((json.dumps({"type": "auth", "token": tok}) + "\n").encode())
                sk.sendall((json.dumps({"type": "user", "message": {"role": "user", "content": content}},
                                       ensure_ascii=False) + "\n").encode())
        await loop.run_in_executor(None, go)

    @staticmethod
    def _size(path: str) -> int:
        try:
            return os.path.getsize(path)
        except OSError:
            return 0

    @staticmethod
    def _scan(path: str, offset: int, needle: str) -> tuple[int, str | None]:
        """Read transcript lines from offset; return (new offset, first stage seen)."""
        try:
            with open(path, "rb") as f:
                f.seek(offset)
                data = f.read()
        except OSError:
            return offset, None
        stage = None
        nl = data.rfind(b"\n")
        if nl < 0:
            return offset, None
        chunk = data[:nl + 1]
        for raw in chunk.split(b"\n"):
            if needle.encode() not in raw:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            t, op = rec.get("type"), rec.get("operation")
            if t == "queue-operation" and op == "enqueue":
                stage = stage or "accepted"
            elif (t == "queue-operation" and op == "remove") or t == "queued_command" \
                    or (t == "user" and isinstance(rec.get("origin"), dict) and rec["origin"].get("kind") == "peer") \
                    or (t == "attachment"):
                return offset + nl + 1, "read"
            elif t == "user":
                return offset + nl + 1, "read"
        return offset + nl + 1, stage

    async def deliver(self, agent: str, sender: str, msg: dict, relay_text: str) -> tuple[str, str]:
        """(status, reason): delivered once the transcript shows the enqueue;
        failed if two posts produce none; ("nosession", ...) if the agent has
        no live inbox so the caller can take its other path."""
        s = self.resolve(agent)
        if s is None:
            return "nosession", f"{agent} has no live session with an inbox"
        content = self.compose(sender, msg, relay_text)
        needle = self.header(sender, msg)
        lock = self._locks.setdefault(agent, asyncio.Lock())
        async with lock:
            for attempt in (1, 2):
                offset = self._size(s.transcript)
                try:
                    await self._post(s, content)
                except OSError as e:
                    return "failed", f"inbox post to {s!r} failed: {e}"
                deadline = time.time() + ACCEPT_WAIT
                stage = None
                while time.time() < deadline:
                    await asyncio.sleep(POLL)
                    offset, stage = self._scan(s.transcript, offset, needle)
                    if stage:
                        break
                    if not pid_alive(s.pid):
                        break
                if stage:
                    log.info("inbox %s: %s by %r (attempt %d)", msg.get("id", "")[:8], stage, s, attempt)
                    if stage == "accepted":
                        self._watch(agent, s, needle, content, offset, msg)
                    return "delivered", ""
                s2 = self.resolve(agent)
                if s2 is None:
                    return "failed", f"{agent} session went away before accepting the message"
                if s2.pid != s.pid:
                    log.warning("inbox %s: session for %s changed (pid %d -> %d) before accept; re-posting",
                                msg.get("id", "")[:8], agent, s.pid, s2.pid)
                else:
                    log.warning("inbox %s: no enqueue from %r within %.0fs; re-posting once", msg.get("id", "")[:8], s, ACCEPT_WAIT)
                s = s2
            return "failed", f"{agent} did not accept the message after two posts"

    # --- stage (b): read, or re-post on restart -------------------------------
    def _watch(self, agent, s, needle, content, offset, msg):
        if len(self._watchers) >= MAX_WATCHERS:
            return
        t = asyncio.get_running_loop().create_task(self._watch_read(agent, s, needle, content, offset, msg))
        self._watchers.add(t)
        t.add_done_callback(self._watchers.discard)

    async def _watch_read(self, agent, s, needle, content, offset, msg):
        mid = str(msg.get("id", ""))[:8]
        while True:
            await asyncio.sleep(READ_POLL)
            offset, stage = self._scan(s.transcript, offset, needle)
            if stage == "read":
                self.read_count += 1
                log.info("inbox %s: read by %r", mid, s)
                return
            if pid_alive(s.pid):
                continue
            # the session died before reading: the CLI does not replay, so re-post once to the new session
            await asyncio.sleep(3)
            s2 = self.resolve(agent)
            if s2 is None or s2.pid == s.pid:
                log.error("inbox %s: session %r died before reading and no new session appeared; message lost", mid, s)
                return
            log.warning("inbox %s: %r died before reading; re-posting to %r", mid, s, s2)
            try:
                offset = self._size(s2.transcript)
                await self._post(s2, content)
            except OSError as e:
                log.error("inbox %s: re-post failed: %s", mid, e)
                return
            s = s2
