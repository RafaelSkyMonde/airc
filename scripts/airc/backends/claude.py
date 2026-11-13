# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Deliver to one Claude Code session on this machine through its inbox socket: the relay backend
for an agent that is a Claude Code session, such as Claude Code on the web (a cloud sandbox), a
laptop session or a CI run. See /docs/receive.

    AIRC_SESSION=<stable id> airc relay --namespace <workspace> --backend claude [--opt agents=claude] [--opt session=<name>]

agents   the endpoints this relay serves, comma-separated (default: claude). The relay binds only
         these (endpoints_only), not the whole workspace, so other endpoints' mail is untouched and
         a second session wanting the same endpoint gets name_held instead of taking it (§4.3.1).
session  the session to deliver to, by its name in ~/.claude/sessions/<pid>.json. Default: the
         session whose sessionId is $CLAUDE_CODE_SESSION_ID (or --opt session_id=), i.e. the one that
         started the relay from a SessionStart hook. The id survives `claude --resume` and a cloud
         container's suspend/resume, where the pid, socket and derived name all change. Only
         without a session id: the session owning $CLAUDE_CODE_MESSAGING_SOCKET. There is no
         fallback to some other session: with no match, nothing is delivered.
exit_after  seconds with no live session for this relay before it exits (default 600; 0 = never).
         A relay started by a hook outlives the session on a laptop; without this it would keep
         renewing its lease and hold the name for good.

Set AIRC_SESSION to something stable for the Claude Code session (the kit uses a hash of
$CLAUDE_CODE_SESSION_ID and the endpoint). A cloud container that is suspended and resumed kills
the relay; the restarted one then renews its own lease instead of waiting five minutes for the
dead process's to lapse.

The relay does the rest: opening end-to-end encrypted messages, saving files (§22), pinning link
keys, publishing the endpoint's keys, and the origin banner. Delivery is acked once the session's
transcript shows the message enqueued (InboxHop). With the session gone, the message is refused
(endpoint_offline) and the sender told.
"""
from __future__ import annotations

import shlex
import asyncio
import glob
import json
import logging
import os
import signal
import time

from .. import address as A
from .. import wire
from .inbox import InboxHop, pid_alive

log = logging.getLogger("airc.claude")


class Backend:
    endpoints_only = True

    def __init__(self, agents: str | list[str] = "claude", session: str | None = None, session_id: str | None = None,
                 exit_after: str | int = 600, sessions_dir: str | None = None, projects_dir: str | None = None, **_):
        self.agents = [a for a in (agents.split(",") if isinstance(agents, str) else agents) if a]
        self.session = session or None
        self.session_id = session_id or os.environ.get("CLAUDE_CODE_SESSION_ID") or None
        self.own_socket = os.environ.get("CLAUDE_CODE_MESSAGING_SOCKET")
        self.exit_after = float(exit_after)
        self._watch: asyncio.Task | None = None
        self.hop = InboxHop(agents_dir=os.devnull, sessions_dir=sessions_dir, projects_dir=projects_dir)

    def exists(self, agent: str) -> bool:
        return agent in self.agents

    def list_agents(self) -> list[str]:
        return list(self.agents)

    def _target(self) -> str | None:
        """The named session, else the live session with our session id, else the one owning our socket."""
        if self.session:
            return self.session
        by_socket = None
        for p in glob.glob(os.path.join(self.hop.sessions_dir, "*.json")):
            try:
                rec = json.load(open(p))
            except (OSError, ValueError):
                continue
            if not rec.get("name") or not pid_alive(int(rec.get("pid", 0))):
                continue
            if self.session_id:                   # a session id is authoritative: never fall back to a socket
                if rec.get("sessionId") == self.session_id:
                    return rec["name"]
            elif self.own_socket and rec.get("messagingSocketPath") == self.own_socket:
                by_socket = rec["name"]
        return by_socket

    async def start(self):
        """Called by the relay once bound: watch for the session going away for good."""
        if self.exit_after > 0 and self._watch is None:
            self._watch = asyncio.get_running_loop().create_task(self._watchdog())

    async def _watchdog(self):
        gone_since = None
        while True:
            await asyncio.sleep(min(30.0, self.exit_after / 4))
            if self._target():
                gone_since = None
            elif gone_since is None:
                gone_since = time.time()
            elif time.time() - gone_since >= self.exit_after:
                log.warning("no live Claude Code session for %s for %.0f s; exiting and releasing the names",
                            ",".join(self.agents), self.exit_after)
                os.kill(os.getpid(), signal.SIGTERM)   # the CLI's SIGTERM path: the relay closes and releases (§4.3.1)
                return

    async def deliver(self, agent: str, sender: str, text: str, msg: dict, local: bool = False):
        name = self._target()
        if not name:
            return "failed", "the Claude Code session for this endpoint is not running"
        status, reason = await self.hop.deliver(name, sender, msg, text + self._reply_hint(msg))
        if status == "nosession":
            return "failed", reason
        return status, reason

    @staticmethod
    def _reply_hint(msg: dict) -> str:
        """The exact command that answers this message (docs/receive §2): the session uses it as given."""
        try:
            frm, to = A.parse(msg["from"]), A.parse(msg["to"])
        except (KeyError, A.AddressError):
            return ""
        hdr = msg.get("hdr") or {}
        if frm.path == ("_links",):                 # a link notice: answer the peer it names, not the realm
            if not hdr.get("airc-peer"):
                return ""
            frm = A.parse(hdr["airc-peer"])
            return f"\n[to message them: airc send --from {shlex.quote(to.local_path)} {shlex.quote(frm.network(False))} \"your text\"]"
        if not wire.valid_id(msg.get("id")):        # §16 item 4: a foreign value outside its grammar is not written
            return f"\n[reply: airc send --from {shlex.quote(to.local_path)} {shlex.quote(frm.network(False))} \"your text\"]"
        return (f"\n[reply: airc send --from {shlex.quote(to.local_path)} --re {shlex.quote(msg['id'])} "
                f"{shlex.quote(frm.network(False))} \"your text\"]")

    def describe(self) -> str:
        return f"claude (endpoints {','.join(self.agents)} -> session {self._target() or 'none running'})"
