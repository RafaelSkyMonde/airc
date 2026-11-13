# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Delivery into a co fleet: the site layer for the co tooling.

An agent is a directory <agents_dir>/<name> whose running Claude Code session
listens on <name>/channel.sock (co_channel.send). This backend carries what
`co tell` does today so that routing bare names through AIRC changes nothing:

  - compaction: while the agent's compaction lock is fresh, the message goes to
    <agent>/queued-messages.jsonl (co-compact-agent drains it after the
    restart) and the sender is told "queued";
  - auto-start: autostart=local (the default, and what co tell does today)
    starts a stopped agent through `co tell` when the sender is in this
    fleet; autostart=all does it for foreign senders too (it spends this
    fleet's resources on their say-so); autostart=off never does, and the
    sender gets "failed: endpoint_offline";
  - the fleet's own message log (_messages.log, with a body preview), written
    here when a message is DELIVERED, because the body never enters aircd's
    event log. Not written when a message is queued: the drain after the
    restart delivers it through this path again and logs it then.

Phase B: for agents listed in `inbox_agents` (or all agents when the list is
empty and lasthop=inbox), delivery goes over Claude Code's per-session inbox
socket instead of channel.sock, confirmed by the session's transcript (see
backends/inbox.py). An agent with no live session falls back to the paths
above, so stopped and compacting agents behave as before.

Options: agents_dir, co_dir (where co_channel.py lives), autostart, profile (full | icons | names | off), status (on | off)
(off|local|all, default local), log (bool, default True),
lasthop (channel|inbox, default channel), inbox_agents (comma-separated
allow-list), sessions_dir, projects_dir.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import logging
import os
import re
import subprocess
import sys
import time


class Backend:
    def __init__(self, agents_dir: str | None = None, co_dir: str | None = None, autostart="local",
                 log: bool = True, lasthop: str = "channel", inbox_agents: str = "",
                 sessions_dir: str | None = None, projects_dir: str | None = None, profile: str = "full",
                 status: str | bool = "off", **_):
        self.co_dir = co_dir or os.environ.get("CO_SCRIPT_DIR") or self._find_co_dir()
        if self.co_dir and self.co_dir not in sys.path:
            sys.path.insert(0, self.co_dir)
        try:
            self.co_channel = importlib.import_module("co_channel")
            self.co_paths = importlib.import_module("co_paths")
            self.co_status = importlib.import_module("co_status")
        except ImportError as e:
            raise RuntimeError(f"co backend: co tools not importable from {self.co_dir!r}: {e}")
        self.agents_dir = agents_dir or os.environ.get("CO_AGENTS_DIR") or self.co_paths.AGENTS_DIR
        # what each agent's public profile says (spec §21): full = name, Mission sentence and icon;
        # icons = the name and icon, no text; names = the name only; off = no profile
        self.profile_mode = profile if profile in ("full", "icons", "names", "off") else "full"
        # publish whether each agent's session is running (spec §21.2): off unless the operator opts in
        self.status_enabled = status in (True, "on", "true", "yes")
        if autostart is True:
            autostart = "all"
        if autostart in (False, None, "false", "off", "no"):
            autostart = "off"
        if autostart not in ("off", "local", "all"):
            raise RuntimeError(f"co backend: autostart must be off|local|all, not {autostart!r}")
        self.autostart = autostart
        self.log_enabled = bool(log)
        self.log_path = os.path.join(self.co_paths.STATE_DIR, "_messages.log")
        if lasthop not in ("channel", "inbox"):
            raise RuntimeError(f"co backend: lasthop must be channel|inbox, not {lasthop!r}")
        self.lasthop = lasthop
        self.inbox_agents = {a.strip() for a in str(inbox_agents or "").split(",") if a.strip()}
        self.inbox = None
        if lasthop == "inbox":
            from .inbox import InboxHop
            self.inbox = InboxHop(self.agents_dir, sessions_dir, projects_dir)

    async def start(self):
        """Called by the relay after binding. Structural self-test of inbox
        mode; on failure inbox is disabled for this run and channel is used."""
        if not self.inbox:
            return
        ok, why = self.inbox.selftest(sorted(self.inbox_agents))
        if ok:
            logging.getLogger("airc.inbox").info("inbox last hop enabled for %s: %s",
                                                 sorted(self.inbox_agents) or "all agents", why)
        else:
            logging.getLogger("airc.inbox").error("inbox last hop DISABLED for this run: %s", why)
            self.inbox = None

    def _uses_inbox(self, agent: str) -> bool:
        return self.inbox is not None and (not self.inbox_agents or agent in self.inbox_agents)

    @staticmethod
    def _find_co_dir():
        for cand in (os.path.join(os.environ.get("CO_SRC_ROOT", ""), "shellscr", "co"),
                     "/opt/co/shellscr/co"):
            if cand and os.path.isfile(os.path.join(cand, "co_channel.py")):
                return cand
        return None

    def describe(self) -> str:
        hop = f", lasthop=inbox[{','.join(sorted(self.inbox_agents)) or '*'}]" if self.lasthop == "inbox" else ""
        return f"co(agents_dir={self.agents_dir}, autostart={self.autostart}{hop})"

    def exists(self, agent: str) -> bool:
        return os.path.isdir(os.path.join(self.agents_dir, agent))

    def profile(self, agent: str) -> dict | None:
        """The agent's public profile (spec §21): its name, the first sentence of its goals.md
        Mission (already public on the co dashboard) and its icon.png as a thumbnail."""
        from .. import profile as PR
        d = os.path.join(self.agents_dir, agent)
        if not os.path.isdir(d) or self.profile_mode == "off":
            return None
        rec: dict = {"name": agent}
        if self.profile_mode == "names":
            return rec
        if self.profile_mode == "full":                         # icons: no Mission sentence, text stays private
            try:
                with open(os.path.join(d, "goals.md"), encoding="utf-8") as f:
                    goals = f.read()
                m = re.search(r"^## Mission[^\n]*\n(.*?)(?=^#{1,2} |\Z)", goals, re.S | re.M)
                for para in re.split(r"\n\s*\n", m.group(1) if m else ""):
                    para = para.strip()
                    if para and not para.startswith((">", "#", "|", "```")):    # the first plain paragraph, not a quote
                        rec["about"] = PR.first_sentence(para)
                        break
            except OSError:
                pass
        icon = os.path.join(d, "icon.png")
        if os.path.isfile(icon):
            key = (icon, os.path.getmtime(icon))
            cache = self.__dict__.setdefault("_thumbs", {})
            if key not in cache:
                cache[key] = PR.thumbnail(icon)
            if cache[key]:
                rec["image"] = cache[key]
        return rec

    def session_states(self) -> dict[str, bool]:
        """agent -> is its session running (its channel server answers a ping)."""
        return {a: bool(self.co_channel.ping(a, 1)[0]) for a in self.list_agents()}

    def list_agents(self) -> list[str]:
        """Every agent this backend can deliver to (the relay publishes their E2E keys)."""
        try:
            return sorted(d for d in os.listdir(self.agents_dir)
                          if not d.startswith((".", "_")) and os.path.isdir(os.path.join(self.agents_dir, d)))
        except OSError:
            return []

    # --- pieces of co tell, reproduced byte for byte -------------------------
    def _queue(self, agent: str, sender: str, text: str) -> bool:
        qpath = os.path.join(self.agents_dir, agent, "queued-messages.jsonl")
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "sender": sender, "message": text}
        try:
            with open(qpath, "a") as f:
                f.write(json.dumps(rec) + "\n")
            return True
        except OSError:
            return False

    def _log(self, sender: str, agent: str, text: str) -> None:
        if not self.log_enabled:
            return
        try:
            one = " ".join(text.split())            # the log is one line per message
            short = one[:300] + ("..." if len(one) > 300 else "")
            os.makedirs(os.path.dirname(self.log_path), exist_ok=True)   # a fresh machine has no co state dir yet
            with open(self.log_path, "a") as f:
                f.write(f"{time.strftime('%H:%M:%S')} {sender:<16s} → {agent:<16s} {short}\n")
        except OSError:
            pass

    async def deliver(self, agent: str, sender: str, text: str, msg: dict, local: bool = False):
        loop = asyncio.get_running_loop()
        if self._uses_inbox(agent) and not self.co_status.is_compacting(agent):
            status, reason = await self.inbox.deliver(agent, sender, msg, text)
            if status == "delivered":
                self._log(sender, agent, text)
                return "delivered", ""
            if status == "failed":
                return "failed", reason
            # "nosession": no live inbox; fall through to the channel/auto-start paths
        if self.co_status.is_compacting(agent):
            if self._queue(agent, sender, text):
                return "queued", f"{agent} is compacting; queued for delivery after restart"
            return "failed", f"{agent} is compacting and its queue is not writable"
        ok = await loop.run_in_executor(None, self.co_channel.send, agent, sender, text, 1)
        if ok:
            self._log(sender, agent, text)
            return "delivered", ""
        if self.autostart == "all" or (self.autostart == "local" and local):
            # CO_AIRC_LASTHOP=1: co tell must take its local path (start, queue,
            # channel send) and never hand the target back to airc, or we loop.
            env = dict(os.environ, CO_SESSION_NAME=sender, CO_AIRC_LASTHOP="1")
            co_bin = os.path.join(self.co_dir, "co") if self.co_dir else "co"   # the unit's PATH is minimal
            rc = await loop.run_in_executor(
                None, lambda: subprocess.run([co_bin, "tell", agent, text], env=env, capture_output=True, text=True, timeout=90))
            if rc.returncode == 0:
                status = "queued" if "Queued" in rc.stdout else "delivered"
                if status == "delivered":
                    self._log(sender, agent, text)      # the last-hop co tell does not log; we do
                return status, rc.stdout.strip()[:120]
            return "failed", (rc.stderr or rc.stdout).strip()[-200:] or "co tell failed"
        return "failed", f"{agent} is not running (channel unreachable)"
