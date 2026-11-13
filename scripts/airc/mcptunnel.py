# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Tool tunnels (spec §23): MCP carried over AIRC.

export: bind an address and serve a local stdio MCP server to the endpoints that write to it, one
        server process per importing address (MCP sessions are stateful), exporting only the tools
        the operator allowed.
import: a local stdio MCP server for this agent: each JSON-RPC message on stdin goes over AIRC to the
        exported address, and the answers come back on stdout. Logs go to stderr.

Both work over a local aircd socket or a hosted workspace (--server), and seal their messages when
the other side publishes keys (§19), as `airc send` does.
"""
import asyncio
import json
import os
import sys

from . import address as A
from . import e2e as E2E
from . import wire

MEDIA_TYPE = "application/mcp+json"
BIN_ABOVE = 900 * 1024        # §23: larger JSON-RPC messages travel in a binary section
TTL = 600                     # §23: a tool call that waits longer is not useful


def log(text: str) -> None:
    print(f"airc mcp: {text}", file=sys.stderr, flush=True)


async def send(c, to: str, text: str, frm: str, re_id: str | None = None, plain: bool = False) -> dict:
    """One MCP message to `to`, sealed when it publishes keys; the binary-section form when large."""
    body, data = (text, None) if len(text.encode()) <= BIN_ABOVE else ("", text.encode())
    sender = getattr(c, "hc", None) or c                # an HTTPS session sends through its HttpClient
    if plain:
        return await sender.send(to, body, frm=frm, mtype=MEDIA_TYPE, re_id=re_id, ttl=TTL, bin=data)
    try:
        a, _note = await sender.send_e2e(to, body, frm=frm, mtype=MEDIA_TYPE, re_id=re_id, ttl=TTL, bin=data)
    except E2E.E2EError as e:
        return wire.ack("?", "failed", f"not sent: {e.reason}", e.code)
    return a


def opened(m: dict) -> dict:
    """m with an encrypted message opened (§19.6); raises E2E.E2EError if it cannot be."""
    if m.get("type") == E2E.MEDIA_TYPE and E2E.AVAILABLE:
        return E2E.Keystore(A.parse(m["to"]).key).open(m)
    return m


def payload(m: dict) -> str:
    """The JSON-RPC text a §23 message carries: the body, or the binary section when the body is empty."""
    if not m.get("body") and m.get("_bin") is not None:
        return m["_bin"].decode()
    return m.get("body") or ""


# ---------------------------------------------------------------- export

class _Session:
    """One importing address's MCP session: a server process and the requests in flight."""

    def __init__(self, ex: "Exporter", peer: str, proc):
        self.ex, self.peer, self.proc = ex, peer, proc
        self.inflight: dict[str, str] = {}             # JSON-RPC id (as JSON text) -> AIRC id of its request
        self.last = asyncio.get_running_loop().time()
        asyncio.get_running_loop().create_task(self._pump())

    async def write(self, obj: dict) -> None:
        self.proc.stdin.write((json.dumps(obj) + "\n").encode())
        await self.proc.stdin.drain()

    async def _pump(self) -> None:
        """Server stdout -> AIRC; a response goes back as a reply to the message that carried its request."""
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                if self.ex.sessions.get(self.peer) is self:
                    del self.ex.sessions[self.peer]
                return
            try:
                msg = json.loads(line)
            except ValueError:
                log("the tool server wrote a line that is not JSON; dropped")
                continue
            if not isinstance(msg, dict):
                continue
            re_id = None
            if "id" in msg and "method" not in msg:
                re_id = self.inflight.pop(json.dumps(msg["id"]), None)
                r = msg.get("result")
                if isinstance(r, dict) and isinstance(r.get("tools"), list) and self.ex.allow is not None:
                    r["tools"] = [t for t in r["tools"] if isinstance(t, dict) and t.get("name") in self.ex.allow]
            await self.ex.reply(self.peer, msg, re_id)


class Exporter:
    def __init__(self, c, me: str, cmd: list[str], allow: set[str] | None, idle: int = 600, plain: bool = False):
        self.c, self.me, self.cmd, self.allow, self.idle, self.plain = c, me, cmd, allow, idle, plain
        self.sessions: dict[str, _Session] = {}

    async def reply(self, peer: str, obj: dict, re_id: str | None) -> None:
        a = await send(self.c, peer, json.dumps(obj), self.me, re_id, self.plain)
        if a.get("status") == "failed":
            log(f"answer to {peer} not delivered: {a.get('reason')}")

    async def _start(self, peer: str) -> _Session:
        old = self.sessions.pop(peer, None)
        if old and old.proc.returncode is None:
            old.proc.terminate()
        proc = await asyncio.create_subprocess_exec(*self.cmd, stdin=asyncio.subprocess.PIPE,
                                                    stdout=asyncio.subprocess.PIPE, limit=16 << 20)
        s = self.sessions[peer] = _Session(self, peer, proc)
        log(f"session for {peer} started (tool server pid {proc.pid})")
        return s

    async def handle(self, m: dict):
        """A message to the exported address: ack once taken (§23 Delivery); the answer follows on its own."""
        try:
            m = opened(m)
        except E2E.E2EError as e:
            return ("failed", e.reason, e.code)
        if m.get("type") != MEDIA_TYPE:
            return ("failed", f"this address is a tool tunnel (spec §23); send {MEDIA_TYPE}", "refused")
        try:
            req = json.loads(payload(m))
        except (ValueError, UnicodeDecodeError):
            return ("failed", "the message is not JSON", "bad_request")
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0":
            return ("failed", "the message is not one JSON-RPC 2.0 message", "bad_request")
        asyncio.get_running_loop().create_task(self._forward(m["from"], m["id"], req))
        return "delivered"

    async def _forward(self, peer: str, airc_id: str, req: dict) -> None:
        method, rid = req.get("method"), req.get("id")
        is_request = method is not None and "id" in req
        if method == "tools/call" and self.allow is not None:
            name = (req.get("params") or {}).get("name")
            if name not in self.allow:
                log(f"{peer} called {name}, which is not exported")
                if is_request:
                    await self.reply(peer, {"jsonrpc": "2.0", "id": rid,
                                            "error": {"code": -32602, "message": f"tool {name} is not exported"}}, airc_id)
                return
        s = self.sessions.get(peer)
        if method == "initialize" or (s and s.proc.returncode is not None):
            s = await self._start(peer)
        elif s is None:
            if is_request:
                await self.reply(peer, {"jsonrpc": "2.0", "id": rid, "error": {
                    "code": -32000, "message": "no MCP session for you here (it ended or never began): send initialize"}}, airc_id)
            return
        s.last = asyncio.get_running_loop().time()
        if is_request:
            s.inflight[json.dumps(rid)] = airc_id
        log(f"{peer}: {method or 'response'}" + (f" {(req.get('params') or {}).get('name')}" if method == "tools/call" else ""))
        try:
            await s.write(req)
        except (BrokenPipeError, ConnectionResetError):
            log(f"the tool server for {peer} has gone")

    async def reap(self) -> None:
        while True:
            await asyncio.sleep(30)
            now = asyncio.get_running_loop().time()
            for peer, s in list(self.sessions.items()):
                if now - s.last > self.idle and s.proc.returncode is None:
                    log(f"session for {peer} idle {int(now - s.last)} s; ended")
                    s.proc.terminate()

    def close(self) -> None:
        for s in self.sessions.values():
            if s.proc.returncode is None:
                s.proc.terminate()


# ---------------------------------------------------------------- import

async def run_import(c, me: str, target: str, plain: bool = False) -> int:
    """stdin (JSON-RPC from this agent's MCP client) -> target over AIRC; target's answers -> stdout."""
    want = c.absolute(target)
    out = sys.stdout
    loop = asyncio.get_running_loop()

    async def handle(m: dict):
        try:
            m = opened(m)
        except E2E.E2EError as e:
            return ("failed", e.reason, e.code)
        if m.get("type") != MEDIA_TYPE or c.absolute(m.get("from", "")) != want:
            return ("failed", f"this address takes only MCP messages from {target}", "refused")
        try:
            text = payload(m)
            json.loads(text)
        except (ValueError, UnicodeDecodeError):
            return ("failed", "the message is not JSON", "bad_request")
        out.write(text.replace("\n", " ") + "\n")
        out.flush()
        return "delivered"

    async def pump_stdin():
        reader = asyncio.StreamReader(limit=16 << 20)
        await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), sys.stdin)
        while True:
            line = await reader.readline()
            if not line:
                return
            text = line.decode().strip()
            if not text:
                continue
            a = await send(c, target, text, me, plain=plain)
            if a.get("status") == "failed":
                log(f"not delivered to {target}: {a.get('reason')}")
                try:                                     # answer a request here, so the agent is not left waiting
                    req = json.loads(text)
                    if isinstance(req, dict) and req.get("method") and "id" in req:
                        out.write(json.dumps({"jsonrpc": "2.0", "id": req["id"], "error": {
                            "code": -32000, "message": f"AIRC tool tunnel to {target}: {a.get('reason')}"}}) + "\n")
                        out.flush()
                except ValueError:
                    pass

    serving = loop.create_task(c.serve(handle))
    try:
        await pump_stdin()
    finally:
        serving.cancel()
    return 0
