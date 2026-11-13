#!/usr/bin/env python3
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Probe for the WebSocket binding (spec §3.4.6; GET /airc/v0/ws, through Fastly Fanout on airc.dev).

Makes a throwaway workspace, binds //<realm>/<ws>/sock in push mode, opens the WebSocket, and reports
with timestamps what arrives: the welcome, Fanout's keep-alive pings, a message sent from another session
(and how fast), the ack and ping answers over the socket, and WebSocket ping/pong.

  ws_proto.py https://stage.airc.dev [--idle 70] [--abrupt] [--watch S]
  ws_proto.py http://localhost:7676 --sim       # no Fanout: post Fanout's WebSocket-over-HTTP events ourselves

--abrupt drops the TCP connection without a close frame, to see how Fanout reports it (access log).
"""
from __future__ import annotations
import argparse, asyncio, base64, json, os, secrets, socket, ssl, struct, sys, tempfile, threading, time
import urllib.error, urllib.parse, urllib.request
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from airc import signing as S                                  # noqa: E402
from airc.httpclient import HttpClient, USER_AGENT              # noqa: E402

T0 = time.monotonic()
def say(*a):
    print(f"{time.monotonic() - T0:7.2f}s", *a, flush=True)


def register(base, name, pub):
    req = urllib.request.Request(base + "/airc/v0/workspaces", data=json.dumps({"name": name, "pub": pub}).encode(),
                                 headers={"Content-Type": "application/json", "User-Agent": USER_AGENT}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


class WsClient:
    """A minimal RFC 6455 client: text frames, ping/pong, close. Frames arrive on a reader thread."""
    def __init__(self, url: str, headers: dict):
        u = urllib.parse.urlsplit(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        raw = socket.create_connection((u.hostname, port), timeout=30)
        self.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) if u.scheme == "https" else raw
        key = base64.b64encode(os.urandom(16)).decode()
        path = u.path + ("?" + u.query if u.query else "")
        lines = [f"GET {path} HTTP/1.1", f"Host: {u.hostname}", "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13", f"User-Agent: {USER_AGENT}"]
        lines += [f"{k}: {v}" for k, v in headers.items()]
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError(f"closed during handshake: {resp!r}")
            resp += chunk
        head, self.buf = resp.split(b"\r\n\r\n", 1)
        self.status = head.split(b"\r\n")[0].decode()
        if " 101 " not in self.status + " ":
            raise RuntimeError(f"handshake refused: {head.decode(errors='replace')}\n{self.buf[:500]!r}")
        self.sock.settimeout(None)
        self.frames: list[tuple[float, str, bytes]] = []
        self.cv = threading.Condition()
        threading.Thread(target=self._reader, daemon=True).start()

    def _recv(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _reader(self):
        names = {1: "text", 2: "binary", 8: "close", 9: "ping", 10: "pong"}
        try:
            while True:
                b0, b1 = self._recv(2)
                op, n = b0 & 0x0F, b1 & 0x7F
                if n == 126:
                    n = struct.unpack(">H", self._recv(2))[0]
                elif n == 127:
                    n = struct.unpack(">Q", self._recv(8))[0]
                data = self._recv(n)
                kind = names.get(op, f"op{op}")
                with self.cv:
                    self.frames.append((time.monotonic(), kind, data))
                    self.cv.notify_all()
                if kind == "ping":
                    self.send(data, 10)
        except (EOFError, OSError):
            with self.cv:
                self.frames.append((time.monotonic(), "eof", b""))
                self.cv.notify_all()

    def send(self, data: bytes | str, op: int = 1):
        if isinstance(data, str):
            data = data.encode()
        mask = os.urandom(4)
        n = len(data)
        head = bytes([0x80 | op]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n) if n < 65536
                                     else bytes([0x80 | 127]) + struct.pack(">Q", n))
        self.sock.sendall(head + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))

    def wait(self, pred, secs: float, start: int = 0):
        """The first frame from index start on that pred accepts, or None after secs."""
        end = time.monotonic() + secs
        with self.cv:
            while True:
                for f in self.frames[start:]:
                    if pred(f):
                        return f
                left = end - time.monotonic()
                if left <= 0:
                    return None
                self.cv.wait(left)


def text_json(f):
    try:
        return json.loads(f[2]) if f[1] == "text" else None
    except ValueError:
        return None


def sim_post(base, events: bytes, meta: dict, headers: dict | None = None):
    """What Fanout would send: one WebSocket-over-HTTP request."""
    h = {"Grip-Sig": "viceroy-test", "Content-Type": "application/websocket-events", "Sec-WebSocket-Extensions": "grip",
         "Connection-Id": "sim-1", "User-Agent": USER_AGENT, **{f"Meta-{k}": v for k, v in meta.items()}, **(headers or {})}
    req = urllib.request.Request(base + "/airc/v0/ws", data=events, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), b""


def parse_events(body: bytes):
    out, i = [], 0
    while i < len(body):
        eol = body.index(b"\r\n", i)
        head = body[i:eol].decode()
        i = eol + 2
        if " " in head:
            t, n = head.split(" ", 1)
            n = int(n, 16)
            out.append((t, body[i:i + n].decode(errors="replace")))
            i += n + 2
        else:
            out.append((head, ""))
    return out


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("base")
    ap.add_argument("--sim", action="store_true", help="no Fanout (viceroy): post its events ourselves")
    ap.add_argument("--idle", type=float, default=70, help="seconds to sit idle counting keep-alives")
    ap.add_argument("--abrupt", action="store_true", help="end by dropping TCP without a close frame")
    ap.add_argument("--watch", type=float, default=0, help="afterwards, watch the workspace's ws.* events this long")
    a = ap.parse_args()
    base = a.base.rstrip("/")
    tmp = tempfile.mkdtemp(prefix="airc-ws-")
    key = S.Signer(f"{tmp}/k.key")
    name = "wsp-" + secrets.token_hex(4)
    reg = register(base, name, key.public_b64)
    realm = reg["realm"]
    say(f"workspace {name} on {realm}")
    rx = HttpClient(base, key); await rx.capabilities()
    tx = HttpClient(base, key); await tx.capabilities()
    me = f"//{realm}/{name}/sock"
    await rx.bind([f"{name}/sock"], mode="push")
    await tx.bind([f"{name}/sender"], mode="pull")
    auth = key.sign_client_request(realm, "GET", "/airc/v0/ws", b"")
    hdrs = {"Authorization": auth, "AIRC-Session": rx.session}
    try:
        if a.sim:
            await sim(base, hdrs, rx, tx, name, me)
        else:
            await real(a, base, hdrs, tx, name, me)
        end, shown = time.monotonic() + a.watch, set()
        while time.monotonic() < end:
            for ev in await tx.events(kinds=["ws.close", "ws.disconnect", "ws.keepalive"]):
                k = (ev.get("kind"), ev.get("ts"))
                if k not in shown and str(ev.get("kind", "")).startswith("ws."):
                    shown.add(k); say("event", ev.get("kind"), "at", ev.get("ts"), f"({time.time() - float(ev.get('ts') or 0):.0f}s ago)")
            await asyncio.sleep(10)
    finally:
        try:
            await rx.workspace("delete", confirm=name)
        except Exception as e:  # noqa: BLE001
            say(f"(cleanup: {e})")


async def sim(base, hdrs, rx, tx, name, me):
    st, h, body = sim_post(base, b"OPEN\r\n", {}, hdrs)
    ev = parse_events(body)
    say("OPEN ->", st, {k: v for k, v in h.items() if k.lower().startswith(("set-meta", "sec-websocket", "keep-alive", "content-type"))})
    for t, c in ev:
        say("   ", t, c[:160])
    meta = {k[9:]: v for k, v in h.items() if k.lower().startswith("set-meta-")}
    r = await tx.send(me, "hello over ws", frm=f"{name}/sender")
    say("sent:", r)
    st, h, body = sim_post(base, b"OPEN\r\n", {}, {**hdrs})  # a second OPEN: the replayed nonce must be refused
    say("replayed OPEN ->", st)
    ack = json.dumps({"t": "ack", "id": r["id"], "status": "delivered"}).encode()
    st, h, body = sim_post(base, b"TEXT %X\r\n" % len(ack) + ack + b"\r\n", meta)
    say("ack ->", st, parse_events(body))
    say("inbox after ack:", [m.get("id") for m in await rx.inbox()])
    snd = json.dumps({"t": "send", "rid": "s1", "msg": {"t": "msg", "from": f"{name}/sock", "to": f"{name}/sender", "body": "sent up the socket"}}).encode()
    st, h, body = sim_post(base, b"TEXT %X\r\n" % len(snd) + snd + b"\r\n", meta)
    say("send ->", st, parse_events(body))
    bad = b'{"t":"send","rid":"s2","msg":{"t":"msg","from":"someone-else/x","to":"' + name.encode() + b'/sender","body":"spoof"}}'
    st, h, body = sim_post(base, b"TEXT %X\r\n" % len(bad) + bad + b"\r\n", meta)
    say("spoofed send ->", st, parse_events(body))
    for evs, label in [(b'TEXT C\r\n{"t":"ping"}\r\n', "app ping"),
                       (b"PING\r\n", "ws ping"), (b"", "keep-alive request"),
                       (b"CLOSE 2\r\n\x03\xe8\r\n", "close")]:
        st, h, body = sim_post(base, evs, meta)
        say(f"{label} ->", st, parse_events(body))
    st, h, body = sim_post(base, b"PING\r\n", {})
    say("no meta ->", st, parse_events(body))


async def real(a, base, hdrs, tx, name, me):
    t = time.monotonic()
    ws = WsClient(f"{base}/airc/v0/ws", hdrs)
    say(f"handshake {ws.status} in {time.monotonic() - t:.2f}s")
    w = ws.wait(lambda f: (text_json(f) or {}).get("t") == "welcome", 10)
    say("welcome:", w and w[2][:200])
    for f in list(ws.frames):
        say("  frame", f[1], f[2][:200])
    # a message from another session: how fast does it come down the socket?
    n0 = len(ws.frames)
    t = time.monotonic()
    r = await tx.send(me, "hello over ws", frm=f"{name}/sender")
    sent = time.monotonic()
    m = ws.wait(lambda f: (text_json(f) or {}).get("t") == "msg", 20, n0)
    if m:
        say(f"push: msg arrived {m[0] - t:.2f}s after send started (send call took {sent - t:.2f}s); send ack {r}")
        mid = text_json(m)["id"]
        n1 = len(ws.frames)
        ws.send(json.dumps({"t": "ack", "id": mid, "status": "delivered"}))
        r = ws.wait(lambda f: (text_json(f) or {}).get("t") == "acked", 10, n1)
        say("ack over ws ->", r and r[2], f"{r[0] - ws.frames[n1 - 1][0]:.2f}s" if r else "")
    else:
        say("push: NO msg within 20 s; frames:", [(f[1], f[2][:80]) for f in ws.frames[n0:]])
    n1 = len(ws.frames)
    t = time.monotonic()
    ws.send(json.dumps({"t": "send", "rid": "s1", "msg": {"t": "msg", "from": f"{name}/sock", "to": f"{name}/sender", "body": "sent up the socket"}}))
    r = ws.wait(lambda f: (text_json(f) or {}).get("rid") == "s1", 15, n1)
    say(f"send over ws -> {r and r[2][:200]} in {time.monotonic() - t:.2f}s")
    inbox = await tx.inbox()
    say("sender's inbox has it:", any(m.get("body") == "sent up the socket" for m in inbox))
    n2 = len(ws.frames)
    ws.send(json.dumps({"t": "ping"}))
    r = ws.wait(lambda f: (text_json(f) or {}).get("t") == "pong", 10, n2)
    say("app ping ->", r and r[2])
    n3 = len(ws.frames)
    ws.send(b"probe", 9)
    r = ws.wait(lambda f: f[1] == "pong", 10, n3)
    say("ws ping ->", r and (r[1], r[2]))
    say(f"idle {a.idle:g}s: counting what Fanout sends")
    n4 = len(ws.frames)
    time.sleep(a.idle)
    idle = ws.frames[n4:]
    say(f"during idle: {len(idle)} frames:", [(round(f[0] - T0, 1), f[1], f[2][:60]) for f in idle])
    if a.abrupt:
        say("dropping TCP without a close frame")
        ws.sock.shutdown(socket.SHUT_RDWR); ws.sock.close()
    else:
        n5 = len(ws.frames)
        ws.send(struct.pack(">H", 1000), 8)
        r = ws.wait(lambda f: f[1] in ("close", "eof"), 10, n5)
        say("close ->", r and (r[1], r[2]))
    say("done; check the access log for kind=ws-* lines")


if __name__ == "__main__":
    asyncio.run(main())
