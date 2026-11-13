# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Client of a realm's HTTPS face (spec §3.4.2): what a laptop relay or a
one-shot `airc send --server https://airc.dev` uses. Standard library only.

    c = HttpClient("https://airc.dev", Signer("~/.airc/workspace.key"))
    await c.bind(["joe/"], mode="push")
    ack = await c.send("//example.com/alice/x", "hello", frm="joe/reviewer")
    ws = await WsSocket(c).open()       # push channel (§3.4.6): messages down, acks and sends up
    async for f in ws.frames():
        if f["t"] == "msg": ...; await ws.ack(f["id"])

The realm name is learned from the capabilities document, which the client
fetches once; every request is signed with the workspace key.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import secrets
import socket
import ssl
import struct
import threading
import time
import urllib.parse
from typing import AsyncIterator

from . import signing as S
from . import wire
from . import wsock
from . import __version__

USER_AGENT = f"airc/{__version__}"   # a named client: CDNs refuse anonymous Python (Cloudflare 1010)

log = logging.getLogger("airc.http")


class HttpClientError(Exception):
    pass


def session_id(stable: str | None = None) -> str:
    """This process's session id (spec §4.3.1): random, or derived from a stable value such as
    $AIRC_SESSION. A stable value that is not a valid id itself (16-64 of A-Z a-z 0-9 _ -) is hashed
    into one. Give each process its own: two processes sharing an id share the names it holds."""
    import hashlib
    import re
    if not stable:
        return secrets.token_urlsafe(18)
    return stable if re.fullmatch(r"[A-Za-z0-9_-]{16,64}", stable) else hashlib.sha256(stable.encode()).hexdigest()[:32]


class Displaced(HttpClientError):
    """Another session took over every name this one held (spec §4.3.1)."""

    def __init__(self, names):
        super().__init__(f"another session took over {', '.join(names)}")


class NameHeld(HttpClientError):
    """Another live session holds a name this bind asked for (spec §4.3.1)."""

    def __init__(self, doc: dict):
        self.name, self.idle, self.suggest = doc.get("name", ""), doc.get("idle"), doc.get("suggest")
        super().__init__(f"{self.name} is held by another session" + (f" (last seen {self.idle}s ago)" if self.idle is not None else "")
                         + (f"; {self.suggest} is free" if self.suggest else ""))


class HttpClient:
    def __init__(self, base_url: str, signer: S.Signer, *, insecure: bool = False, timeout: float = 20):
        self.base = base_url.rstrip("/")
        u = urllib.parse.urlsplit(self.base)
        self.tls = u.scheme == "https"
        self.host = u.hostname
        self.port = u.port or (443 if self.tls else 80)
        self.signer = signer
        self.insecure = insecure
        self.timeout = timeout
        self.realm: str | None = None
        self.namespaces: list[str] = []
        self.features: list[str] = []
        # this process's session (spec §4.3.1). $AIRC_SESSION keeps it across restarts of the same
        # logical session (a relay restarted when its container resumes), so the names it held are
        # still its own rather than held by a dead process for the rest of the lease.
        self.session = session_id(os.environ.get("AIRC_SESSION"))
        self.displaced: list[str] = []               # names another session took over from us
        self._events: asyncio.Queue = asyncio.Queue()
        # HTTP keep-alive: up to 4 idle connections reused across requests (never shared in flight);
        # a stale pooled connection retries a safe GET/HEAD once and never replays a POST
        self._http_lock = threading.Lock()
        self._http_idle: list[http.client.HTTPConnection] = []
        self._http_closed = False
        self._capabilities_lock = threading.Lock()
        self._capabilities_doc: dict | None = None
        self._ws: WsSocket | None = None

    # --- plumbing -----------------------------------------------------------
    def _conn(self, timeout=None):
        """A connection to the realm, through HTTPS_PROXY / HTTP_PROXY (CONNECT) when the environment sets one
        and NO_PROXY does not exempt the host."""
        import urllib.request
        proxy = urllib.request.getproxies().get("https" if self.tls else "http")
        if proxy and urllib.request.proxy_bypass(self.host):
            proxy = None
        ph = pp = None; hdrs = {}
        if proxy:
            pu = urllib.parse.urlsplit(proxy if "://" in proxy else "http://" + proxy)
            ph, pp = pu.hostname, pu.port or (443 if pu.scheme == "https" else 80)
            if pu.username:
                import base64
                cred = f"{urllib.parse.unquote(pu.username)}:{urllib.parse.unquote(pu.password or '')}"
                hdrs["Proxy-Authorization"] = "Basic " + base64.b64encode(cred.encode()).decode()
        if self.tls:
            ctx = ssl.create_default_context()
            if self.insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            if ph:
                c = http.client.HTTPSConnection(ph, pp, timeout=timeout or self.timeout, context=ctx)
                c.set_tunnel(self.host, self.port, headers=hdrs)
                return c
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout or self.timeout, context=ctx)
        if ph:
            c = http.client.HTTPConnection(ph, pp, timeout=timeout or self.timeout)
            c.set_tunnel(self.host, self.port, headers=hdrs)
            return c
        return http.client.HTTPConnection(self.host, self.port, timeout=timeout or self.timeout)

    def _take_http_connection(self):
        # Executor threads must never use one HTTP/1.1 connection concurrently.
        with self._http_lock:
            if self._http_closed:
                raise HttpClientError("the client is closed")
            if self._http_idle:
                return self._http_idle.pop(), True
        return self._conn(), False

    def _return_http_connection(self, c, reusable: bool):
        if reusable and c.sock is not None:
            with self._http_lock:
                if not self._http_closed and len(self._http_idle) < 4:
                    self._http_idle.append(c)
                    return
        c.close()

    async def close(self):
        """Close the active WebSocket and idle HTTP connections owned by this client."""
        ws = self._ws
        if ws is not None:
            await ws.close()
        with self._http_lock:
            self._http_closed = True
            idle, self._http_idle = self._http_idle, []
        for c in idle:
            c.close()

    def _request_sync(self, method: str, path: str, obj=None, auth=True, raw: bool = False):
        framed = isinstance(obj, dict) and "_bin" in obj           # a msg with a binary section (§22)
        body = wire.frame_bytes(obj) if framed else json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode() if obj is not None else b""
        headers = {"Content-Type": "application/airc-frame" if framed else "application/json", "Accept": "application/json",
                   "User-Agent": USER_AGENT, **({"AIRC-Session": self.session} if self.session else {})}
        if auth:
            if not self.realm:
                self._capabilities_sync()
            headers["Authorization"] = self.signer.sign_client_request(self.realm, method, path.split("?")[0], body)
        for attempt in range(2):
            c, reused = self._take_http_connection()
            reusable = False
            try:
                c.request(method, path, body=body if body else None, headers=headers)
                r = c.getresponse()
                data = r.read()
                reusable = not r.will_close
                break
            except (OSError, http.client.HTTPException):
                # A server may expire an idle keep-alive socket. Only replay safe reads:
                # a failed POST might already have taken effect at the server.
                if not (attempt == 0 and reused and method in ("GET", "HEAD")):
                    raise
            finally:
                self._return_http_connection(c, reusable)
        if raw and r.status == 200:
            return data
        try:
            out = json.loads(data.decode() or "null")
        except ValueError:
            peek = data[:200].decode("utf-8", "replace").replace("\n", " ")
            raise HttpClientError(f"HTTP {r.status} from {self.host}: not an AIRC response ({peek!r}); "
                                  f"a proxy or firewall may have answered instead")
        if r.status == 401:
            raise HttpClientError(f"unauthorized: {out.get('reason') if isinstance(out, dict) else out}")
        if r.status == 409 and isinstance(out, dict) and out.get("error") == "name_held":
            raise NameHeld(out)
        if isinstance(out, dict) and out.get("displaced"):
            self.displaced += [n for n in out["displaced"] if n not in self.displaced]
        if r.status >= 400 and not (isinstance(out, dict) and out.get("t") in ("ack", "linked", "passported")):
            raise HttpClientError(f"HTTP {r.status}: {out.get('reason') if isinstance(out, dict) else out}")
        return out

    async def _request(self, method, path, obj=None, auth=True, raw=False):
        # Sends stay on HTTP even while a WebSocket is open: measured on airc.dev, a send over the
        # socket (client -> Fanout -> edge, ack back through the publish API) is slower than a POST on a
        # kept-alive connection (0.9 s against 0.46 s per tool call), and the pool removes the
        # per-request TLS setup that made the socket route attractive.
        return await asyncio.get_running_loop().run_in_executor(None, self._request_sync, method, path, obj, auth, raw)

    async def fetch_bin(self, m: dict) -> dict:
        """m with its binary section (§22) fetched and checked, when it declares one."""
        if "bin" in m and "_bin" not in m:
            data = await self._request("GET", "/airc/v0/bin/" + urllib.parse.quote(m["id"], safe=""), raw=True)
            wire.check_bin(m, data)
            m = dict(m, _bin=data)
        return m

    def _capabilities_sync(self, refresh: bool = False):
        with self._capabilities_lock:
            if self._capabilities_doc is not None and not refresh:
                return self._capabilities_doc
            doc = self._request_sync("GET", f"/.well-known/airc?nonce={os.urandom(8).hex()}", auth=False)
            if not isinstance(doc, dict) or doc.get("t") != "capabilities":
                raise HttpClientError("no capabilities document at that URL")
            self.realm = doc["realm"]
            self.features = list(doc.get("features") or [])
            self._capabilities_doc = doc
            return doc

    async def capabilities(self, refresh: bool = False) -> dict:
        """Discover once per client; refresh=True explicitly fetches a new document."""
        return await asyncio.get_running_loop().run_in_executor(None, self._capabilities_sync, refresh)

    # --- operations ---------------------------------------------------------
    async def bind(self, names: list[str], mode: str = "push", webhook: str | None = None, take_over: bool = False) -> dict:
        """Bind names for this session (§4.3.1); raises NameHeld when another live session holds one.
        names=[] releases this session's binds."""
        body = {"names": names, "mode": mode, **({"webhook": webhook} if webhook else {}), **({"take_over": True} if take_over else {})}
        return await self._request("POST", "/airc/v0/bind", body)

    async def release(self) -> None:
        """Free this session's names at once rather than when the lease lapses."""
        try:
            await self._request("POST", "/airc/v0/bind", {"names": [], "mode": "pull"})
        except (HttpClientError, OSError):
            pass

    async def send(self, to: str, body: str, *, frm: str, mtype: str = "text/plain", re_id: str | None = None,
                   ttl: int | None = None, hdr: dict | None = None, bin: bytes | None = None) -> dict:
        m = wire.new_msg(frm, to, body, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)
        if bin is not None:
            wire.attach_bin(m, bin)
        return await self._request("POST", "/airc/v0/send", m)

    async def inbox(self, mx: int = 50) -> list[dict]:
        r = await self._request("GET", f"/airc/v0/inbox?max={mx}")
        return r.get("msgs", []) if isinstance(r, dict) else []

    async def ack(self, msg_id: str, status: str = "delivered", reason: str = "", code: str | None = None, by: str | None = None) -> None:
        await self._request("POST", "/airc/v0/ack", [wire.ack(msg_id, status, reason, code, by)])

    async def link(self, op: str, **fields) -> dict:
        """Link control (§11). An offer or accept carries this endpoint's end-to-end identity key
        (e2e_ik, §19.9) unless the caller passes one (or e2e_ik=None explicitly is not possible: pass "")."""
        if op in ("offer", "accept") and "e2e_ik" not in fields:
            fields["e2e_ik"] = await self._own_ik(fields.get("as"))
        return await self._request("POST", "/airc/v0/link", {"t": "link", "op": op, **{k: v for k, v in fields.items() if v}})

    async def _own_ik(self, as_: str | None) -> str | None:
        """This endpoint's identity key, its record published if needed; None without cryptography
        or when `as` is not a full workspace/agent path."""
        from . import e2e as E2E
        from . import address as A
        if not E2E.AVAILABLE or not as_:
            return None
        try:
            if not getattr(self, "realm", None):
                await self.capabilities()
            ep = A.parse(as_ if as_.startswith(("//", "airc:")) else f"//{self.realm}/{as_.lstrip('/')}")
            if len(ep.path) < 2:
                return None
            ks = E2E.Keystore(ep.key)
            await E2E.ensure_published(ks, self.keys_publish)
            return ks.ik
        except Exception:  # noqa: BLE001  (no key, store trouble: the offer still goes, without the key)
            return None

    # --- workspaces on a hosted realm (spec §3.4.4, §3.4.5) ---------------------
    async def register(self, name: str, *, label: str = "", recovery: bool = False) -> dict:
        """Create a workspace for this client's key. The response may carry a recovery code (shown once)."""
        return await self._request("POST", "/airc/v0/workspaces", {"name": name, "pub": self.signer.public_b64, "label": label,
                                                                 **({"recovery": True} if recovery else {})}, auth=False)

    async def join(self, code: str, *, label: str = "", revoke_others: bool = False, channel: str | None = None) -> dict:
        """Add this client's key to a workspace with a join or recovery code."""
        return await self._request("POST", "/airc/v0/workspaces/join", {"code": code, "pub": self.signer.public_b64, "label": label,
                                                                      **({"revoke_others": True} if revoke_others else {}),
                                                                      **({"channel": channel} if channel else {})}, auth=False)

    async def workspace(self, op: str | None = None, **fields) -> dict:
        """No op: the workspace's keys, join codes and recovery state. Ops: join-code(label, uses, expires),
        revoke-join(id), revoke-key(kid), recovery-code, front(mode, agent | entry) (spec §20)."""
        if op is None:
            return await self._request("GET", "/airc/v0/workspace")
        return await self._request("POST", "/airc/v0/workspace", {"op": op, **{k: v for k, v in fields.items() if v is not None}})

    async def keys_get(self, endpoint: str) -> dict | None:
        """E2E key record for any endpoint (§19.3); another realm's is fetched by our realm."""
        import urllib.parse
        try:
            r = await self._request("GET", "/airc/v0/keys?endpoint=" + urllib.parse.quote(endpoint, safe=""))
        except HttpClientError:
            return None
        return r if isinstance(r, dict) and r.get("t") == "e2e-keys" else None

    async def keys_publish(self, record: dict) -> tuple[bool, str]:
        try:
            await self._request("POST", "/airc/v0/keys", record)
            return True, ""
        except HttpClientError as e:
            return False, str(e)

    async def profile_publish(self, record: dict) -> tuple[bool, str]:
        """Publish an endpoint's public profile (§21.1)."""
        try:
            r = await self._request("POST", "/airc/v0/profile", record)
            return True, r.get("reason", "") if isinstance(r, dict) else ""
        except HttpClientError as e:
            return False, str(e)

    async def profile_status(self, statuses: list[dict]) -> tuple[bool, str]:
        """Publish endpoints' status (§21.2): [{"endpoint", "status": push-active|push-inactive}]."""
        try:
            r = await self._request("POST", "/airc/v0/profile/status", {"statuses": statuses})
            return True, r.get("reason", "") if isinstance(r, dict) else ""
        except HttpClientError as e:
            return False, str(e)

    async def profile_delete(self, endpoint: str) -> tuple[bool, str]:
        return await self.profile_publish({"endpoint": endpoint, "delete": True})

    async def channel_close(self, endpoint: str) -> tuple[bool, str]:
        """Close a channel (§21.4): its profile, keys and status go, and a message to it fails path_gone."""
        return await self.profile_publish({"endpoint": endpoint, "close": True})

    async def profile_get(self, endpoint: str) -> dict | None:
        import urllib.parse
        try:
            r = await self._request("GET", "/airc/v0/profile?endpoint=" + urllib.parse.quote(endpoint, safe=""))
        except HttpClientError:
            return None
        return r if isinstance(r, dict) and r.get("t") == "profile" else None

    async def send_e2e(self, to: str, body: str, *, frm: str, re_id: str | None = None, ttl: int | None = None,
                       mtype: str = "text/plain", bin: bytes | None = None, hdr: dict | None = None) -> tuple[dict, str]:
        """Send with automatic end-to-end encryption (§19); from/to are made absolute for this realm.
        hdr (e.g. airc-receipt, §6.7) stays outside the sealed envelope."""
        from . import e2e as E2E
        from . import address as A
        realm = (await self.capabilities())["realm"]
        ns = frm.strip("/").split("/")[0] if not frm.startswith("//") and "://" not in frm else ""
        m = wire.new_msg(str(A.parse(frm, realm, "")), str(A.parse(to, realm, ns)), body, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)
        if bin is not None:
            wire.attach_bin(m, bin)
        return await E2E.auto_send(m, self.keys_get, self.keys_publish, lambda x: self._request("POST", "/airc/v0/send", x))

    async def passport(self, op: str, **fields) -> dict:
        return await self._request("POST", "/airc/v0/passport", {"t": "passport", "op": op, **{k: v for k, v in fields.items() if v is not None}})

    async def events(self, since: float = 0, kinds: list[str] | None = None) -> list[dict]:
        r = await self._request("GET", f"/airc/v0/events?since={since}&kinds={','.join(kinds or [])}")
        return r.get("events", [])

class WsSocket:
    """An open GET /airc/v0/ws (spec §3.4.6): pushes come down it, and send, ack and ping go up it. Frames
    are read on a daemon thread, not the default executor (the interpreter waits for executor threads at exit,
    and a held socket never ends by itself); replies are matched to requests by rid. A socket that has
    been silent for SILENCE seconds is taken for dead: the server pings within 30 s of quiet."""
    SILENCE = 75.0

    def __init__(self, hc: "HttpClient"):
        self.hc = hc
        self.sock = None
        self.closed = False
        self.last_heard = time.monotonic()
        self._wlock = threading.Lock()
        self._pending: dict[str, asyncio.Future] = {}
        self._frames: asyncio.Queue = asyncio.Queue()
        self._loop = None

    def _open_sync(self):
        hc = self.hc
        if not hc.realm:
            hc._capabilities_sync()
        c = hc._conn(timeout=30)
        c.connect()                                         # through the proxy tunnel, when there is one
        sock = c.sock
        key = wsock.new_key()
        path = "/airc/v0/ws"
        hdrs = {"Host": hc.host if hc.port in (80, 443) else f"{hc.host}:{hc.port}", "Upgrade": "websocket", "Connection": "Upgrade",
                "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13", "User-Agent": USER_AGENT,
                "Authorization": hc.signer.sign_client_request(hc.realm, "GET", path, b""),
                **({"AIRC-Session": hc.session} if hc.session else {})}
        sock.sendall((f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = sock.recv(4096)
            if not chunk:
                raise HttpClientError(f"the socket closed during the handshake: {resp[:200]!r}")
            resp += chunk
            if len(resp) > 65536:
                raise HttpClientError("handshake response too large")
        head, rest = resp.split(b"\r\n\r\n", 1)
        lines = head.decode(errors="replace").split("\r\n")
        status = lines[0].split(" ")[1] if len(lines[0].split(" ")) > 1 else "?"
        fields = {k.strip().lower(): v.strip() for k, _, v in (l.partition(":") for l in lines[1:])}
        if status != "101":
            body = rest
            n = int(fields.get("content-length", "0") or 0)
            while len(body) < n:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
            sock.close()
            try:
                reason = json.loads(body.decode()).get("reason", "")
            except (ValueError, AttributeError):
                reason = body[:120].decode(errors="replace")
            raise HttpClientError(f"HTTP {status}: {reason}")
        if fields.get("sec-websocket-accept") != wsock.accept_key(key):
            sock.close()
            raise HttpClientError("the WebSocket handshake did not verify")
        sock.settimeout(None)
        self.sock, self._buf = sock, rest

    async def open(self):
        self._loop = asyncio.get_running_loop()
        await self._loop.run_in_executor(None, self._open_sync)
        self.hc._ws = self
        threading.Thread(target=self._reader, name="airc-ws", daemon=True).start()
        return self

    def _read(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def _post(self, fn, *a):
        try:
            self._loop.call_soon_threadsafe(fn, *a)
        except RuntimeError:                                # the loop has gone
            pass

    def _reader(self):
        dec = wsock.Decoder(require_mask=False)
        try:
            while True:
                op, data = wsock.read_sync(self._read, dec)
                self.last_heard = time.monotonic()
                if op == wsock.TEXT:
                    try:
                        f = json.loads(data.decode())
                    except ValueError:
                        continue
                    if isinstance(f, dict):
                        self._post(self._deliver, f)
                elif op == wsock.PING:
                    self._write(wsock.PONG, data)
                elif op == wsock.CLOSE:
                    break
        except Exception as e:  # noqa: BLE001
            if not self.closed:
                self._post(self._frames.put_nowait, {"t": "error", "code": "socket", "reason": str(e) or type(e).__name__})
        finally:
            if self.hc._ws is self:
                self.hc._ws = None
            self._post(self._frames.put_nowait, None)

    def _deliver(self, f: dict):
        fut = self._pending.pop(f.get("rid"), None) if isinstance(f.get("rid"), str) else None
        if fut is not None:
            if not fut.done():
                fut.set_result(f)
        else:
            self._frames.put_nowait(f)

    def _write(self, op: int, data):
        with self._wlock:
            self.sock.sendall(wsock.encode(op, data, mask=True))

    async def request(self, frame: dict, timeout: float = 30) -> dict:
        """Send a frame that has a reply (send, acks, ping) and wait for it."""
        rid = secrets.token_hex(6)
        fut = asyncio.get_running_loop().create_future()
        self._pending[rid] = fut
        try:
            await asyncio.get_running_loop().run_in_executor(None, self._write, wsock.TEXT, json.dumps(dict(frame, rid=rid), separators=(",", ":"), ensure_ascii=False))
            r = await asyncio.wait_for(fut, timeout)
        finally:
            self._pending.pop(rid, None)
        if r.get("t") == "error":
            raise HttpClientError(f"{r.get('code')}: {r.get('reason')}")
        return r

    async def send(self, to: str, body: str, *, frm: str, mtype: str = "text/plain", re_id: str | None = None,
                   ttl: int | None = None, hdr: dict | None = None) -> dict:
        """A message over the socket; its ack. Files (§22) still go by POST /send."""
        m = wire.new_msg(frm, to, body, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)
        return (await self.request({"t": "send", "msg": m})).get("ack", {})

    async def ack(self, msg_id: str, status: str = "delivered", reason: str = "", code: str | None = None, by: str | None = None) -> int:
        return int((await self.request({"t": "acks", "list": [wire.ack(msg_id, status, reason, code, by)]})).get("n", 0))

    async def frames(self) -> AsyncIterator[dict]:
        """Server frames that are not replies: welcome, msg, inbox, displaced, ping. Ends when the socket
        closes or goes silent; raises HttpClientError on a socket error."""
        while True:
            try:
                f = await asyncio.wait_for(self._frames.get(), max(1.0, self.SILENCE - (time.monotonic() - self.last_heard)))
            except asyncio.TimeoutError:
                if time.monotonic() - self.last_heard >= self.SILENCE:
                    raise HttpClientError(f"the socket was silent for {self.SILENCE:g} s")
                continue
            if f is None:
                return
            if f.get("t") == "error" and f.get("code") == "socket":
                raise HttpClientError(f"socket: {f.get('reason')}")
            yield f

    async def close(self):
        if self.hc._ws is self:
            self.hc._ws = None
        if self.closed:
            return
        self.closed = True
        try:
            self._write(wsock.CLOSE, struct.pack(">H", 1000))
        except Exception:  # noqa: BLE001
            pass
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.sock.close()
        except Exception:  # noqa: BLE001
            pass


class HttpRelaySession:
    """Adapter so relay.Relay can run over the HTTPS binding: same bind() /
    serve(handler) / realm / close() surface as client.Client."""

    def __init__(self, hc: HttpClient):
        self.hc = hc
        self.closed = False
        self.bound: list[str] = []                          # what this session holds, as the server wrote it
        self._recent: list[str] = []                        # ids handled lately: a pushed copy and the backlog may overlap
        self._ws: WsSocket | None = None                    # the open WebSocket, when serve() holds one: acks go up it

    @property
    def realm(self):
        return self.hc.realm

    async def keys_get(self, endpoint):
        return await self.hc.keys_get(endpoint)

    async def keys_publish(self, record):
        return await self.hc.keys_publish(record)

    async def profile_publish(self, record):
        return await self.hc.profile_publish(record)

    async def profile_status(self, statuses):
        return await self.hc.profile_status(statuses)

    async def send(self, to: str, body: str, *, frm: str, mtype: str = "text/plain", re_id: str | None = None,
                   ttl: int | None = None, hdr: dict | None = None) -> dict:
        """A message from this relay's side (a receipt, §6.7): POST /send with the ack as the result."""
        return await self.hc.send(to, body, frm=frm, mtype=mtype, re_id=re_id, ttl=ttl, hdr=hdr)

    async def bind(self, names, take_over: bool = False):
        b = await self.hc.bind(names, mode="push", take_over=take_over)
        self.bound = list(b.get("names", names))
        return self.bound

    async def _drain(self, handler):
        for m in await self.hc.inbox():
            await self._handle(handler, m)
        if self.bound and all(n in self.hc.displaced for n in self.bound):
            raise Displaced(self.bound)

    async def _serve_ws(self, handler, say) -> bool:
        """Hold one WebSocket until it closes: pushes and the backlog come down it, acks go up it, and the
        open socket keeps the lease, so nothing else is asked of the realm. True if it opened."""
        ws = await WsSocket(self.hc).open()
        self._ws = ws
        try:
            say("push: holding the WebSocket")
            async for f in ws.frames():
                t = f.get("t")
                if t == "msg":
                    await self._handle(handler, f)
                elif t == "inbox":                          # more waiting than the socket carried
                    await self._drain(handler)
                elif t == "welcome":
                    self.hc.namespaces = f.get("ns", [])
                elif t == "displaced":
                    self.hc.displaced += [n for n in f.get("names", []) if n not in self.hc.displaced]
                    if self.bound and all(n in self.hc.displaced for n in self.bound):
                        raise Displaced(self.bound)
            return True
        finally:
            self._ws = None
            await ws.close()

    async def serve(self, handler, poll: float = 5.0, on_mode=None):
        """Take messages and ack each. A realm that offers the WebSocket (feature "ws", §3.4.6) gets one socket
        that carries everything and keeps the lease, reopened when it closes. Without it (the realm does not
        list ws, or the socket cannot be opened three times running), poll the inbox every poll seconds.
        on_mode(text) is told which mode is in effect, and why it changed."""
        say = on_mode or (lambda text: None)
        why = "this realm offers no WebSocket"
        if "ws" in self.hc.features:
            fails, ever = 0, False
            while True:
                try:
                    await self._serve_ws(handler, say)
                    ever, fails = True, 0
                    say("push: the WebSocket closed; reopening")
                except Displaced:
                    raise
                except (HttpClientError, OSError, EOFError) as e:
                    fails += 1
                    if fails >= 3 or not ever:
                        why = f"no WebSocket ({str(e)[:80]})"
                        break
                    say(f"push: the WebSocket failed ({str(e)[:80]}); reopening")
                await asyncio.sleep(2 * max(1, fails))
        say(f"polling every {poll:g} s: {why}")
        while True:
            await self._drain(handler)
            await asyncio.sleep(poll)

    async def _handle(self, handler, m):
        if m.get("id") in self._recent:
            return
        self._recent = (self._recent + [m.get("id")])[-500:]
        try:
            m = await self.hc.fetch_bin(m)
        except (HttpClientError, wire.WireError) as e:
            self._recent.remove(m.get("id"))                  # try again on the next check
            log.warning("binary section of %s not fetched: %s", m.get("id"), e)
            return
        try:
            r = await handler(m)
        except Exception as e:  # noqa: BLE001
            r = ("failed", f"handler error: {e}")
        if r is None:
            await self._ack(m["id"])
        elif isinstance(r, str):
            await self._ack(m["id"], r)
        else:
            await self._ack(m["id"], r[0], r[1] if len(r) > 1 else "", r[2] if len(r) > 2 else None, r[3] if len(r) > 3 else None)

    async def _ack(self, msg_id, status="delivered", reason="", code=None, by=None):
        """Over the open WebSocket when there is one, else POST /ack."""
        ws = self._ws
        if ws is not None and not ws.closed:
            try:
                await ws.ack(msg_id, status, reason, code, by)
                return
            except (HttpClientError, OSError, asyncio.TimeoutError):
                pass
        await self.hc.ack(msg_id, status, reason, code, by)

    async def close(self):
        if not self.closed:
            try:
                if self.bound:
                    await self.hc.release()
            finally:
                self.closed = True
                await self.hc.close()


class HttpCliSession(HttpRelaySession):
    """The CLI's commands over the HTTPS binding (--server): the same surface as client.Client where
    the binding has it (link, passport, keys, profiles, bind/serve). Local-server reports (status,
    events stream) are not offered and say so."""

    features = ("keys", "profile")

    def __init__(self, hc: HttpClient, ns: str):
        super().__init__(hc)
        self.ns = ns
        self.namespaces = [ns]

    def absolute(self, addr: str) -> str:
        from . import address as A
        return str(A.parse(addr, self.realm, self.ns))

    async def _call(self, fn, *a, **kw) -> dict:
        try:
            return await fn(*a, **kw)
        except HttpClientError as e:
            return {"ok": False, "reason": str(e)}

    async def link(self, op, **fields):
        return await self._call(self.hc.link, op, **fields)

    async def passport(self, op, **fields):
        return await self._call(self.hc.passport, op, **fields)

    async def profile_get(self, endpoint):
        return await self.hc.profile_get(endpoint)

    async def profile_delete(self, endpoint):
        return await self.hc.profile_delete(endpoint)

    async def channel_close(self, endpoint):
        return await self.hc.channel_close(endpoint)

    async def bind(self, names, mode: str = "push", take_over: bool = False):
        # push: the realm sends each new message down this session's WebSocket (through Fanout on
        # airc.dev); a realm without one keeps them queued, and serve() polls
        b = await self.hc.bind(names, mode=mode, take_over=take_over)
        self.bound = list(b.get("names", names))
        return self.bound

    async def stats(self):
        raise HttpClientError("not available over HTTPS: it reports on a local aircd (drop --server)")

    async def subscribe(self, kinds=None):
        raise HttpClientError("the live event stream is not available over HTTPS; use GET /airc/v0/events")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.close()

