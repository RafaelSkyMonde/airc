# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""The HTTPS binding (spec §3.4): the same frames, one per request.

Server side (HttpFace): a minimal HTTP/1.1 listener on the server's asyncio
loop, no dependencies. Routes:

  GET  /.well-known/airc?nonce=          signed capabilities document
  GET  /.well-known/did.json             the realm's DID document (§24.1)
  GET  /<ns>/<agent>/did.json            an endpoint's DID document from its key record (§24.2)
  POST /airc/v0/msg                      peer face: one msg -> one ack
  POST /airc/v0/send                     client: one msg -> one ack
  POST /airc/v0/bind                     client: names + delivery mode (push|webhook|pull)
  GET  /airc/v0/inbox?max=               client: queued messages, oldest first, not removed
  POST /airc/v0/ack                      client: list of acks
  GET  /airc/v0/ws                       client: WebSocket, push plus send/ack (§3.4.6)
  POST /airc/v0/link, /airc/v0/passport  client: the frames unchanged
  GET  /airc/v0/events?since=&kinds=     client: audit tail for its namespaces

Client requests carry  Authorization: AIRC-Key <kid>:<ts>:<nonce>:<sig>
(signing.canonical_client_request), verified against the realm's
client_keys table {kid: {"pub": <b64>, "ns": [...]}}.

Outbound (HttpPeerLink): a peer reachable over HTTPS looks to the router
like any other link: send() POSTs the frame and feeds the returned ack back
through the server's pending table. Before the first message the peer's
capabilities document is fetched with a fresh nonce and verified.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import re
import ssl
import time
import urllib.parse
import urllib.request
import urllib.error

from . import PROTO, __version__
from . import address as A
from . import signing as S
from . import wire
from . import wsock
from . import did as DID
from . import cards as CARDS
from . import __spec_draft__ as SPEC_DRAFT

log = logging.getLogger("aircd.http")

MAX_BODY = wire.MAX_FRAME + wire.MAX_BIN + 1
WS_PING = 25.0                 # the server pings a WebSocket after this long without other traffic (§3.4.6)
CAPS_TTL = 3600.0
LEASE = 300.0                  # an HTTPS session's binds stay live this long after its last signed request (§4.3.1)
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}\Z")


def op_of(path: str) -> str:
    return path[len("/airc/v0/"):] if path.startswith("/airc/v0/") else ""


# §3.4 / §14.2: a non-200 response's body is an error frame whose code explains its status; these
# are the codes the hosted realm (src/aircd_edge) uses for each status, so both answer alike
STATUS_CODES = {400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
                413: "frame_too_large", 415: "bin_unsupported", 429: "rate_limited", 501: "not_implemented",
                503: "unavailable"}


class HttpError(Exception):
    def __init__(self, status: int, reason: str, code: str | None = None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.code = code or STATUS_CODES.get(status, "bad_request")


# --------------------------------------------------------------------------- conns
class NullConn:
    closed = False

    async def send(self, frame):
        raise wire.WireError("closed", "no connection")

    async def close(self):
        pass

    def peer_uid(self):
        return None


class WsConn:
    """A client's open WebSocket (§3.4.6): each frame one text message."""

    def __init__(self, writer: asyncio.StreamWriter, bins: dict | None = None, kid: str = ""):
        self.writer = writer
        self.closed = False
        self._lock = asyncio.Lock()
        self.bins, self.kid = bins if bins is not None else {}, kid
        self.last_write = time.time()

    async def send(self, frame: dict):
        if self.closed:
            raise wire.WireError("closed")
        if "_bin" in frame:                                    # text only: the client fetches the section
            self.bins[frame["id"]] = (self.kid, frame["_bin"])
            frame = wire.strip(frame)
        await self.write(wsock.TEXT, json.dumps(frame, separators=(",", ":"), ensure_ascii=False))

    async def write(self, op: int, data):
        async with self._lock:
            self.writer.write(wsock.encode(op, data, mask=False))
            await self.writer.drain()
        self.last_write = time.time()

    async def close(self):
        if not self.closed:
            try:
                await asyncio.wait_for(self.write(wsock.CLOSE, b"\x03\xe8"), 2)
            except Exception:
                pass
        self.closed = True
        try:
            self.writer.close()
        except Exception:
            pass

    def peer_uid(self):
        return None


class WebhookConn:
    """Delivery by POSTing the message to the client's URL; its response is the ack."""

    def __init__(self, server, url: str, signer):
        self.server = server
        self.url = url
        self.signer = signer
        self.closed = False

    async def send(self, frame: dict):
        if self.signer and not (frame.get("hdr") or {}).get("sig"):
            self.signer.sign_message(frame)
        try:
            ack = await _post_json(self.url, frame, insecure=self.server.cfg.get("tls", {}).get("insecure_skip_verify"))
        except (OSError, ValueError) as e:
            raise wire.WireError("closed", f"webhook {self.url}: {e}")
        if isinstance(ack, dict) and ack.get("t") == "ack":
            self.server._on_ack(ack)

    async def close(self):
        self.closed = True

    def peer_uid(self):
        return None


class HttpPeerLink:
    """A remote realm reached over its HTTPS peer face. Quacks like Link."""

    def __init__(self, server, realm: str, base_url: str):
        self.server = server
        self.realm = realm
        self.base_url = base_url.rstrip("/")
        self.kind = "peer"
        self.authenticated = False
        self.outbound = True
        self.subscriber = None
        self.binds = []
        self.namespaces = []
        self.uid = None
        self.agent = "https"
        self.last_activity = time.time()
        self.conn = self
        self.closed = False
        self._verified_at = 0.0
        self.error = ""                                         # why verify() last failed, for the sender's queued ack
        self.features: list[str] = []                           # from its capabilities: no "bin", no binary sections (§22)

    async def verify(self) -> bool:
        """Fetch and verify the capabilities document (cached CAPS_TTL)."""
        if time.time() - self._verified_at < CAPS_TTL:
            return True
        if self.server._peer_trusted_unsigned(self.realm):
            self.features = ["bin"]                             # a configured, trusted peer: assume it takes sections
            self.authenticated = True
            self._verified_at = time.time()
            return True
        nonce = os.urandom(12).hex()
        try:
            doc = await _get_json(f"{self.base_url}/.well-known/airc?nonce={nonce}",
                                  insecure=self.server.cfg.get("tls", {}).get("insecure_skip_verify"))
            keys = await self.server.resolver.public_keys(self.realm)
        except (OSError, ValueError, S.SigningUnavailable) as e:
            log.warning("capabilities of %s unavailable: %s", self.realm, e)
            self.error = f"capabilities fetch: {e}"
            return False
        if not keys or not S.verify_capabilities(doc, self.realm, nonce, keys, accept=self.server.signing_cfg["accept_algs"]):
            log.warning("capabilities of %s did not verify", self.realm)
            self.error = "capabilities did not verify against the _airc TXT key" if keys else "no _airc TXT key in DNS"
            return False
        self.features = list(doc.get("features") or [])
        self.authenticated = True
        self._verified_at = time.time()
        return True

    async def send(self, frame: dict):
        self.last_activity = time.time()
        try:
            ack = await _post_json(f"{self.base_url}/airc/v0/msg", frame,
                                   insecure=self.server.cfg.get("tls", {}).get("insecure_skip_verify"))
        except (OSError, ValueError) as e:
            raise wire.WireError("closed", f"https peer {self.realm}: {e}")
        if isinstance(ack, dict) and ack.get("t") == "ack":
            self.server._on_ack(ack)

    async def close(self):
        self.closed = True

    def peer_uid(self):
        return None

    def __repr__(self):
        return f"<https-peer {self.realm} {self.base_url}>"


def _ctx(insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _post_json(url: str, obj, headers: dict | None = None, insecure=False, timeout=20) -> dict:
    framed = isinstance(obj, dict) and "_bin" in obj            # a msg with a binary section (§22)
    body = wire.frame_bytes(obj) if framed else json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/airc-frame" if framed else "application/json", **(headers or {})})
    return await asyncio.get_running_loop().run_in_executor(None, lambda: _do(req, insecure, timeout))


async def _get_json(url: str, headers: dict | None = None, insecure=False, timeout=20) -> dict:
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    return await asyncio.get_running_loop().run_in_executor(None, lambda: _do(req, insecure, timeout))


# Outbound requests name themselves: urllib's default "Python-urllib/3.x" is refused by Cloudflare's
# browser-integrity check (403 "error code: 1010"), so a realm behind Cloudflare looked unreachable.
USER_AGENT = f"aircd/{__version__}"


RESPONSE_MAX = 64 * 1024     # S7: what a peer's control document, ack or key record may be; more is refused


def _read_capped(r, limit: int) -> bytes:
    data = r.read(limit + 1)
    if len(data) > limit:
        raise OSError(f"response larger than {limit} bytes")
    return data


def _do(req, insecure, timeout, limit: int = RESPONSE_MAX):
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx(insecure) if req.full_url.startswith("https") else None) as r:
            return wire.loads(_read_capped(r, limit).decode() or "null")
    except urllib.error.HTTPError as e:
        body = _read_capped(e, limit).decode("utf-8", "replace")
        try:
            return wire.loads(body)
        except ValueError:
            raise OSError(f"HTTP {e.code}" + (f" {body[:60].strip()!r}" if body.strip() else ""))
    except UnicodeDecodeError as e:
        raise OSError(f"response is not text: {e}")


# --------------------------------------------------------------------------- server
class HttpClientLink:
    """One session of a remote client (key-authenticated, spec §4.3.1). Registered in server.clients
    while it has binds. Live while it holds a WebSocket, has a webhook, or made a signed request within
    LEASE; with no socket or webhook to push to it is queue_only, and its messages wait for /inbox."""

    def __init__(self, kid: str, namespaces: list[str], binds: list[str], conn, session: str = ""):
        self.session = session or f"key:{kid}"
        self.last_seen = time.time()
        self.mode = "pull"
        self.webhook = None
        self.displaced: list[str] = []
        self.kid = kid
        self.kind = "client"
        self.uid = None
        self.namespaces = namespaces
        self.binds = list(binds)
        self.conn = conn
        self.realm = None
        self.agent = f"https:{kid}"
        self.authenticated = True
        self.outbound = False
        self.subscriber = None
        self.last_activity = time.time()

    @property
    def live(self) -> bool:
        if isinstance(self.conn, WebhookConn) or (isinstance(self.conn, WsConn) and not self.conn.closed):
            return True
        return time.time() - self.last_seen <= LEASE

    @property
    def queue_only(self) -> bool:
        return not isinstance(self.conn, (WsConn, WebhookConn)) or self.conn.closed

    def __repr__(self):
        return f"<https-client {self.kid} session={self.session[:10]} ns={self.namespaces} binds={self.binds}>"


class HttpFace:
    def __init__(self, server):
        self.server = server
        self.servers = []
        self.state_path = os.path.join(server.state_dir, "http_clients.json")
        self.records: dict[str, dict] = {}       # session -> {"kid", "names": [...], "mode", "webhook", "updated"}
        self.sessions: dict[str, HttpClientLink] = {}
        self.inflight_bins: dict[str, tuple[str, bytes]] = {}  # msg id -> (kid, section) pushed over a WebSocket, until acked
        self._nonces: dict[str, dict[str, float]] = {}
        self._load()

    # --- persistence -------------------------------------------------------
    def _load(self):
        try:
            doc = json.load(open(self.state_path))
        except (OSError, ValueError):
            doc = {}
        self.records = doc.get("sessions", {})
        for kid, rec in (doc.get("clients") or {}).items():      # before sessions: one record per key
            self.records.setdefault(f"key:{kid}", {**rec, "kid": kid})

    def _save(self):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"sessions": self.records}, f, indent=1)
        os.replace(tmp, self.state_path)

    def restore_webhooks(self):
        """Sessions survive a restart: each recorded one comes back with its binds, and its lease runs
        from now (a webhook session is live until it rebinds or releases)."""
        for sid, rec in self.records.items():
            kid = rec.get("kid")
            if kid in self.server.client_keys and rec.get("names"):
                link = self._session(sid, kid)
                self._apply(link, rec)

    def _session(self, sid: str, kid: str) -> HttpClientLink:
        link = self.sessions.get(sid)
        if link is None:
            link = HttpClientLink(kid, list(self.server.client_keys[kid]["ns"]), [], NullConn(), sid)
            self.sessions[sid] = link
        return link

    def _apply(self, link: HttpClientLink, rec: dict):
        """Set a session's binds and delivery from its record, and (un)register it with the server."""
        link.binds = self._abs_binds(rec.get("names") or [])
        link.mode = rec.get("mode", "pull")
        link.webhook = rec.get("webhook")
        if link.mode == "webhook" and link.webhook:
            link.conn = WebhookConn(self.server, link.webhook, self.server.signer)
        elif isinstance(link.conn, WebhookConn):
            link.conn = NullConn()
        clients = self.server.clients
        if link.binds and link not in clients:
            clients.append(link)
        elif not link.binds and link in clients:
            clients.remove(link)

    def _prune(self):
        """Forget sessions idle for a day with no webhook: their binds lapsed long ago."""
        now = time.time()
        for sid, link in list(self.sessions.items()):
            if not link.live and now - link.last_seen > 86400:
                del self.sessions[sid]
                self.records.pop(sid, None)
                if link in self.server.clients:
                    self.server.clients.remove(link)

    def _abs_binds(self, names):
        return ["//" + self.server.realm + "/" + n.lower().strip("/") + ("/" if n.endswith("/") else "") for n in names]

    # --- listener ----------------------------------------------------------
    async def start(self, spec: str, ssl_ctx):
        host, port = self.server._hostport(spec, 443 if ssl_ctx else 80)
        s = await asyncio.start_server(self._connection, host, port, ssl=ssl_ctx, limit=wire.STREAM_LIMIT)
        self.servers.append(s)
        log.info("https face on %s:%d (%s)", host, port, "tls" if ssl_ctx else "PLAINTEXT")

    async def stop(self):
        for s in self.servers:
            s.close()
        for l in list(self.sessions.values()):
            if isinstance(l.conn, WsConn):
                await l.conn.close()

    async def _connection(self, reader, writer):
        try:
            try:
                method, path, headers, body = await asyncio.wait_for(self._read_request(reader), 30)
            except asyncio.TimeoutError:
                return
            except HttpError as e:
                await self._respond(writer, e.status, {"t": "error", "code": e.code, "reason": e.reason})
                return
            if method is None:
                return
            try:
                await self._dispatch(method, path, headers, body, writer, reader)
            except HttpError as e:
                await self._respond(writer, e.status, {"t": "error", "code": e.code, "reason": e.reason})
            except Exception as e:
                log.exception("http %s %s", method, path)
                await self._respond(writer, 500, {"t": "error", "code": "server_error", "reason": str(e)})
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _read_request(self, reader):
        line = await reader.readline()
        if not line:
            return None, None, None, None
        try:
            method, target, _version = line.decode().split()
        except ValueError:
            raise HttpError(400, "bad request line")
        headers = {}
        while True:
            h = await reader.readline()
            if h in (b"\r\n", b"\n", b""):
                break
            k, _, v = h.decode(errors="replace").partition(":")
            headers[k.strip().lower()] = v.strip()
        length = int(headers.get("content-length", "0") or 0)
        if length > MAX_BODY:
            if length <= 2 * MAX_BODY:                  # read and drop it, so the client sees the 413 rather than a reset
                while length > 0:
                    chunk = await reader.read(min(length, 1 << 16))
                    if not chunk:
                        break
                    length -= len(chunk)
            raise HttpError(413, "body too large", "frame_too_large")
        body = await reader.readexactly(length) if length else b""
        return method.upper(), target, headers, body

    async def _respond(self, writer, status: int, obj, ctype="application/json", extra: dict | None = None):
        data = obj if isinstance(obj, (bytes, bytearray)) else json.dumps(obj, ensure_ascii=False).encode()
        reason = {200: "OK", 204: "No Content", 302: "Found", 502: "Bad Gateway", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 409: "Conflict",
                  413: "Payload Too Large", 415: "Unsupported Media Type", 429: "Too Many Requests", 500: "Internal Server Error", 503: "Service Unavailable"}.get(status, "OK")
        head = [f"HTTP/1.1 {status} {reason}", f"Content-Type: {ctype}", f"Content-Length: {len(data)}",
                "Connection: close", f"Server: aircd/{__version__}"]
        for k, v in (extra or {}).items():
            head.append(f"{k}: {v}")
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode() + data)
        await writer.drain()

    # --- auth ---------------------------------------------------------------
    def _authenticate(self, headers, method, path, body) -> HttpClientLink:
        auth = headers.get("authorization", "")
        parsed = S.parse_client_auth(auth)
        if not parsed:
            raise HttpError(401, "missing or malformed Authorization: AIRC-Key")
        kid, ts, nonce, _sig = parsed
        rec = self.server.client_keys.get(kid)
        if not rec:
            raise HttpError(401, f"unknown key {kid}")
        try:
            ok = S.verify_client_request(auth, self.server.realm, method, path, body, rec["pub"], self.server.signing_cfg["hello_skew"])
        except S.SigningUnavailable as e:
            raise HttpError(503, str(e))
        if not ok:
            raise HttpError(401, "signature did not verify")
        seen = self._nonces.setdefault(kid, {})
        now = time.time()
        for n, t in list(seen.items()):
            if now - t > 600:
                del seen[n]
        if nonce in seen:
            raise HttpError(401, "nonce replayed")
        seen[nonce] = now
        sid = headers.get("airc-session") or f"key:{kid}"
        if not sid.startswith("key:") and not SESSION_RE.match(sid):
            raise HttpError(400, "AIRC-Session must be 16 to 64 characters of A-Z a-z 0-9 _ -")
        link = self.sessions.get(sid)
        if link is not None and link.kid != kid:
            raise HttpError(403, "that session belongs to another key")
        link = link or HttpClientLink(kid, list(rec["ns"]), [], NullConn(), sid)   # registered on its first bind
        link.namespaces = list(rec["ns"])
        link.last_seen = now
        return link

    # --- routes ---------------------------------------------------------------
    def _trusted_proxy(self, addr) -> bool:
        import ipaddress
        try:
            ip = ipaddress.ip_address(str(addr).strip().strip("[]"))
        except ValueError:
            return False
        for p in (self.server.cfg.get("http") or {}).get("trusted_proxies", ["127.0.0.1", "::1"]):
            try:
                if ip in ipaddress.ip_network(str(p), strict=False):
                    return True
            except ValueError:
                continue
        return False

    ADMIN_NETWORKS = ["127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]

    @property
    def admin_token(self) -> str:
        """The form token the status page's buttons carry; new at every server start."""
        t = getattr(self, "_admin_token", None)
        if not t:
            import secrets
            t = self._admin_token = secrets.token_urlsafe(18)
        return t

    def admin_allowed(self, addr) -> bool:
        """May this client see /admin? admin.networks (default: loopback and private ranges); [] turns the page off."""
        import ipaddress
        nets = (self.server.cfg.get("admin") or {}).get("networks", self.ADMIN_NETWORKS)
        try:
            ip = ipaddress.ip_address(str(addr or "").strip().strip("[]"))
        except ValueError:
            return False
        for n in nets or []:
            try:
                if ip in ipaddress.ip_network(str(n), strict=False):
                    return True
            except ValueError:
                continue
        return False

    def client_address(self, peer: str | None, xff: str | None) -> str | None:
        """The client's address: the direct peer, unless that is a trusted proxy (http.trusted_proxies,
        default loopback), in which case the rightmost X-Forwarded-For entry that is not itself one."""
        if not peer or not self._trusted_proxy(peer) or not xff:
            return peer
        import ipaddress
        for hop in reversed([h.strip() for h in str(xff).split(",") if h.strip()]):
            try:
                ipaddress.ip_address(hop.strip("[]"))
            except ValueError:
                return peer                              # a malformed entry: trust nothing further left
            if not self._trusted_proxy(hop):
                return hop.strip("[]")
        return peer

    def cards_cfg(self) -> dict:
        c = self.server.cfg.get("cards")
        return c if isinstance(c, dict) else {}

    def cards_on(self) -> bool:
        """§21.5 cards are served when the realm has a signing key, unless the config says `"cards": {"enabled": false}`."""
        return bool(self.server.signer) and self.cards_cfg().get("enabled", True) is not False

    async def _respond_card(self, writer, card: dict):
        srv = self.server
        kid_did = DID.web_did(self.did_host()) + "#airc"
        signed = CARDS.sign_card(card, lambda data: base64.b64decode(srv.signer.sign(data)), kid_did)
        return await self._respond(writer, 200, signed, CARDS.MEDIA_TYPE, {"Cache-Control": "public, max-age=3600"})

    def did_host(self) -> str:
        """§24.1: the host of this realm's did:web, the HTTPS host the server is configured to serve (passports.host
        is that host, docs/operations.md); the realm name when the config gives none."""
        host = str((self.server.cfg.get("passports") or {}).get("host") or "").strip().lower()
        return host or self.server.realm

    def realm_keys(self) -> list[tuple[str, str]]:
        """(kid, base64 public key) for every key this realm publishes in its _airc TXT record: the signer and,
        during a rotation, the extra signers (signing.extra_keys)."""
        srv = self.server
        if not srv.signer:
            return []
        out = [(srv.signer.kid, srv.signer.public_b64)]
        for sg in getattr(srv, "extra_signers", None) or []:
            if sg.kid not in [k for k, _p in out]:
                out.append((sg.kid, sg.public_b64))
        return out

    async def _dispatch(self, method, target, headers, body, writer, reader=None):
        url = urllib.parse.urlsplit(target)
        path, q = url.path, urllib.parse.parse_qs(url.query)
        srv = self.server

        def jbody():
            if headers.get("content-type", "").startswith("application/airc-frame"):
                try:
                    return wire.parse_frame_bytes(body)           # a frame with its binary section (§22)
                except wire.WireError as e:
                    if e.code != "bad_bin":
                        raise HttpError(400, e.reason or e.code)
                    try:                                          # a section that does not match: a failed ack, not an HTTP error
                        frame = wire.decode(body.partition(b"\n")[0])
                    except wire.WireError:
                        raise HttpError(400, e.reason or e.code)
                    frame["_bad_bin"] = e.reason or "the binary section does not match bin / bin_sha256"
                    return frame
            try:
                obj = wire.loads(body.decode()) if body else {}
            except (ValueError, UnicodeDecodeError):
                raise HttpError(400, "body is not JSON")
            if isinstance(obj, dict):                      # internal keys (_bin, _bad_bin) never come from the wire
                for k in [k for k in obj if isinstance(k, str) and k.startswith("_")]:
                    del obj[k]
            return obj

        if method == "GET" and path == "/.well-known/airc":
            nonce = (q.get("nonce") or [""])[0][:128]
            ts = int(time.time())
            doc = {"t": "capabilities", "realm": srv.realm, "proto": PROTO, "bindings": ["https"] + (["stream"] if srv.cfg.get("peer_listen") else []),
                   "kids": [k for k, _p in self.realm_keys()], "nonce": nonce, "ts": ts, "server": f"aircd/{__version__}",
                   "features": ["keys", "profile", "leases", "bin", "ws"]}
            if srv.signer:
                doc["did"] = DID.web_did(self.did_host())                    # §24: this realm's DID; its document is below
                doc["features"].append("did")
                if self.cards_on():
                    doc["features"].append("cards")                           # §21.5: /.well-known/agent-card.json
                doc["sig"] = srv.signer.sign_capabilities(srv.realm, nonce, ts)
            return await self._respond(writer, 200, doc)

        if method == "GET" and path == CARDS.CARD_PATH:
            # §21.5: the realm's Agent Card, signed with the realm key under its DID
            if not self.cards_on():
                raise HttpError(404, "this realm serves no agent cards")
            from . import __version__ as _ver
            card = CARDS.realm_card(srv.realm, self.did_host(), SPEC_DRAFT, f"aircd/{_ver}", self.cards_cfg())
            return await self._respond_card(writer, card)

        if method == "GET" and path.endswith("/agent-card.json") and not path.startswith("/airc/") and not path.startswith("/.well-known/"):
            # §21.5: an endpoint's card, for every endpoint that has an address page (a profile or a key record)
            if not self.cards_on():
                raise HttpError(404, "this realm serves no agent cards")
            segs = [x for x in urllib.parse.unquote(path[:-len("/agent-card.json")]).split("/") if x]
            if len(segs) < 2:
                raise HttpError(404, "not found")
            try:
                addr = A.parse("//" + srv.realm + "/" + "/".join(segs))
            except A.AddressError:
                raise HttpError(404, "not found")
            if addr.is_reserved:
                raise HttpError(404, "not found")
            prof = srv.profile_get(addr.key)
            krec = srv.e2e_keys.get(addr.key)
            if not prof and not (krec and krec.get("ik")):
                raise HttpError(404, "no such agent is listed here")
            from . import __version__ as _ver
            card = CARDS.endpoint_card(srv.realm, self.did_host(), addr.path[0], "/".join(addr.path[1:]), prof, krec,
                                       SPEC_DRAFT, f"aircd/{_ver}", self.cards_cfg())
            return await self._respond_card(writer, card)

        if method == "GET" and path == "/.well-known/did.json":
            # §24.1: the realm's DID document, every _airc TXT key as a Multikey; a realm without a key has no DID
            if not srv.signer:
                raise HttpError(404, "this realm publishes no signing key")
            doc = DID.realm_document(srv.realm, self.did_host(), self.realm_keys(), srv.signer.kid)
            return await self._respond(writer, 200, doc, "application/did+json", {"Cache-Control": "public, max-age=3600"})

        if method == "GET" and path.endswith("/did.json") and not path.startswith("/airc/") and not path.startswith("/.well-known/"):
            # §24.2: an endpoint's DID document from its current key record (§19.2); no record, no document
            segs = [x for x in urllib.parse.unquote(path[:-len("/did.json")]).split("/") if x]
            if len(segs) < 2 or not srv.signer:
                raise HttpError(404, "not found")
            try:
                addr = A.parse("//" + srv.realm + "/" + "/".join(segs))
            except A.AddressError:
                raise HttpError(404, "not found")
            rec = srv.e2e_keys.get(addr.key) if not addr.is_reserved else None
            if not rec or not rec.get("ik"):
                raise HttpError(404, "no key record")
            doc = DID.endpoint_document(srv.realm, self.did_host(), addr.path[0], "/".join(addr.path[1:]), rec)
            return await self._respond(writer, 200, doc, "application/did+json", {"Cache-Control": "public, max-age=3600"})

        if method == "POST" and path == "/airc/v0/msg":
            msg = jbody()
            if not isinstance(msg, dict) or msg.get("t") != "msg":
                raise HttpError(400, "expected a msg frame")
            if "_bad_bin" in msg:
                return await self._respond(writer, 200, wire.ack(str(msg.get("id", "?")), "failed", msg["_bad_bin"], "bad_bin"))
            try:
                from .links import parse_side            # a link control may come from a realm side (§11.1)
                origin_realm = parse_side(str(msg.get("from", ""))).realm
            except A.AddressError as e:
                return await self._respond(writer, 200, wire.ack(str(msg.get("id", "?")), "failed", f"bad address: {e}", "bad_address", srv.resolver_uri))
            origin = HttpPeerLink(srv, origin_realm, "")
            origin.outbound = False
            a = await srv.route(msg, origin)
            if a["status"] == "failed" and not a.get("_emitted"):
                srv._emit_msg(msg, a, origin)
            a.pop("_emitted", None)
            return await self._respond(writer, 200, a)

        if method == "GET" and path in ("/airc/v0/login/oauth", "/airc/v0/login/oauth/callback"):
            # §11.6: the OAuth login a challenge points at (only where offers.challenge is configured)
            if srv.challenges is None or not srv.challenges.oauth:
                raise HttpError(404, "no OAuth login here", "not_found")
            if path.endswith("/callback"):
                st, page = await srv.challenges.oauth_callback(q)
                return await self._respond(writer, st, page.encode(), "text/html; charset=utf-8",
                                           {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
            st, where = srv.challenges.oauth_start((q.get("c") or [""])[0])
            if st == 302:
                return await self._respond(writer, 302, b"", "text/plain", {"Location": where, "Cache-Control": "no-store"})
            return await self._respond(writer, st, where.encode(), "text/plain; charset=utf-8")

        if method == "GET" and path == "/airc/v0/keys":
            # §19.3: anyone may fetch this realm's key records; an authenticated client may also ask
            # for another realm's (we fetch it), others may not use us as a proxy
            ep = (q.get("endpoint") or [""])[0]
            authed = bool(headers.get("authorization"))
            if authed:
                self._authenticate(headers, method, path, body)
            rec, why = await srv.e2e_get(ep, remote_ok=authed)
            if rec is None:
                raise HttpError(404, why or "no key record")
            return await self._respond(writer, 200, rec)

        if method == "GET" and path == "/airc/v0/profile":
            ep = (q.get("endpoint") or [""])[0]
            rec = srv.profile_get(ep)                                    # §21.1: public, this realm only
            try:
                st = srv.status_of(A.parse(ep).key)
            except A.AddressError:
                st = None
            if rec is None and st is None:
                raise HttpError(404, "no profile")
            out = {k: v for k, v in (rec or {"t": "profile", "endpoint": ep}).items() if k != "image"}
            if st:
                out["status"], out["status_age"] = st
            try:
                krec = srv.e2e_keys.get(A.parse(ep).key)
            except A.AddressError:
                krec = None
            if krec and krec.get("ik"):
                out["did"] = DID.did_key(krec["ik"])                        # §24.2: the identity key as did:key
            return await self._respond(writer, 200, out)

        if method == "GET" and path == "/airc/v0/profile/image":
            from . import profile as PR
            rec = srv.profile_get((q.get("endpoint") or [""])[0])
            img = PR.image_bytes(rec.get("image")) if rec else None
            if img is None:
                raise HttpError(404, "no image")
            return await self._respond(writer, 200, img[1], img[0], {"X-Content-Type-Options": "nosniff", "Cache-Control": "public, max-age=3600"})

        if path in ("/admin", "/admin.json", "/admin/action"):
            # the operator's status page: links, their use, passports, the policy. Internal networks only (admin.networks).
            pn = writer.get_extra_info("peername")
            who = self.client_address(pn[0] if isinstance(pn, tuple) and pn else None, headers.get("x-forwarded-for"))
            if not self.admin_allowed(who):
                raise HttpError(404, "not found")
            from . import adminpage
            notice = ""
            if path == "/admin/action":
                if method != "POST":
                    raise HttpError(405, "POST")
                form = {k: v[0] for k, v in urllib.parse.parse_qs(body.decode("utf-8", "replace"), max_num_fields=8).items()}
                # a browser on the internal network could be sent here by any page it visits: the form token
                # (per server start, only in our own page) and a matching Origin keep that from doing anything
                origin = headers.get("origin")
                host = (headers.get("host") or "").strip()
                if origin and urllib.parse.urlsplit(origin).netloc.lower() != host.lower():
                    raise HttpError(403, "cross-site")
                if not form.get("token") or form["token"] != self.admin_token:
                    raise HttpError(403, "bad form token")
                ok, why = await srv.admin_action(str(form.get("action") or ""), str(form.get("id") or ""))
                loc = "/admin?" + urllib.parse.urlencode({"ok" if ok else "err": why})
                return await self._respond(writer, 303, b"", "text/plain", {"Location": loc, "Cache-Control": "no-store"})
            if method != "GET":
                raise HttpError(405, "GET")
            view = adminpage.view(srv)
            if path.endswith(".json"):
                return await self._respond(writer, 200, view, extra={"Cache-Control": "no-store"})
            notice = (q.get("ok") or [""])[0], (q.get("err") or [""])[0]
            return await self._respond(writer, 200, adminpage.html(view, token=self.admin_token, notice=notice).encode(),
                                       "text/html; charset=utf-8",
                                       {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
                                        "X-Robots-Tag": "noindex, nofollow", "Content-Security-Policy": adminpage.CSP})

        if method == "GET" and not path.startswith("/airc/") and not path.startswith("/.well-known/"):
            # §21.3: the web page of an address, HTML or (with .md or Accept: text/markdown) markdown
            md = "text/markdown" in headers.get("accept", "")
            p = urllib.parse.unquote(path)
            if p.endswith(".md"):
                md, p = True, p[:-3]
            page = srv.address_page(p)
            if page is None:
                raise HttpError(404, "not found")
            status, text, title = page
            from . import profile as PR
            text = PR.with_credit(text)                 # LICENSE §4: the credit line, in both variants
            if md:
                return await self._respond(writer, status, text.encode(), "text/markdown; charset=utf-8")
            from . import profile as PR
            return await self._respond(writer, status, PR.to_html(text, title, p.rstrip("/") + ".md").encode(), "text/html; charset=utf-8",
                                       {"X-Content-Type-Options": "nosniff", "Content-Security-Policy": PR.PAGE_CSP})

        if not path.startswith("/airc/v0/"):
            raise HttpError(404, "not found")

        link = self._authenticate(headers, method, path, body)
        pn = writer.get_extra_info("peername")
        link.client_ip = self.client_address(pn[0] if isinstance(pn, tuple) and pn else None,
                                             headers.get("x-forwarded-for"))     # §11.6: for the code-send hook

        if method == "POST" and op_of(path) == "profile/status":
            ok, why = srv.status_publish(link, (jbody() or {}).get("statuses"))
            if not ok:
                raise HttpError(400, why)
            return await self._respond(writer, 200, {"t": "profiled", "ok": True, "reason": why})

        if method == "POST" and op_of(path) == "profile":
            ok, why = srv.profile_publish(link, jbody())
            if not ok:
                raise HttpError(400, why)
            return await self._respond(writer, 200, {"t": "profiled", "ok": True, "reason": why})

        if method == "POST" and op_of(path) == "keys":
            ok, why = srv.e2e_publish(link, jbody())
            if not ok:
                raise HttpError(400, why)
            return await self._respond(writer, 200, {"t": "keyed", "ok": True})
        op = path[len("/airc/v0/"):]

        if method == "POST" and op == "send":
            msg = jbody()
            if not isinstance(msg, dict) or msg.get("t") != "msg":
                raise HttpError(400, "expected a msg frame")
            return await self._respond(writer, 200, await self._send_msg(link, msg))

        if method == "POST" and op == "bind":
            b = jbody()
            names = b.get("names") if isinstance(b.get("names"), list) else None
            mode = b.get("mode", "pull")
            if names == []:                                     # release (§4.3.1)
                if link.session in self.sessions:
                    self._apply(link, {"names": []})
                    del self.sessions[link.session]
                    self.records.pop(link.session, None)
                    self._save()
                return await self._respond(writer, 200, {"t": "bound", "names": [], "mode": mode})
            if not names or mode not in ("push", "webhook", "pull"):
                raise HttpError(400, "names (list) and mode push|webhook|pull required")
            if mode == "webhook" and not str(b.get("webhook", "")).startswith(("https://", "http://")):
                raise HttpError(400, "webhook mode needs a webhook URL")
            for n in names:   # same checks as the stream bind
                probe = tuple("x" if s in ("*", "**") else s for s in str(n).lower().strip("/").split("/") if s)
                try:
                    a_ = A.parse("//" + srv.realm + "/" + "/".join(probe))
                except A.AddressError as e:
                    raise HttpError(400, f"{n}: {e}")
                own = str(n).endswith("/") and any(tuple(x.split("/")) == probe for x in link.namespaces)
                if (a_.is_reserved and not srv.allow_reserved_binds) or (not own and not srv._ns_allows(link, probe)):
                    raise HttpError(403, f"{n} is outside your namespaces {link.namespaces}", "outside_namespace")
            from .server import BindHeld
            wanted = self._abs_binds(names)
            try:
                await srv.claim(link, [p for p in wanted if p not in link.binds], bool(b.get("take_over")))
            except BindHeld as e:
                idle = int(time.time() - getattr(e.holder, "last_seen", time.time()))
                return await self._respond(writer, 409, {"t": "error", "error": "name_held", "name": e.pattern, "idle": idle,
                                                         "suggest": e.suggest, "reason": f"{e.pattern} is held by another session"})
            self._prune()
            link = self.sessions.setdefault(link.session, link)
            self.records[link.session] = {"kid": link.kid, "names": names, "mode": mode, "webhook": b.get("webhook"), "updated": time.time()}
            self._save()
            self._apply(link, self.records[link.session])
            for p in link.binds:                           # listening as a closed channel opens it again (§21.4)
                if not p.endswith("/") and "*" not in p:
                    srv.channel_reopen(A.parse(p).key)
            if mode == "webhook":
                for ns in {n.strip("/").split("/")[0] for n in names}:
                    srv._spawn(srv._flush_namespace(ns))
            log.info("https client %s session %s bound %s mode=%s", link.kid, link.session[:10], names, mode)
            out = {"t": "bound", "names": link.binds, "mode": mode}
            if link.displaced:
                out["displaced"], link.displaced = link.displaced, []
            return await self._respond(writer, 200, out)

        if method == "GET" and op == "inbox":
            mx = min(int((q.get("max") or ["50"])[0]), 200)
            out = []
            for ns in link.namespaces:
                for m in srv.spool.peek(ns, mx):
                    try:
                        to = A.parse(m["to"])
                    except A.AddressError:
                        continue
                    if srv._client_for(to) is link:            # the messages this session's live binds win (§4.3)
                        out.append(m)
            out.sort(key=lambda m: m.get("ts", 0))
            doc = {"t": "inbox", "msgs": out[:mx]}
            if link.displaced:
                doc["displaced"], link.displaced = link.displaced, []
            return await self._respond(writer, 200, doc)

        if method == "GET" and op.startswith("bin/"):             # a message's binary section (§22), raw
            mid = urllib.parse.unquote(op[4:])
            held = self.inflight_bins.get(mid)
            if held and held[0] == link.kid:
                return await self._respond(writer, 200, held[1], "application/octet-stream")
            for ns in link.namespaces:
                if any(m.get("id") == mid for m in srv.spool.peek(ns, 1000)):
                    data = srv.spool.bin(mid)
                    if data is not None:
                        return await self._respond(writer, 200, data, "application/octet-stream")
            raise HttpError(404, "no such binary section for you", "not_found")

        if method == "POST" and op == "ack":
            return await self._respond(writer, 200, {"t": "acked", "n": self._ack_list(link, jbody())})

        if method == "GET" and op == "ws":
            if link.session not in self.sessions or not link.binds:
                raise HttpError(400, "bind first")
            return await self._ws(self.sessions[link.session], headers, reader, writer)

        if method == "POST" and op == "link":
            return await self._respond(writer, 200, await srv._on_link_frame(link, jbody()))

        if method == "POST" and op == "passport":
            return await self._respond(writer, 200, await srv._on_passport_frame(link, jbody()))

        if method == "GET" and op == "events":
            from .events import EventLog
            since = float((q.get("since") or ["0"])[0])
            kinds = set((q.get("kinds") or [""])[0].split(",")) - {""}
            prefixes = srv._ns_keys(link) or []
            evs = [e for e in EventLog.tail(srv.events.path, 2000)
                   if e.get("ts", 0) >= since and (not kinds or e["kind"] in kinds or e["kind"].split(".")[0] in kinds)
                   and any(isinstance(e.get(k), str) and any(e[k].startswith(p) for p in prefixes) for k in ("from", "to", "endpoint"))]
            return await self._respond(writer, 200, {"t": "events", "events": evs[-500:]})

        raise HttpError(404, "not found")

    async def _send_msg(self, link: HttpClientLink, msg: dict) -> dict:
        """A client's msg routed (POST /send, or send over the WebSocket): its ack."""
        srv = self.server
        if "_bad_bin" in msg:
            return wire.ack(str(msg.get("id", "?")), "failed", msg["_bad_bin"], "bad_bin")
        a = await srv.route(msg, link)
        if a["status"] == "failed" and not a.get("_emitted"):
            srv._emit_msg(msg, a, link)
        a.pop("_emitted", None)
        return a

    def _ack_list(self, link: HttpClientLink, acks) -> int:
        """Settle an ack or a list of acks (POST /ack, or over the WebSocket); how many settled."""
        srv = self.server
        if isinstance(acks, dict):
            acks = [acks]
        n = 0
        for a in acks or []:
            if not isinstance(a, dict) or not a.get("id"):
                continue
            mid = a["id"]
            self.inflight_bins.pop(mid, None)
            if mid in srv.pending:
                srv._on_ack(a)                      # an in-flight push/webhook delivery
                n += 1
                continue
            for ns in link.namespaces:               # a pulled message
                m = next((x for x in srv.spool.peek(ns, 1000) if x.get("id") == mid), None)
                if m and srv.spool.remove(ns, mid):
                    n += 1
                    st = a.get("status", "delivered")
                    if st != "failed":
                        srv.spool.mark_seen(mid)
                    srv._emit_msg(m, wire.ack(mid, st, a.get("reason", ""), a.get("code"), a.get("by")), None, kind=f"msg.{st}", hop="spool")
                    break
        return n

    async def _ws(self, link: HttpClientLink, headers: dict, reader, writer):
        """GET /airc/v0/ws (§3.4.6): one WebSocket for push, send, ack and ping. The open socket holds the
        session's lease; the server pings it after WS_PING seconds of silence."""
        srv = self.server
        key = headers.get("sec-websocket-key", "")
        if "websocket" not in headers.get("upgrade", "").lower() or not key or reader is None:
            raise HttpError(400, "this path takes a WebSocket")
        writer.write((f"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {wsock.accept_key(key)}\r\nServer: aircd/{__version__}\r\n\r\n").encode())
        await writer.drain()
        conn = WsConn(writer, self.inflight_bins, link.kid)
        if isinstance(link.conn, WsConn):                       # this session's earlier socket: replaced
            await link.conn.close()
        link.conn = conn
        log.info("https client %s session %s socket open %s", link.kid, link.session[:10], link.binds)
        await conn.send({"t": "welcome", "realm": srv.realm, "ns": link.namespaces, "proto": PROTO, "binds": link.binds, "push": "ws"})
        for ns in {b.split("/")[3] for b in link.binds if b.count("/") >= 3}:
            srv._spawn(srv._flush_namespace(ns))

        async def pinger():
            while not conn.closed:
                await asyncio.sleep(max(1.0, WS_PING - (time.time() - conn.last_write)))
                if time.time() - conn.last_write >= WS_PING - 0.5:
                    await conn.send({"t": "ping"})

        async def reply(req: dict, frame: dict):
            if isinstance(req.get("rid"), str):
                frame["rid"] = req["rid"]
            await conn.send(frame)

        async def on_text(data: bytes):
            try:
                f = json.loads(data.decode())
                if not isinstance(f, dict):
                    raise ValueError
            except ValueError:
                return await conn.send({"t": "error", "code": "bad_request", "reason": "one JSON frame per text message"})
            t = f.get("t")
            link.last_seen = time.time()
            if t in ("ack", "acks"):
                return await reply(f, {"t": "acked", "n": self._ack_list(link, f.get("list") if t == "acks" else f)})
            if t == "send":
                m = f.get("msg")
                if not isinstance(m, dict) or m.get("t") != "msg":
                    return await reply(f, {"t": "error", "code": "bad_request", "reason": "send carries one msg frame in msg"})
                return await reply(f, {"t": "sent", "ack": await self._send_msg(link, m)})
            if t == "ping":
                return await reply(f, {"t": "pong"})
            await reply(f, {"t": "error", "code": "bad_request", "reason": "unknown frame: the socket takes send, ack, acks and ping"})

        ping_task = asyncio.ensure_future(pinger())
        dec = wsock.Decoder(require_mask=True)
        try:
            while not conn.closed:
                op, data = await wsock.read_async(reader, dec)
                if op == wsock.TEXT:
                    srv._spawn(on_text(data))                    # a slow send does not hold up acks behind it
                elif op == wsock.PING:
                    await conn.write(wsock.PONG, data)
                elif op == wsock.CLOSE:
                    await conn.write(wsock.CLOSE, data[:2])
                    break
        except (asyncio.IncompleteReadError, ConnectionError, wsock.WsError, wire.WireError):
            pass
        finally:
            ping_task.cancel()
            await conn.close()
            if link.conn is conn:
                link.conn = NullConn()
                link.last_seen = time.time()                    # the lease runs from the socket's end
            log.info("https client %s session %s socket closed", link.kid, link.session[:10])
