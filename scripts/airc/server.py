# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""aircd — the realm server.

One aircd serves one realm (a DNS name). It has two faces:

  client face   local endpoints connect here (Unix socket, or loopback TCP),
                identify themselves (SO_PEERCRED uid -> namespaces), bind the
                names they receive for, and send messages.
  peer face     other realms' servers connect here (TCP, TLS in production)
                to deliver messages addressed to this realm; we connect out
                to them the same way.

Routing a message:
  1. canonicalize from/to; drop if expired or a duplicate id
  2. policy check (from, to)
  3. destination in my realm  -> hand to the client bound for it, or spool
     destination elsewhere    -> resolve the realm, send over a peer link,
                                 or spool if the peer is unreachable
  4. ack the origin with delivered | queued | failed

Every hop acks. The ack a sender receives is the end-to-end status when the
chain answers within ACK_TIMEOUT, otherwise "queued" (handed on, final
status unknown).
"""
from __future__ import annotations

import asyncio
import secrets
import json
import re
import logging
import os
import urllib.request
from collections import OrderedDict
import socket
import ssl
import time
import urllib.parse

from . import PROTO, DEFAULT_PEER_PORT, __version__
from . import address as A
from .links import LinkStore, MEDIA_TYPE as LINK_TYPE, parse_duration, ID_RE as LINK_ID_RE, parse_side, side_matches, side_kind, show_side
from . import passports as P
from . import e2e as E2E
from . import profile as PR
from .passports import PassportStore, MEDIA_TYPE as PASSPORT_TYPE
from . import signing as S
from .client import RECEIPT_TYPE, RECEIPT_STATES
from .events import EventLog, Subscriber
from .httpbind import HttpFace, HttpPeerLink, WsConn
from .policy import Policy
from .resolver import DnsUnavailable, Resolver
from .spool import Spool
from . import wire
from .wire import Conn, WireError

log = logging.getLogger("aircd")

ACK_TIMEOUT = 15.0
PEER_IDLE_CLOSE = 600.0
RETRY_INTERVAL = 30.0


def _peer_uid_tcp(ip: str, port: int) -> int | None:
    """uid owning a loopback TCP client socket, from /proc/net/tcp{,6}.

    The client's socket appears with local_address == ip:port. Works without
    privileges on Linux and is only meaningful for loopback peers.
    """
    want_port = f"{port:04X}"
    tables = ["/proc/net/tcp", "/proc/net/tcp6"]
    try:
        if ":" in ip:
            packed = socket.inet_pton(socket.AF_INET6, ip)
            want_ips = {"".join(f"{int.from_bytes(packed[i:i+4], 'big'):08X}" for i in range(0, 16, 4))}
            # v4-mapped appears in tcp6 as 0000000000000000FFFF0000xxxxxxxx
        else:
            packed = socket.inet_pton(socket.AF_INET, ip)
            le = int.from_bytes(packed, "little")
            want_ips = {f"{le:08X}", f"0000000000000000FFFF0000{le:08X}"}
    except OSError:
        return None
    for t in tables:
        try:
            with open(t) as f:
                next(f)
                for line in f:
                    parts = line.split()
                    laddr, lport = parts[1].split(":")
                    if lport == want_port and laddr in want_ips:
                        return int(parts[7])
        except (OSError, ValueError, IndexError, StopIteration):
            continue
    return None


def _q(v, limit: int = 200) -> str:
    """A foreign value quoted into a notice of our own (§16 item 4): cleaned and in double quotes."""
    return '"' + wire.clean(v, limit).replace('"', "'") + '"'


def _load_seed(spec: str) -> bytes:
    """A site key (§12.8): a path to a file holding a 32-byte ed25519 seed (raw, or base64 text), or the
    base64 seed itself."""
    import base64
    raw = None
    path = os.path.expanduser(str(spec))
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        if len(data) == 32:
            raw = data
        else:
            spec = data.decode("ascii", "replace").strip()
    if raw is None:
        try:
            raw = base64.b64decode(spec, validate=True)
        except ValueError:
            raw = b""
    if len(raw) != 32:
        raise SystemExit("config: passports.site_key must be a 32-byte ed25519 seed (file, or base64)")
    return raw


def _seed_pub(seed: bytes) -> str:
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization as ser
    k = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    return base64.b64encode(k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()


def _seed_sign(seed: bytes, data: bytes) -> str:
    import base64
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return base64.b64encode(ed25519.Ed25519PrivateKey.from_private_bytes(seed).sign(data)).decode()



def _delivery(ack) -> dict:
    """§4.6 `delivery`: the ack status of the control sent to the other side; absent when nothing was sent."""
    st = (ack or {}).get("status") if isinstance(ack, dict) else None
    return {"delivery": st} if st else {}

class SeedKey:
    """A site key held as a seed: .public_b64 and .sign(bytes) -> base64, like signing.Signer."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.public_b64 = _seed_pub(seed)

    def sign(self, data: bytes) -> str:
        return _seed_sign(self.seed, data)


class PassportRefused(Exception):
    def __init__(self, reason: str, code: str):
        super().__init__(reason)
        self.reason, self.code = reason, code


def proto_ok(proto) -> bool:
    """§4.1: airc/<major>.<minor> with our major; any minor (a newer minor only adds what we may ignore)."""
    m = re.fullmatch(r"airc/(\d+)\.(\d+)", str(proto or ""))
    return bool(m) and int(m.group(1)) == int(PROTO.split("/")[1].split(".")[0])


class BindHeld(Exception):
    """A bind asked for a pattern another live session holds (spec §4.3.1)."""

    def __init__(self, pattern: str, holder, suggest: str):
        super().__init__(pattern)
        self.pattern, self.holder, self.suggest = pattern, holder, suggest


class Link:
    """A connected party: client or peer."""

    def __init__(self, conn: Conn, kind: str):
        self.conn = conn
        self.kind = kind            # "client" | "peer"
        self.uid: int | None = None
        self.namespaces: list[str] = []     # client: namespaces it may speak for
        self.binds: list[str] = []           # client: absolute patterns it receives
        self.realm: str | None = None        # peer: its realm
        self.agent = ""
        self.last_activity = time.time()
        self.outbound = False               # peer: we dialled it
        self.authenticated = False          # peer: proved its realm key (hello/welcome signature)
        self.subscriber = None              # client: live event subscription

    # A stream-binding client's session is its connection (spec §4.3.1): live until it closes.
    live = True
    queue_only = False                  # an HTTPS session with nowhere to push: its messages wait in the queue

    def __repr__(self):
        who = self.realm if self.kind == "peer" else f"uid={self.uid} ns={self.namespaces} binds={self.binds}"
        return f"<{self.kind} {who}>"


class Server:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.realm = cfg["realm"].lower()
        self.uid_ns: dict[int, list[str]] = {int(k): (v if isinstance(v, list) else [v])
                                             for k, v in (cfg.get("uid_namespaces") or {}).items()}
        self.known_ns: set[str] = set(cfg.get("namespaces") or []) | {n for v in self.uid_ns.values() for n in v}
        self.trust_client_claims = bool(cfg.get("trust_client_claims", False))
        self.allow_reserved_binds = bool(cfg.get("allow_reserved_binds", False))
        # (redeemer, scope, redemption) -> {"exp", "at", "pins", "token_sha256", "scope"} (§12.5)
        self._redemptions: dict[tuple[str, str, str], dict] = {}
        self._offer_grants: dict[str, dict] = {}       # §12.9: offer id -> the grant that answered it, for the accept notice
        self.resolver_uri = f"airc://{self.realm}/_resolver"
        spool_dir = cfg.get("spool_dir") or os.path.join(os.path.expanduser("~"), ".airc", "spool")
        self.state_dir = cfg.get("state_dir") or os.path.dirname(spool_dir.rstrip("/")) or "."
        self.links = LinkStore(os.path.join(self.state_dir, "links.json"))
        self.links.exempt = lambda l, k: self._must_accept(l, parse_side(k))     # §12.7: must_accept wins over a key rejection
        lcfg = cfg.get("links") or {}
        self.links_cfg = {"accept_offers": lcfg.get("accept_offers", True),
                          "auto_accept": list(lcfg.get("auto_accept") or []),
                          "max_pending_per_offerer": int(lcfg.get("max_pending_per_offerer", 20)),
                          "max_ttl": lcfg.get("max_ttl"),
                          "offers_per_hour": int(lcfg.get("offers_per_hour", 60)),    # §11.5, per source realm
                          "opt_out": bool(lcfg.get("opt_out", True)),                 # §12.7, §12.8
                          # §12.8: links an endpoint must accept, by the other side's address or a key of its passport
                          "must_accept": [m for m in (lcfg.get("must_accept") or []) if isinstance(m, dict)
                                          and (isinstance(m.get("peer"), str) or isinstance(m.get("key"), str))]}
        self._offer_times: dict[str, list[float]] = {}
        self.admin_uids = {int(u) for u in (cfg.get("admin_uids") or [])} | {0, os.getuid()}
        self.passports = PassportStore(os.path.join(self.state_dir, "passports.json"))
        # E2E key directory (spec §19.3): endpoint key -> its signed key record, as published
        self.e2e_path = os.path.join(self.state_dir, "e2e-keys.json")
        self.e2e_keys: dict[str, dict] = {}
        try:
            with open(self.e2e_path) as f:
                self.e2e_keys = json.load(f)
        except (OSError, ValueError):
            pass
        # Closed channels (spec §21.4): endpoint key -> when closed; a message to one fails path_gone
        self.closed_path = os.path.join(self.state_dir, "closed.json")
        try:
            with open(self.closed_path) as f:
                self.closed = {k: t for k, t in json.load(f).items() if time.time() - t < 30 * 86400}
        except (OSError, ValueError):
            self.closed = {}
        # Local aliases (a site convenience, not protocol): fleet -> {alias: "//realm/ns/"}; see address.alias_expand
        self.aliases_path = os.path.join(self.state_dir, "aliases.json")
        self.aliases: dict[str, dict[str, str]] = {}
        try:
            with open(self.aliases_path) as f:
                raw = json.load(f)
            for fleet, table in (raw.items() if isinstance(raw, dict) else []):
                if isinstance(table, dict):
                    self.aliases[fleet] = {k: v for k, v in table.items() if isinstance(k, str) and isinstance(v, str)}
        except (OSError, ValueError):
            pass
        # Profiles (spec §21): endpoint key -> its public profile record
        self.statuses: dict[str, tuple[str, float]] = {}      # §21.2: endpoint key -> (status, when received); memory only
        self.profiles_path = os.path.join(self.state_dir, "profiles.json")
        self.profiles: dict[str, dict] = {}
        try:
            with open(self.profiles_path) as f:
                self.profiles = json.load(f)
        except (OSError, ValueError):
            pass
        self.events = EventLog(cfg.get("events_log") or os.path.join(self.state_dir, "events.jsonl"),
                               int(cfg.get("events_max_bytes", 50 * 1024 * 1024)))
        # Receipts (spec §6.7): the site's policy for seen/done receipts its endpoints send, applied on egress
        self.receipts_cfg = self._receipts_policy(cfg.get("receipts") or {})
        # messages delivered here that asked for receipts: id -> {"from", "to", "type", "asked"}, bounded (for the hook)
        self._receipt_asked: OrderedDict[str, dict] = OrderedDict()
        self.passports_cfg = self._passport_policy(cfg.get("passports") or {})
        self._redeem_failures: dict[str, list[float]] = {}
        # remote clients of the HTTPS binding: kid -> {"pub": b64, "ns": [...]}
        self.client_keys = {}
        for kid, rec in (cfg.get("client_keys") or {}).items():
            ns = rec.get("ns") if isinstance(rec.get("ns"), list) else [rec.get("ns")]
            self.client_keys[kid] = {"pub": rec["pub"], "ns": [n.lower() for n in ns if n]}
            self.known_ns.update(self.client_keys[kid]["ns"])
        self.http = HttpFace(self)
        pol = cfg.get("policy") or {}
        self.policy = Policy(pol.get("rules"), pol.get("default_allow", True), links=self.links)
        # §9.3, §7.3: the longest ttl accepted, and ids remembered for that plus the allowed clock skew
        self.max_ttl = int(cfg.get("max_ttl", 7 * 86400))
        self.clock_skew = int(cfg.get("clock_skew", 86400))
        self.spool = Spool(spool_dir, seen_keep=self.max_ttl + self.clock_skew)
        scfg = cfg.get("signing") or {}
        self.resolver = Resolver(cfg.get("peers"), known_keys=scfg.get("known_keys"))
        # how long a hop may take to ack before the message is spooled as queued, and how
        # often the spool is retried; tests shrink both (the defaults suit real networks)
        self.ack_timeout = float(cfg.get("ack_timeout", ACK_TIMEOUT))
        self.retry_interval = float(cfg.get("retry_interval", RETRY_INTERVAL))
        # Signing: on whenever this realm talks to peers. The key is created on
        # first start; publish its public half in DNS (see log line / --show-key).
        self.signing_cfg = {
            "enabled": bool(scfg.get("enabled", True)),
            "require": bool(scfg.get("require", True)),          # refuse unsigned/unverifiable peer traffic
            "trusted_unsigned": [r.lower() for r in (scfg.get("trusted_unsigned") or [])],
            "hello_skew": int(scfg.get("hello_skew", S.HELLO_SKEW)),
            "accept_algs": tuple(a for a in (scfg.get("accept_algs") or S.ACCEPTED_ALGS) if a != "none"),
            "extra_keys": list(scfg.get("extra_keys") or []),   # transition: also sign with these key files
        }
        self.extra_signers = []
        self.signer = None
        if self.signing_cfg["enabled"] and (cfg.get("peer_listen") or cfg.get("peers") or scfg.get("key") or scfg.get("always")):
            try:
                self.signer = S.Signer(scfg.get("key") or os.path.join(self.state_dir, "realm.key"))
                self.extra_signers = [S.Signer(k) for k in self.signing_cfg["extra_keys"]]
            except S.SigningUnavailable as e:
                if cfg.get("peer_listen"):
                    raise SystemExit(f"aircd: {e}")
                log.warning("%s; this realm cannot sign or verify peer traffic", e)
        if self._site_key_from_realm and self.signer and not self.passports_cfg["site_key"]:
            # §12.8: by default the realm's own key is the site key (entitled for the realm, signs alone when no
            # client key signed, e.g. a passport issued to accept a link offer, §12.9); "site_key": "none" turns it off
            self.passports_cfg.update(site_key=self.signer, site_pub=self.signer.public_b64)
        self.challenges = None                          # §11.6, optional: only with offers.challenge rules
        if (cfg.get("offers") or {}).get("challenge"):
            from .challenges import Challenges
            self.challenges = Challenges(self, cfg.get("offers") or {}, cfg.get("challenges") or {})
        self.clients: list[Link] = []
        self.peers: dict[str, list[Link]] = {}
        self.peer_errors: dict[str, str] = {}      # realm -> why its endpoints failed last time (for the queued ack)
        self.pending: dict[str, asyncio.Future] = {}
        # msg ids we spooled after an ack timeout, still awaiting the late ack
        self._in_flight: set[str] = set()
        self._in_flight_link: dict[str, object] = {}   # msg id -> the link it timed out on (B2)
        self._routing: dict[str, asyncio.Future] = {}   # msg id -> its routing outcome, while it is being routed (B9)
        # msg ids whose late ack arrived: drop them from the spool on flush
        self._settled: dict[str, str] = {}
        self._spooled_at: dict[str, str] = {}      # msg id -> spool key of a timed-out copy, so a late ack can drop it at once
        self.servers: list[asyncio.base_events.Server] = []
        self.stats = {"started": time.time(), "in": 0, "out": 0, "delivered": 0, "queued": 0, "failed": 0}
        self._ssl_server = self._make_server_ssl()
        self._tasks: set[asyncio.Task] = set()

    # ------------------------------------------------------------------ setup
    def _make_server_ssl(self):
        tls = self.cfg.get("tls") or {}
        if not tls.get("cert"):
            return None
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(tls["cert"], tls.get("key"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def _client_ssl(self, host: str):
        tls = self.cfg.get("tls") or {}
        ctx = ssl.create_default_context()
        if tls.get("ca"):
            ctx.load_verify_locations(tls["ca"])
        if tls.get("insecure_skip_verify"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def start(self):
        cu = self.cfg.get("client_unix")
        if cu:
            os.makedirs(os.path.dirname(cu), exist_ok=True)
            if os.path.exists(cu):
                # refuse to clobber a live server
                try:
                    r, w = await asyncio.wait_for(asyncio.open_unix_connection(cu, limit=wire.STREAM_LIMIT), 1)
                    w.close()
                    raise RuntimeError(f"another aircd is listening on {cu}")
                except (ConnectionRefusedError, FileNotFoundError, asyncio.TimeoutError):
                    os.unlink(cu)
            s = await asyncio.start_unix_server(lambda r, w: self._accept(r, w, "client"), path=cu, limit=wire.STREAM_LIMIT)
            mode = int(str(self.cfg.get("client_unix_mode", "666")), 8)
            if self.trust_client_claims and mode & 0o077:
                # A claimed namespace on a socket any local uid can reach would
                # let anyone speak as anyone. Testing knob, so confine it.
                log.warning("trust_client_claims is on: forcing socket mode 0600 (was %o)", mode)
                mode = 0o600
            os.chmod(cu, mode)
            self.servers.append(s)
            log.info("client face on unix:%s", cu)
        ct = self.cfg.get("client_tcp")
        if ct:
            host, port = self._hostport(ct, 2473)
            s = await asyncio.start_server(lambda r, w: self._accept(r, w, "client"), host, port, limit=wire.STREAM_LIMIT)
            self.servers.append(s)
            log.info("client face on tcp:%s:%d", host, port)
        pl = self.cfg.get("peer_listen")
        if pl:
            host, port = self._hostport(pl, DEFAULT_PEER_PORT)
            s = await asyncio.start_server(lambda r, w: self._accept(r, w, "peer"), host, port, ssl=self._ssl_server, limit=wire.STREAM_LIMIT)
            self.servers.append(s)
            log.info("peer face on %s:%d (%s)", host, port, "tls" if self._ssl_server else "PLAINTEXT")
        if self.cfg.get("https_listen"):
            if not self._ssl_server:
                raise SystemExit("aircd: https_listen needs tls.cert/tls.key (use http_listen for a plaintext test face)")
            await self.http.start(self.cfg["https_listen"], self._ssl_server)
        if self.cfg.get("http_listen"):
            await self.http.start(self.cfg["http_listen"], None)
        self.http.restore_webhooks()
        self._spawn(self._retry_loop())
        log.info("aircd %s realm=%s namespaces=%s", __version__, self.realm, sorted(self.known_ns))
        if self.signer:
            log.info("signing key kid=%s; publish: %s", self.signer.kid, S.txt_record(self.realm, self.signer.public_b64))

    async def stop(self):
        for s in self.servers:
            s.close()
        await self.http.stop()
        for t in list(self._tasks):
            t.cancel()
        for l in list(self.clients) + [p for ps in self.peers.values() for p in ps]:
            await l.conn.close()

    @staticmethod
    def _hostport(spec: str, default_port: int):
        if spec.startswith("["):
            host, _, rest = spec[1:].partition("]")
            return host, int(rest.lstrip(":") or default_port)
        host, _, port = spec.rpartition(":")
        if not host:
            return spec, default_port
        return host, int(port or default_port)

    def _spawn(self, coro):
        t = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(t)
        t.add_done_callback(self._tasks.discard)
        return t

    # ------------------------------------------------------------ connections
    async def _accept(self, reader, writer, face: str):
        conn = Conn(reader, writer)
        link = Link(conn, face)
        try:
            await self._serve(link)
        except WireError as e:
            log.info("%r protocol error: %s", link, e)
            try:
                await conn.send(wire.error(e.code, e.reason))
            except Exception:
                pass
        except Exception:
            log.exception("link %r crashed", link)
        finally:
            self._unregister(link)
            await conn.close()

    async def _serve(self, link: Link):
        hello = await asyncio.wait_for(link.conn.recv(), 30)
        if not hello or hello.get("t") != "hello":
            raise WireError("expected_hello")
        if not proto_ok(hello.get("proto")):
            raise WireError("bad_proto", f"{hello.get('proto')!r}: this server speaks {PROTO}")
        link.agent = str(hello.get("agent", ""))[:100]
        role = hello.get("role")
        if link.kind == "client" and role == "client":
            await self._hello_client(link, hello)
        elif link.kind == "peer" and role == "peer":
            await self._hello_peer(link, hello)
        else:
            raise WireError("wrong_face", f"role {role!r} on the {link.kind} face")
        await self._read_loop(link)

    async def _hello_client(self, link: Link, hello: dict):
        uid = link.conn.peer_uid()
        if uid is None:
            peer = link.conn.writer.get_extra_info("peername")
            if peer and peer[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
                uid = _peer_uid_tcp(peer[0], peer[1])
        link.uid = uid
        link.features = [str(f) for f in hello.get("features") or [] if isinstance(f, str)]
        ns = list(self.uid_ns.get(uid, [])) if uid is not None else []
        if not ns and self.trust_client_claims and hello.get("ns"):
            claim = hello["ns"] if isinstance(hello["ns"], list) else [hello["ns"]]
            ns = [str(c).lower() for c in claim]
            self.known_ns.update(ns)
        link.namespaces = ns
        self.clients.append(link)
        await link.conn.send({"t": "welcome", "realm": self.realm, "ns": ns, "proto": PROTO, "features": ["keys", "profile", "leases", "bin", "aliases"],
                              "server": f"aircd/{__version__}", "aliases": self._aliases_for(ns)})
        log.info("client connected %r agent=%s", link, link.agent)

    async def _hello_peer(self, link: Link, hello: dict):
        realm = str(hello.get("realm", "")).lower().rstrip(".")
        if not realm:
            raise WireError("bad_hello", "peer must state its realm")
        link.realm = realm
        link.authenticated = await self._authenticate_hello(realm, hello)
        self.peers.setdefault(realm, []).append(link)
        welcome = {"t": "welcome", "realm": self.realm, "proto": PROTO, "server": f"aircd/{__version__}"}
        if self.signer and hello.get("nonce"):
            welcome["sig"] = self.signer.sign_welcome(self.realm, realm, str(hello["nonce"]))
            welcome["kid"] = self.signer.kid
        await link.conn.send(welcome)
        log.info("peer connected %s (%s) %s", realm, link.conn.writer.get_extra_info("peername"),
                 "authenticated" if link.authenticated else "UNAUTHENTICATED")
        self.events.emit("peer.up", realm=realm, authenticated=link.authenticated, outbound=False)
        if link.authenticated:
            self._spawn(self._flush_realm(realm))

    async def _authenticate_hello(self, realm: str, hello: dict) -> bool:
        """Did the dialler prove it holds `realm`'s key? Trusted-unsigned realms
        pass without a signature (static peers, tests)."""
        if realm in self.signing_cfg["trusted_unsigned"] or not self.signing_cfg["enabled"]:
            return True
        if not hello.get("sig"):
            return False
        try:
            keys = await self.resolver.public_keys(realm)
            return S.verify_hello(hello, self.realm, keys, self.signing_cfg["hello_skew"], self.signing_cfg["accept_algs"])
        except S.SigningUnavailable:
            return False

    def _peer_trusted_unsigned(self, realm: str) -> bool:
        return realm in self.signing_cfg["trusted_unsigned"] or not self.signing_cfg["enabled"] or not self.signing_cfg["require"]

    def _unregister(self, link: Link):
        # B2: a message that timed out on this link and was spooled waits for a late ack that can no longer come;
        # release it so the next flush resends the spooled copy, and settle any future still waiting on it
        for mid in [m for m, l in self._in_flight_link.items() if l is link]:
            self._in_flight_link.pop(mid, None)
            self._in_flight.discard(mid)
            fut = self.pending.pop(mid, None)
            if fut is not None and not fut.done():
                fut.set_result(wire.ack(mid, "failed", "link closed before the ack", "link_down"))
        if link in self.clients:
            self.clients.remove(link)
            if link.subscriber:
                self.events.unsubscribe(link.subscriber)
            log.info("client gone %r", link)
        if link.realm and link in self.peers.get(link.realm, []):
            self.peers[link.realm].remove(link)
            if not self.peers[link.realm]:
                del self.peers[link.realm]
            log.info("peer gone %s", link.realm)
            self.events.emit("peer.down", realm=link.realm, authenticated=link.authenticated, outbound=link.outbound)

    async def _read_loop(self, link: Link):
        while True:
            frame = await link.conn.recv()
            if frame is None:
                return
            link.last_activity = time.time()
            t = frame["t"]
            if t == "msg":
                self._spawn(self._on_msg(link, frame))
            elif t == "ack":
                self._on_ack(frame)
            elif t == "bind" and link.kind == "client":
                await self._on_bind(link, frame)
            elif t == "ping":
                await link.conn.send({"t": "pong", "n": frame.get("n")})
            elif t == "pong":
                pass
            elif t == "stat" and link.kind == "client":
                snap = self.snapshot()
                if not self._is_admin(link):           # S14: other clients' uids and binds, and the backlog, are the operator's
                    snap = {"realm": snap["realm"], "uptime": snap["uptime"], "counters": snap["counters"]}
                await link.conn.send({"t": "stats", **snap})
            elif t == "link" and link.kind == "client":
                await link.conn.send(await self._on_link_frame(link, frame))
            elif t == "passport" and link.kind == "client":
                await link.conn.send(await self._on_passport_frame(link, frame))
            elif t == "keys" and link.kind == "client":
                await link.conn.send(await self._on_keys_frame(link, frame))
            elif t == "profile" and link.kind == "client":
                await link.conn.send(self._on_profile_frame(link, frame))
            elif t == "alias" and link.kind == "client":
                await link.conn.send(await self._on_alias_frame(link, frame))
            elif t == "subscribe" and link.kind == "client":
                if link.subscriber:
                    self.events.unsubscribe(link.subscriber)
                kinds = frame.get("kinds") if isinstance(frame.get("kinds"), list) else None
                link.subscriber = Subscriber(link.conn.send, kinds, self._ns_keys(link))
                self.events.subscribe(link.subscriber)
                await link.conn.send({"t": "subscribed", "kinds": kinds, "scope": "all" if self._ns_keys(link) is None else link.namespaces})
            elif t == "error":
                log.warning("%r sent error: %s %s", link, frame.get("code"), frame.get("reason"))
                return
            else:
                raise WireError("unexpected_frame", t)

    # ------------------------------------------------------------------ aliases
    MAX_ALIASES = 100

    def _local_namespaces(self) -> set[str]:
        names = set(self.known_ns)
        for v in self.uid_ns.values():
            names.update(v)
        return {n.split("/")[0].lower() for n in names}

    def _aliases_for(self, namespaces: list[str]) -> dict[str, str]:
        """The alias table of a client's fleet (its first namespace); any alias that now names a local fleet is dropped."""
        if not namespaces:
            return {}
        local = self._local_namespaces()
        return {k: v for k, v in self.aliases.get(namespaces[0], {}).items() if k not in local}

    async def _on_alias_frame(self, link: Link, frame: dict) -> dict:
        """op list | add (alias, prefix) | remove (alias). Each fleet manages its own table; nothing here is protocol."""
        def out(ok: bool, reason: str = "") -> dict:
            r = {"t": "aliased", "ok": ok, "aliases": self._aliases_for(link.namespaces)}
            if reason:
                r["reason"] = reason
            return r
        if not link.namespaces:
            return out(False, "this connection has no fleet namespace")
        fleet = link.namespaces[0]
        op = frame.get("op")
        if op == "list":
            return out(True)
        name = str(frame.get("alias", "")).strip().lower()
        table = dict(self.aliases.get(fleet, {}))
        if op == "remove":
            if name not in table:
                return out(False, f"no alias {name!r}")
            del table[name]
        elif op == "add":
            if not A._SEG.match(name) or name.startswith("_"):
                return out(False, "an alias is one address segment (letters, digits, - and _), not starting with _")
            if name in self._local_namespaces():
                return out(False, f"{name!r} is a fleet on this host; choose another alias")
            try:
                pre = A.alias_prefix(str(frame.get("prefix", "")))
            except A.AddressError as e:
                return out(False, f"bad prefix: {e}")
            if pre.in_realm(self.realm):
                return out(False, "aliases are for other realms; addresses here already have short forms")
            if name not in table and len(table) >= self.MAX_ALIASES:
                return out(False, f"at most {self.MAX_ALIASES} aliases per fleet")
            table[name] = ("//" + pre.authority + "/") if not pre.path else pre.network()   # //realm/ or //realm/ns/
        else:
            return out(False, "op must be list, add or remove")
        self.aliases[fleet] = table
        self._save_json(self.aliases_path, self.aliases)
        current = self._aliases_for(link.namespaces)
        for other in list(self.clients):                       # connected clients of the fleet pick the change up at once
            if other is not link and other.namespaces[:1] == [fleet] and "aliases" in getattr(other, "features", []):
                try:
                    await other.conn.send({"t": "aliases", "aliases": current})
                except (OSError, WireError):
                    pass
        return out(True)

    # ------------------------------------------------------------------ bind
    def _ns_allows(self, link: Link, path: tuple[str, ...]) -> bool:
        """May this client bind/send as `path`? path[0..] must start with one of its namespaces."""
        for ns in link.namespaces:
            nsp = tuple(ns.split("/"))
            if path[:len(nsp)] == nsp and len(path) > len(nsp):
                return True
        return False

    def _holder(self, pattern: str, other_than) -> Link | None:
        """The live session, other than `other_than`, that holds exactly `pattern` (spec §4.3.1)."""
        for l in self.clients:
            if l is not other_than and l.live and pattern in l.binds:
                return l
        return None

    def suggest_free(self, pattern: str, other_than) -> str:
        """`pattern` with -2, -3, ... on its last segment: the first one nobody holds live."""
        tail = "/" if pattern.endswith("/") else ""
        base = pattern.rstrip("/")
        if base[2:].count("/") < 2:                     # //realm/ws: the workspace itself has no alternative
            return ""
        for i in range(2, 100):
            cand = f"{base}-{i}{tail}"
            if not self._holder(cand, other_than):
                return cand
        return ""

    async def claim(self, link: Link, patterns: list[str], take_over: bool) -> list[str]:
        """One live session per pattern: raise BindHeld for a pattern another session holds live, or,
        with take_over, move it here. The caller then sets link.binds."""
        taken = []
        for p in patterns:
            h = self._holder(p, link)
            if h is None:
                continue
            if not take_over:
                raise BindHeld(p, h, self.suggest_free(p, link))
            taken.append((p, h))
        for p, h in taken:
            h.binds = [b for b in h.binds if b != p]
            log.info("%r took over %s from %r", link, p, h)
            await self._displace(h, p)
        return [p for p, _ in taken]

    async def _displace(self, h: Link, pattern: str):
        if hasattr(h, "displaced"):                             # an HTTPS session: told on its next request,
            h.displaced.append(pattern)
            if isinstance(h.conn, WsConn) and not h.conn.closed:   # and at once over its open WebSocket
                try:
                    await h.conn.send({"t": "displaced", "names": [pattern]})
                except Exception:  # noqa: BLE001
                    pass
            return
        if not h.binds:
            try:
                await h.conn.send(wire.error("displaced", f"another session took over {pattern}"))
            finally:
                await h.conn.close()

    async def _on_bind(self, link: Link, frame: dict):
        names = frame.get("names")
        if names == []:                                         # release (§4.3.1)
            link.binds = []
            await link.conn.send({"t": "bound", "names": []})
            return
        if not isinstance(names, list) or not names:
            raise WireError("bad_bind", "names must be a non-empty list")
        accepted = []
        for n in names:
            text = str(n).lower().lstrip("/")
            ns_form = text.endswith("/")
            segs = tuple(s for s in text.strip("/").split("/") if s)
            probe = tuple("x" if s in ("*", "**") else s for s in segs)
            try:
                a = A.parse("//" + self.realm + "/" + "/".join(probe))
            except A.AddressError as e:
                raise WireError("bad_bind", f"{n}: {e}")
            if a.is_reserved and not self.allow_reserved_binds:
                raise WireError("forbidden", f"{n}: names starting with '_' are reserved")
            # A namespace bind "ns/" may name one of the client's namespaces
            # itself; an endpoint bind must lie strictly inside one.
            own_ns = ns_form and any(tuple(x.split("/")) == probe for x in link.namespaces)
            if not own_ns and not self._ns_allows(link, probe):
                raise WireError("forbidden", f"{n} is outside your namespaces {link.namespaces}")
            accepted.append("//" + self.realm + "/" + "/".join(segs) + ("/" if ns_form else ""))
        try:
            await self.claim(link, [p for p in accepted if p not in link.binds], bool(frame.get("take_over")))
        except BindHeld as e:
            raise WireError("name_held", f"{e.pattern} is held by another session; {e.suggest or 'choose another name'}")
        link.binds.extend(p for p in accepted if p not in link.binds)
        for p in accepted:                              # listening as a closed channel opens it again
            if not p.endswith("/") and "*" not in p:
                self.channel_reopen(A.parse(p).key)
        bound = {"t": "bound", "names": accepted}
        front = {}
        for p in accepted:
            if p.endswith("/") and p.count("/") == 4:                  # //realm/ns/
                ns = p.split("/")[3]
                f = self._front(ns)
                if f["mode"] == "agent":
                    front[ns] = f["agent"]
        if front:
            bound["front"] = front                                     # spec §20.3
        await link.conn.send(bound)
        log.info("bound %r", link)
        for ns in {p.split("/")[3] for p in accepted}:
            self._spawn(self._flush_namespace(ns))

    def _client_for(self, to: A.Address) -> Link | None:
        """The client that resolves `to`. Delegation (spec §6): a client bound
        for endpoint P also receives everything beneath P/, unless something
        more specific is bound. Score = depth of the literal prefix matched,
        with an exact endpoint match beating a prefix of the same depth."""
        if (len(to.path) == 1 and not to.namespace_ref and to.in_realm(self.realm) and to.path[0] in self.known_ns):
            front = self._front(to.path[0])       # the bare workspace address: its front-door agent's (§20.3)
            if front["mode"] == "agent" and front["agent"]:
                to = A.parse(f"//{self.realm}/{to.path[0]}/{front['agent']}")
        best, best_score = None, -1
        for link in self.clients:
            if not link.live:
                continue
            for p in link.binds:
                body = p[2:].split("/", 1)[1] if "/" in p[2:] else ""
                segs = [s for s in body.strip("/").split("/") if s]
                literal = sum(1 for s in segs if s not in ("*", "**"))
                if A.pattern_match(p, to):
                    score = literal * 2 + (1 if "*" not in p and not p.endswith("/") else 0)
                else:
                    # delegation: exact endpoint bind whose path is a proper prefix of `to`
                    if "*" in p or p.endswith("/"):
                        continue
                    try:
                        bound = A.parse(p)
                    except A.AddressError:
                        continue
                    if not (to.under(bound) and len(to.path) > len(bound.path)):
                        continue
                    score = literal * 2
                if score >= best_score:
                    best, best_score = link, score
        return best

    # --------------------------------------------------------------- routing
    def _on_ack(self, frame: dict):
        mid = frame.get("id")
        fut = self.pending.get(mid)
        if fut and not fut.done():
            fut.set_result(frame)
        self._in_flight_link.pop(mid, None)
        if mid in self._in_flight:
            # The hop answered after we timed out and spooled the message. Any
            # final ack settles it (§6.6): delivered/queued, and failed too,
            # since a failed ack is final; the spooled copy is dropped, not
            # resent. Only failed link_down (the hop lost its own link) keeps
            # the copy for the next flush, like a dropped link.
            self._in_flight.discard(mid)
            self.pending.pop(mid, None)
            status = frame.get("status", "delivered")
            key = self._spooled_at.pop(mid, None)
            keep = status == "failed" and frame.get("code") == "link_down"
            if not keep:
                if key is not None and self.spool.remove(key, mid):
                    if status != "failed":
                        self.spool.mark_seen(mid)   # gone from the inbox now, not at the next retry tick
                else:
                    self._settled[mid] = status
            log.info("late ack for %s: %s%s", mid, status, " (spooled copy kept)" if keep else "")

    async def _forward_and_wait(self, link: Link, msg: dict) -> dict:
        """Send msg over link and wait for its ack (or synthesize one)."""
        mid = msg["id"]
        loop = asyncio.get_running_loop()
        fut = self.pending.get(mid)
        if fut is None or fut.done():
            fut = loop.create_future()
            self.pending[mid] = fut
        if "_bin" in msg and "bin" not in getattr(link, "features", ["bin"]):
            self.pending.pop(mid, None)                 # §22: only to clients and HTTPS peers that said they take binary sections
            return wire.ack(mid, "failed", ("the recipient's client" if link.kind == "client" else f"realm {link.realm}") + " cannot receive files or other binary sections", "bin_unsupported",
                            self.resolver_uri)
        try:
            await link.conn.send(msg)
        except Exception as e:
            self.pending.pop(mid, None)
            return wire.ack(mid, "failed", f"link write failed: {e}", "link_down")    # §6.6: the hop is gone, not a refusal
        try:
            a = await asyncio.wait_for(asyncio.shield(fut), self.ack_timeout)
        except asyncio.TimeoutError:
            # Keep the future registered so a late ack can still settle it;
            # the caller spools the message under its destination key, so
            # "queued" is a promise we can keep. See _spool_timed_out.
            self._in_flight.add(mid)
            self._in_flight_link[mid] = link          # B2: released if this link closes first
            return wire.ack(mid, "queued", "no ack from next hop within timeout; spooled", "no_ack", self.resolver_uri)
        if self.pending.get(mid) is fut:
            self.pending.pop(mid, None)
        return a

    def _spool_timed_out(self, key: str, msg: dict, a: dict) -> None:
        if msg["id"] in self._in_flight:
            self.spool.enqueue(key, msg)
            self._spooled_at[msg["id"]] = key

    def _flushable(self, key: str, m: dict) -> bool:
        """Decide what to do with a spooled message before resending it.

        settled by a late ack  -> drop it (delivered or failed already)
        still in flight        -> put it back, do not send a second copy
        otherwise              -> send
        """
        mid = m["id"]
        if mid in self._settled:
            log.info("dropping spooled %s: settled %s", mid, self._settled.pop(mid))
            self._spooled_at.pop(mid, None)
            return False
        if mid in self._in_flight:
            self.spool.enqueue(key, m)
            return False
        self._spooled_at.pop(mid, None)
        return True

    async def _on_msg(self, link: Link, msg: dict):
        try:
            a = await self.route(msg, link)
        except WireError as e:                          # §6.2: malformed frame content
            a = wire.ack(str(msg.get("id", "?"))[:128], "failed", str(e), "bad_address", self.resolver_uri)
        except Exception as e:
            log.exception("route failed")
            a = wire.ack(msg.get("id", "?"), "failed", f"server error: {e}")
        if a["status"] == "failed" and not a.get("_emitted"):
            self._emit_msg(msg, a, link)
        a.pop("_emitted", None)
        try:
            await link.conn.send(a)
        except Exception:
            pass

    async def route(self, msg: dict, origin: Link) -> dict:
        """Route one message. A copy of a message still being routed (the same id) waits for the first and
        gets its outcome as a duplicate, so the window between the seen check and marking it seen cannot
        deliver it twice (B9)."""
        mid = msg.get("id") if isinstance(msg, dict) else None
        prior = self._routing.get(mid) if isinstance(mid, str) else None
        if prior is not None:
            first = await asyncio.shield(prior)
            return wire.ack(mid, first.get("status", "failed"), "duplicate of a message being routed", "duplicate",
                            self.resolver_uri)
        fut = asyncio.get_running_loop().create_future() if isinstance(mid, str) else None
        if fut is not None:
            self._routing[mid] = fut
        a = None
        try:
            a = await self._route(msg, origin)
            return a
        finally:
            if fut is not None:
                self._routing.pop(mid, None)
                fut.set_result(a or wire.ack(mid, "failed", "server error"))

    async def _route(self, msg: dict, origin: Link) -> dict:
        try:
            wire.validate_msg(msg)
        except WireError as e:
            # §4.2: an id or re outside the grammar is refused on the peer face and bad_request on the client face;
            # other malformed fields are bad_address (§6.2)
            code = ("refused" if getattr(origin, "kind", None) == "peer" else "bad_request") if e.code == "bad_id" else "bad_address"
            return self._fail(str(msg.get("id", "?"))[:128], e.reason or e.code, code)
        mid = msg["id"]
        self.stats["in"] += 1
        # --- canonicalize and authenticate the origin -----------------------
        if origin.kind == "client":
            ctx_ns = origin.namespaces[0] if origin.namespaces else ""
            try:
                frm = A.parse(msg["from"], self.realm, ctx_ns)
                to = A.parse(msg["to"], self.realm, ctx_ns)
            except A.AddressError as e:
                return self._fail(mid, f"bad address: {e}", "bad_address")
            if not frm.in_realm(self.realm) or not self._ns_allows(origin, frm.path):
                return self._fail(mid, f"you may not send as {frm} (namespaces {origin.namespaces})", "refused")
            msg["via"] = []
        else:
            # a link control may name a whole realm as a side (§11.1, §12): from or to airc://<realm>/
            parse = parse_side if msg.get("type") in (LINK_TYPE, PASSPORT_TYPE) else A.parse
            try:
                frm = parse(msg["from"])
                to = parse(msg["to"])
            except A.AddressError as e:
                return self._fail(mid, f"bad address: {e}", "bad_address")
            if frm.realm != origin.realm:
                return self._fail(mid, f"peer {origin.realm} may not relay for {frm.realm}", "refused")
            if not to.in_realm(self.realm):
                return self._fail(mid, f"{self.realm} does not transit traffic for {to.realm}", "refused")
            if not self._peer_trusted_unsigned(frm.realm):
                try:
                    keys = await self.resolver.public_keys(frm.realm)
                except S.SigningUnavailable as e:
                    return self._fail(mid, str(e), "refused")
                if not keys:
                    return self._fail(mid, f"no published signing key for {frm.realm} (_airc.{frm.realm} TXT)", "refused")
                if not S.verify_message(msg, keys, self.signing_cfg["accept_algs"]):
                    return self._fail(mid, f"signature missing or invalid for {frm}", "refused")
        if int(msg.get("ttl", wire.DEFAULT_TTL)) > self.max_ttl:      # §9.3: seen memory must outlast every ttl
            return self._fail(mid, "ttl too long", "refused")
        # Wire form is the URI; the fragment rides along untouched (spec §7.2).
        msg["from"], msg["to"] = str(frm), str(to)
        if wire.expired(msg):
            return self._fail(mid, "expired", "expired")
        if self.spool.seen(mid):
            return wire.ack(mid, "delivered", "duplicate", "duplicate", self.resolver_uri)
        # --- passport redemption addressed to this realm's _passport ----------
        if msg.get("type") == PASSPORT_TYPE:
            if origin.kind == "client":                 # §11.4: the server writes passport control; clients use passport frames
                return self._fail(mid, "passport control messages come from servers; use a passport frame (airc passport ...)", "refused")
            if to.in_realm(self.realm) and to.path == (P.ENDPOINT_NAME,):
                a = await self._passport_control(msg, frm, origin)
                self.stats[a["status"]] = self.stats.get(a["status"], 0) + 1
                return self._seen_if_taken(a)
            if not to.in_realm(self.realm):
                return self._seen_if_taken(await self._deliver_remote(msg, to))
            return self._fail(mid, f"passport control must be addressed to //{self.realm}/{P.ENDPOINT_NAME}", "bad_address")
        # --- link control traffic rides ordinary msg frames -------------------
        if msg.get("type") == LINK_TYPE:
            a = await self._link_control(msg, frm, to, origin)
            self.stats[a["status"]] = self.stats.get(a["status"], 0) + 1
            return self._seen_if_taken(a)
        # --- the workspace front door (spec §20) -----------------------------
        route_to = to
        if (to.in_realm(self.realm) and to.port is None and not to.namespace_ref and len(to.path) == 1
                and not to.is_reserved and to.path[0] in self.known_ns):
            front = self._front(to.path[0])
            if front["mode"] == "off":
                return self._fail(mid, "this workspace has no front door", "no_such_path")
            if front["mode"] == "directory":
                a = self._directory_answer(msg, frm, to)
                self.spool.mark_seen(mid)
                self._emit_msg(msg, a, origin, frm, to)
                a["_emitted"] = True
                return a
            route_to = A.parse(f"//{self.realm}/{to.path[0]}/{front['agent']}")
        # --- policy ---------------------------------------------------------
        ok, why = self.policy.check(frm, route_to)
        if not ok:
            hint = "; to ask for permission, send a link offer (spec §11.5)" if not frm.in_realm(self.realm) else ""
            return self._fail(mid, f"not authorized ({why}){hint}", "refused")
        by_link = re.match(r"link (L[0-9a-f]{8})\b", why or "")
        # --- receipts (spec §6.7): a receipt one of our endpoints sends goes only where the site allows ----
        receipt = None
        if msg.get("type") == RECEIPT_TYPE:
            receipt, why = await self._receipt_check(msg, frm, to, origin)
            if why:
                return self._fail(mid, why, "refused")
        # --- end-to-end encryption rules (spec §19.7) ------------------------
        why = self._e2e_refusal(msg, frm, route_to)
        if why:
            self.events.emit("msg.refused", id=mid, **{"from": str(frm)}, to=str(to), code="e2e_required", reason=why)
            return self._fail(mid, why, "e2e_required")
        # --- deliver --------------------------------------------------------
        if not to.in_realm(self.realm):
            # open the reply window before sending: the other side may answer before it acks (§20.2)
            self.policy.note_delivery(frm, route_to)
        if to.in_realm(self.realm) and to.port is None:
            if to.namespace_ref:
                # Fan-out to a namespace is syntactically valid and refused here (spec §7.1).
                return self._fail(mid, f"{to} is a namespace, not an endpoint", "namespace_not_endpoint")
            if to.path == ("_resolver",):
                a = wire.ack(mid, "delivered", "aircd ok", None, self.resolver_uri)
            elif to.is_reserved and to.path[-1] in A.WELL_KNOWN and self._client_for(to) is None:
                a = self._fail(mid, f"{to.name} is not provided by this authority", "no_such_path")
            else:
                a = await self._deliver_local(msg, route_to)
        else:
            a = await self._deliver_remote(msg, to)
        if a["status"] in ("delivered", "queued"):
            self.spool.mark_seen(mid)
            self.policy.note_delivery(frm, route_to)
            if by_link:
                self.links.note_use(by_link.group(1), str(frm), str(to), sent=self._link_sent(by_link.group(1), frm, to))
            if receipt:                                     # §6.7: relays record seen/done in the audit stream
                self.events.emit("msg.receipt", id=mid, re=msg.get("re"), state=receipt, **{"from": str(frm)}, to=str(to),
                                 status=a["status"], hop="client" if origin.kind == "client" else "peer")
            elif to.in_realm(self.realm) and isinstance((msg.get("hdr") or {}).get("airc-receipt"), str):
                self._remember_asked(msg, frm, to)
        self.stats[a["status"]] = self.stats.get(a["status"], 0) + 1
        log.info("%s -> %s : %s%s", frm, to, a["status"], f" ({a['reason']})" if a.get("reason") else "")
        self._emit_msg(msg, a, origin, frm, to)
        a["_emitted"] = True
        return a

    # ------------------------------------------------------------------ receipts (spec §6.7)
    @staticmethod
    def _receipts_policy(rcfg: dict) -> dict:
        """{"default": on|off|hook, "foreign": ..., "scopes": {scope: mode}, "hook": url}. Shipped default: on for
        senders in this realm, off for other realms (a receipt reveals when an agent's owner is active)."""
        def mode(v, dflt):
            v = str(v).lower() if v is not None else dflt
            return v if v in ("on", "off", "hook") else dflt
        scopes = {str(k): mode(v, "on") for k, v in (rcfg.get("scopes") or {}).items() if isinstance(k, str) and k.strip()}
        hook = rcfg.get("hook") if isinstance(rcfg.get("hook"), str) else None
        return {"default": mode(rcfg.get("default"), "on"), "foreign": mode(rcfg.get("foreign"), "off"),
                "scopes": scopes, "hook": hook}

    def _scope_pattern(self, scope: str) -> str:
        """A scope as written in aircd.json (alice/, alice/ops, //realm/alice/) as an address pattern."""
        p = scope.strip()
        if p.lower().startswith("airc://"):
            p = p[len("airc:"):]
        return p if p.startswith("//") else f"//{self.realm}/{p.lstrip('/')}"

    def receipt_policy(self, endpoint: A.Address, sender_realm: str) -> tuple[str, str]:
        """(mode, scope) for a receipt `endpoint` sends to a sender in `sender_realm`: the narrowest matching
        scope wins (an endpoint over its namespace over a wider namespace), else default (this realm) or
        foreign (another realm)."""
        best = None
        for scope, mode in self.receipts_cfg["scopes"].items():
            pat = self._scope_pattern(scope)
            try:
                if not A.pattern_match(pat, endpoint):
                    continue
            except A.AddressError:
                continue
            path = pat.partition("//")[2].partition("/")[2]
            rank = (0 if path.endswith("/") else 1, len([x for x in path.split("/") if x]))
            if best is None or rank > best[0]:
                best = (rank, mode, scope)
        if best:
            return best[1], best[2]
        if sender_realm == self.realm:
            return self.receipts_cfg["default"], f"{self.realm} (default)"
        return self.receipts_cfg["foreign"], "senders in other realms (foreign)"

    def _remember_asked(self, msg: dict, frm: A.Address, to: A.Address) -> None:
        self._receipt_asked[msg["id"]] = {"from": str(frm), "to": to.key, "type": msg.get("type") or "text/plain",
                                          "asked": msg["hdr"]["airc-receipt"]}
        while len(self._receipt_asked) > 10000:
            self._receipt_asked.popitem(last=False)

    async def _receipt_check(self, msg: dict, frm: A.Address, to: A.Address, origin) -> tuple[str | None, str | None]:
        """(state, why refused). The shape is checked on every face; the site's policy applies to receipts our own
        endpoints send (the client face): off refuses, hook asks the site's hook and fails closed, on sends."""
        try:
            body = json.loads(msg.get("body") or "")
        except ValueError:
            body = None
        state = body.get("state") if isinstance(body, dict) else None
        if state not in RECEIPT_STATES or not msg.get("re"):
            return None, "malformed receipt: body must be {\"state\": seen|done, \"ts\": ...} and re the message it answers"
        hdr = msg.get("hdr")
        if isinstance(hdr, dict):
            hdr.pop("airc-receipt", None)                        # a receipt never carries airc-receipt
        if origin.kind != "client":
            return state, None
        mode, scope = self.receipt_policy(frm, to.realm)
        if mode == "off":
            return state, f"receipts are off for {scope}"
        if mode == "hook":
            orig = self._receipt_asked.get(msg["re"]) or {}
            payload = {"id": msg["re"], "from": str(frm), "to": str(to), "state": state, "sender_realm": to.realm,
                       "type": orig.get("type"), "asked": orig.get("asked")}
            ok, why = await self._receipt_hook(payload)
            if not ok:
                return state, f"receipt not allowed for {scope}: {why}"
        return state, None

    async def _receipt_hook(self, payload: dict) -> tuple[bool, str]:
        """POST the receipt's metadata to the site's hook; {"allow": true} sends it, anything else (a deny, an
        error, a timeout of 3 s) does not: fail closed."""
        url = self.receipts_cfg["hook"]
        if not url:
            return False, "no receipt hook configured"

        def go():
            req = urllib.request.Request(url, data=json.dumps(payload).encode(), method="POST",
                                         headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as r:
                return json.loads(r.read(65536).decode("utf-8", "replace"))
        try:
            d = await asyncio.wait_for(asyncio.get_running_loop().run_in_executor(None, go), 3.5)
        except Exception as e:  # noqa: BLE001  (URLError, timeout, bad JSON)
            log.info("receipt hook %s: %s", url, e)
            return False, f"hook unreachable ({type(e).__name__})"
        if isinstance(d, dict) and d.get("allow") is True:
            return True, ""
        why = d.get("reason") if isinstance(d, dict) and isinstance(d.get("reason"), str) else "denied by the site's hook"
        return False, why

    def _seen_if_taken(self, a: dict) -> dict:
        """§6.6 / §7.3: a control acked delivered or queued is seen like any message, so a replay of it
        is acked duplicate rather than applied again."""
        if a["status"] in ("delivered", "queued") and a.get("code") != "duplicate":
            self.spool.mark_seen(a["id"])
        return a

    def _emit_msg(self, msg: dict, a: dict, origin, frm=None, to=None, kind: str | None = None, hop: str | None = None):
        """hop (§13): client | peer (who handed it to us), local (this server's own), spool (a flush)."""
        hdr = msg.get("hdr") or {}
        self.events.emit(kind or f"msg.{a['status']}",
                         id=msg.get("id"), **{"from": msg.get("from"), "to": msg.get("to")},
                         status=a.get("status"), code=a.get("code"), reason=a.get("reason") or None,
                         by=a.get("by"), hop=hop or ("client" if origin is not None and origin.kind == "client"
                                                     else "peer" if origin is not None else "local"),
                         type=msg.get("type") if msg.get("type") not in (None, "text/plain") else None,
                         re=msg.get("re"), bytes=len(str(msg.get("body", "")).encode()),
                         link=hdr.get("airc-link"), passport=hdr.get("airc-passport"))

    def _fail(self, mid, reason, code=None, by=None):
        self.stats["failed"] += 1
        log.info("msg %s failed: %s", mid, reason)
        return wire.ack(mid, "failed", reason, code, by or self.resolver_uri)

    async def _deliver_local(self, msg: dict, to: A.Address) -> dict:
        if to.key in self.closed:                      # a closed channel (§21.4); listening as it clears this
            return wire.ack(msg["id"], "failed", f"no such channel: {to.local_path} was closed", "path_gone", self.resolver_uri)
        link = self._client_for(to)
        if link is not None and link.queue_only:
            # the winning session has nowhere to push (pull, or a push session without its WebSocket):
            # the message waits, and that session's /inbox returns it
            self.spool.enqueue(to.path[0], msg)
            return wire.ack(msg["id"], "queued", f"{to.local_path} is not connected; queued", "endpoint_offline",
                            self.resolver_uri)
        if link is not None:
            self.stats["out"] += 1
            a = await self._forward_and_wait(link, msg)
            if a["status"] == "failed" and a.get("code") == "link_down":
                # client vanished mid-flight: queue for its return (§6.4: nothing bound now)
                self.spool.enqueue(to.path[0], msg)
                return wire.ack(msg["id"], "queued", "endpoint disconnected; queued", "endpoint_offline", self.resolver_uri)
            self._spool_timed_out(to.path[0], msg, a)
            return a
        if to.path[0] in self.known_ns:
            self.spool.enqueue(to.path[0], msg)
            return wire.ack(msg["id"], "queued", f"no resolver bound for {to.local_path}; queued",
                            "endpoint_offline", self.resolver_uri)
        return wire.ack(msg["id"], "failed", f"no such path {to.local_path}", "no_such_path", self.resolver_uri)

    async def _deliver_remote(self, msg: dict, to: A.Address) -> dict:
        via = list(msg.get("via") or [])
        if self.realm in via or len(via) >= wire.MAX_HOPS:
            return wire.ack(msg["id"], "failed", "routing loop", "routing_loop", self.resolver_uri)
        msg["via"] = via + [self.realm]
        if self.signer and not (msg.get("hdr") or {}).get("sig"):
            self.signer.sign_message(msg, self.extra_signers)
        key = to.authority
        link, why = await self._peer_link(to.realm, to.port)
        if link is None:
            if why == "no_such_authority":
                return wire.ack(msg["id"], "failed", f"no AIRC authority at {key}", why, self.resolver_uri)
            self.spool.enqueue(key, msg)
            detail = self.peer_errors.get(key)
            return wire.ack(msg["id"], "queued", f"{key} unreachable" + (f" ({detail})" if detail else "") + "; queued",
                            "authority_unreachable", self.resolver_uri)
        self.stats["out"] += 1
        a = await self._forward_and_wait(link, msg)
        if a["status"] == "failed" and a.get("code") == "link_down":
            self.spool.enqueue(key, msg)
            return wire.ack(msg["id"], "queued", f"{key} link dropped; queued", "authority_unreachable", self.resolver_uri)
        self._spool_timed_out(key, msg, a)
        return a

    # ------------------------------------------------------------ peer links
    async def _peer_link(self, realm: str, port: int | None = None) -> tuple[Link | None, str]:
        """(link, "") or (None, reason) — reason is no_such_authority when DNS
        has nothing for the realm (permanent) and authority_unreachable when
        it resolved but nothing answered (retry later)."""
        key = realm if port is None else f"{realm}:{port}"
        for l in self.peers.get(key, []):
            if not l.conn.closed and l.authenticated:
                return l, ""
        try:
            eps = await self.resolver.resolve(realm, port)
        except DnsUnavailable as e:                  # §6.5: a lookup went unanswered: maybe there, retry later
            log.warning("resolve %s: %s", key, e)
            self.peer_errors[key] = str(e)[:300]
            return None, "authority_unreachable"
        except OSError as e:
            log.warning("resolve %s: %s", key, e)
            return None, "no_such_authority"
        tried = []                           # why each endpoint failed: the queued ack names it (a CDN's 403 is not a dead host)
        for ep in eps:
            if getattr(ep, "binding", "stream") == "https":
                link = HttpPeerLink(self, key, ep.url)
                if await link.verify():
                    self.peers.setdefault(key, []).append(link)
                    log.info("https peer -> %s via %s", key, ep.url)
                    self.events.emit("peer.up", realm=key, authenticated=True, outbound=True, via=ep.url)
                    self._spawn(self._flush_realm(key))         # §7.4: an authenticated link up, either direction
                    return link, ""
                tried.append(f"{ep.url}: {link.error}")
                continue
            try:
                sslctx = self._client_ssl(ep.host) if ep.tls else None
                r, w = await asyncio.wait_for(
                    asyncio.open_connection(ep.host, ep.port, ssl=sslctx, server_hostname=ep.host if sslctx else None, limit=wire.STREAM_LIMIT), 10)
            except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
                log.warning("connect %s via %s: %s", realm, ep, e)
                tried.append(f"{ep}: {e or type(e).__name__}")
                continue
            conn = Conn(r, w)
            link = Link(conn, "peer")
            link.outbound = True
            try:
                hello = {"t": "hello", "proto": PROTO, "role": "peer", "realm": self.realm, "agent": f"aircd/{__version__}", "features": ["bin"]}
                nonce = os.urandom(12).hex()
                if self.signer:
                    hello.update(self.signer.sign_hello(realm, self.realm, nonce))
                else:
                    hello["nonce"] = nonce
                await conn.send(hello)
                welcome = await asyncio.wait_for(conn.recv(), 10)
                if not welcome or welcome.get("t") != "welcome":
                    raise WireError("no_welcome", str(welcome))
                if str(welcome.get("realm", "")).lower() != realm:
                    raise WireError("realm_mismatch", f"{ep} says it is {welcome.get('realm')}")
                if not self._peer_trusted_unsigned(realm):
                    keys = await self.resolver.public_keys(realm)
                    if not keys or not S.verify_welcome(welcome, realm, self.realm, nonce, keys, self.signing_cfg["accept_algs"]):
                        raise WireError("peer_unverified", f"{ep} did not prove it holds {realm}'s key")
            except (WireError, OSError, asyncio.TimeoutError, S.SigningUnavailable) as e:
                log.warning("handshake with %s via %s failed: %s", realm, ep, e)
                tried.append(f"{ep}: handshake {e or type(e).__name__}")
                await conn.close()
                continue
            link.authenticated = True        # we dialled it: resolved via DNS, TLS to the target, welcome verified
            link.realm = key
            self.peers.setdefault(key, []).append(link)
            log.info("peer link up -> %s via %s", key, ep)
            self.events.emit("peer.up", realm=key, authenticated=True, outbound=True, via=str(ep))
            self._spawn(self._run_outbound(link))
            self._spawn(self._flush_realm(key))                 # §7.4: an authenticated link up, either direction
            return link, ""
        self.peer_errors[key] = "; ".join(tried)[:300]
        return None, "authority_unreachable"

    async def _run_outbound(self, link: Link):
        try:
            await self._read_loop(link)
        except WireError as e:
            log.info("peer %s protocol error: %s", link.realm, e)
        except Exception:
            log.exception("peer link %s crashed", link.realm)
        finally:
            self._unregister(link)
            await link.conn.close()

    # ------------------------------------------------------------- the spool
    async def _flush_namespace(self, ns: str):
        msgs = self.spool.drain(ns)
        for m in msgs:
            if not self._flushable(ns, m):
                continue
            try:
                to = A.parse(m["to"])
            except A.AddressError:
                continue
            link = self._client_for(to)
            if link is None or link.queue_only:                 # nobody to push to: it waits for a read
                self.spool.enqueue(ns, m)
                continue
            a = await self._forward_and_wait(link, m)
            if a["status"] == "failed" and a.get("code") == "link_down":
                self.spool.enqueue(ns, m)
            self._spool_timed_out(ns, m, a)
            log.info("flushed %s -> %s : %s", m["from"], m["to"], a["status"])
            self._emit_msg(m, a, None, kind="msg.flushed", hop="spool")

    async def _flush_realm(self, realm: str):
        msgs = self.spool.drain(realm)
        if not msgs:
            return
        host, _, port = realm.rpartition(":") if realm.count(":") == 1 else (realm, "", "")
        link, _why = await self._peer_link(host or realm, int(port) if port else None)
        if link is None:
            self.spool.requeue(realm, msgs)
            return
        for m in msgs:
            if not self._flushable(realm, m):
                continue
            a = await self._forward_and_wait(link, m)
            if a["status"] == "failed" and a.get("code") == "link_down":
                self.spool.enqueue(realm, m)
            self._spool_timed_out(realm, m, a)
            log.info("flushed %s -> %s : %s", m["from"], m["to"], a["status"])
            self._emit_msg(m, a, None, kind="msg.flushed", hop="spool")

    async def _retry_loop(self):
        while True:
            await asyncio.sleep(self.retry_interval)
            try:
                for key in self.spool.backlog_keys():
                    if "." in key and key not in self.known_ns:
                        await self._flush_realm(key)
                    else:
                        await self._flush_namespace(key)
                now = time.time()
                for realm, links in list(self.peers.items()):
                    for l in links:
                        if l.outbound and now - l.last_activity > PEER_IDLE_CLOSE:
                            await l.conn.close()
            except Exception:
                log.exception("retry loop")

    # ------------------------------------------------------------- front door (§20)
    FRONT_MAX = 100

    def _front(self, ns: str) -> dict:
        """The front door of namespace ns, from config:
             "front": {"<ns>": "directory" | "off" | "agent:<name>"
                              | {"mode": ..., "agent": ..., "about": "…", "entries": [{"agent", "note"?, "hidden"?}]}}
        Default: directory."""
        raw = (self.cfg.get("front") or {}).get(ns, "directory")
        if isinstance(raw, str):
            mode, _, agent = raw.partition(":")
            raw = {"mode": mode, "agent": agent}
        f = {"mode": str(raw.get("mode") or "directory"), "agent": str(raw.get("agent") or "").strip("/"),
             "entries": [e for e in (raw.get("entries") or []) if isinstance(e, dict) and e.get("agent")],
             "about": " ".join(str(raw.get("about") or "").split())[:300]}
        if f["mode"] not in ("directory", "agent", "off") or (f["mode"] == "agent" and not f["agent"]):
            log.warning("front door for %s misconfigured (%r); using directory", ns, raw)
            f["mode"] = "directory"
        return f

    def directory(self, ns: str) -> list[dict]:
        """Listed agents of ns (spec §20.2): endpoints with published key records, plus the
        configured entries, minus hidden ones; sorted, at most FRONT_MAX."""
        prefix = f"airc://{self.realm}/{ns}/"
        out: dict[str, dict] = {}
        for key, rec in self.e2e_keys.items():
            if key.startswith(prefix) and not key[len(prefix):].startswith("_"):
                out[key[len(prefix):]] = {"agent": key[len(prefix):], "keys": True, "require": bool(rec.get("require"))}
        for key, prof in self.profiles.items():                  # §21.1: a profile lists its endpoint too
            if key.startswith(prefix) and not key[len(prefix):].startswith("_"):
                ent = out.setdefault(key[len(prefix):], {"agent": key[len(prefix):], "keys": False, "require": False})
                for f in ("icon", "about", "name"):
                    if prof.get(f):
                        ent[f] = prof[f]
                ent["image"] = bool(prof.get("image"))
        for e in self._front(ns)["entries"]:
            name = str(e["agent"]).strip("/").lower()
            if e.get("hidden"):
                out.pop(name, None)
                continue
            if f"{prefix}{name}" in self.closed:       # §21.4: a closed channel leaves the directory, hand-added
                continue                                # entry included (the config entry returns when it reopens)
            ent = out.setdefault(name, {"agent": name, "keys": False, "require": False})
            if e.get("note"):
                ent["note"] = str(e["note"])[:200]
        for name, ent in out.items():
            st = self.status_of(f"{prefix}{name}")
            if st:
                ent["status"] = st[0]
        return [out[k] for k in sorted(out)][:self.FRONT_MAX]

    def _directory_answer(self, msg: dict, frm: A.Address, to: A.Address) -> dict:
        """Reply to the sender, and only the sender, with the workspace's directory."""
        mid = msg["id"]
        hdr = msg.get("hdr") or {}
        if msg.get("re") or frm.is_reserved or hdr.get("airc-front") or hdr.get("airc-echo-of"):
            return wire.ack(mid, "delivered", "front door: not answered (a reply or an automatic message)",
                            None, self.resolver_uri)
        ns = to.path[0]
        entries = self.directory(ns)
        base = f"//{self.realm}/{ns}"
        lines = [f"[airc directory] {base}", ""]
        about = self._front(ns)["about"]
        if about:
            lines += [about, ""]
        if entries:
            lines.append(f"Agents listed in this workspace ({len(entries)}):")
            for e in entries:
                enc = ("end-to-end keys published, encrypted messages only" if e["require"]
                       else "end-to-end keys published" if e["keys"] else "no end-to-end keys")
                desc = e.get("note") or e.get("about")
                lines.append(f"- {(e['icon'] + ' ') if e.get('icon') else ''}{base}/{e['agent']}"
                             + (f" — {desc}" if desc else "") + f" ({enc})"
                             + (f" [{PR.STATUS_WORDS[e['status']]}]" if e.get("status") else ""))
            if frm.in_realm(self.realm) and frm.path[:1] == (ns,):
                lines += ["", "These are your own workspace's endpoints: message them directly."]
            else:
                lines += ["", "To reach one, send it a link offer saying who you are (spec §11.5), for example:",
                          f"  airc link offer {base}/{entries[0]['agent']} --label \"who you are and why\"",
                          "Most agents accept messages only over a link or a passport."]
        else:
            lines.append("No agents are listed here. Ask whoever gave you this address which agent to contact.")
        hdrs = {"airc-front": "directory", "airc-directory": " ".join(f"airc:{base}/{e['agent']}" for e in entries)}
        reply = wire.new_msg(f"airc:{base}", str(frm), "\n".join(lines), re_id=mid, hdr=hdrs)
        why = self._e2e_refusal(reply, to, frm)
        if why:
            return wire.ack(mid, "delivered", f"front door: directory withheld ({why})", None, self.resolver_uri)
        self._spawn(self._send_own(reply, frm))
        n = len(entries)
        return wire.ack(mid, "delivered", f"directory of {n} agent{'' if n == 1 else 's'} sent to you", None, self.resolver_uri)

    async def _send_own(self, msg: dict, to: A.Address):
        """Deliver a message this server originates (local or remote), logging failures."""
        try:
            a = await (self._deliver_local(msg, to) if to.in_realm(self.realm) and to.port is None
                       else self._deliver_remote(msg, to))
            if a["status"] == "failed":
                log.info("server message %s to %s not delivered: %s", msg["id"], to, a.get("reason"))
        except Exception:
            log.exception("server message to %s", to)

    # ------------------------------------------------------------------ links
    def _ns_keys(self, link: Link) -> list[str] | None:
        """Key prefixes a client may see/act for; None means everything (admin)."""
        if link.uid is not None and link.uid in self.admin_uids and not link.namespaces:
            return None
        return [f"airc://{self.realm}/{ns}/" for ns in link.namespaces]

    # ------------------------------------------------------------- E2E key directory (§19.3)
    def _e2e_save(self):
        tmp = self.e2e_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.e2e_keys, f)
        os.replace(tmp, self.e2e_path)

    def _e2e_ik_of(self, key: str) -> str | None:
        rec = self.e2e_keys.get(key)
        return rec.get("ik") if rec else None

    def e2e_publish(self, link, record: dict) -> tuple[bool, str]:
        try:
            ep = A.parse(str(record.get("endpoint") or ""))
        except A.AddressError as e:
            return False, f"bad endpoint: {e}"
        if not ep.in_realm(self.realm) or not self._owns(link, ep.key):
            return False, f"you may not publish keys for {ep}"
        ok, why = E2E.verify_record(record, ep.key)
        if not ok:
            return False, why
        cur = self.e2e_keys.get(ep.key)
        if cur and int(cur.get("ts", 0)) > int(record.get("ts", 0)):
            return False, "an newer record is already published"
        self.e2e_keys[ep.key] = record
        self.channel_reopen(ep.key)                     # publishing for a closed channel opens it again
        self._e2e_save()
        self.events.emit("e2e.publish", endpoint=ep.key, ifp=E2E.fingerprint(record["ik"]))
        return True, ""

    async def e2e_get(self, endpoint: str, remote_ok: bool) -> tuple[dict | None, str]:
        """The key record for endpoint: ours from the directory; another realm's fetched from its
        peer face when remote_ok (authenticated clients only, so we are not an open proxy)."""
        try:
            ep = A.parse(endpoint)
        except A.AddressError as e:
            return None, f"bad endpoint: {e}"
        if ep.in_realm(self.realm):
            rec = self.e2e_keys.get(ep.key)
            return (rec, "") if rec else (None, "no key record")
        if not remote_ok:
            return None, "not this realm"
        plink, why = await self._peer_link(ep.realm, ep.port)
        base = getattr(plink, "base_url", None)
        if not base:
            return None, f"{ep.realm} has no HTTPS face to ask ({why or 'stream only'})"
        try:
            from .httpbind import _get_json
            rec = await _get_json(f"{base}/airc/v0/keys?endpoint={urllib.parse.quote(ep.key, safe='')}",
                                  insecure=self.cfg.get("tls", {}).get("insecure_skip_verify"))
        except (OSError, ValueError) as e:
            return None, f"{ep.realm}: {e}"
        return (rec, "") if isinstance(rec, dict) and rec.get("t") == "e2e-keys" else (None, "no key record")

    # ------------------------------------------------------------- profiles (§21)
    def _save_json(self, path: str, obj) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(obj, f, ensure_ascii=False)
        os.replace(tmp, path)

    def channel_close(self, key: str) -> None:
        """Close a channel (§21.4): its profile, E2E keys and status go, nothing listens as it, what waits
        for it is dropped, and a message to it fails path_gone until it is opened again."""
        if self.profiles.pop(key, None) is not None:
            self._save_json(self.profiles_path, self.profiles)
        if self.e2e_keys.pop(key, None) is not None:
            self._save_json(self.e2e_path, self.e2e_keys)
        self.statuses.pop(key, None)
        addr = A.parse(key)
        pattern = "//" + self.realm + "/" + addr.local_path
        for l in self.clients:
            if pattern in l.binds:
                l.binds = [b for b in l.binds if b != pattern]
        for m in self.spool.peek(addr.path[0], 10000):
            try:
                if A.parse(m["to"]).key == key:
                    self.spool.remove(addr.path[0], m["id"])
            except (A.AddressError, KeyError):
                continue
        self.closed[key] = time.time()
        self._save_json(self.closed_path, self.closed)
        self.events.emit("channel.close", endpoint=key)

    def channel_reopen(self, key: str) -> None:
        if self.closed.pop(key, None) is not None:
            self._save_json(self.closed_path, self.closed)

    def profile_publish(self, link, record: dict) -> tuple[bool, str]:
        if isinstance(record, dict) and record.get("close") is True:    # close the channel (§21.4)
            try:
                ep = A.parse(str(record.get("endpoint") or ""))
            except A.AddressError as e:
                return False, f"bad endpoint: {e}"
            if not ep.in_realm(self.realm) or len(ep.path) < 2 or not self._owns(link, ep.key):
                return False, f"you may not close {ep}"
            self.channel_close(ep.key)
            return True, "closed"
        if isinstance(record, dict) and record.get("delete") is True:   # take the profile and its page down
            try:
                ep = A.parse(str(record.get("endpoint") or ""))
            except A.AddressError as e:
                return False, f"bad endpoint: {e}"
            if not ep.in_realm(self.realm) or not self._owns(link, ep.key):
                return False, f"you may not delete the profile of {ep}"
            if self.profiles.pop(ep.key, None) is not None:
                tmp = self.profiles_path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(self.profiles, f, ensure_ascii=False)
                os.replace(tmp, self.profiles_path)
                self.events.emit("profile.delete", endpoint=ep.key)
            return True, "deleted"
        ok, why = PR.validate(record)
        if not ok:
            return False, why
        try:
            ep = A.parse(record["endpoint"])
        except A.AddressError as e:
            return False, f"bad endpoint: {e}"
        if not ep.in_realm(self.realm) or len(ep.path) < 2 or ep.is_reserved or not self._owns(link, ep.key):
            return False, f"you may not publish a profile for {ep}"
        cur = self.profiles.get(ep.key)
        if cur and int(cur.get("ts", 0)) > int(record["ts"]):
            return False, "a newer profile is already published"
        rec = PR.clean({**record, "endpoint": ep.key})
        if cur and {k: v for k, v in cur.items() if k != "ts"} == {k: v for k, v in rec.items() if k != "ts"}:
            return True, "unchanged"
        self.profiles[ep.key] = rec
        tmp = self.profiles_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.profiles, f, ensure_ascii=False)
        os.replace(tmp, self.profiles_path)
        self.events.emit("profile.publish", endpoint=ep.key)
        return True, ""

    def profile_get(self, endpoint: str) -> dict | None:
        try:
            ep = A.parse(endpoint)
        except A.AddressError:
            return None
        return self.profiles.get(ep.key) if ep.in_realm(self.realm) else None

    STATUS_FRESH = 300          # §21.2: a status not refreshed for 5 minutes reads as offline

    def status_publish(self, link, statuses) -> tuple[bool, str]:
        if not isinstance(statuses, list) or not statuses:
            return False, "statuses must be a non-empty list of {endpoint, status}"
        now, n = time.time(), 0
        for s in statuses[:1000]:
            try:
                ep = A.parse(str((s or {}).get("endpoint") or ""))
            except A.AddressError as e:
                return False, f"bad endpoint: {e}"
            st = (s or {}).get("status")
            if st not in PR.PUBLISHED_STATUSES:
                return False, f"status must be one of {', '.join(PR.PUBLISHED_STATUSES)}"
            if not ep.in_realm(self.realm) or len(ep.path) < 2 or not self._owns(link, ep.key):
                return False, f"you may not publish the status of {ep}"
            self.statuses[ep.key] = (st, now); n += 1
        for k in [k for k, (_, t) in self.statuses.items() if now - t > self.STATUS_FORGET]:
            del self.statuses[k]                        # §21.2: forgotten after a day
        return True, f"{n} statuses"

    STATUS_FORGET = 86400       # §21.2: a server may forget a status after a day

    def status_of(self, key: str) -> tuple[str, int] | None:
        """(status, age in seconds) for an endpoint, or None when nothing is known (§21.2): a published
        status, offline once 5 minutes stale, forgotten after a day; with none published, pull when the
        session that would take its messages binds in pull mode over HTTPS (it polls /inbox)."""
        rec = self.statuses.get(key)
        if rec:
            age = int(time.time() - rec[1])
            if age <= self.STATUS_FORGET:
                return ("offline" if age > self.STATUS_FRESH else rec[0]), age
            del self.statuses[key]
        try:
            a = A.parse(key)
        except A.AddressError:
            return None
        if a.in_realm(self.realm) and len(a.path) >= 2:
            l = self._client_for(a)
            if l is not None and getattr(l, "mode", None) == "pull":
                return "pull", 0
        return None

    def _on_profile_frame(self, link, frame: dict) -> dict:
        op = frame.get("op")
        if op == "status":
            ok, why = self.status_publish(link, frame.get("statuses"))
            return {"t": "profiled", "ok": ok, "reason": why}
        if op == "publish":
            ok, why = self.profile_publish(link, frame.get("record") or {})
            return {"t": "profiled", "ok": ok, "reason": why}
        if op == "get":
            rec = self.profile_get(str(frame.get("endpoint") or ""))
            if rec is not None:
                try:
                    st = self.status_of(A.parse(rec["endpoint"]).key)
                except A.AddressError:
                    st = None
                if st:
                    rec = {**rec, "status": st[0], "status_age": st[1]}
            return {"t": "profiled", "ok": rec is not None, "record": rec, "reason": "" if rec else "no profile"}
        return {"t": "profiled", "ok": False, "reason": "op must be publish or get"}

    def address_page(self, path: str) -> tuple[int, str, str] | None:
        """(status, markdown, title) for the web page of address path "<ns>[/<agent>...]" (§21.3),
        or None if the path is not an address of this realm."""
        segs = [x for x in path.strip("/").split("/") if x]
        if not segs:
            return None
        try:
            addr = A.parse("//" + self.realm + "/" + "/".join(segs))
        except A.AddressError:
            return None
        if addr.is_reserved:
            return None
        ns = addr.path[0]
        typed = f"//{self.realm}/{'/'.join(addr.path)}"
        if ns not in self.known_ns:
            return 404, PR.missing_page(self.realm, "/".join(addr.path), False), typed
        listed = {e["agent"]: e for e in self.directory(ns)}
        if len(addr.path) == 1:
            f = self._front(ns)
            entries = list(listed.values()) if f["mode"] == "directory" else []
            return 200, PR.workspace_page(self.realm, ns, f["mode"], f["agent"] or None, entries, f["about"]), typed
        agent = "/".join(addr.path[1:])
        if agent not in listed:
            return 404, PR.missing_page(self.realm, "/".join(addr.path), True), typed
        keyrec = self.e2e_keys.get(addr.key)
        ifp = E2E.fingerprint(keyrec["ik"]) if keyrec and E2E.AVAILABLE and keyrec.get("ik") else None
        return 200, PR.agent_page(self.realm, ns, agent, self.profiles.get(addr.key), keyrec, ifp, self.status_of(addr.key)), typed

    async def _on_keys_frame(self, link, frame: dict) -> dict:
        op = frame.get("op")
        if op == "publish":
            ok, why = self.e2e_publish(link, frame.get("record") or {})
            return {"t": "keyed", "ok": ok, "reason": why}
        if op == "get":
            rec, why = await self.e2e_get(str(frame.get("endpoint") or ""), remote_ok=True)
            return {"t": "keyed", "ok": rec is not None, "record": rec, "reason": why}
        return {"t": "keyed", "ok": False, "reason": f"unknown op {op!r}"}

    def _e2e_refusal(self, msg: dict, frm: A.Address, to: A.Address) -> str | None:
        """Why this message may not pass unencrypted, or None (spec §19.7). Site rules, from config:
             "e2e": {"require_outbound": [patterns], "require_inbound": [patterns], "require": [both]}
        require_outbound: plaintext from here to a matching address is not forwarded (site egress);
        require_inbound: plaintext from a matching sender is not accepted. Also an endpoint whose
        published key record says "require": true accepts only encrypted messages. The check is on
        the envelope's shape: it stops mistakes, not an insider who mislabels plaintext on purpose."""
        if to.is_reserved:
            return None
        sealed, what = E2E.looks_sealed(msg)
        if sealed:
            return None
        if msg.get("type") == E2E.MEDIA_TYPE:
            return f"refused: {what}"
        cfg = self.cfg.get("e2e") or {}
        both = list(cfg.get("require") or [])
        if frm.in_realm(self.realm) and not to.in_realm(self.realm):
            for p in both + list(cfg.get("require_outbound") or []):
                if A.pattern_match(p, to):
                    return (f"this site sends only end-to-end encrypted messages to {to.realm} (e2e rule {p}); "
                            f"{to} must publish encryption keys, and the sender's client seals to them (spec §19)")
        if not frm.in_realm(self.realm):
            for p in both + list(cfg.get("require_inbound") or []):
                if A.pattern_match(p, frm):
                    return (f"{self.realm} accepts only end-to-end encrypted messages from {frm.realm} (e2e rule {p}); "
                            f"seal the message to the recipient's published key (spec §19)")
        if to.in_realm(self.realm) and (self.e2e_keys.get(to.key) or {}).get("require"):
            return f"{to} accepts only end-to-end encrypted messages (its key record says require); seal to its key (spec §19)"
        return None

    def _owns(self, link: Link, key: str) -> bool:
        pref = self._ns_keys(link)
        return pref is None or any(key.startswith(p) for p in pref)

    async def _on_link_frame(self, link: Link, frame: dict) -> dict:
        """Client face: {"t":"link","op":offer|accept|decline|revoke|list, ...}."""
        op = frame.get("op")
        ctx_ns = link.namespaces[0] if link.namespaces else ""
        def err(reason, code="refused"):
            return {"t": "linked", "ok": False, "reason": reason, "code": code}
        try:
            if op == "list":
                return {"t": "linked", "ok": True, "links": self.links.involving(
                    None if (frame.get("all") and self._ns_keys(link) is None) else (self._ns_keys(link) or []))}
            me = parse_side(str(frame.get("as") or ""), self.realm, ctx_ns)
        except A.AddressError as e:
            return err(f"bad 'as' address: {e}", "bad_address")
        if not me.in_realm(self.realm) or not self._may_act_for(link, me.key):
            return err(f"you may not act as {me}")
        if op in ("revoke", "unreject") and frame.get("key") is not None and not frame.get("id"):
            return await self._reject_key(link, me, op, frame.get("key"), err)     # §12.7: refuse by key
        if op == "unreject":
            return err("unreject needs key (a pin)", "bad_request")
        if me.key.endswith("/") and op != "revoke":
            return err("a namespace or the realm may only revoke a link it is a side of", "bad_request")
        # §4.6, §19.9: the timestamp and signature the acting endpoint's client made (both optional)
        ts, sig = frame.get("ts"), frame.get("sig")
        if ts is not None and (not isinstance(ts, (int, float)) or isinstance(ts, bool) or abs(ts - time.time()) > 86400):
            return err("ts must be the current time in Unix seconds", "bad_request")
        if sig is not None and (not isinstance(sig, str) or op not in ("offer", "accept", "decline", "revoke")):
            return err("bad sig", "bad_request")
        ik = frame.get("e2e_ik") if isinstance(frame.get("e2e_ik"), str) and len(frame["e2e_ik"]) == 44 else self._e2e_ik_of(me.key)
        if sig and not ik:
            return err("a signed link control needs the endpoint's identity key (e2e_ik, or a published key record)", "bad_request")
        if sig and ts is None:
            return err("a signed link control needs the ts it signed", "bad_request")
        if op == "offer":
            try:
                peer = A.parse(str(frame.get("peer") or ""), self.realm, ctx_ns)
                lid = frame.get("id")
                if lid is not None and not (isinstance(lid, str) and LINK_ID_RE.match(lid)):
                    raise ValueError("bad link id (L and 8 lower-case hex digits)")
                if lid is not None and self.links.get(lid) is not None:
                    raise ValueError(f"link {lid} already exists; an offer needs a new id")
                exp_at = frame.get("expires_at")
                max_ttl = int(self.links_cfg["max_ttl"]) if self.links_cfg["max_ttl"] else None
                if exp_at is not None:                 # §4.6: the absolute expiry the client signed, stored unchanged
                    if not isinstance(exp_at, int) or isinstance(exp_at, bool) or exp_at <= time.time():
                        raise ValueError("expires_at must be a future time in Unix seconds")
                    if max_ttl and exp_at - time.time() > max_ttl + 300:
                        raise ValueError(f"expires_at is beyond this realm's longest link lifetime ({max_ttl} s)")
                    ttl = None
                else:
                    ttl = parse_duration(frame.get("expires"))
                    if max_ttl and (ttl is None or ttl > max_ttl):
                        if sig:                         # capping would change what the client signed
                            raise ValueError(f"this realm caps link lifetimes at {max_ttl} s; sign an expires_at within it")
                        ttl = max_ttl
                rec = LinkStore.make(me.key, peer.key, direction=frame.get("direction") or "both",
                                     label=str(frame.get("label") or ""), expires_in=ttl, offered_by=me.key, link_id=lid)
                if exp_at is not None:
                    rec["expires"] = exp_at
            except (A.AddressError, ValueError) as e:
                return err(str(e), "bad_address" if isinstance(e, A.AddressError) else "bad_request")
            if peer.key == me.key:
                return err("cannot link an endpoint to itself", "bad_address")
            if self.links.pending_from(me.key) >= self.links_cfg["max_pending_per_offerer"]:
                return err("too many pending offers")
            cred = frame.get("credential")
            if cred is not None and not (isinstance(cred, str) and len(cred) <= 1000):
                return err("credential must be a string of at most 1000 characters", "bad_request")
            if sig and E2E.AVAILABLE and not E2E.verify_sig(ik, sig, E2E.link_control_fields(rec, "offer", ts)):
                return err("link control signature invalid")
            self.links.put(rec)
            proof, contact = frame.get("proof"), frame.get("contact")
            if (proof is not None and not isinstance(proof, dict)) or (contact is not None and not isinstance(contact, dict)):
                return err("proof and contact are objects (spec §11.6)", "bad_request")
            ack = await self._send_control(me, peer, "offer", rec, origin=link, e2e_ik=ik, sig=sig, ts=ts, credential=cred,
                                           proof=proof, contact=contact, client_ip=self._client_ip(link))
            if ack.get("code") == "challenge":         # §11.6: relay the challenges; this offer was not made
                self.links.links.pop(rec["id"], None)
                self.links._save()
                return {"t": "linked", "ok": False, "code": "challenge", "reason": ack.get("reason", ""),
                        "challenges": ack.get("challenges") or [], **_delivery(ack)}
            return {"t": "linked", "ok": ack["status"] != "failed", "link": self.links.get(rec["id"]),
                    **_delivery(ack), "reason": ack.get("reason", "")}
        if op in ("accept", "decline", "revoke"):
            rec = self.links.get(str(frame.get("id") or ""))
            if rec and op == "revoke" and me.key not in (rec["a"], rec["b"]) and not me.key.endswith("/") \
                    and (side_matches(rec["a"], me.key) or side_matches(rec["b"], me.key)):
                return await self._opt_out(link, me, rec, err)
            if not rec or me.key not in (rec["a"], rec["b"]):
                return err("no such link for you", "no_such_path")
            if op in ("accept", "decline"):
                if rec["state"] != "pending":
                    return err(f"link is {rec['state']}")
                if rec["offered_by"] == me.key:
                    return err("the offerer cannot accept its own offer")
            elif rec["state"] not in ("pending", "active"):     # §11.2: revoke a pending or active link
                return err(f"link is {rec['state']}")
            elif not me.key.endswith("/") and self._must_accept(rec, me):     # §12.8
                return err("this link is required by site policy")
            if sig and E2E.AVAILABLE and not E2E.verify_sig(ik, sig, E2E.link_control_fields(rec, op, ts)):
                return err("link control signature invalid")
            if op == "accept":                                  # §12.9: accepting issues a passport for the offerer
                ok, why, ack = await self._accept_offer(rec, me, frame, link, e2e_ik=ik, sig=sig, ts=ts)
                cur = self.links.get(rec["id"])
                if not ok:
                    return {"t": "linked", "ok": False, "link": cur, "reason": why, "code": ack.get("code") or "refused",
                            **_delivery(ack)}
                return {"t": "linked", "ok": True, "link": cur, **_delivery(ack), "reason": ack.get("reason", "")}
            new_state = {"decline": "declined", "revoke": "revoked"}[op]
            rec = self.links.set_state(rec["id"], new_state, by=me.key)
            other = parse_side(rec["b"] if rec["a"] == me.key else rec["a"])
            ack = await self._send_control(me, other, op, rec, origin=link, e2e_ik=ik, sig=sig, ts=ts)
            return {"t": "linked", "ok": True, "link": rec, **_delivery(ack), "reason": ack.get("reason", "")}
        return err(f"unknown op {op!r}", "bad_frame")

    def _link_sent(self, link_id: str, frm, to) -> bool:
        """For the status page: did this message leave from our side of the link (sent) or arrive into it?
        Across realms that is which realm it came from. Within this realm both ends are ours, so "sent" means from
        the link's first-listed end (a, shown on the left of the status page's "between" column)."""
        if (frm.realm == self.realm) != (to.realm == self.realm):
            return frm.realm == self.realm
        a = (self.links.links.get(link_id) or {}).get("a")
        return side_matches(a, str(frm)) if a else True

    async def admin_action(self, action: str, ident: str) -> tuple[bool, str]:
        """An operator's action from the status page (/admin): revoke an active link, withdraw an offer we made,
        decline one made to us, or revoke a passport. Taken by the server for the local side, so the peer's
        notice says the server acted (no endpoint signature), as a workspace deletion would."""
        if action in ("revoke-link", "withdraw-offer", "decline-offer"):
            rec = self.links.get(ident)
            if not rec:
                return False, "no such link"
            local = next((k for k in (rec["a"], rec["b"]) if parse_side(k).in_realm(self.realm)), None)
            if local is None:
                return False, "neither side of that link is in this realm"
            me, other = parse_side(local), parse_side(rec["b"] if rec["a"] == local else rec["a"])
            if action == "revoke-link":
                if rec["state"] not in ("pending", "active"):
                    return False, f"link is {rec['state']}"
                op = "revoke"
            elif action == "withdraw-offer":
                if rec["state"] != "pending" or rec.get("offered_by") != local:
                    return False, "not a pending offer made from this realm"
                op = "revoke"                                    # §11.2: an offer is withdrawn by revoking it
            else:
                if rec["state"] != "pending" or rec.get("offered_by") == local:
                    return False, "not a pending offer made to this realm"
                op = "decline"
            rec = self.links.set_state(rec["id"], {"revoke": "revoked", "decline": "declined"}[op], by=me.key)
            self.events.emit(f"link.{op}", link=rec["id"], by=me.key, via="admin")
            ack = await self._send_control(me, other, op, rec)
            if other.in_realm(self.realm):            # both sides are ours: tell the acting side as well
                text = f"[airc: link {rec['id']} with {show_side(other, self.realm, me.namespace)} {rec['state']} by this realm's operator.]"
                note = wire.new_msg(f"airc://{self.realm}/_links", str(me), text,
                                    hdr={"airc-link": rec["id"], "airc-link-action": {"revoked": "revoke", "declined": "decline"}.get(rec["state"], rec["state"]), "airc-peer": other.key})
                await self._notify_endpoint(note, me)
            return True, f"{rec['id']} {rec['state']}; peer notified: {ack.get('status')}"
        if action == "revoke-passport":
            rec = self.passports.get(ident)
            if not rec:
                return False, "no such passport"
            if rec.get("state") != "active":
                return False, f"passport is {rec.get('state')}"
            self.passports.revoke(rec, f"airc://{self.realm}/_admin")
            self.events.emit("passport.revoke", passport=rec["id"], scope=rec["scope"], by="admin")
            return True, f"{rec['id']} revoked; links already made from it stay"
        return False, f"unknown action {action!r}"

    MAX_ACCEPT_PASSPORT_TTL = 600       # §12.9: a passport answering an offer lives at most 600 s

    @staticmethod
    def _mapped_direction(offer_dir: str) -> str:
        """§12.9: the offer's direction with a = the offeree."""
        return {"a-initiates": "b-initiates", "b-initiates": "a-initiates"}.get(offer_dir, "both")

    def _offer_terms(self, rec: dict, fields: dict) -> dict:
        """The terms of the passport that accepts offer rec (§12.9), from what the accepting client signed
        (fields) or defaults; raises PassportRefused when they are wider than the offer."""
        now = time.time()
        mapped = self._mapped_direction(rec["direction"])
        direction = fields.get("direction") or mapped
        if direction != mapped and rec["direction"] != "both":
            raise PassportRefused(f"the passport's direction must be {mapped}, as the offer's", "bad_request")
        exp_at = fields.get("expires_at")
        if exp_at is None:
            exp_at = int(now + self.MAX_ACCEPT_PASSPORT_TTL)
        elif not isinstance(exp_at, int) or isinstance(exp_at, bool) or exp_at > now + self.MAX_ACCEPT_PASSPORT_TTL + 5:
            raise PassportRefused("a passport accepting an offer expires within 600 s", "bad_request")
        remaining = int(rec["expires"] - now) if rec.get("expires") else None
        if remaining is not None and remaining <= 0:
            raise PassportRefused("the offer has expired", "refused")
        lt = fields.get("link_ttl")
        if lt is None:
            lt = self.passports_cfg["link_ttl"] if remaining is None else min(self.passports_cfg["link_ttl"], remaining)
        elif remaining is not None and isinstance(lt, int) and lt > remaining + 5:
            raise PassportRefused("the link would outlive the offer", "bad_request")
        return {"direction": direction, "expires_at": exp_at, "link_ttl": lt}

    async def _accept_offer(self, rec: dict, me: A.Address, fields: dict, client_link=None, e2e_ik=None, sig=None,
                            ts=None) -> tuple[bool, str, dict]:
        """§12.9 steps 1-2 at the offeree's server: issue a passport for the offerer under this realm's policy
        and send it in the accept control. The link becomes active when the offerer's server redeems it.
        Returns (ok, reason, ack of the accept control); on failure the offer stays pending."""
        offerer = parse_side(rec["offered_by"])
        if isinstance(fields.get("passport"), str):    # §12.10: answer with a delegated passport (a forward)
            try:
                fp = P.parse(fields["passport"])
                if not fp.get("layers") and fp["host"] not in (self.passports_cfg["host"], self.realm):
                    raise P.PassportFormatError("another realm")
            except P.PassportFormatError:
                return False, ("an accept may answer with a passport to a scope in this realm, or with a delegated "
                               "passport (§12.9, §12.10)"), {"code": "bad_request"}
            ack = await self._send_control(me, offerer, "accept", rec, origin=client_link, e2e_ik=e2e_ik, sig=sig, ts=ts,
                                           passport=fields["passport"])
            if ack.get("status") != "delivered":
                return False, f"the offer stays pending: {ack.get('reason') or 'the forward was not followed'}", ack
            cur = self.links.get(rec["id"])
            m = re.search(r"forwarded as link (L[0-9a-f]{8})", ack.get("reason", ""))
            if cur is not None and cur["state"] == "pending" and m:
                cur["answered"] = m.group(1)
                self.links._save()
            return True, ack.get("reason", ""), ack
        mode = self.passports_cfg["who"]["endpoint"]
        why = self._may_ask(client_link, me, me.key, "endpoint") if client_link is not None else \
            ("this realm issues no endpoint passports" if mode == "off" else None)
        if why:
            return False, f"cannot accept: {why}", {"code": "unauthorized"}
        try:
            t = self._offer_terms(rec, fields)
            token = fields.get("token") or P.new_token()
            prec, url = self._issue(me.key, me.key, token, t["expires_at"], 1, t["direction"], offerer.key[len("airc:"):],
                                    t["link_ttl"], fields.get("auth") or [], rec.get("label") or "",
                                    extra={"for_offer": rec["id"]}, offer=P.offer_hash_of(rec))
        except PassportRefused as e:
            log.info("accept of %s by %s refused by policy: %s", rec["id"], me, e.reason)
            return False, f"cannot accept: {e.reason}", {"code": e.code}
        ack = await self._send_control(me, offerer, "accept", rec, origin=client_link, e2e_ik=e2e_ik, sig=sig, ts=ts,
                                       passport=url)
        cur = self.links.get(rec["id"]) or {}
        if ack.get("status") != "delivered" or cur.get("state") != "active":
            if prec["state"] == "active":
                self.passports.revoke(prec, me.key)          # nobody else can use it, but it should not linger
            reason = ack.get("reason") or "the offerer's server did not redeem the passport"
            return False, f"the offer stays pending: {reason}", ack
        return True, ack.get("reason", ""), ack

    @staticmethod
    def _client_ip(link) -> str | None:
        """The address of a client's request (§11.6 client_ip): its TCP peer, or its HTTPS request's."""
        ip = getattr(link, "client_ip", None)
        if ip:
            return ip
        try:
            pn = link.conn.writer.get_extra_info("peername")
        except AttributeError:
            return None
        return pn[0] if isinstance(pn, tuple) and pn else None

    def _is_admin(self, link) -> bool:
        return getattr(link, "uid", None) is not None and link.uid in self.admin_uids

    def _may_act_for(self, link, key: str) -> bool:
        """An endpoint or namespace in the client's namespaces; the realm side only for an administrator."""
        if key.count("/") == 3 and key.endswith("/"):
            return self._is_admin(link)
        return self._owns(link, key)

    async def _opt_out(self, link, me: A.Address, group: dict, err) -> dict:
        """§12.7: an endpoint beneath a group side of a link refuses it for itself. A new revoked record
        {a: endpoint, b: other side}, newer than the group link, and a revoke control for it."""
        if not self.links_cfg["opt_out"]:
            return err("this realm does not let endpoints opt out of group links (links.opt_out)")
        if self._must_accept(group, me):
            return err("this link is required by site policy")
        if group["state"] not in ("pending", "active"):
            return err(f"link is {group['state']}")
        mine_a = side_matches(group["a"], me.key) and group["a"] != me.key
        other_key = group["b"] if mine_a else group["a"]
        if side_matches(other_key, me.key):
            return err("cannot opt out of a link whose both sides cover you")
        rec = LinkStore.make(me.key, other_key, direction=group["direction"], label=group.get("label") or "",
                             offered_by=me.key, origin={"opt_out_of": group["id"]})
        rec["created"] = max(rec["created"], round(float(group.get("created") or 0) + 0.001, 3))
        rec["state"] = "revoked"
        rec["revoked_at"] = round(time.time(), 3)
        rec["revoked_by"] = me.key
        self.links.put(rec)
        log.info("link %s: %s opted out of %s", rec["id"], me, group["id"])
        ack = await self._send_control(me, parse_side(other_key), "revoke", rec, origin=link)
        return {"t": "linked", "ok": True, "link": rec, **_delivery(ack), "reason": ack.get("reason", "")}

    async def _reject_key(self, link, me: A.Address, op: str, pin_, err) -> dict:
        """§12.7: link op=revoke with key and no id records {a: endpoint, b: "*", state: revoked,
        origin: {reject_key: pin}} and closes, with revoke controls, the links covering the endpoint whose
        passport that key authorized (origin.pins), except those site policy requires (links.must_accept);
        op=unreject removes it, which lifts the refusal for future grants (closed links stay closed)."""
        if not (isinstance(pin_, str) and re.fullmatch(r"[0-9A-Za-z]{22}", pin_)):
            return err("key must be a pin (22 base62 characters, §12.1)", "bad_request")
        if me.key.endswith("/"):
            return err("an endpoint refuses a key for itself; a namespace or the realm cannot", "bad_request")
        if not self.links_cfg["opt_out"]:
            return err("this realm does not let endpoints refuse links (links.opt_out)")
        mine = [l for l in self.links.rejections(me.key) if l["origin"]["reject_key"] == pin_]
        if op == "unreject":
            if not mine:
                return err(f"{me} does not reject key {pin_}", "no_such_path")
            for l in mine:
                self.links.links.pop(l["id"], None)
            self.links._save()
            log.info("%s no longer rejects key %s", me, pin_)
            self.events.emit("link.unreject", link=mine[0]["id"], **{"from": me.key}, key=pin_)
            return {"t": "linked", "ok": True, "link": mine[0]}
        if mine:
            rec = mine[0]
        else:
            rec = LinkStore.make(me.key, "*", offered_by=me.key, origin={"reject_key": pin_})
            rec.update(state="revoked", revoked_at=round(time.time(), 3), revoked_by=me.key)
            self.links.put(rec)
            log.info("link %s: %s rejects key %s", rec["id"], me, pin_)
            self.events.emit("link.reject", link=rec["id"], **{"from": me.key}, key=pin_)
        closed = []
        for l in list(self.links.links.values()):
            if l is rec or l["b"] == "*" or l["state"] not in ("pending", "active"):
                continue
            if pin_ not in ((l.get("origin") or {}).get("pins") or []):
                continue
            if not (side_matches(l["a"], me.key) or side_matches(l["b"], me.key)) or self._must_accept(l, me):
                continue
            if me.key in (l["a"], l["b"]):
                self.links.set_state(l["id"], "revoked", by=me.key)
                other = parse_side(l["b"] if l["a"] == me.key else l["a"])
                await self._send_control(me, other, "revoke", self.links.get(l["id"]), origin=link)
                closed.append(l["id"])
            else:                                       # a group link: opted out of for this endpoint alone
                r = await self._opt_out(link, me, l, err)
                if r.get("ok"):
                    closed.append(l["id"])
        return {"t": "linked", "ok": True, "link": rec, "closed": closed,
                "reason": f"closed {len(closed)} link(s)" if closed else ""}

    async def _send_control(self, frm: A.Address, to: A.Address, action: str, rec: dict, origin=None,
                            e2e_ik: str | None = None, redemption: str | None = None, sig: str | None = None,
                            ts: float | None = None, passport_auth: dict | None = None, passport: str | None = None,
                            credential: str | None = None, proof: dict | None = None, contact: dict | None = None,
                            client_ip: str | None = None) -> dict:
        """Route a link control message from frm to to. The server originates
        it, so it bypasses the client's namespace check (frm was checked by
        the caller) and goes straight to local handling or the peer. sig and ts: the acting
        endpoint's own signature and the ts it signed (§19.9), passed on unaltered."""
        ctl = {"action": action, "link": rec}
        if isinstance(redemption, str) and 0 < len(redemption) <= 200:
            ctl["redemption"] = redemption            # §12.5: echoed from the redeem it answers
        if passport_auth:
            ctl["passport_auth"] = passport_auth      # §12.6: the keys that authorized the passport
        if passport:
            ctl["passport"] = passport                # §12.9: an accept carries the passport the offerer redeems
        if isinstance(credential, str) and action == "offer":
            ctl["credential"] = credential            # §4.6: opaque, passed on unaltered, never displayed
        if action == "offer" and isinstance(proof, dict):
            ctl["proof"] = proof                      # §11.6: the answer to a challenge
        if action == "offer" and isinstance(contact, dict):
            ctl["contact"] = contact                  # §11.6: given up front
        ik = e2e_ik if isinstance(e2e_ik, str) and len(e2e_ik) == 44 else self._e2e_ik_of(frm.key)
        if ik and sig and action != "grant":
            ctl["e2e"] = {"ik": ik, "sig": sig}       # §19.9: key and signature, exactly as the client gave them
        elif ik and action != "decline":
            ctl["e2e"] = {"ik": ik}                   # §19.9: the acting endpoint's identity key
        body = json.dumps(ctl, separators=(",", ":"))
        msg = wire.new_msg(str(frm), str(to), body, mtype=LINK_TYPE, hdr={"airc-link": rec["id"]})
        if ts is not None:
            msg["ts"] = ts                            # §4.6: the control carries the ts its signature covers
        if to.in_realm(self.realm) and to.port is None:
            return await self._link_control(msg, frm, to, None, client_ip=client_ip)
        return await self._deliver_remote(msg, to)

    async def _link_control(self, msg: dict, frm: A.Address, to: A.Address, origin, client_ip: str | None = None) -> dict:
        """A link control message addressed to a local endpoint (or, when the
        server itself originated it for a local peer, handled in-process)."""
        mid = msg["id"]
        try:
            body = json.loads(msg["body"])
            action = body.get("action")
            raw_link = body.get("link") or {}
            rec = LinkStore.validate(raw_link)
            e2e = body.get("e2e") if isinstance(body.get("e2e"), dict) else {}
            peer_ik, peer_sig = e2e.get("ik"), e2e.get("sig")
            if not isinstance(peer_sig, str) or action == "grant":   # §19.9: a grant's authorization is passport_auth
                peer_sig = None
        except (ValueError, TypeError, A.AddressError) as e:
            return self._fail(mid, f"bad link control: {e}", "bad_address")
        if getattr(origin, "kind", None) == "client":
            # link control is this server's to send (spec §11.4): clients use link frames
            return self._fail(mid, "link control messages come from servers; use a link frame (airc link ...)", "refused")
        if not to.in_realm(self.realm):
            return self._fail(mid, "link control for another realm", "refused")
        if frm.key not in (rec["a"], rec["b"]) or to.key not in (rec["a"], rec["b"]) or frm.key == to.key:
            return self._fail(mid, "link endpoints do not match from/to", "refused")
        known = self.links.get(rec["id"])
        if known is not None and {known["a"], known["b"]} != {frm.key, to.key}:
            # an id another pair's link already has: a control may only ever touch its own pair's record
            return self._fail(mid, f"link {rec['id']} is not between these endpoints", "refused")
        signed = None                                  # §19.9: the fields the acting endpoint signed
        if peer_sig:
            # the integers that went into the canonical string: ts in ms (§9.3 rounding), expires in seconds
            signed = {"a": rec["a"], "b": rec["b"], "direction": rec["direction"], "ts": E2E.ts_ms(msg.get("ts", 0))}
            if raw_link.get("expires") not in (None, ""):
                signed["expires"] = int(float(raw_link["expires"]))
            if not isinstance(peer_ik, str):
                return self._fail(mid, "link control signature invalid", "refused")
            if E2E.AVAILABLE and not E2E.verify_sig(peer_ik, peer_sig, E2E.canonical_link_control(
                    action, rec["id"], rec["a"], rec["b"], rec["direction"], raw_link.get("expires"), msg.get("ts", 0))):
                return self._fail(mid, "link control signature invalid", "refused")
        # origin None: this server sent it to itself for a local pair (§11.4: it notifies a local actor
        # too). The actor's side already applied the action to the one shared store, so only the
        # notice (and auto_accept) remain; every precondition below is for a control from a peer.
        local = origin is None
        grant_pins: list[str] = []
        notice_action = action
        done_reason = None
        if action == "offer":
            if not self.links_cfg["accept_offers"]:
                return self._fail(mid, "this realm does not accept link offers", "refused")
            if rec["offered_by"] != frm.key or rec["state"] != "pending":
                return self._fail(mid, "malformed offer", "refused")
            if body.get("credential") is not None and not (isinstance(body["credential"], str) and len(body["credential"]) <= 1000):
                return self._fail(mid, "an offer's credential is a string of at most 1000 characters", "refused")
            # S4, §11.6: the cheap offer throttles come before any proof is checked or any code is sent
            if not local:
                if known is not None:                   # §11.4: id not yet known
                    return self._fail(mid, f"link {rec['id']} already exists; an offer needs a new id", "refused")
                if self.links.pending_from(frm.key) >= self.links_cfg["max_pending_per_offerer"]:   # §11.5
                    return self._fail(mid, "too many pending offers from you", "refused")
                if self._offers_throttled(frm.realm):                                              # §11.5
                    return self._fail(mid, f"too many link offers from {frm.realm}; try later", "refused")
            challenge_then = None
            if self.challenges is not None:             # §11.6: a proof this realm's policy asks of the offer
                rule = self.challenges.rule_for(frm, to)
                if local and rule and rule["any"] and self._offers_throttled(f"local:{frm.key}"):
                    return self._fail(mid, "too many link offers from you; try later", "refused")
                ok, why, chs = await self.challenges.check(frm, to, body.get("proof"), body.get("contact"),
                                                           client_ip=client_ip if local else None)
                if not ok:
                    log.info("offer %s from %s challenged: %s", rec["id"], frm, why)
                    a = self._fail(mid, why, "challenge")
                    a["challenges"] = chs
                    return a
                challenge_then = rule["then"] if rule and rule["any"] else None   # an exempting rule changes nothing
            if not local:
                self.links.put(rec)
            # §16 item 4: the label is the offerer's text: cleaned, quoted, and also in hdr airc-link-label
            notice = (f"[airc: link offer {rec['id']} from {frm.relative_to(self.realm, to.namespace)}"
                      f"{' labelled ' + _q(rec['label']) if rec['label'] else ''}: they ask to open a message link "
                      f"with {to.relative_to(self.realm, to.namespace)}, direction {rec['direction']}. "
                      "Only their realm is verified: the name and the label are their own claim (a hosted realm "
                      "such as airc.dev lets anyone register an unclaimed name). "
                      f"Accept: airc link accept {rec['id']} --as {to.local_path}   "
                      f"Decline: airc link decline {rec['id']} --as {to.local_path}]")
            if (challenge_then == "accept" or any(A.pattern_match(p, to) for p in self.links_cfg["auto_accept"])) \
                    and self.links.get(rec["id"])["state"] == "pending":
                # §11.4, §12.9: accepted through a passport, as by the endpoint; after this offer is acked
                self._spawn(self._auto_accept(self.links.get(rec["id"]), to, frm))
                notice = None
        elif action == "grant":
            # A link the issuer of a passport created already active: a = the scope (must be the sender),
            # b = the redeemer (must be us), and only in answer to a redemption this server sent (§12.5)
            if rec["a"] != frm.key or rec["b"] != to.key or rec["state"] != "active":
                return self._fail(mid, "malformed grant", "refused")
            if not self.links_cfg["accept_offers"]:
                return self._fail(mid, "this realm does not accept links", "refused")
            red = self._take_redemption(to.key, frm.key, body.get("redemption"))
            if red is None:
                return self._fail(mid, "no redemption of that passport is outstanding", "refused")
            answers_offer = (red.get("offer") == rec["id"] and known is not None and known["state"] == "pending"
                             and known["offered_by"] == to.key)
            if known is not None and not local and not answers_offer:   # §11.4: id not yet known (§12.9: or our offer's)
                return self._fail(mid, f"link {rec['id']} already exists; a grant needs a new id", "refused")
            if red.get("offer") and not answers_offer and not local:
                return self._fail(mid, "the grant does not answer our offer", "refused")
            why = self._grant_problem(body.get("passport_auth"), red, rec)
            if why is None and red.get("realm_key") and not local \
                    and not S.verify_message(msg, [red["realm_key"]], self.signing_cfg["accept_algs"]):
                log.info("grant %s from %s refused: not signed with the passport's realm pin", rec["id"], frm)
                return self._fail(mid, self.REALM_PIN_BAD, "refused")       # §12.3
            if why is None and (red.get("offer") or red.get("forward")):     # §12.9: the signed offer hash is our offer's
                pa = body.get("passport_auth") or {}
                signed_offer = pa.get("offer") or ""
                if pa.get("kind") == "delegated":     # §12.10: a forward carries it in its last layer's body
                    try:
                        signed_offer = P.decode_layer(pa["layers"][-1])["body"].get("offer") or ""
                    except (ValueError, KeyError, IndexError, TypeError, UnicodeDecodeError):
                        signed_offer = ""
                own = red["offer_rec"] if red.get("offer") else red["forward"]["offer_rec"]
                if signed_offer != P.offer_hash_of(own):
                    log.info("grant %s from %s refused: its passport does not answer offer %s", rec["id"], frm, own["id"])
                    return self._fail(mid, "passport does not answer this offer", "refused")
            if why is None and red.get("forward", {}).get("plain"):     # §12.9: bound to exactly the offerer
                if str((body.get("passport_auth") or {}).get("bind_to") or "") != to.key[len("airc:"):]:
                    why = "it is not bound to exactly the offerer"
                    log.info("answering grant %s from %s refused: %s", rec["id"], frm, why)
                    return self._fail(mid, f"passport not authorized: {why}", "refused")
            if why is None and red.get("forward"):      # §12.9: a forwarded link no wider than the offer either
                why = self._forward_wider(red["forward"]["offer_rec"], rec)
                if why:
                    log.info("forwarded grant %s from %s refused: %s", rec["id"], frm, why)
                    return self._fail(mid, f"passport not authorized: {why}", "refused")
            if why is None and red.get("offer"):
                why = self._wider_than_offer(body.get("passport_auth"), red["offer_rec"], rec, to)
                if why:
                    log.info("grant %s from %s refused: %s", rec["id"], frm, why)
                    return self._fail(mid, f"passport not authorized: {why}", "refused")
            if why is not None:
                log.info("grant %s from %s refused: %s", rec["id"], frm, why)
                return self._fail(mid, "passport not authorized" + (f": {why}" if red.get("forward") else ""), "refused")
            gkeys = [a.get("key") for a in body["passport_auth"]["auth"]]
            for r in self.passports_cfg["accept_require"]:                 # §12.8 redeeming side
                if P.scope_pattern_match(r["to"], to.key) and r["key"] not in gkeys:
                    log.info("grant %s from %s refused: lacks a key required for %s", rec["id"], frm, to)
                    return self._fail(mid, "passport lacks a key required here", "refused")
            pins_all = list(red["pins"]) + P.layer_pins(red.get("layers") or [])
            rec["passport_keys"] = gkeys
            rec["origin"] = dict(rec.get("origin") or {}, pins=pins_all)     # §12.7: what a key rejection matches
            hit = self.links.rejected_pin(to.key, pins_all, rec)
            if hit:                                                           # §12.7: rejected by key at redemption
                log.info("grant %s from %s refused: key %s is rejected by %s", rec["id"], frm, hit, to)
                return self._fail(mid, f"passport refused: key {hit} is rejected by {to.key}", "refused")
            if not local:
                self.links.put(rec)
            grant_pins = red["pins"]
            kind = side_kind(rec["a"])
            if not (kind == "endpoint" and isinstance(peer_ik, str) and self._pin_of(peer_ik) in grant_pins):
                peer_ik = None                         # §12.6, §19.9: an identity pin only from the scope endpoint's own key
            if red.get("forward"):                     # §12.10: told once, by the accept that forwarded it
                self._offer_grants[red["forward"]["offer_id"]] = {"forwarded": rec["id"], "scope": rec["a"],
                                                                  "pins": list(red["pins"])}
                notice = None
            elif red.get("offer"):                     # §12.9: the offerer sees only that its offer was accepted:
                self._offer_grants[rec["id"]] = {"pins": grant_pins, "ik": peer_ik, "scope": rec["a"],   # the accept
                                                 "passport": (rec.get("origin") or {}).get("passport") or ""}  # tells it
                notice = None
            else:
                lab = f" labelled {_q(rec['label'])}" if rec.get("label") else ""
                notice = (f"[airc: link {rec['id']} with {show_side(frm, self.realm, to.namespace)}{lab} is open: "
                          f"you redeemed their passport for {kind} {rec['a']}, authorized by key(s) {', '.join(grant_pins)}. "
                          f"Direction {rec['direction']}. Revoke: airc link revoke {rec['id']} --as {to.local_path}]")
        elif action == "accept":
            # §12.9 step 3: redeem the passport only if it answers our own pending offer from this offeree
            cur = known
            if cur is None or cur["offered_by"] != to.key or cur["state"] != "pending" or frm.key == to.key:
                return self._fail(mid, f"link {rec['id']} is no pending offer of ours to you; accept ignored", "refused")
            if not isinstance(body.get("passport"), str):
                return self._fail(mid, "an accept must carry a passport (spec §12.9)", "refused")
            def rerr(reason, code="refused"):
                return {"ok": False, "reason": reason, "code": code}
            # the offeree's own endpoint: the ordinary §12.9 path (the link takes the offer's id); another scope in
            # its realm (a receptionist's answer) or a delegated passport (§12.10): followed by policy, a new link
            r = await self._redeem(None, to, {"passport": body["passport"]}, rerr, offer=cur, answer_from=frm)
            g = self._offer_grants.get(cur["id"], {})
            if g.get("forwarded"):
                self._offer_grants.pop(cur["id"], None)
                if r.get("ok") and r.get("link"):
                    cur = self.links.get(cur["id"])
                    cur["answered"] = g["forwarded"]   # the offer stays pending, marked answered
                    self.links._save()
                    nh = {"airc-link": g["forwarded"], "airc-link-action": "accept", "airc-peer": g["scope"],
                          "airc-passport-scope": g["scope"]}
                    if isinstance(peer_ik, str) and self._pin_of(peer_ik) in (g.get("pins") or []):
                        nh["airc-passport-pins"] = ".".join(g["pins"])     # the offeree's own key signed it
                    note = wire.new_msg(self._notice_from(), str(to),
                                        f"[airc: {show_side(frm, self.realm, to.namespace)} answered your link offer {cur['id']}: "
                                        f"link {g['forwarded']} with {g['scope']} is open.]", hdr=nh)
                    self._spawn(self._notify_endpoint(note, to))
                    log.info("offer %s from %s answered with link %s to %s", cur["id"], frm, g["forwarded"], g["scope"])
                    return wire.ack(mid, "delivered", f"link {cur['id']} answered; forwarded as link {g['forwarded']}",
                                    None, self.resolver_uri)
                r = dict(r, ok=False, reason=r.get("reason") or "the passport was not redeemed")
            now_rec = self.links.get(cur["id"]) or {}
            if not r.get("ok") or now_rec.get("state") != "active":
                why = r.get("reason") or "the passport was not redeemed"
                log.info("accept of %s from %s not completed: %s", cur["id"], frm, why)
                note = wire.new_msg(self._notice_from(), str(to),
                                    f"[airc: {show_side(frm, self.realm, to.namespace)} accepted your link offer {cur['id']}, but "
                                    f"the link could not be opened (reason: {_q(why)}); the offer stays pending.]",
                                    hdr={"airc-link": cur["id"], "airc-link-action": "accept", "airc-peer": frm.key})
                self._spawn(self._notify_endpoint(note, to))
                return self._fail(mid, f"accept not completed: {why}", "refused")
            g = self._offer_grants.pop(cur["id"], {})
            grant_pins = g.get("pins") or []
            if isinstance(g.get("ik"), str) and not isinstance(peer_ik, str):
                peer_ik = g["ik"]
            if not (isinstance(peer_ik, str) and self._pin_of(peer_ik) in grant_pins):
                grant_pins = []                        # §12.9: a passport pin only where the offeree signed it itself;
                                                       # otherwise the accept's key is handled as in §19.9
            notice = f"[airc: link {cur['id']} with {show_side(frm, self.realm, to.namespace)} accepted.]"
            done_reason = f"link {cur['id']} accepted; granted"
        elif action in ("decline", "revoke"):
            cur = known
            if cur is None:
                if action == "revoke":
                    rec["state"] = "revoked"
                    cur = self.links.put(rec)    # a revoke for a link we never saw still blocks
                else:
                    return self._fail(mid, f"unknown link {rec['id']}", "no_such_path")
            elif not local:
                if action == "decline":
                    if cur["offered_by"] != to.key:
                        return self._fail(mid, "only the offeree answers an offer", "refused")
                    if cur["state"] != "pending":   # §11.2; a decline never touches an active link
                        return self._fail(mid, f"link {cur['id']} is {cur['state']}, not pending", "refused")
                elif cur["state"] not in ("pending", "active"):
                    return self._fail(mid, f"link {cur['id']} is {cur['state']}", "refused")
                new_state = {"decline": "declined", "revoke": "revoked"}[action]
                self.links.set_state(cur["id"], new_state, by=frm.key)
            verb = {"decline": "declined", "revoke": "revoked"}[action]
            notice = f"[airc: link {cur['id']} with {show_side(frm, self.realm, to.namespace)} {verb}.]"
        else:
            return self._fail(mid, f"unknown link action {action!r}", "bad_address")
        log.info("link %s %s: %s -> %s", rec["id"], action, frm, to)
        self.events.emit(f"link.{action}", link=rec["id"], **{"from": str(frm), "to": str(to)},
                         state=(self.links.get(rec["id"]) or rec).get("state"), label=rec.get("label") or None)
        # Tell the local endpoint as a plain message it can read. In the
        # background: the control is acknowledged once the record is stored,
        # and the notice is delivered or spooled like any other message.
        nh = {"airc-link": rec["id"], "airc-link-action": notice_action, "airc-peer": frm.key}
        if rec.get("label"):
            nh["airc-link-label"] = rec["label"]       # the other party's own text, verbatim, outside the sentence
        cred = body.get("credential")
        if action == "offer" and isinstance(cred, str) and len(cred) <= 1000:
            nh["airc-offer-credential"] = cred         # §11.4: for the receiving agent to check; not in the text
        if isinstance(peer_ik, str) and len(peer_ik) == 44:
            nh["airc-peer-ik"] = peer_ik               # §19.9: the endpoint pins it with source "link"
        if signed is not None:
            nh["airc-peer-sig"] = peer_sig             # §19.9: so the endpoint can check it itself
            nh["airc-peer-control"] = signed           # the other signed fields (a, b, direction, expires, ts)
        if action == "grant" or (action == "accept" and grant_pins):
            g = self.links.get(rec["id"]) or rec
            nh["airc-passport"] = (g.get("origin") or {}).get("passport") or ""
            nh["airc-passport-scope"] = g["a"]
            nh["airc-passport-pins"] = ".".join(grant_pins)
        if notice is not None and not to.namespace_ref and to.path:     # a namespace or realm side has no inbox to notify
            note = wire.new_msg(self._notice_from(), str(to), notice, hdr=nh)
            self._spawn(self._notify_endpoint(note, to))
        return wire.ack(mid, "delivered", done_reason or f"link {rec['id']} {action} recorded", None, self.resolver_uri)

    def _notice_from(self) -> str:
        """Link and passport notices are this server's own statements (spec §2.6, §11.4): they come
        from //<realm>/_links, signed by this realm, and name the other party in hdr airc-peer."""
        return f"airc://{self.realm}/_links"

    async def _notify_endpoint(self, note: dict, to: A.Address):
        try:
            a = await self._deliver_local(note, to)
            if a["status"] == "failed":
                log.info("link notice to %s not delivered: %s", to, a.get("reason"))
        except Exception:
            log.exception("link notice to %s", to)

    def _offers_throttled(self, src: str) -> bool:
        """§11.5: at most links.offers_per_hour offers admitted per source realm in an hour; counts this one."""
        now = time.time()
        hist = [t for t in self._offer_times.get(src, []) if now - t < 3600]
        if len(hist) >= self.links_cfg["offers_per_hour"]:
            self._offer_times[src] = hist
            return True
        self._offer_times[src] = hist + [now]
        return False

    def _redeem_throttled(self, key: str) -> bool:
        now = time.time()
        hist = [t for t in self._redeem_failures.get(key, []) if now - t < 3600]
        self._redeem_failures[key] = hist
        return len(hist) >= self.passports_cfg["redeem_failures_per_hour"]

    # -------------------------------------------------------------- passports
    def _passport_policy(self, pcfg: dict) -> dict:
        """The site policy for passports (§12.8), from aircd.json "passports" (see aircd.example.json)."""
        kinds = ("endpoint", "namespace", "realm")
        who = {"endpoint": "agents", "namespace": "owner", "realm": "admin"}
        who.update({k: v for k, v in (pcfg.get("who") or {}).items() if k in kinds})
        for k, v in who.items():
            if v not in ("agents", "owner", "admin", "off"):
                raise SystemExit(f"config: passports.who.{k} must be agents, owner, admin or off")
        present = {"endpoint": ["*"], "namespace": ["*"], "realm": []}
        present.update({k: list(v) for k, v in (pcfg.get("present_from") or {}).items() if k in kinds})
        accept = {"endpoint": ["*"], "namespace": ["*"], "realm": ["*"]}
        accept.update({k: list(v) for k, v in (pcfg.get("accept_from") or {}).items() if k in kinds})
        keys = []
        for k in pcfg.get("keys") or []:
            keys.append({"scope": P.scope_of(k["scope"], self.realm), "key": k["key"], "pin": P.pin(k["key"]), "set_by": "config"})
        require = [{"scope": r.get("scope", "*"), "key": r["key"], "role": r.get("role") or "required key"}
                   for r in pcfg.get("require") or []]
        site = None
        if pcfg.get("site_key") and pcfg.get("site_key") not in ("none", "realm"):
            site = SeedKey(_load_seed(pcfg["site_key"]))
        self._site_key_from_realm = pcfg.get("site_key") in (None, "", "realm")   # set once the realm key is loaded
        return {
            "host": (pcfg.get("host") or f"airc.{self.realm}").lower(),
            "who": who, "keys": keys, "require": require, "site_key": site,
            "site_pub": site.public_b64 if site else None,
            "present_from": present, "accept_from": accept,
            "redeem_as_namespace": bool(pcfg.get("redeem_as_namespace", True)),
            # §12.10, §12.8: who may ask for a delegation, to which realms; which root realms a forwarded knock may reach
            "delegate_who": pcfg.get("delegate_who", "owner"),
            "delegate_to": list(pcfg.get("delegate_to") or ["*"]),
            "follow_forwards": list(pcfg.get("follow_forwards", ["*"])),
            # §12.8 redeeming side: keys a grant must carry for a local endpoint or namespace to accept it
            "accept_require": [{"to": self._local_pattern(r.get("to", "*")), "key": r["key"]}
                               for r in pcfg.get("accept_require") or [] if isinstance(r, dict) and r.get("key")],
            "default_ttl": int(pcfg.get("default_ttl", P.DEFAULT_TTL)),
            "max_ttl": int(pcfg.get("max_ttl", 90 * 86400)),
            "default_uses": int(pcfg.get("default_uses", P.DEFAULT_USES)),
            "max_uses": int(pcfg.get("max_uses", 100)),
            "link_ttl": int(pcfg.get("link_ttl", P.DEFAULT_LINK_TTL)),
            "max_keys": int(pcfg.get("max_keys", 4)),
            "redeem_failures_per_hour": int(pcfg.get("redeem_failures_per_hour", 20)),
        }

    def _local_pattern(self, p: str) -> str:
        """A pattern as configured: '*', network form, or local form (resolved against this realm)."""
        p = str(p).strip()
        if p == "*" or p.startswith("//") or p.lower().startswith("airc:"):
            return p
        return f"//{self.realm}/{p.lstrip('/')}"

    def _link_keys(self, rec: dict) -> list[str]:
        """The keys that signed the passport a link came from: kept with the link on the redeeming side,
        found in the passport record on the issuing side."""
        if rec.get("passport_keys"):
            return list(rec["passport_keys"])
        pr = self.passports.get(str((rec.get("origin") or {}).get("passport") or ""))
        return [a["key"] for a in (pr or {}).get("auth") or [] if isinstance(a, dict)]

    def _must_accept(self, rec: dict, me: A.Address) -> bool:
        """§12.8: whether site policy requires endpoint me to accept link rec (it may not revoke or opt out)."""
        rules = self.links_cfg["must_accept"]
        if not rules:
            return False
        other = rec["b"] if side_matches(rec["a"], me.key) and not side_matches(rec["b"], me.key) else rec["a"]
        keys = None
        for m in rules:
            if isinstance(m.get("peer"), str):
                pat = self._local_pattern(m["peer"])
                if pat == "*" or P.scope_pattern_match(pat, other):
                    return True
            if isinstance(m.get("key"), str):
                keys = self._link_keys(rec) if keys is None else keys
                if m["key"] in keys:
                    return True
        return False

    @staticmethod
    def _pin_of(key) -> str | None:
        try:
            return P.pin(key)
        except (ValueError, TypeError):
            return None

    def _may_delegate(self, link, scope: str) -> str | None:
        mode = self.passports_cfg["delegate_who"]
        if mode == "off":
            return "this realm issues no delegations"
        if self._is_admin(link) or mode == "agents":
            return None
        if mode == "admin":
            return "only an administrator may ask for a delegation here"
        return None if (P.scope_kind(scope) != "realm" and self._owns(link, scope)) else "you may not delegate this scope"

    def _may_ask(self, link, me: A.Address, scope: str, kind: str) -> str | None:
        """§12.4 step 1: may this client ask for a passport of this scope? None, or why not."""
        mode = self.passports_cfg["who"][kind]
        if mode == "off":
            return f"this realm issues no {kind} passports"
        if self._is_admin(link):
            return None
        if mode == "admin":
            return f"only an administrator may ask for a {kind} passport here"
        if kind == "realm":
            return None if mode == "agents" else "only an administrator may ask for a realm passport here"
        if not self._owns(link, scope):
            return f"{scope} is outside your namespaces"
        if mode == "agents" and kind == "endpoint" and not P.entitles(me.key, scope) and not self._owns(link, me.key):
            return f"{me} may not ask for a passport of {scope}"
        return None

    def _entitled(self, key: str, scope: str) -> bool:
        """§12.8: whether key may authorize passports for scope. Defaults: an endpoint's published identity
        key for that endpoint and beneath it; the site key for the whole realm. Plus configured and
        key-add entitlements, each covering its scope and everything beneath it."""
        pc = self.passports_cfg
        if pc["site_pub"] and key == pc["site_pub"]:
            return True
        for ent in pc["keys"] + self.passports.keys:
            if ent["key"] == key and P.entitles(ent["scope"], scope):
                return True
        if scope.endswith("/"):
            return False
        # the published E2E identity key of the scope endpoint or of an endpoint above it
        parts = scope.split("/")
        for n in range(len(parts), 3, -1):
            if self._e2e_ik_of("/".join(parts[:n])) == key:
                return True
        return False

    def _required(self, scope: str) -> list[dict]:
        return [r for r in self.passports_cfg["require"] if P.scope_pattern_match(r["scope"], scope)]

    def _auth_entitlement_problem(self, auth: list[dict], scope: str) -> str | None:
        for a in auth:
            if not self._entitled(a["key"], scope):
                return f"key {self._pin_of(a['key'])} is not entitled to authorize passports for {scope}"
        have = {a["key"] for a in auth}
        for r in self._required(scope):
            if r["key"] not in have:
                return f"the passport lacks the {r['role']} ({self._pin_of(r['key'])}) that this realm requires for {scope}"
        return None

    def _passport_url(self, rec: dict, token: str) -> str:
        """The passport; for a delegation (§12.10) its base, with the reference in place of the token."""
        return P.render(self.passports_cfg["host"], rec["scope"], rec["token_hash"] if rec.get("delegates") else token,
                        [P.pin(a["key"]) for a in rec["auth"]], self._realm_pin())

    def _realm_pin(self) -> str | None:
        """§12.3: the pin of the key that signs this realm's capabilities document, for .r=<pin>."""
        return P.pin(self.signer.public_b64) if self.signer else None

    def _issue(self, scope: str, issued_by: str, token, exp_at, uses, direction, bind_to, link_ttl, auth,
               label: str = "", extra: dict | None = None, delegates=None, rules=None, offer=None) -> tuple[dict, str]:
        """§12.4 steps 2-5 for a scope the requester may ask for: check the terms, verify every signature,
        check entitlement, add the site key's signature where policy requires it (or where nobody else
        signed), refuse a missing required key, store. Returns (record, url); raises PassportRefused."""
        pc = self.passports_cfg
        try:
            if not P.valid_token(token):
                raise ValueError("token must be base62, 22 to 64 characters, generated by the client (§12.2)")
            if not isinstance(exp_at, int) or isinstance(exp_at, bool) or exp_at <= time.time():
                raise ValueError("expires_at must be a future time in integer Unix seconds")
            if exp_at - time.time() > pc["max_ttl"] + 300:
                raise ValueError(f"expires_at is beyond this realm's longest passport lifetime ({pc['max_ttl']} s)")
            if not isinstance(uses, int) or isinstance(uses, bool) or uses < 1:
                raise ValueError("uses must be a positive integer")
            if uses > pc["max_uses"]:
                raise ValueError(f"this realm allows at most {pc['max_uses']} uses")
            if direction not in P.DIRECTIONS:
                raise ValueError("bad direction")
            if bind_to:
                A.pattern_match(bind_to, A.parse("//example.invalid/x"))   # syntax check only
            if link_ttl is not None and (not isinstance(link_ttl, int) or isinstance(link_ttl, bool) or link_ttl <= 0):
                raise ValueError("link_ttl must be a positive integer number of seconds")
            max_lt = int(self.links_cfg["max_ttl"]) if self.links_cfg["max_ttl"] else None
            if max_lt and (link_ttl is None or link_ttl > max_lt):
                raise ValueError(f"this realm caps link lifetimes at {max_lt} s")
            if offer is not None and not (isinstance(offer, str) and P._REF.match(offer)):
                raise ValueError("offer must be an offer hash (64 lowercase hex digits, §12.9)")
            if delegates is not None:                   # §12.10: a delegation
                if offer:
                    raise ValueError("a delegation answers no offer; a forwarding layer carries the offer hash (§12.10)")
                delegates = P.norm_delegates(delegates)
                if rules is not None and not isinstance(rules, dict):
                    raise ValueError("rules must be an object")
                for d in delegates:
                    if not P._realm_allowed(pc["delegate_to"], d["realm"]):
                        raise PassportRefused(f"this realm does not delegate to {d['realm']}", "unauthorized")
                data = P.canonical_delegate(scope, P.token_hash(token), direction, exp_at, uses, bind_to, link_ttl,
                                            delegates, rules)
            else:
                data = P.canonical(scope, P.token_hash(token), direction, exp_at, uses, bind_to, link_ttl, offer)
            why = P.auth_problem(auth, data)
            if why:
                raise ValueError(why)
        except (ValueError, A.AddressError) as e:
            raise PassportRefused(str(e), "bad_request")
        auth = [{"key": a["key"], "sig": a["sig"]} for a in auth]
        for a in auth:                                              # §12.4 step 3
            if not self._entitled(a["key"], scope):
                raise PassportRefused(f"key {self._pin_of(a['key'])} is not entitled to authorize passports for {scope}", "unauthorized")
        have = {a["key"] for a in auth}
        need_site = any(r["key"] == pc["site_pub"] for r in self._required(scope)) or not auth
        if pc["site_key"] and pc["site_pub"] not in have and need_site:
            auth.append({"key": pc["site_pub"], "sig": pc["site_key"].sign(data)})
        why = self._auth_entitlement_problem(auth, scope)            # §12.4 step 4
        if why:
            raise PassportRefused(why, "unauthorized")
        if not auth:
            raise PassportRefused("a passport needs at least one authorizing key: sign it with an entitled key", "unauthorized")
        if len(auth) > pc["max_keys"]:
            raise PassportRefused(f"this realm accepts at most {pc['max_keys']} authorizing keys", "bad_request")
        try:
            rec = self.passports.issue(scope, token, label=label, expires=exp_at, uses=uses, direction=direction,
                                       bind_to=bind_to, link_ttl=link_ttl, issued_by=issued_by, auth=auth,
                                       delegates=delegates, rules=rules, offer=offer)
        except ValueError as e:
            raise PassportRefused(str(e), "bad_request")
        if extra:
            rec.update(extra)
            self.passports._save()
        log.info("passport %s for %s issued by %s (uses=%d, to=%s, keys=%d)", rec["id"], scope, issued_by, uses, bind_to, len(auth))
        self.events.emit("passport.issue", passport=rec["id"], scope=scope, endpoint=issued_by, uses=uses,
                         expires=rec["expires"], bind_to=bind_to, label=rec.get("label") or None)
        return rec, self._passport_url(rec, token)

    async def _on_passport_frame(self, link: Link, frame: dict) -> dict:
        """Client face: {"t":"passport","op":new|list|revoke|redeem|key-add|key-list|key-remove, ...} (§4.7)."""
        op = frame.get("op")
        ctx_ns = link.namespaces[0] if link.namespaces else ""
        pc = self.passports_cfg
        def err(reason, code="refused"):
            return {"t": "passported", "ok": False, "reason": reason, "code": code}
        prefixes = None if (frame.get("all") and self._is_admin(link)) else self._ns_keys(link)
        if op == "list":
            return {"t": "passported", "ok": True, "passports": self.passports.for_scopes(prefixes)}
        if op == "revoke-layer":                        # §12.10: this realm, as a delegate, closes a layer it signed
            return await self._send_revoke_layer(link, frame, err)
        if op == "key-list":
            ks = pc["keys"] + self.passports.keys
            if prefixes is not None:
                ks = [k for k in ks if any(k["scope"].startswith(p) for p in prefixes)]
            return {"t": "passported", "ok": True,
                    "keys": [{"scope": k["scope"], "key": k["key"], "pin": k["pin"], "set_by": k["set_by"]} for k in ks]}
        try:
            me = parse_side(str(frame.get("as") or ""), self.realm, ctx_ns)
        except A.AddressError as e:
            return err(f"bad 'as' address: {e}", "bad_address")
        if not me.in_realm(self.realm) or not self._may_act_for(link, me.key):
            return err(f"you may not act as {me}")
        if op in ("new", "key-add", "key-remove"):
            try:
                scope = P.scope_of(str(frame["scope"]), self.realm, ctx_ns) if frame.get("scope") else me.key
            except A.AddressError as e:
                return err(f"bad scope: {e}", "bad_address")
            if parse_side(scope).realm != self.realm or parse_side(scope).port is not None:
                return err(f"{scope} is not in this realm", "bad_address")
            kind = P.scope_kind(scope)
        if op in ("key-add", "key-remove"):
            if not (self._is_admin(link) or (kind != "realm" and self._owns(link, scope))):
                return err(f"you may not set passport keys for {scope}", "unauthorized")
            key = frame.get("key")
            if self._pin_of(key) is None:
                return err("key must be a base64 ed25519 public key", "bad_request")
            if op == "key-add":
                k = self.passports.key_add(scope, key, "admin" if self._is_admin(link) else me.key)
                self.events.emit("passport.key-add", scope=scope, pin=k["pin"], by=me.key)
                return {"t": "passported", "ok": True, "keys": [{x: k[x] for x in ("scope", "key", "pin", "set_by")}]}
            if not self.passports.key_remove(scope, key):
                return err("no such key for that scope", "no_such_path")
            self.events.emit("passport.key-remove", scope=scope, pin=self._pin_of(key), by=me.key)
            return {"t": "passported", "ok": True, "keys": []}
        if op == "new":
            why = self._may_ask(link, me, scope, kind)
            delegating = frame.get("delegates") is not None
            if not why and delegating:                  # §12.8: whether to issue delegations, and who may ask
                why = self._may_delegate(link, scope)
            if why:
                return err(why, "unauthorized")
            offer = frame.get("offer")
            if frame.get("for_offer") is not None:      # §12.9: a receptionist's answer, for a pending offer to me
                o = self.links.get(str(frame.get("for_offer")))
                to = o["b"] if o and o.get("offered_by") == o.get("a") else (o or {}).get("a", "")
                mine = to == me.key or (me.key.endswith("/") and to.startswith(me.key))   # the offeree, or inside my namespace
                if not o or o["state"] != "pending" or not mine:
                    return err(f"no pending offer {frame.get('for_offer')} to {me}", "no_such_path")
                h = P.offer_hash_of(o)
                if offer is not None and offer != h:
                    return err("offer is not the hash of that pending offer", "bad_request")
                offer = h
            try:
                rec, url = self._issue(scope, me.key, frame.get("token"), frame.get("expires_at"),
                                       frame.get("uses", pc["default_uses"]), frame.get("direction") or "both",
                                       frame.get("to") or None, frame.get("link_ttl", pc["link_ttl"]),
                                       frame.get("auth") if frame.get("auth") is not None else [], str(frame.get("label") or ""),
                                       delegates=frame.get("delegates") if delegating else None, rules=frame.get("rules"),
                                       offer=offer or None)
            except PassportRefused as e:
                return err(e.reason, e.code)
            out = {"t": "passported", "ok": True, "passport": P.PassportStore.public(rec), "url": url}
            if delegating:
                out["reference"] = rec["token_hash"]      # §12.10: what the delegate gets; never the token
            return out
        if op == "revoke":
            rec = self.passports.get(str(frame.get("id") or ""))
            if not rec or not (self._is_admin(link) or self._may_act_for(link, rec["scope"])):
                return err("no such passport for you", "no_such_path")
            self.passports.revoke(rec, me.key)
            self.events.emit("passport.revoke", passport=rec["id"], scope=rec["scope"], by=me.key)
            revoked_links = []
            if frame.get("and_links"):
                for l in list(self.links.links.values()):
                    if l.get("origin", {}).get("passport") == rec["id"] and l["state"] in ("pending", "active"):
                        self.links.set_state(l["id"], "revoked", by=me.key)
                        await self._send_control(parse_side(l["a"]), parse_side(l["b"]), "revoke", self.links.get(l["id"]))
                        revoked_links.append(l["id"])
            return {"t": "passported", "ok": True, "passport": P.PassportStore.public(rec), "revoked_links": revoked_links}
        if op == "redeem":
            return await self._redeem(link, me, frame, err)
        return err(f"unknown op {op!r}", "bad_frame")

    async def _redeem(self, link, me: A.Address, frame: dict, err, offer: dict | None = None,
                      expect_scope: str | None = None, forward: dict | None = None, answer_from: A.Address | None = None) -> dict:
        """§12.5: redeem a passport for me (an endpoint, or a namespace where policy allows). offer and
        expect_scope: for a passport answering our offer (§12.9), the offer and the offeree endpoint."""
        pc = self.passports_cfg
        if me.key.endswith("/"):
            if not me.path:
                return err("the realm cannot redeem a passport; redeem as an endpoint or a namespace", "bad_request")
            if not pc["redeem_as_namespace"]:
                return err("this realm does not let its endpoints redeem as a namespace", "refused")
        try:
            pp = P.parse(frame.get("passport"))
        except P.PassportFormatError as e:
            return err(str(e), "bad_request")
        issuer, code, why = await self._passport_issuer(pp["host"])
        if issuer is None:
            return err(f"cannot verify the passport's host {pp['host']}: {why}", code)
        realm_key = None
        if pp.get("realm_pin"):                         # §12.3: trust exactly that realm key, not DNS alone
            realm_key, why = await self._realm_pin_key(issuer, pp["host"], pp["realm_pin"])
            if why:
                return err(why, "refused")
        try:
            scope = P.scope_of(f"//{issuer}/{pp['path']}" if pp["path"] else f"//{issuer}/")
        except A.AddressError as e:
            return err(f"cannot read passport: {e}", "bad_request")
        kind = P.scope_kind(scope)
        if answer_from is not None:                     # §12.9 step 3: what an accept's passport may be
            if pp.get("layers"):
                forward, offer = {"offer": offer, "offeree": answer_from}, None
            elif scope != answer_from.key:              # another scope in the offeree's realm (a receptionist)
                if issuer != answer_from.authority:
                    return err(f"the passport's realm {issuer} is not the offeree's realm {answer_from.authority}", "refused")
                if not P._realm_allowed(pc["follow_forwards"], issuer):
                    return err(f"forward refused: this realm does not follow forwarded knocks to {issuer} "
                               "(passports.follow_forwards)", "refused")
                forward, offer = {"offer": offer, "offeree": answer_from, "plain": True}, None
        if expect_scope is not None and scope != expect_scope:               # §12.9 step 3
            return err(f"the passport's scope {scope} is not the offeree {expect_scope}", "refused")
        if not self._realm_listed(pc["accept_from"][kind], issuer):          # §12.5 step 2
            return err(f"this realm accepts no {kind} passports from {issuer}", "refused")
        layers = pp.get("layers") or []
        if forward is not None and not forward.get("plain"):     # §12.9 step 3, §12.10: a forwarded knock
            why = self._forward_problem(pp, issuer, me, forward)
            if why:
                return err(f"forward refused: {why}", "refused")
        redemption = secrets.token_urlsafe(18)          # §12.5: the grant must carry this back, once
        self._redemptions[(me.key, scope, redemption)] = {
            "exp": time.time() + 600, "at": time.time(), "pins": list(pp["pins"]),
            "token_sha256": pp["token"] if layers else P.token_hash(pp["token"]), "scope": scope, "layers": layers,
            "realm_key": realm_key,
            **({"offer": offer["id"], "offer_rec": dict(offer)} if offer else {}),
            **({"forward": {"offer_id": forward["offer"]["id"], "offer_rec": dict(forward["offer"]),
                            "offeree_realm": forward["offeree"].authority, "plain": bool(forward.get("plain"))}}
               if forward else {})}
        if layers:                                      # §12.10: the reference and the layers, never a token
            body = json.dumps({"action": "redeem", "scope": scope, "reference": pp["token"], "layers": layers,
                               "redeemer": me.key, "redemption": redemption}, separators=(",", ":"))
        else:
            body = json.dumps({"action": "redeem", "scope": scope, "token": pp["token"], "redeemer": me.key,
                               "redemption": redemption}, separators=(",", ":"))
        target = A.parse(f"//{issuer}/{P.ENDPOINT_NAME}")
        msg = wire.new_msg(str(me), str(target), body, mtype=PASSPORT_TYPE, ttl=600)
        if target.in_realm(self.realm):
            a = await self._passport_control(msg, me, None)
        else:
            a = await self._deliver_remote(msg, target)
        ok = a["status"] == "delivered"
        reason = self._peer_safe(a) if answer_from is not None else a.get("reason", "")   # S7: a peer asked for this
        out = {"t": "passported", "ok": ok, "status": a["status"], "reason": reason}
        if a.get("code"):
            out["code"] = a["code"]
        if ok and a.get("reason", "").startswith("link "):
            link = self.links.get(a["reason"].split()[1])
            if link is None:
                out["ok"] = False                    # §4.7: no link record, so none is carried
            else:
                out["link"] = link
        return out

    def _forward_problem(self, pp: dict, root: str, me: A.Address, forward: dict) -> str | None:
        """§12.10 Forwarding a knock, the checks the offerer can make before redeeming: a delegated passport,
        its last layer bound to exactly the offerer, signed (where the previous layer shows it) by a key
        the chain names for the offeree's realm, to a root realm our policy follows. The realm of a
        one-layer chain's key is checked on the grant, from the delegation's delegates."""
        layers = pp.get("layers") or []
        if not layers:
            return "the passport is neither the offeree's own nor a delegated one"
        if not P._realm_allowed(self.passports_cfg["follow_forwards"], root):
            return f"this realm does not follow forwarded knocks to {root} (passports.follow_forwards)"
        try:
            last = P.decode_layer(layers[-1])
            prev = P.decode_layer(layers[-2]) if len(layers) > 1 else None
        except (ValueError, UnicodeDecodeError) as e:
            return f"a layer is malformed ({e})"
        if last["body"].get("bind_to") != me.key[len("airc:"):]:
            return "its last layer is not bound to exactly the offerer"
        if prev is not None and P._realm_of(last["pin"], prev["body"].get("delegates") or []) != forward["offeree"].authority:
            return f"its last layer was not signed by a key of {forward['offeree'].authority}"
        return None

    @staticmethod
    def _realm_listed(patterns: list[str], realm: str) -> bool:
        return any(p == "*" or p.lower() == realm for p in patterns)

    def _redeemer_listed(self, patterns: list[str], redeemer: A.Address) -> bool:
        for p in patterns:
            if p == "*" or p.lower() == redeemer.realm:
                return True
            if p.startswith("//") or p.startswith("airc:"):
                try:
                    if A.pattern_match(p, redeemer) or (p.endswith("/") and P.entitles(P.scope_of(p), redeemer.key)):
                        return True
                except A.AddressError:
                    continue
        return False

    async def _passport_issuer(self, host: str) -> tuple[str | None, str, str]:
        """§12.5 step 1: the realm a passport host serves, from its verified capabilities document.
        Configured peers (static or plaintext, as in tests) are trusted as configured.
        Returns (realm, "", "") or (None, code, why)."""
        if host in (self.passports_cfg["host"], self.realm):
            return self.realm, "", ""
        for realm, pc in (self.cfg.get("peers") or {}).items():
            realm = realm.lower()
            base = pc.get("https") if isinstance(pc, dict) else None
            names = {realm, f"airc.{realm}", str((pc or {}).get("passport_host") or "").lower()}
            if base and urllib.parse.urlsplit(base).netloc.lower() == host:
                names.add(host)
            if host not in names:
                continue
            if base:
                link = HttpPeerLink(self, realm, base)
                if not await link.verify():
                    log.info("passport host %s (%s): %s", host, realm, link.error)
                    return None, "authority_unreachable", self.ISSUER_GENERIC
            return realm, "", ""
        nonce = os.urandom(12).hex()
        try:
            from .httpbind import _get_json
            doc = await _get_json(f"https://{host}/.well-known/airc?nonce={nonce}",
                                  insecure=self.cfg.get("tls", {}).get("insecure_skip_verify"))
            realm = str((doc or {}).get("realm") or "").lower()
            A.parse(f"//{realm}/x")
        except (OSError, ValueError, A.AddressError) as e:
            log.info("passport host %s: capabilities fetch: %s", host, e)      # S7: the detail stays here
            return None, "authority_unreachable", self.ISSUER_GENERIC
        link = HttpPeerLink(self, realm, f"https://{host}")
        if not await link.verify():
            log.info("passport host %s (%s): %s", host, realm, link.error)
            return None, "authority_unreachable", self.ISSUER_GENERIC
        return realm, "", ""

    REALM_PIN_BAD = "passport: the realm pin does not match the issuer's key"

    async def _realm_pin_key(self, issuer: str, host: str, rpin: str) -> tuple[str | None, str | None]:
        """§12.3: the realm key a passport's .r=<pin> names: among the keys the issuer publishes, and the one
        its capabilities document (served by host) verifies with. Returns (key or None, None) or (None, why).
        This realm's own pin is checked against its signer; a configured peer trusted without keys (a test
        stand-in for DNS) has nothing to check against; a configured stream peer serves no capabilities
        document, so only the published keys are checked."""
        if issuer == self.realm:
            return (None, None) if rpin == self._realm_pin() else (None, self.REALM_PIN_BAD)
        peer = next((pc for r, pc in (self.cfg.get("peers") or {}).items() if r.lower() == issuer), None)
        if peer is not None and issuer not in self.resolver.known_keys and self._peer_trusted_unsigned(issuer):
            return None, None
        try:
            keys = await self.resolver.public_keys(issuer)
        except S.SigningUnavailable:
            return None, self.REALM_PIN_BAD
        key = next((k for k in keys if self._pin_of(k) == rpin), None)
        if key is None:
            log.info("passport realm pin %s is not among the keys %s publishes", rpin, issuer)
            return None, self.REALM_PIN_BAD
        base = peer.get("https") if isinstance(peer, dict) else None
        if peer is not None and not base:
            return key, None
        nonce = os.urandom(12).hex()
        try:
            from .httpbind import _get_json
            doc = await _get_json(f"{(base or f'https://{host}').rstrip('/')}/.well-known/airc?nonce={nonce}",
                                  insecure=self.cfg.get("tls", {}).get("insecure_skip_verify"))
            ok = S.verify_capabilities(doc or {}, issuer, nonce, [key], accept=self.signing_cfg["accept_algs"])
        except (OSError, ValueError, S.SigningUnavailable) as e:
            log.info("passport realm pin: capabilities of %s: %s", issuer, e)
            ok = False
        if not ok:
            log.info("passport realm pin %s: the capabilities of %s do not verify with that key", rpin, issuer)
            return None, self.REALM_PIN_BAD
        return key, None

    ISSUER_GENERIC = "the passport's host did not serve a verifiable capabilities document"
    _UNREACHABLE = ("authority_unreachable", "no_such_authority", "link_down", "no_ack")

    def _peer_safe(self, a: dict) -> str:
        """An ack's reason fit to pass on to a peer (S7): a failure to reach a third host says only that."""
        if a.get("code") in self._UNREACHABLE or a.get("status") == "queued":
            return "the other realm could not be reached"
        return a.get("reason", "")

    def _take_redemption(self, redeemer: str, scope: str, redemption) -> dict | None:
        """Consume the outstanding redemption by redeemer of a passport of scope whose value the grant
        echoes (§12.5): its record, or None. One redemption, one grant: the value is gone after."""
        now = time.time()
        self._redemptions = {k: r for k, r in self._redemptions.items() if r["exp"] > now}
        if not isinstance(redemption, str):
            return None
        return self._redemptions.pop((redeemer, scope, redemption), None)

    def _wider_than_offer(self, pa: dict, offer: dict, rec: dict, me: A.Address) -> str | None:
        """§12.9: a passport answering our offer is bound to us, single-use, short-lived, and no wider than
        the offer: the mapped direction (any, for an offer of both), a link no longer-lived than the offer."""
        now = time.time()
        mapped = self._mapped_direction(offer["direction"])
        if offer["direction"] != "both" and pa.get("direction") != mapped:
            return f"its direction {pa.get('direction')} is wider than the offer's"
        if str(pa.get("bind_to") or "") != me.key[len("airc:"):]:
            return "it is not bound to the offerer alone"
        if pa.get("uses") != 1:
            return "it is not single-use"
        if pa.get("expires") in (None, "") or float(pa["expires"]) > now + self.MAX_ACCEPT_PASSPORT_TTL + self.LINK_EXPIRY_SKEW:
            return "it lives longer than 600 s"
        if offer.get("expires"):
            if rec.get("expires") is None or float(rec["expires"]) > float(offer["expires"]) + self.LINK_EXPIRY_SKEW:
                return "the link would outlive the offer"
        return None

    def _forward_wider(self, offer: dict, rec: dict) -> str | None:
        mapped = self._mapped_direction(offer["direction"])
        if offer["direction"] != "both" and rec["direction"] != mapped:
            return f"the forwarded link's direction {rec['direction']} is wider than the offer's"
        if offer.get("expires") and (rec.get("expires") is None
                                     or float(rec["expires"]) > float(offer["expires"]) + self.LINK_EXPIRY_SKEW):
            return "the forwarded link would outlive the offer"
        return None

    async def _auto_accept(self, rec: dict, me: A.Address, offerer: A.Address):
        """§11.4 auto_accept: accept as in §12.9, under the same issuing policy; tell the endpoint."""
        try:
            ok, why, _ = await self._accept_offer(rec, me, {})
        except Exception as e:
            log.exception("auto_accept of %s", rec["id"])
            ok, why = False, str(e)
        text = (f"[airc: link {rec['id']} with {offerer.relative_to(self.realm, me.namespace)} opened automatically (auto_accept).]"
                if ok else f"[airc: link offer {rec['id']} from {offerer.relative_to(self.realm, me.namespace)} could not be "
                           f"accepted automatically (reason: {_q(why)}); it stays pending. Accept: airc link accept {rec['id']} --as {me.local_path}]")
        note = wire.new_msg(self._notice_from(), str(me), text,
                            hdr={"airc-link": rec["id"], "airc-link-action": "accept" if ok else "offer", "airc-peer": offerer.key})
        await self._notify_endpoint(note, me)

    LINK_EXPIRY_SKEW = 300          # clock difference allowed between the issuer and us when checking a granted link's expiry

    def _grant_problem(self, pa, red: dict, rec: dict) -> str | None:
        """§12.6 redeemer checks 1-4 on a grant's passport_auth: None when it holds, else what is wrong."""
        if not isinstance(pa, dict) or not isinstance(pa.get("auth"), list) or not pa["auth"]:
            return "no passport_auth"
        try:
            pins = [P.pin(a["key"]) for a in pa["auth"]]
            if len(set(pins)) != len(pins) or set(pins) != set(red["pins"]):
                return "its keys are not the passport's pins"                      # 1
            if str(pa.get("token_sha256", "")).lower() != red["token_sha256"]:
                return "it is for another token"                                    # 2
            if pa.get("scope") != red["scope"]:
                return "it is for another scope"
            if not E2E.AVAILABLE:
                return "this server cannot check signatures (python package cryptography missing)"
            data = P.canonical_of(pa)
            for a in pa["auth"]:                                                    # 3
                if not P.verify(a["key"], a.get("sig"), data):
                    return f"the signature of key {P.pin(a['key'])} does not verify"
            want_dir, lt = pa.get("direction"), pa.get("link_ttl")
            if pa.get("kind") == "delegated" or red.get("layers"):           # §12.10: every layer, against its pins
                if pa.get("kind") != "delegated" or list(pa.get("layers") or []) != list(red.get("layers") or []):
                    return "its layers are not the passport's"
                try:
                    ch = P.check_chain(pa, pa["layers"])
                except P.ChainError as e:
                    return str(e)
                want_dir, lt = ch["direction"], ch["link_ttl"]
                if not all(self._bind_match(bt, parse_side(rec["b"])) for bt in ch["bind_tos"]):
                    return "the redeemer does not match a bind_to along the chain"
                fw = red.get("forward")
                if fw and ch["chain"][-1]["realm"] != fw["offeree_realm"]:
                    return "the forward does not come from the offeree's realm"
            if rec["a"] != red["scope"] or rec["direction"] != want_dir:          # 4
                return "the link does not match its terms"
            if lt not in (None, ""):
                if rec.get("expires") is None or float(rec["expires"]) > time.time() + float(lt) + self.LINK_EXPIRY_SKEW:
                    return "the link outlives the signed link_ttl"
        except (KeyError, ValueError, TypeError) as e:
            return f"malformed ({e.__class__.__name__})"
        return None

    async def _passport_control(self, msg: dict, frm: A.Address, origin) -> dict:
        """§12.6: a redeem request for one of our passports. frm is the redeemer (an endpoint or a
        namespace, verified by the origin server's identity rules), delivered to airc://<us>/_passport."""
        mid = msg["id"]
        try:
            body = json.loads(msg["body"])
            if body.get("action") == "revoke-layer":
                return self._revoke_layer(mid, body, frm)
            delegated = body.get("reference") is not None
            if body.get("action") != "redeem" or not isinstance(body.get("scope"), str):
                raise ValueError("expected a redeem action with a scope")
            if delegated:
                if not (isinstance(body["reference"], str) and P._REF.match(body["reference"])
                        and isinstance(body.get("layers"), list) and all(isinstance(x, str) for x in body["layers"])):
                    raise ValueError("a delegated redeem carries a reference and its layers")
            elif not isinstance(body.get("token"), str):
                raise ValueError("expected a redeem action with a token")
        except (ValueError, TypeError) as e:
            return self._fail(mid, f"bad passport control: {e}", "bad_address")
        redeemer = frm
        src_key = redeemer.realm if origin is not None and origin.kind == "peer" else redeemer.key
        if self._redeem_throttled(src_key):
            return self._fail(mid, "too many failed redemptions", "refused")
        if delegated:                                   # §12.10 step 1: the record whose token_hash is the reference
            rec = next((r for r in self.passports.recs.values() if r["token_hash"] == body["reference"] and r.get("delegates")), None)
        else:
            rec = self.passports.by_token(body["token"])
            if rec is not None and rec.get("delegates"):
                rec = None                              # a delegation cannot be redeemed without a delegate layer
        try:
            want_scope = P.scope_of(body["scope"])
        except A.AddressError:
            want_scope = None
        why = None
        now = time.time()
        if rec is None or rec.get("scope") != want_scope:
            why = "passport_unknown"
        elif not isinstance(rec.get("auth"), list) or not rec["auth"]:
            self._redeem_failures.setdefault(src_key, []).append(now)
            log.info("passport %s redeem by %s refused: a record from before draft 0.10", rec["id"], redeemer)
            return self._fail(mid, P.WITHDRAWN, "refused")
        elif rec["state"] == "revoked":
            why = "passport_revoked"
        elif rec.get("expires") and rec["expires"] < now:
            why = "passport_expired"
        elif len(rec["used"]) >= rec["uses"]:
            why = "passport_exhausted"
        elif rec.get("bind_to") and not self._bind_match(rec["bind_to"], redeemer):
            why = "passport_not_for_you"
        elif side_matches(rec["scope"], redeemer.key) or side_matches(redeemer.key, rec["scope"]):
            why = "passport_not_for_you"
        elif not self._redeemer_listed(self.passports_cfg["present_from"][P.scope_kind(rec["scope"])], redeemer):
            why = "passport_not_for_you"
        elif P.auth_problem(rec["auth"], P.canonical_of(rec)) or self._auth_entitlement_problem(rec["auth"], rec["scope"]):
            why = "passport_revoked"
        if why:
            self._redeem_failures.setdefault(src_key, []).append(now)
            log.info("passport redeem by %s refused: %s", redeemer, why)
            self.events.emit("passport.redeem", scope=(rec or {}).get("scope"), **{"from": redeemer.key}, status="failed", code=why)
            return self._fail(mid, why.replace("_", " "), "refused")
        chain = None
        if delegated:                                   # §12.10 steps 2-3
            revoked = {(x["realm"], x["id"]) for x in rec.get("revoked_layers") or []}
            try:
                chain = P.check_chain(rec, body["layers"], now,
                                      lambda realm, lid: "revoked" if (realm, lid) in revoked else None)
                for c, b in zip(chain["chain"], chain["bodies"]):
                    if b.get("uses") is not None and (rec.get("layer_uses") or {}).get(f"{c['realm']}/{c['id']}", 0) >= b["uses"]:
                        raise P.ChainError(f"layer {c['realm']} {c['id']} has no uses left")
                if not all(self._bind_match(bt, redeemer) for bt in chain["bind_tos"]):
                    raise P.ChainError("the redeemer does not match a bind_to along the chain")
            except P.ChainError as e:
                self._redeem_failures.setdefault(src_key, []).append(now)
                log.info("delegated redeem by %s refused: %s", redeemer, e)
                self.events.emit("passport.redeem", scope=rec["scope"], **{"from": redeemer.key}, status="failed", code="delegation")
                return self._fail(mid, f"delegation refused: {e}", "refused")
        scope = parse_side(rec["scope"])
        kind = P.scope_kind(rec["scope"])
        offer_id = rec.get("for_offer")                 # §12.9: a passport accepting an offer; the link takes its id
        offer = self.links.get(offer_id) if offer_id else None
        if offer_id and not (offer and offer["state"] == "pending" and offer["offered_by"] == redeemer.key
                             and {offer["a"], offer["b"]} == {scope.key, redeemer.key}):
            self._redeem_failures.setdefault(src_key, []).append(now)
            return self._fail(mid, "passport not for you", "refused")
        link = LinkStore.make(scope.key, redeemer.key, direction=chain["direction"] if chain else rec["direction"],
                              label=rec["label"], expires_in=chain["link_ttl"] if chain else rec.get("link_ttl"),
                              offered_by=scope.key, link_id=offer_id,
                              origin={"passport": rec["id"], "scope": kind, "issued_by": rec["issued_by"],
                                      "redeemed_by": redeemer.key, **({"offer": offer_id} if offer_id else {}),
                                      **({"chain": chain["chain"]} if chain else {}),
                                      "pins": [P.pin(a["key"]) for a in rec["auth"]] + [c["pin"] for c in (chain or {}).get("chain", [])]})
        hit = self.links.rejected_pin(scope.key, link["origin"]["pins"], link) if kind == "endpoint" else None
        if hit:                                         # §12.7: the scope endpoint rejects a key that authorized it
            self._redeem_failures.setdefault(src_key, []).append(now)
            log.info("passport %s redeem by %s refused: key %s is rejected by %s", rec["id"], redeemer, hit, scope)
            return self._fail(mid, f"passport refused: key {hit} is rejected by {scope.key}", "refused")
        link["state"] = "active"
        link["accepted_at"] = round(time.time(), 3)
        if offer:
            self.links.links[offer_id] = link           # replaces the pending offer under the same id
            self.links._save()
        else:
            self.links.put(link)
        if chain:                                       # §12.10 step 4: a use of every layer
            lu = rec.setdefault("layer_uses", {})
            for c in chain["chain"]:
                lu[f"{c['realm']}/{c['id']}"] = lu.get(f"{c['realm']}/{c['id']}", 0) + 1
        self.passports.use(rec, redeemer.key, link["id"])
        log.info("passport %s redeemed by %s -> link %s", rec["id"], redeemer, link["id"])
        self.events.emit("passport.redeem", passport=rec["id"], scope=rec["scope"], **{"from": redeemer.key},
                         link=link["id"], uses_left=rec["uses"] - len(rec["used"]))
        pa = {"scope": rec["scope"], "token_sha256": rec["token_hash"], "direction": rec["direction"],
              "expires": rec.get("expires"), "uses": rec["uses"], "bind_to": rec.get("bind_to") or "",
              "link_ttl": rec.get("link_ttl"), "offer": rec.get("offer") or "", "auth": [dict(a) for a in rec["auth"]]}
        if chain:
            pa.update(kind="delegated", delegates=rec["delegates"], rules=rec.get("rules") or {}, layers=list(body["layers"]))
        # the redeemer's server records the link before we answer the redeem
        a = await self._send_control(scope, redeemer, "grant", link, redemption=body.get("redemption"), passport_auth=pa)
        # tell the scope endpoint, or for a group scope the endpoint that issued the passport
        told = scope if kind == "endpoint" else parse_side(rec["issued_by"])
        if told.path and not told.namespace_ref and told.in_realm(self.realm) and not offer:   # §12.9: the accept answers
            lab = f" labelled {_q(rec['label'])}" if rec.get("label") else ""
            notice = (f"[airc: {redeemer.relative_to(self.realm, told.namespace)} redeemed your passport {rec['id']}{lab} "
                      f"for {kind} {show_side(scope, self.realm, told.namespace)}: link {link['id']} is open, direction "
                      f"{link['direction']}, {rec['uses'] - len(rec['used'])} use(s) left. "
                      f"Revoke: airc link revoke {link['id']} --as {scope.local_path or '/'}]")
            note = wire.new_msg(self._notice_from(), str(told), notice,
                                hdr={"airc-link": link["id"], "airc-link-action": "grant", "airc-passport": rec["id"],
                                     "airc-peer": redeemer.key})
            self._spawn(self._notify_endpoint(note, told))
        if a["status"] != "delivered":
            if offer:                                   # §12.9 step 4: the offer stays pending
                self.links.links[offer_id] = offer
                self.links._save()
            elif redeemer.in_realm(self.realm) and redeemer.port is None:
                self.links.links.pop(link["id"], None)  # one shared store: a grant the redeemer refused opens nothing
                self.links._save()
            elif a["status"] == "failed":               # the redeemer refused it: our side opens nothing either
                self.links.set_state(link["id"], "revoked", by=scope.key)
            return wire.ack(mid, "delivered", f"link {link['id']} granted; your server did not record it ({self._peer_safe(a)})",
                            None, self.resolver_uri)
        return wire.ack(mid, "delivered", f"link {link['id']} granted", None, self.resolver_uri)

    async def _send_revoke_layer(self, link, frame: dict, err) -> dict:
        """Client op revoke-layer {root | passport, reference?, layer} (administrators): send R the control
        from airc://<this realm>/."""
        if not self._is_admin(link):
            return err("only an administrator may close a layer for this realm", "unauthorized")
        root, ref = frame.get("root"), frame.get("reference")
        if isinstance(frame.get("passport"), str):
            try:
                pp = P.parse(frame["passport"])
            except P.PassportFormatError as e:
                return err(str(e), "bad_request")
            root, code, why = await self._passport_issuer(pp["host"])
            if root is None:
                return err(f"cannot verify the passport's host: {why}", code)
            ref = ref or pp["token"]
        try:
            target = A.parse(f"//{root}/{P.ENDPOINT_NAME}")
        except (A.AddressError, TypeError):
            return err("revoke-layer needs the root realm (root) or the passport", "bad_request")
        if not (isinstance(ref, str) and P._REF.match(ref) and isinstance(frame.get("layer"), str)):
            return err("revoke-layer needs the reference and the layer id", "bad_request")
        body = json.dumps({"action": "revoke-layer", "reference": ref, "layer": frame["layer"]}, separators=(",", ":"))
        msg = wire.new_msg(f"airc://{self.realm}/", str(target), body, mtype=PASSPORT_TYPE, ttl=600)
        if target.in_realm(self.realm):
            a = self._revoke_layer(msg["id"], json.loads(body), parse_side(f"airc://{self.realm}/"))
        else:
            a = await self._deliver_remote(msg, target)
        return {"t": "passported", "ok": a["status"] == "delivered", "status": a["status"], "reason": a.get("reason", ""),
                **({"code": a["code"]} if a.get("code") else {})}

    def _revoke_layer(self, mid: str, body: dict, frm: A.Address) -> dict:
        """§12.10 Closing: a delegate realm D (from airc://D/) revokes a layer it signed, and every link made
        through it. Recorded as (D, id), so D can only ever close layers its own keys signed."""
        if frm.path:
            return self._fail(mid, "revoke-layer comes from a realm (airc://<realm>/)", "refused")
        lid = body.get("layer")
        rec = next((r for r in self.passports.recs.values()
                    if r["token_hash"] == body.get("reference") and r.get("delegates")), None)
        if rec is None or not (isinstance(lid, str) and re.fullmatch(r"[0-9A-Za-z]{11,64}", lid)):
            return self._fail(mid, "no such delegation or layer", "refused")
        # A layer is identified with the realm its parent named for its key, so a mark (D, id) only ever
        # matches layers D's own keys signed, including ones R has not seen yet.
        mark = {"realm": frm.authority, "id": lid}
        if mark not in rec.setdefault("revoked_layers", []):
            rec["revoked_layers"].append(mark)
            self.passports._save()
        n = 0
        for l in list(self.links.links.values()):
            ch = (l.get("origin") or {}).get("chain") or []
            if (l.get("origin") or {}).get("passport") == rec["id"] and l["state"] in ("pending", "active") \
                    and any(c["realm"] == frm.authority and c["id"] == lid for c in ch):
                self.links.set_state(l["id"], "revoked", by=f"airc://{frm.authority}/")
                self._spawn(self._send_control(parse_side(l["a"]), parse_side(l["b"]), "revoke", self.links.get(l["id"])))
                n += 1
        log.info("delegation %s: layer %s of %s revoked, %d link(s)", rec["id"], lid, frm.authority, n)
        self.events.emit("passport.revoke-layer", passport=rec["id"], layer=lid, by=frm.authority, links=n)
        return wire.ack(mid, "delivered", f"layer {lid} revoked; {n} link(s) revoked", None, self.resolver_uri)

    @staticmethod
    def _bind_match(pattern: str, who: A.Address) -> bool:
        try:                                    # §12.6: a namespace or realm redeemer matches only if covered whole
            return A.pattern_covers(pattern, who) if who.key.endswith("/") else A.pattern_match(pattern, who)
        except A.AddressError:
            return False

    def snapshot(self) -> dict:
        return {
            "realm": self.realm,
            "uptime": round(time.time() - self.stats["started"]),
            "counters": {k: v for k, v in self.stats.items() if k != "started"},
            "clients": [{"uid": c.uid, "ns": c.namespaces, "binds": c.binds, "agent": c.agent} for c in self.clients],
            "peers": {r: len(ls) for r, ls in self.peers.items()},
            "events_log": self.events.path,
            "signing": ({"kid": self.signer.kid, "public_key": self.signer.public_b64, "require": self.signing_cfg["require"]}
                        if self.signer else None),
            "backlog": {k: self.spool.pending(k) for k in self.spool.backlog_keys()},
            "links": {s: sum(1 for l in self.links.links.values() if l["state"] == s) for s in ("pending", "active", "revoked")},
            "passports": {s: sum(1 for r in self.passports.recs.values() if r["state"] == s) for s in ("active", "exhausted", "revoked")},
        }


def load_config(path: str) -> dict:
    import json
    with open(path) as f:
        cfg = json.load(f)
    if "realm" not in cfg:
        raise SystemExit("config: 'realm' is required")
    return cfg


async def serve(cfg: dict):
    srv = Server(cfg)
    await srv.start()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    import signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    await stop.wait()
    await srv.stop()


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="aircd", description="AIRC realm server")
    ap.add_argument("-c", "--config", required=True, help="JSON config file")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--show-key", action="store_true", help="print this realm's public signing key and DNS record, then exit")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = load_config(args.config)
    if args.show_key:
        scfg = cfg.get("signing") or {}
        spool_dir = cfg.get("spool_dir") or os.path.join(os.path.expanduser("~"), ".airc", "spool")
        state_dir = cfg.get("state_dir") or os.path.dirname(spool_dir.rstrip("/")) or "."
        k = S.Signer(scfg.get("key") or os.path.join(state_dir, "realm.key"))
        print(f"realm:  {cfg['realm']}\nkid:    {k.kid}\npublic: {k.public_b64}\nDNS:    {S.txt_record(cfg['realm'], k.public_b64)}")
        return
    asyncio.run(serve(cfg))


if __name__ == "__main__":
    main()
