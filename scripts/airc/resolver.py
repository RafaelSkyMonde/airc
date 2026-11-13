# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Realm discovery: which host:port serves //realm/...?

Order of resolution for realm R:
  1. static override from the server config  ("peers": {R: {...}})
  2. DNS SRV  _airc-https._tcp.R / _airc._tcp.R -> target host + port (lowest priority first;
     within a priority, RFC 2782 weighted random selection, redrawn on every resolve)
  3. DNS A/AAAA of  airc.R      -> port DEFAULT_PEER_PORT
  4. DNS A/AAAA of  R           -> port DEFAULT_PEER_PORT

A realm may also publish   _airc.R  TXT "v=airc1 k=ed25519 p=<base64 pubkey>"
which is the key peers will verify message signatures against (phase 2).

The SRV/TXT lookups are done with a tiny built-in DNS client (stdlib only,
UDP to the nameservers in /etc/resolv.conf, TCP fallback on truncation) so the
reference implementation has no third-party dependency. Results are cached
for their TTL (min 30s, max 1h).
"""
from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import struct
import time
from dataclasses import dataclass

from . import DEFAULT_PEER_PORT

_TYPE_A, _TYPE_TXT, _TYPE_AAAA, _TYPE_SRV = 1, 16, 28, 33


@dataclass
class Endpoint:
    host: str
    port: int
    tls: bool = True
    source: str = ""
    binding: str = "stream"      # "stream" (JSONL) or "https"
    priority: int = 0            # SRV fields (§8.1), for the weighted ordering; 0 for other sources
    weight: int = 0

    @property
    def url(self) -> str:
        scheme = "https" if self.tls else "http"
        default = 443 if self.tls else 80
        return f"{scheme}://{self.host}" + ("" if self.port == default else f":{self.port}")

    def __str__(self):
        return f"{self.binding}:{self.host}:{self.port}{'' if self.tls else ' (plain)'} [{self.source}]"


def _nameservers():
    out = []
    try:
        with open("/etc/resolv.conf") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver":
                    out.append(parts[1])
    except OSError:
        pass
    return out or ["127.0.0.53", "8.8.8.8"]


def _build_query(name: str, qtype: int) -> tuple[bytes, int]:
    qid = random.randrange(65536)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.rstrip(".").split("."))
    return header + q + b"\x00" + struct.pack(">HH", qtype, 1), qid


def _read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = off
    hops = 0
    while True:
        l = buf[off]
        if l & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            hops += 1
            if hops > 32:
                raise ValueError("compression loop")
            continue
        off += 1
        if l == 0:
            if not jumped:
                end = off
            break
        labels.append(buf[off:off + l].decode(errors="replace"))
        off += l
    return ".".join(labels), end


def _parse_answers(buf: bytes, qid: int, qtype: int):
    rid, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    if rid != qid:
        raise ValueError("id mismatch")
    if flags & 0x000F not in (0, 3):  # NOERROR or NXDOMAIN
        raise ValueError(f"rcode {flags & 0xF}")
    off = 12
    for _ in range(qd):
        _, off = _read_name(buf, off)
        off += 4
    out = []
    for _ in range(an):
        _, off = _read_name(buf, off)
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        if rtype == qtype:
            if qtype == _TYPE_SRV:
                pri, wt, port = struct.unpack(">HHH", rdata[:6])
                target, _ = _read_name(buf, off + 6)
                out.append((ttl, (pri, wt, port, target)))
            elif qtype == _TYPE_TXT:
                txt, p = [], 0
                while p < len(rdata):
                    n = rdata[p]
                    txt.append(rdata[p + 1:p + 1 + n].decode(errors="replace"))
                    p += 1 + n
                out.append((ttl, "".join(txt)))
            elif qtype == _TYPE_A:
                out.append((ttl, socket.inet_ntop(socket.AF_INET, rdata)))
            elif qtype == _TYPE_AAAA:
                out.append((ttl, socket.inet_ntop(socket.AF_INET6, rdata)))
        off += rdlen
    return (flags & 0x0200) != 0, out  # truncated?, answers


def _query_sync(name: str, qtype: int, timeout: float = 3.0):
    last = None
    for ns in _nameservers():
        pkt, qid = _build_query(name, qtype)
        try:
            fam = socket.AF_INET6 if ":" in ns else socket.AF_INET
            with socket.socket(fam, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.sendto(pkt, (ns, 53))
                buf, _ = s.recvfrom(4096)
            tc, answers = _parse_answers(buf, qid, qtype)
            if tc:
                with socket.create_connection((ns, 53), timeout=timeout) as s:
                    s.sendall(struct.pack(">H", len(pkt)) + pkt)
                    ln = struct.unpack(">H", s.recv(2))[0]
                    buf = b""
                    while len(buf) < ln:
                        chunk = s.recv(ln - len(buf))
                        if not chunk:
                            break
                        buf += chunk
                _, answers = _parse_answers(buf, qid, qtype)
            return answers
        except (OSError, ValueError, struct.error) as e:
            last = e
            continue
    raise OSError(f"dns lookup failed for {name}: {last}")


def srv_order(eps: list[Endpoint], rng=random) -> list[Endpoint]:
    """RFC 2782 order: groups of one binding and priority keep their order (lowest priority first);
    within a group, repeatedly pick one at random with probability proportional to its weight (a
    zero weight still gets a small chance, as the RFC's running-sum draw gives it when listed first)."""
    out, i = [], 0
    while i < len(eps):
        j = i
        while j < len(eps) and (eps[j].binding, eps[j].priority) == (eps[i].binding, eps[i].priority):
            j += 1
        group = sorted(eps[i:j], key=lambda e: e.weight != 0)        # zero weights first (RFC 2782)
        while group:
            total = sum(e.weight for e in group)
            pick, run = rng.randint(0, total), 0
            for k, e in enumerate(group):
                run += e.weight
                if run >= pick:
                    out.append(group.pop(k))
                    break
        i = j
    return out


class DnsUnavailable(OSError):
    """Discovery found nothing, but some lookup went unanswered (timeout, SERVFAIL): the realm may well
    exist, so the caller retries later (authority_unreachable), unlike a clean "no records" (no_such_authority)."""


async def query(name: str, qtype: int):
    return await asyncio.get_running_loop().run_in_executor(None, _query_sync, name, qtype)


class Resolver:
    def __init__(self, overrides: dict | None = None, known_keys: dict | None = None):
        # overrides: realm -> {"host":..., "port":..., "tls": bool}
        # known_keys: realm -> [base64 ed25519 public keys], bypassing DNS
        self.overrides = {k.lower(): v for k, v in (overrides or {}).items()}
        self.known_keys = {k.lower(): (v if isinstance(v, list) else [v]) for k, v in (known_keys or {}).items()}
        self._cache: dict[str, tuple[float, list[Endpoint]]] = {}
        self._key_cache: dict[str, tuple[float, list[str]]] = {}

    async def resolve(self, realm: str, port: int | None = None) -> list[Endpoint]:
        """Endpoints for an authority. An explicit port skips SRV (spec §5.1
        rule 3); an IP-literal realm skips DNS entirely."""
        realm = realm.lower()
        if port is not None:
            return [Endpoint(realm, port, True, "explicit-port")]
        try:
            ipaddress.ip_address(realm)
            return [Endpoint(realm, DEFAULT_PEER_PORT, True, "ip-literal")]
        except ValueError:
            pass
        ov = self.overrides.get(realm)
        if ov:
            eps = []
            if ov.get("https"):
                # "https": "https://host:port" or "http://host:port" (tests)
                u = ov["https"]
                tls = u.startswith("https://")
                hp = u.split("://", 1)[1].rstrip("/")
                host, _, port = hp.rpartition(":") if ":" in hp and not hp.endswith("]") else (hp, "", "")
                eps.append(Endpoint(host or hp, int(port) if port else (443 if tls else 80), tls, "config", "https"))
            if ov.get("host") or not eps:
                eps.append(Endpoint(ov.get("host", realm), int(ov.get("port", DEFAULT_PEER_PORT)),
                                    bool(ov.get("tls", True)), "config", "stream"))
            return eps
        hit = self._cache.get(realm)
        now = time.time()
        if hit and hit[0] > now:
            return srv_order(hit[1])
        eps, ttl = await self._discover(realm)
        self._cache[realm] = (now + max(30, min(ttl, 3600)), eps)
        return srv_order(eps)

    async def _discover(self, realm: str) -> tuple[list[Endpoint], int]:
        """Both bindings' SRV records; HTTPS first (every federated server has it)."""
        eps, ttl, unanswered = [], 3600, []
        for svc, binding, default_port in (("_airc-https._tcp", "https", 443), ("_airc._tcp", "stream", DEFAULT_PEER_PORT)):
            try:
                srv = await query(f"{svc}.{realm}", _TYPE_SRV)
            except OSError as e:
                srv = []
                unanswered.append(str(e))
            if srv:
                ttl = min(ttl, min(t for t, _ in srv))
                recs = sorted((r for _, r in srv), key=lambda r: r[0])        # by priority; resolve() draws by weight
                eps += [Endpoint(r[3], r[2] or default_port, True, "srv", binding, r[0], r[1]) for r in recs if r[3] not in ("", ".")]
        if eps:
            return eps, ttl
        for host in (f"airc.{realm}", realm):
            a = []
            for qtype in (_TYPE_A, _TYPE_AAAA):              # §8.1: an IPv6-only host is a host too
                try:
                    a += await query(host, qtype)
                except OSError as e:
                    unanswered.append(str(e))
            if a:
                t = min(t for t, _ in a)
                return [Endpoint(host, 443, True, "a", "https"), Endpoint(host, DEFAULT_PEER_PORT, True, "a", "stream")], t
        if unanswered:
            raise DnsUnavailable(f"no AIRC server found for realm {realm} yet; {unanswered[0]}")
        raise OSError(f"no AIRC server found for realm {realm}")

    async def public_keys(self, realm: str) -> list[str]:
        """Base64 ed25519 public keys for a realm: the static `known_keys`
        entry if configured, else every _airc.<realm> TXT record of the form
        "v=airc1 k=ed25519 p=<key>" (cached for its TTL, misses for 60 s)."""
        realm = realm.lower()
        if realm in self.known_keys:
            return list(self.known_keys[realm])
        hit = self._key_cache.get(realm)
        now = time.time()
        if hit and hit[0] > now:
            return hit[1]
        keys, ttl = [], 60
        try:
            recs = await query(f"_airc.{realm}", _TYPE_TXT)
        except OSError:
            recs = []
        for t, txt in recs:
            fields = dict(p.split("=", 1) for p in txt.replace(";", " ").split() if "=" in p)
            if fields.get("v") == "airc1" and fields.get("k", "ed25519") == "ed25519" and fields.get("p"):
                keys.append(fields["p"])
                ttl = min(ttl if keys[1:] else t, t)
        self._key_cache[realm] = (now + max(30, min(ttl, 3600)) if keys else now + 60, keys)
        return keys

    async def public_key(self, realm: str) -> str | None:
        keys = await self.public_keys(realm)
        return keys[0] if keys else None
