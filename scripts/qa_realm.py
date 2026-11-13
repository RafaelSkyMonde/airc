#!/usr/bin/env python3
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Interop checks against another implementation's realm, with one key it registered for us.

    scripts/qa_realm.py <base url> <keyfile> <namespace> [--realm-key-check] [--ping] [--no-big] [--schema]

scripts/qa.py needs open signup (it registers throwaway workspaces). A realm built
by someone else usually gives us one pre-registered key for a test namespace instead;
this runs what fits that: the capabilities signature, client-face auth (clock window,
nonce replay, body hash, query string, unknown key), bind modes, send / inbox / ack
within the namespace, dedupe by id, push over the WebSocket when the capabilities list "ws" (spec 3.4.6: welcome,
backlog, a live message's latency, the sender's ack, ack and send up the socket; --ping waits for a keepalive), a link
offered, accepted and revoked between two endpoints of the namespace, and, when the capabilities list "bin", binary
sections (spec 22): a framed send, the frame without its bytes in /inbox and on the WebSocket, GET /airc/v0/bin/<id> before and after the ack, a section that does not match its
hash, one over 8 MiB and a body over the framed limit (--no-big skips the two large uploads). --schema validates every frame and
response the checker sees against schemas/airc-frames.schema.json (needs the jsonschema package) and lists what does not fit. Each
check prints PASS or FAIL; a FAIL also prints the request and the response, for the report to the realm's owner. Exit status 1 on a FAIL.
"""
import asyncio
import hashlib
import http.client
import json
import os
import secrets
import ssl
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from airc import signing as S, wire                               # noqa: E402
from airc.httpclient import HttpClient, HttpClientError, WsSocket, USER_AGENT   # noqa: E402

fails = 0
RECORDER = None       # --schema: a test_schema.Recorder; Raw responses are added to it by hand below


def check(cond, what, detail=""):
    global fails
    print(("  PASS  " if cond else "  FAIL  ") + what)
    if not cond:
        fails += 1
        if detail:
            for ln in detail.strip().splitlines():
                print("          " + ln)
    return cond


class Raw:
    """Hand-signed requests, so a check can sign exactly what it wants to test."""
    def __init__(self, base, signer, realm):
        u = urllib.parse.urlsplit(base)
        self.host, self.port, self.tls = u.hostname, u.port or (443 if u.scheme == "https" else 80), u.scheme == "https"
        self.signer, self.realm = signer, realm

    def auth(self, method, path, body, *, ts=None, nonce=None, signer=None):
        k = signer or self.signer
        ts = int(time.time()) if ts is None else ts
        nonce = nonce or os.urandom(12).hex()
        sig = k.sign(S.canonical_client_request(self.realm, method, path, ts, nonce, body))
        return f"AIRC-Key {k.kid}:{ts}:{nonce}:{sig}"

    def send(self, method, path, body=b"", auth=None, headers=None, raw=False):
        c = (http.client.HTTPSConnection(self.host, self.port, timeout=20, context=ssl.create_default_context())
             if self.tls else http.client.HTTPConnection(self.host, self.port, timeout=20))
        h = {"User-Agent": USER_AGENT, "Content-Type": "application/json", **({"Authorization": auth} if auth else {}), **(headers or {})}
        c.request(method, path, body=body or None, headers=h)
        r = c.getresponse()
        data = r.read()
        self.ctype = r.getheader("Content-Type", "")
        c.close()
        if RECORDER is not None and data[:1] in (b"{", b"["):
            try:
                RECORDER.records.append(("raw", json.loads(data.decode("utf-8", "replace"))))
            except ValueError:
                pass
        return r.status, (data if raw else data.decode("utf-8", "replace"))

    @staticmethod
    def show(method, path, body, auth, status, data):
        a = (auth or "")[:60] + ("…" if auth and len(auth) > 60 else "")
        return f"request:  {method} {path}  Authorization: {a}\n          body: {body[:200]!r}\nresponse: HTTP {status} {data[:300]}"


class Stream:
    """An open GET /airc/v0/ws (spec 3.4.6), through the shipped client; frames land in a queue with their
    arrival time. status: 101 when it opened, else the HTTP status of the refusal."""
    @classmethod
    async def open(cls, hc: HttpClient) -> "Stream":
        import re
        st = cls()
        st.ws, st.status, st.body, st.task = None, None, "", None
        try:
            st.ws = await WsSocket(hc).open()
            st.status = 101
        except (HttpClientError, OSError) as e:
            m = re.match(r"HTTP (\d+)", str(e))
            st.status, st.body = (int(m.group(1)) if m else 0), str(e)
            return st
        st.q = asyncio.Queue()
        st.task = asyncio.ensure_future(st._pump())
        return st

    async def _pump(self):
        try:
            async for f in self.ws.frames():
                await self.q.put((time.monotonic(), f))
        except Exception as e:  # noqa: BLE001
            await self.q.put((time.monotonic(), {"t": "_closed", "error": repr(e)}))

    async def next(self, timeout):
        try:
            return await asyncio.wait_for(self.q.get(), timeout)
        except asyncio.TimeoutError:
            return None, None

    async def find(self, pred, timeout):
        end = time.monotonic() + timeout
        seen = []
        while time.monotonic() < end:
            at, f = await self.next(max(0.1, end - time.monotonic()))
            if f is None:
                break
            seen.append(f)
            if pred(f):
                return at, f, seen
        return None, None, seen

    async def close(self):
        if self.task:
            self.task.cancel()
        if self.ws:
            await self.ws.close()


async def push_checks(hc, raw, x, y):
    r = await hc.bind([x, y], mode="push")
    if not check(isinstance(r, dict) and r.get("t") == "bound", f"bind {x} and {y} in push mode", json.dumps(r)[:300]):
        return
    for m in await hc.inbox():
        await hc.ack(m["id"])
    early = wire.new_msg(x, y, "before the socket " + secrets.token_hex(3))
    await hc._request("POST", "/airc/v0/send", early)              # queued before the socket opens: comes in the backlog
    st = await Stream.open(hc)
    if not check(st.status == 101, f"GET /airc/v0/ws: {st.status}", st.body[:300]):
        await hc.bind([x, y], mode="pull")
        return
    at, w = await st.next(10)
    check(bool(w) and w.get("t") == "welcome", "the first frame is a welcome", json.dumps(w)[:300])
    if w and w.get("t") == "welcome":
        check(bool(w.get("realm")) and str(w.get("proto", "")).startswith("airc/"), f"welcome carries realm and proto ({w.get('realm')}, {w.get('proto')})", json.dumps(w)[:300])
        print(f"  info  welcome: {json.dumps(w)[:200]}")
    _, b, seen = await st.find(lambda f: f.get("t") == "msg" and f.get("id") == early["id"], 10)
    check(b is not None, "a message queued before the socket opened arrives in the backlog",
          "frames seen: " + json.dumps([f.get("t") for f in seen]))
    if b:
        await hc.ack(early["id"])
    live = wire.new_msg(x, y, "live push " + secrets.token_hex(3))
    t0 = time.monotonic()
    ack = await hc._request("POST", "/airc/v0/send", live)
    t_ack = time.monotonic() - t0
    at, f, seen = await st.find(lambda f: f.get("t") == "msg" and f.get("id") == live["id"], 10)
    took = (at - t0) if at else None
    check(f is not None and took is not None and took < 1.5, f"a live message reaches the socket in {took:.2f} s" if took else "a live message reaches the socket within 10 s",
          "frames seen: " + json.dumps([g.get("t") for g in seen]))
    if f:
        check(f.get("body") == live["body"] and f.get("from", "").endswith(x), "the pushed frame is the message, intact", json.dumps(f)[:300])
    print(f"  info  sender's ack while pushing: {ack.get('status')} {ack.get('code', '')} after {t_ack:.2f} s "
          f"(spec: 'delivered' if the server waits for the client's ack, else 'queued pushed')")
    check(ack.get("status") in ("delivered", "queued") and (ack.get("status") == "delivered" or ack.get("code") in ("pushed", "no_ack", "endpoint_offline")),
          "the sender's ack is one of the spec's push outcomes", json.dumps(ack)[:300])
    if f:
        n = await st.ws.ack(live["id"])
        check(n == 1, f"an ack up the socket settles it (acked n={n})")
        left = [1]
        for _ in range(20):
            left = [g for g in await hc.inbox() if g.get("id") == live["id"]]
            if not left:
                break
            await asyncio.sleep(0.5)
        check(not left, "after the client's ack the pushed message leaves the queue")
    if "--ping" in sys.argv:
        _, p, seen = await st.find(lambda f: f.get("t") == "ping", 32)
        check(p is not None, "a ping arrives within 32 s on an idle socket", "frames seen: " + json.dumps([g.get("t") for g in seen]))
    sa = await st.ws.send(y, "sent up the socket " + secrets.token_hex(3), frm=x)
    check(sa.get("t") == "ack" and sa.get("status") in ("delivered", "queued"), f"a send up the socket gets its ack ({sa.get('status')} {sa.get('code', '')})", json.dumps(sa)[:300])
    for g in await hc.inbox():
        await hc.ack(g["id"])
    await st.close()
    await hc.bind([x, y], mode="pull")


def framed(m: dict, data: bytes) -> bytes:
    """A msg and its binary section as an application/airc-frame body (spec 22)."""
    m = dict(m, bin=len(data), bin_sha256=hashlib.sha256(data).hexdigest())
    return json.dumps(m, separators=(",", ":")).encode() + b"\n" + data


def jcode(text):
    try:
        d = json.loads(text)
        return d.get("status", ""), d.get("code", "")
    except (ValueError, AttributeError):
        return "", ""


async def bin_checks(hc, raw, x, y):
    FR = {"Content-Type": "application/airc-frame"}

    def post(body):
        a = raw.auth("POST", "/airc/v0/send", body)
        st, d = raw.send("POST", "/airc/v0/send", body, auth=a, headers=FR)
        return a, st, d

    async def fetch_until(mid, want, tries=20):
        st = d = None
        for _ in range(tries):
            st, d = raw.send("GET", "/airc/v0/bin/" + mid, auth=raw.auth("GET", "/airc/v0/bin/" + mid, b""), raw=True)
            if want(st):
                break
            await asyncio.sleep(0.5)
        return st, d

    for m in await hc.inbox():
        await hc.ack(m["id"])
    data = os.urandom(3000) + b"qa section"
    m = wire.new_msg(x, y, "qa section " + secrets.token_hex(3))
    body = framed(m, data)
    a, st, d = post(body)
    status, code = jcode(d)
    check(st == 200 and status in ("delivered", "queued"), f"a framed send (application/airc-frame, {len(data)}-byte section): HTTP {st} {status} {code}",
          Raw.show("POST", "/airc/v0/send", body, a, st, d))
    got = []
    for _ in range(20):
        got = [g for g in await hc.inbox() if g.get("id") == m["id"]]
        if got:
            break
        await asyncio.sleep(0.5)
    if check(bool(got), "the message is in the inbox"):
        g = got[0]
        check(g.get("bin") == len(data) and g.get("bin_sha256") == hashlib.sha256(data).hexdigest(),
              "the inbox frame declares bin and bin_sha256", json.dumps(g)[:300])
        check(not any(k in g for k in ("_bin", "data", "bytes")) and len(json.dumps(g)) < len(data),
              "the inbox frame carries no bytes", json.dumps(g)[:300])
        st, b = await fetch_until(m["id"], lambda s: s == 200)
        check(st == 200 and b == data, f"GET /airc/v0/bin/<id> returns the section: HTTP {st}, {len(b or b'')} bytes, {raw.ctype}",
              f"response: HTTP {st} {(b or b'')[:200]!r}")
        check("application/octet-stream" in raw.ctype if st == 200 else False, "the section comes as application/octet-stream", raw.ctype)
        await hc.ack(m["id"])
        st, b = await fetch_until(m["id"], lambda s: s == 404)
        check(st == 404, f"after the ack GET /airc/v0/bin/<id> answers 404 (HTTP {st})", f"response: HTTP {st} {(b or b'')[:200]!r}")
    st, b = raw.send("GET", "/airc/v0/bin/no-such-id", auth=raw.auth("GET", "/airc/v0/bin/no-such-id", b""))
    check(st == 404, f"GET /airc/v0/bin/<unknown id> answers 404 (HTTP {st})", f"response: HTTP {st} {b[:200]}")
    check(st == 404 and jcode(b)[1] == "not_found", f"... with code not_found (spec 22; got {jcode(b)[1]!r})", f"response: HTTP {st} {b[:200]}")

    m = wire.new_msg(x, y, "qa mismatch " + secrets.token_hex(3))
    body = framed(m, b"the real bytes")
    head, _, sec = body.partition(b"\n")
    bad = head + b"\n" + b"other bytes!!!"                       # same length, another hash
    a, st, d = post(bad)
    status, code = jcode(d)
    check(st == 200 and status == "failed", f"a section that does not match bin_sha256 is refused: HTTP {st} {status} {code}",
          Raw.show("POST", "/airc/v0/send", bad, a, st, d))
    check(code == "bad_bin", f"... with code bad_bin (spec 22; got {code!r})", Raw.show("POST", "/airc/v0/send", bad, a, st, d))
    await asyncio.sleep(1)
    check(not [g for g in await hc.inbox() if g.get("id") == m["id"]], "the refused message is not queued")

    if "--no-big" in sys.argv:
        print("  info  --no-big: skipped the section over 8 MiB and the body over the framed limit")
        return
    m = wire.new_msg(x, y, "qa too big " + secrets.token_hex(3))
    body = framed(m, b"\0" * ((8 << 20) + 1))
    a, st, d = post(body)
    status, code = jcode(d)
    check(st == 413 or status == "failed", f"a section of 8 MiB plus one byte is refused: HTTP {st} {status or ''} {code}",
          Raw.show("POST", "/airc/v0/send", body[:300], a, st, d))
    body = framed(wire.new_msg(x, y, "qa over the limit"), b"\0" * (9 << 20))
    a, st, d = post(body)
    check(st == 413, f"a body over 9 MiB answers 413 (HTTP {st})", Raw.show("POST", "/airc/v0/send", body[:300], a, st, d))
    check(st == 413 and jcode(d)[1] == "frame_too_large", f"... with code frame_too_large (spec 3.4; got {jcode(d)[1]!r})",
          Raw.show("POST", "/airc/v0/send", body[:300], a, st, d))


async def bin_push_checks(hc, raw, x, y):
    r = await hc.bind([x, y], mode="push")
    if not check(isinstance(r, dict) and r.get("t") == "bound", "bind in push mode", json.dumps(r)[:300]):
        return
    st = await Stream.open(hc)
    if st.status == 501:
        print("  info  GET /airc/v0/ws: 501, no WebSocket here; skipped the pushed section")
        await hc.bind([x, y], mode="pull")
        return
    if not check(st.status == 101, f"GET /airc/v0/ws: {st.status}", st.body[:300]):
        await hc.bind([x, y], mode="pull")
        return
    data = os.urandom(2000)
    m = wire.new_msg(x, y, "qa pushed section " + secrets.token_hex(3))
    body = framed(m, data)
    raw.send("POST", "/airc/v0/send", body, auth=raw.auth("POST", "/airc/v0/send", body), headers={"Content-Type": "application/airc-frame"})
    _, f, seen = await st.find(lambda f: f.get("t") == "msg" and f.get("id") == m["id"], 10)
    if check(f is not None, "the framed message reaches the socket", "frames seen: " + json.dumps([g.get("t") for g in seen])):
        check(f.get("bin") == len(data) and f.get("bin_sha256") == hashlib.sha256(data).hexdigest() and len(json.dumps(f)) < len(data),
              "the pushed frame declares the section and carries no bytes", json.dumps(f)[:300])
        s2, b = raw.send("GET", "/airc/v0/bin/" + m["id"], auth=raw.auth("GET", "/airc/v0/bin/" + m["id"], b""), raw=True)
        check(s2 == 200 and b == data, f"GET /airc/v0/bin/<id> for the pushed message: HTTP {s2}, {len(b)} bytes", f"response: HTTP {s2} {b[:200]!r}")
        await hc.ack(m["id"])
    await st.close()
    await hc.bind([x, y], mode="pull")


async def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    base, keyfile, ns = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3].strip("/")
    global RECORDER
    if "--schema" in sys.argv:
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests"))
        import test_schema as SCHEMA                     # noqa: F401
        if SCHEMA.jsonschema is None:
            print("--schema needs the jsonschema package (pip install jsonschema)")
            return 2
        RECORDER = SCHEMA.Recorder().start()
    k = S.Signer(keyfile)
    hc = HttpClient(base, k)
    caps = await hc.capabilities()
    realm = caps["realm"]
    print(f"realm {realm} at {base}, server {caps.get('server', '?')}, key {k.kid}, namespace {ns}/")
    raw = Raw(base, k, realm)

    print("capabilities")
    check(caps.get("t") == "capabilities" and caps.get("proto", "").startswith("airc/"), "capabilities document: t and proto")
    check(str(caps.get("sig", "")).startswith("ed25519:"), "capabilities are signed")
    if "--realm-key-check" in sys.argv:
        from airc.resolver import Resolver
        try:
            pubs = await Resolver().public_keys(realm)
            check(S.verify_capabilities(caps, realm, caps.get("nonce"), pubs) is True, "capabilities signature verifies against the _airc TXT key")
        except Exception as e:  # noqa: BLE001
            check(False, "capabilities signature verifies against the _airc TXT key", repr(e))

    print("client-face auth (spec 3.4.2)")
    p = "/airc/v0/inbox"
    for what, kw, want_ok in (("a correctly signed request is accepted", {}, True),
                              ("a timestamp 10 minutes old is refused (300 s window)", {"ts": int(time.time()) - 600}, False),
                              ("a timestamp 10 minutes ahead is refused", {"ts": int(time.time()) + 600}, False)):
        a = raw.auth("GET", p, b"", **kw)
        st, d = raw.send("GET", p, auth=a)
        check((st == 200) == want_ok and (want_ok or st == 401), what, Raw.show("GET", p, b"", a, st, d))
    a = raw.auth("GET", p, b"")
    st1, _ = raw.send("GET", p, auth=a)
    st2, d2 = raw.send("GET", p, auth=a)
    check(st1 == 200 and st2 == 401, "the same nonce twice: the second is refused", Raw.show("GET", p, b"", a, st2, d2))
    a = raw.auth("GET", p + "?max=5", b"")                     # signed WITH the query string: wrong per spec
    st, d = raw.send("GET", p + "?max=5", auth=a)
    check(st == 401, "a signature over the path with its query string is refused (sign the path only)", Raw.show("GET", p + "?max=5", b"", a, st, d))
    a = raw.auth("GET", p, b"")
    st, d = raw.send("GET", p + "?max=5", auth=a)
    check(st == 200, "a signature over the bare path, sent with ?max=5, is accepted", Raw.show("GET", p + "?max=5", b"", a, st, d))
    body = json.dumps({"names": [f"{ns}/qa-auth"], "mode": "pull"}).encode()
    a = raw.auth("POST", "/airc/v0/bind", b"{}")               # hash of a different body
    st, d = raw.send("POST", "/airc/v0/bind", body, auth=a)
    check(st == 401, "a body that does not match the signed hash is refused", Raw.show("POST", "/airc/v0/bind", body, a, st, d))
    import tempfile
    stranger = S.Signer(os.path.join(tempfile.mkdtemp(), "stranger.key"))   # a fresh key the realm never saw
    a = raw.auth("GET", p, b"", signer=stranger)
    st, d = raw.send("GET", p, auth=a)
    check(st == 401, "an unknown key is refused", Raw.show("GET", p, b"", a, st, d))
    st, d = raw.send("GET", p)
    check(st == 401, "no Authorization header is refused", Raw.show("GET", p, b"", None, st, d))

    print("bind modes (spec 3.4.2)")
    x, y = f"{ns}/qa-x-{secrets.token_hex(2)}", f"{ns}/qa-y-{secrets.token_hex(2)}"
    r = await hc.bind([x, y], mode="pull")
    check(isinstance(r, dict) and r.get("t") == "bound", f"bind {x} and {y} in pull mode", json.dumps(r)[:300])
    for mode in ("push", "webhook"):
        body = json.dumps({"names": [x, y], "mode": mode, **({"webhook": "https://example.invalid/hook"} if mode == "webhook" else {})}).encode()
        a = raw.auth("POST", "/airc/v0/bind", body)
        st, d = raw.send("POST", "/airc/v0/bind", body, auth=a, headers={"AIRC-Session": hc.session} if hc.session else None)
        print(f"  info  bind mode={mode}: HTTP {st} {d[:120]}")
    await hc.bind([x, y], mode="pull")

    print("send, inbox, ack (spec 3.4.2, 6.6, 7.3)")
    for m in await hc.inbox():                                   # start from an empty queue
        await hc.ack(m["id"])
    m = wire.new_msg(x, y, "qa ping " + secrets.token_hex(4))
    a1 = await hc._request("POST", "/airc/v0/send", m)
    check(a1.get("t") == "ack" and a1.get("status") in ("delivered", "queued"), f"send {x} -> {y}: ack {a1.get('status')} {a1.get('code', '')}", json.dumps(a1)[:300])
    got = []
    for _ in range(20):
        got = [g for g in await hc.inbox() if g.get("id") == m["id"]]
        if got:
            break
        await asyncio.sleep(0.5)
    check(bool(got), "the message is in the inbox")
    if got:
        g = got[0]
        check(g.get("from", "").endswith(x) and g.get("to", "").endswith(y) and g.get("body") == m["body"], "from, to and body arrive intact", json.dumps(g)[:300])
    a2 = await hc._request("POST", "/airc/v0/send", m)          # the same id again
    dup = [g for g in await hc.inbox() if g.get("id") == m["id"]]
    check(len(dup) <= 1, f"resending the same id does not queue a second copy (ack: {a2.get('status')} {a2.get('code', '')})", json.dumps(a2)[:300])
    await hc.ack(m["id"])
    left = [1]
    for _ in range(20):
        left = [g for g in await hc.inbox() if g.get("id") == m["id"]]
        if not left:
            break
        await asyncio.sleep(0.5)
    check(not left, "after ack the message leaves the inbox")
    a3 = await hc._request("POST", "/airc/v0/send", m)          # after ack: still a duplicate, must not reappear
    back = [g for g in await hc.inbox() if g.get("id") == m["id"]]
    check(not back, f"the same id sent after its ack does not come back (ack: {a3.get('status')} {a3.get('code', '')})", json.dumps(a3)[:300])
    other = await hc._request("POST", "/airc/v0/send", wire.new_msg("someoneelse/x", y, "not mine"))
    check(other.get("status") == "failed" or other.get("t") != "ack", f"sending from outside {ns}/ is refused (ack: {other.get('status')} {other.get('code', '')})", json.dumps(other)[:300])
    exp = wire.new_msg(x, y, "expired", ttl=1)
    exp["ts"] = time.time() - 3600
    a4 = await hc._request("POST", "/airc/v0/send", exp)
    late = [g for g in await hc.inbox() if g.get("id") == exp["id"]]
    check(not late, f"a message past its ttl is not delivered (ack: {a4.get('status')} {a4.get('code', '')})", json.dumps(a4)[:300])
    for g in late:
        await hc.ack(g["id"])

    print("push over the WebSocket (spec 3.4.6)")
    ws = "ws" in (caps.get("features") or [])
    if ws:
        await push_checks(hc, raw, x, y)
    else:
        print("  info  the capabilities do not list ws: skipped (clients poll this realm)")

    print("binary sections (spec 22)")
    if "bin" in (caps.get("features") or []):
        await bin_checks(hc, raw, x, y)
        if ws:
            await bin_push_checks(hc, raw, x, y)
    else:
        print("  info  the capabilities do not list bin: skipped")

    print("links (spec 11)")
    try:
        o = await hc.link("offer", **{"as": x, "peer": f"//{realm}/{y}", "label": "qa link"})
        lid = o.get("link", {}).get("id") or o.get("id")
        check(o.get("t") == "linked" and bool(lid), f"offer {x} -> {y}: {lid}", json.dumps(o)[:300])
        acc = await hc.link("accept", **{"as": y, "id": lid})
        st = (acc.get("link") or {}).get("state") or acc.get("state")
        check(st == "active", f"accept as {y}: state {st}", json.dumps(acc)[:300])
        rv = await hc.link("revoke", **{"as": x, "id": lid})
        st = (rv.get("link") or {}).get("state") or rv.get("state")
        check(st == "revoked", f"revoke as {x}: state {st}", json.dumps(rv)[:300])
        ls = await hc.link("list", **{"as": x})
        mine = [l for l in (ls.get("links") or []) if l.get("id") == lid]
        check(bool(mine) and mine[0].get("state") == "revoked", "the link list shows it revoked", json.dumps(ls)[:300])
    except Exception as e:  # noqa: BLE001
        check(False, "links: offer, accept, revoke", repr(e))
    for m in await hc.inbox():                                   # notices and leftovers
        await hc.ack(m["id"])
    await hc.release()
    if RECORDER is not None:
        RECORDER.stop()
        import test_schema as SCHEMA
        print("schema (schemas/airc-frames.schema.json)")
        rep = SCHEMA.validate_records(RECORDER.records)
        check(rep.total > 0 and not rep.failures and not rep.unknown,
              f"every frame and response seen validates: {rep.total} checks, {len(rep.failures)} distinct violations",
              "\n".join(rep.lines("")))
        if not rep.failures:
            print("          " + rep.lines("")[0])
    print("PASS" if not fails else f"FAIL: {fails} check(s) failed")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
