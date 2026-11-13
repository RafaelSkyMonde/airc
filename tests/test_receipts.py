#!/usr/bin/env python3
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Receipts (spec §6.7): seen/done receipts asked for with hdr airc-receipt, sent by the recipient's relay or
listener as replies of type application/airc-receipt+json, under the recipient site's policy (on | off | hook,
by scope, same-realm vs foreign senders), recorded as msg.receipt events. Uses test_airc's two-realm fixture;
run it on its own, after test_airc (the suites share fixed loopback ports)."""
import asyncio
import contextlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
sys.path.insert(0, HERE)

# `airc done` and the relay keep what each message asked for in a small index: never the real ~/.airc one here
RECEIPTS_DIR = tempfile.mkdtemp(prefix="airc-test-receipts-")
os.environ["AIRC_RECEIPTS_INDEX"] = os.path.join(RECEIPTS_DIR, "receipts.json")

from test_airc import Realms, HTTP_A, HTTP_B        # noqa: E402  (also points AIRC_E2E_DIR at a temp dir)
from airc import address as A                       # noqa: E402
from airc.client import (RECEIPT_TYPE, ReceiptSender, AskedIndex, receipts_asked, receipt_state,   # noqa: E402
                         receipt_body)
from airc.events import EventLog                    # noqa: E402
from airc.server import Server                      # noqa: E402

ASK = {"airc-receipt": "seen,done"}


async def nxt(c, timeout=5):
    return await asyncio.wait_for(c.messages().__anext__(), timeout)


async def xfer(send_coro, receiver, timeout=5):
    """(ack, message) for a send to a plain client: the receiver must ack before the sender's ack says delivered."""
    t = asyncio.ensure_future(send_coro)
    m = await asyncio.wait_for(receiver.messages().__anext__(), timeout)
    await receiver.ack(m["id"])
    return await t, m


async def none_within(c, secs):
    """The next message within secs, or None: used to show a receipt did NOT come."""
    try:
        return await asyncio.wait_for(c.messages().__anext__(), secs)
    except asyncio.TimeoutError:
        return None


class Hook:
    """A site's receipt hook: mode allow | deny | sleep | garbage, remembering every payload it was sent."""

    def __init__(self):
        self.mode = "allow"
        self.seen: list[dict] = []
        hook = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    hook.seen.append(json.loads(self.rfile.read(n)))
                except ValueError:
                    hook.seen.append({"bad": True})
                if hook.mode == "sleep":
                    time.sleep(5)
                body = (b"not json" if hook.mode == "garbage" else
                        json.dumps({"allow": True} if hook.mode == "allow" else {"allow": False, "reason": "probing"}).encode())
                try:
                    self.send_response(200); self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
                except OSError:
                    pass                                              # the server gave up on us (the timeout case)
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.srv.daemon_threads = True
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}/receipts"

    def close(self):
        self.srv.shutdown(); self.srv.server_close()


class ReceiptTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.mkdtemp(prefix="airc-test-")
        self.r = None
        self.tasks = []

    async def asyncTearDown(self):
        for t in self.tasks:
            t.cancel()
        if self.r:
            await self.r.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def _start(self, receipts=None, **kw):
        self.r = Realms(self.tmp, **kw)
        if receipts is not None:
            self.r.cfg_a["receipts"] = receipts
        await self.r.start()

    async def _relay(self, ns="carol", agents=("analyst", "other")):
        from airc.relay import Relay
        from airc.backends import load
        backend = load("stdout", agents=list(agents))
        relay = Relay(ns, backend, socket=f"{self.tmp}/a.sock")
        self.tasks.append(asyncio.ensure_future(relay.run_forever()))
        await asyncio.sleep(0.5)
        return relay, backend

    def _check_receipt(self, m, state, re_id, frm):
        self.assertEqual(m["type"], RECEIPT_TYPE)
        self.assertEqual(m["re"], re_id)
        self.assertEqual(m["from"], frm)
        body = json.loads(m["body"])
        self.assertEqual(body["state"], state); self.assertIsInstance(body["ts"], int)
        self.assertEqual(receipt_state(m), state)
        self.assertNotIn("airc-receipt", m.get("hdr") or {})       # a receipt never carries airc-receipt

    # ------------------------------------------------------------------ the relay path, same realm
    async def test_seen_from_relay_and_event(self):
        """A sender asks for seen,done; the relay hands the message to its agent and `seen` comes back as a reply
        of the receipt type; done does not come by itself; the server records msg.receipt."""
        await self._start()
        relay, backend = await self._relay()
        x = await self.r.client("a"); await x.bind(["alice/x"])
        a = await x.send("carol/analyst", "hello", frm="alice/x", hdr=dict(ASK))
        self.assertEqual(a["status"], "delivered")
        self.assertTrue(backend.log[-1][2].endswith("hello"))
        m = await nxt(x)
        self._check_receipt(m, "seen", a["id"], "airc://home.test/carol/analyst")
        await x.ack(m["id"])
        self.assertIsNone(await none_within(x, 1.0))                 # no `done` unless the agent says so
        ev = [e for e in EventLog.tail(self.r.a.events.path, 50) if e["kind"] == "msg.receipt"]
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["state"], ev[0]["re"], ev[0]["from"], ev[0]["to"], ev[0]["id"]),
                         ("seen", a["id"], "airc://home.test/carol/analyst", "airc://home.test/alice/x", m["id"]))
        # a message that asked for nothing gets nothing; one that asked for done only gets nothing from the relay
        await x.send("carol/analyst", "plain", frm="alice/x")
        await x.send("carol/analyst", "done only", frm="alice/x", hdr={"airc-receipt": "done"})
        await x.send("carol/analyst", "unknown type", frm="alice/x", hdr={"airc-receipt": "read"})
        self.assertIsNone(await none_within(x, 1.0))
        await x.close()

    # ------------------------------------------------------------------ foreign senders
    async def test_foreign_sender_off_by_default_on_when_configured(self):
        """The shipped default is off for senders in other realms: the relay's receipt is refused by its own server
        and the foreign sender sees none. With foreign: on it arrives, across the peer link."""
        await self._start()
        relay, backend = await self._relay()
        bob = await self.r.client("b", ns_claim=["support"]); await bob.bind(["support/bob"])
        a = await bob.send("//home.test/carol/analyst", "from afar", frm="support/bob", hdr=dict(ASK))
        self.assertEqual(a["status"], "delivered")
        self.assertIn("from afar", backend.log[-1][2])
        self.assertIsNone(await none_within(bob, 1.5))
        self.assertFalse(any(e["kind"] == "msg.receipt" for e in EventLog.tail(self.r.a.events.path, 50)))
        self.r.a.receipts_cfg = Server._receipts_policy({"foreign": "on"})
        a2 = await bob.send("//home.test/carol/analyst", "again", frm="support/bob", hdr=dict(ASK))
        self.assertEqual(a2["status"], "delivered")
        m = await nxt(bob)
        self._check_receipt(m, "seen", a2["id"], "airc://home.test/carol/analyst")
        self.assertEqual(m["via"], ["home.test"])
        await bob.ack(m["id"]); await asyncio.sleep(0.3)             # the event follows the peer's ack
        # both realms record it (the fixture's two servers share one events file): A on egress, B on ingress
        ev = [e for e in EventLog.tail(self.r.a.events.path, 50) if e["kind"] == "msg.receipt"]
        self.assertEqual(sorted((e["re"], e["to"], e["state"], e["hop"]) for e in ev),
                         [(a2["id"], "airc://partner.test/support/bob", "seen", "client"),
                          (a2["id"], "airc://partner.test/support/bob", "seen", "peer")])
        await bob.close()

    # ------------------------------------------------------------------ scopes
    async def test_off_scope_refuses_receipt_but_delivers_message(self):
        await self._start(receipts={"scopes": {"carol/": "off", "carol/analyst": "on"}})
        relay, backend = await self._relay()
        x = await self.r.client("a"); await x.bind(["alice/x"])
        a = await x.send("carol/other", "to other", frm="alice/x", hdr=dict(ASK))
        self.assertEqual(a["status"], "delivered")                   # the message itself is delivered normally
        self.assertTrue(backend.log[-1][2].endswith("to other"))
        self.assertIsNone(await none_within(x, 1.0))                 # only the receipt is suppressed
        a2 = await x.send("carol/analyst", "to analyst", frm="alice/x", hdr=dict(ASK))
        m = await nxt(x)
        self._check_receipt(m, "seen", a2["id"], "airc://home.test/carol/analyst")    # the narrower scope wins
        # the refusal as the sending client sees it
        y = await self.r.client("a")
        r = await y.send("alice/x", receipt_body("seen"), frm="carol/other", mtype=RECEIPT_TYPE, re_id=a["id"])
        self.assertEqual((r["status"], r["code"], r["reason"]), ("failed", "refused", "receipts are off for carol/"))
        await x.close(); await y.close()

    async def test_narrowest_scope_wins(self):
        srv = Server({"realm": "home.test", "spool_dir": f"{self.tmp}/s",
                      "receipts": {"default": "on", "foreign": "off",
                                   "scopes": {"carol/": "off", "carol/analyst": "on", "carol/ops/": "hook",
                                              "//home.test/alice/ops": "off", "airc://home.test/dave/": "hook"}}})
        pol = lambda ep, realm="home.test": srv.receipt_policy(A.parse(ep), realm)   # noqa: E731
        self.assertEqual(pol("//home.test/carol/analyst"), ("on", "carol/analyst"))
        self.assertEqual(pol("//home.test/carol/other"), ("off", "carol/"))
        self.assertEqual(pol("//home.test/carol/ops/x"), ("hook", "carol/ops/"))     # the deeper namespace
        self.assertEqual(pol("//home.test/alice/ops"), ("off", "//home.test/alice/ops"))
        self.assertEqual(pol("//home.test/alice/x")[0], "on")                        # default: same realm
        self.assertEqual(pol("//home.test/alice/x", "partner.test")[0], "off")       # foreign
        self.assertEqual(pol("//home.test/dave/y", "partner.test"), ("hook", "airc://home.test/dave/"))   # scope beats foreign
        # shipped default when the key is absent, and bad values fall back
        self.assertEqual(Server._receipts_policy({}), {"default": "on", "foreign": "off", "scopes": {}, "hook": None})
        self.assertEqual(Server._receipts_policy({"default": "maybe", "foreign": "ON", "hook": 7})["default"], "on")
        self.assertEqual(Server._receipts_policy({"foreign": "ON"})["foreign"], "on")

    # ------------------------------------------------------------------ hook
    async def test_hook_allow_deny_timeout(self):
        hook = Hook()
        try:
            await self._start(receipts={"default": "hook", "hook": hook.url})
            x = await self.r.client("a"); await x.bind(["alice/x"])
            y = await self.r.client("a"); await y.bind(["carol/y"])
            t = asyncio.ensure_future(x.send("carol/y", "please ack", frm="alice/x", hdr=dict(ASK)))
            m = await nxt(y); await y.ack(m["id"]); a = await t
            self.assertEqual(a["status"], "delivered")
            send_receipt = lambda st: y.send("alice/x", receipt_body(st), frm="carol/y", mtype=RECEIPT_TYPE, re_id=m["id"])  # noqa: E731
            # allow: the receipt passes, and the hook saw the metadata (no body)
            r, rx = await xfer(send_receipt("seen"), x)
            self.assertEqual(r["status"], "delivered")
            self._check_receipt(rx, "seen", m["id"], "airc://home.test/carol/y")
            p = hook.seen[-1]
            self.assertEqual((p["id"], p["from"], p["to"], p["state"], p["sender_realm"], p["type"], p["asked"]),
                             (m["id"], "airc://home.test/carol/y", "airc://home.test/alice/x", "seen", "home.test",
                              "text/plain", "seen,done"))
            self.assertNotIn("body", p)
            # deny
            hook.mode = "deny"
            r = await send_receipt("done")
            self.assertEqual((r["status"], r["code"]), ("failed", "refused")); self.assertIn("probing", r["reason"])
            # anything but {"allow": true} denies
            hook.mode = "garbage"
            r = await send_receipt("done")
            self.assertEqual((r["status"], r["code"]), ("failed", "refused"))
            # a timeout denies (fail closed), within the 3 s budget
            hook.mode = "sleep"
            t0 = time.monotonic()
            r = await send_receipt("done")
            self.assertEqual((r["status"], r["code"]), ("failed", "refused"))
            self.assertGreaterEqual(time.monotonic() - t0, 2.5); self.assertLess(time.monotonic() - t0, 5)
            self.assertIsNone(await none_within(x, 0.3))
            # the hook's decision concerns receipts only: a plain reply is not asked about
            hook.mode = "deny"; n = len(hook.seen)
            r, _ = await xfer(y.send("alice/x", "a real reply", frm="carol/y", re_id=m["id"]), x)
            self.assertEqual(r["status"], "delivered"); self.assertEqual(len(hook.seen), n)
            await x.close(); await y.close()
        finally:
            hook.close()

    async def test_hook_mode_without_url_denies(self):
        await self._start(receipts={"default": "hook"})
        x = await self.r.client("a"); await x.bind(["alice/x"])
        y = await self.r.client("a")
        r = await y.send("alice/x", receipt_body("seen"), frm="carol/y", mtype=RECEIPT_TYPE, re_id="m-1")
        self.assertEqual((r["status"], r["code"]), ("failed", "refused")); self.assertIn("hook", r["reason"])
        await x.close(); await y.close()

    # ------------------------------------------------------------------ the receipt itself
    async def test_never_receipt_a_receipt_and_once_per_type(self):
        class Fake:
            def __init__(self):
                self.sent = []

            async def send(self, to, body, *, frm, mtype, re_id, **kw):
                self.sent.append((to, json.loads(body), frm, mtype, re_id))
                return {"status": "delivered"}
        fake = Fake()
        rs = ReceiptSender(fake, delay=0)
        msg = {"id": "m1", "from": "airc://home.test/alice/x", "to": "airc://home.test/carol/y#run-1",
               "hdr": dict(ASK), "type": "text/plain", "body": "hi"}
        self.assertEqual(receipts_asked(msg), {"seen", "done"})
        self.assertTrue(rs.fire(msg, "seen")); self.assertFalse(rs.fire(msg, "seen"))     # once per type per id
        self.assertTrue(rs.fire(msg, "done")); self.assertFalse(rs.fire(msg, "done"))
        await rs.drain()
        self.assertEqual([(s[0], s[1]["state"], s[2], s[3], s[4]) for s in fake.sent],
                         [("airc://home.test/alice/x", "seen", "airc://home.test/carol/y", RECEIPT_TYPE, "m1"),
                          ("airc://home.test/alice/x", "done", "airc://home.test/carol/y", RECEIPT_TYPE, "m1")])
        # a receipt is never receipted, even if it (wrongly) asks; unknown and unasked types are not sent
        rcpt = {"id": "m2", "from": "airc://home.test/carol/y", "to": "airc://home.test/alice/x", "re": "m1",
                "type": RECEIPT_TYPE, "body": receipt_body("seen"), "hdr": dict(ASK)}
        self.assertEqual(receipts_asked(rcpt), set()); self.assertFalse(rs.fire(rcpt, "seen"))
        only_seen = dict(msg, id="m3", hdr={"airc-receipt": "seen"})
        self.assertFalse(rs.fire(only_seen, "done")); self.assertTrue(rs.fire(only_seen, "seen"))
        self.assertFalse(rs.fire(dict(msg, id="m4", hdr={"airc-receipt": "read"}), "seen"))
        self.assertFalse(rs.fire(dict(msg, id="m5", hdr={}), "seen"))
        await rs.drain()
        self.assertEqual(len(fake.sent), 3)
        # a failing send never raises out of the sender
        class Bad(Fake):
            async def send(self, *a, **kw):
                raise OSError("down")
        rb = ReceiptSender(Bad(), delay=0)
        self.assertTrue(rb.fire(msg, "seen")); await rb.drain()
        # receipt_state: only a well-formed receipt
        self.assertIsNone(receipt_state(dict(rcpt, body="nope"))); self.assertIsNone(receipt_state(dict(rcpt, re=None)))
        self.assertIsNone(receipt_state(dict(rcpt, body=json.dumps({"state": "read"}))))

    async def test_server_strips_header_and_refuses_malformed(self):
        """The server drops airc-receipt from a receipt on its way, and refuses a receipt that is not one."""
        await self._start()
        x = await self.r.client("a"); await x.bind(["alice/x"])
        y = await self.r.client("a")
        r, m = await xfer(y.send("alice/x", receipt_body("seen"), frm="carol/y", mtype=RECEIPT_TYPE, re_id="m-1",
                                 hdr={"airc-receipt": "seen", "x-keep": "yes"}), x)
        self.assertEqual(r["status"], "delivered")
        self._check_receipt(m, "seen", "m-1", "airc://home.test/carol/y"); self.assertEqual(m["hdr"].get("x-keep"), "yes")
        for body, re_id in (("nope", "m-1"), (json.dumps({"state": "read"}), "m-1"), (receipt_body("seen"), None)):
            r = await y.send("alice/x", body, frm="carol/y", mtype=RECEIPT_TYPE, re_id=re_id)
            self.assertEqual((r["status"], r["code"]), ("failed", "refused"), body); self.assertIn("malformed", r["reason"])
        await x.close(); await y.close()

    # ------------------------------------------------------------------ done: only by airc done
    async def test_done_only_via_cli(self):
        from airc import cli
        await self._start()
        relay, backend = await self._relay()
        x = await self.r.client("a"); await x.bind(["alice/x"])
        a = await x.send("carol/analyst", "do this", frm="alice/x", hdr=dict(ASK))
        self.assertEqual(a["status"], "delivered")
        m = await nxt(x); self._check_receipt(m, "seen", a["id"], "airc://home.test/carol/analyst"); await x.ack(m["id"])
        self.assertIsNone(await none_within(x, 1.0))                 # nothing automatic
        rec = AskedIndex().get(a["id"])
        self.assertEqual((rec["from"], rec["to"], rec["asked"]), ("airc://home.test/alice/x", "airc://home.test/carol/analyst", ["done", "seen"]))
        ns = lambda **kw: types.SimpleNamespace(**{"socket": f"{self.tmp}/a.sock", "server": None, "claim_ns": None,   # noqa: E731
                                                   "key": None, "insecure": False, "verbose": False, "to": None,
                                                   "me": None, "json": False, **kw})
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(await cli.cmd_done(ns(id=a["id"])), 0)
        m = await nxt(x); self._check_receipt(m, "done", a["id"], "airc://home.test/carol/analyst"); await x.ack(m["id"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            self.assertEqual(await cli.cmd_done(ns(id=a["id"])), 0)              # once: the second says so and sends nothing
            self.assertEqual(await cli.cmd_done(ns(id="unknown-id")), 2)         # not taken here, no --to
        self.assertIn("already sent", err.getvalue()); self.assertIn("--to", err.getvalue())
        self.assertIsNone(await none_within(x, 0.7))
        # a message that asked for seen only: done is not sent
        a2 = await x.send("carol/analyst", "look", frm="alice/x", hdr={"airc-receipt": "seen"})
        m = await nxt(x); self.assertEqual(receipt_state(m), "seen"); await x.ack(m["id"])
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(await cli.cmd_done(ns(id=a2["id"])), 1)
        self.assertIsNone(await none_within(x, 0.5))
        # with --to the operator asserts the request: sent as the named endpoint
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(await cli.cmd_done(ns(id="ext-1", to="alice/x", me="carol/other")), 0)
        m = await nxt(x); self._check_receipt(m, "done", "ext-1", "airc://home.test/carol/other")
        ev = [e for e in EventLog.tail(self.r.a.events.path, 50) if e["kind"] == "msg.receipt"]
        self.assertEqual([e["state"] for e in ev], ["seen", "done", "seen", "done"])
        await x.close()

    # ------------------------------------------------------------------ the sender's view: send --wait
    async def test_send_wait_reports_receipts_then_reply(self):
        """airc send --receipt seen --wait prints `seen by <endpoint> after N s` when the receipt comes, keeps
        waiting, and ends with the reply; --json emits the receipt frame."""
        from airc import signing as S
        from airc import cli
        wk = S.Signer(f"{self.tmp}/workspace.key")
        await self._start(signed=True, http=(HTTP_A, HTTP_B), client_keys_a={wk.kid: {"pub": wk.public_b64, "ns": ["joe"]}})
        relay, backend = await self._relay()

        def run(args):
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    rc = cli.main(args)
                except SystemExit as e:
                    rc = e.code
            return rc, out.getvalue()
        base = ["--server", f"http://127.0.0.1:{HTTP_A}", "--key", f"{self.tmp}/workspace.key", "send", "--from", "joe/asker"]
        for extra in ([], ["--json"]):
            n = len(backend.log)
            task = asyncio.ensure_future(asyncio.to_thread(run, base + extra + ["--wait", "15", "--receipt", "seen,done", "carol/analyst", "ping"]))
            for _ in range(100):                                      # the relay has it: the agent "answers" after a moment
                if len(backend.log) > n:
                    break
                await asyncio.sleep(0.1)
            text = backend.log[-1][2]
            mid = re.search(r"\[airc id=([^\s\]]+)", text).group(1)
            await asyncio.sleep(1.0)
            self.assertFalse(task.done())                              # the receipt did not end the wait
            x = await self.r.client("a")
            await x.send("joe/asker", "pong", frm="carol/analyst", re_id=mid)
            rc, out = await asyncio.wait_for(task, 20)
            self.assertEqual(rc, 0, out)
            if not extra:
                self.assertRegex(out, r"seen by //home\.test/carol/analyst after \d+\.\d s")
                self.assertIn("pong", out)
                self.assertLess(out.index("seen by"), out.index("pong"))
            else:
                frames = [json.loads(l) for l in out.splitlines() if l.startswith("{")]
                kinds = [(f.get("type"), f.get("re")) for f in frames[1:]]
                self.assertEqual(kinds[0], (RECEIPT_TYPE, mid)); self.assertEqual(frames[1]["from"], "airc://home.test/carol/analyst")
                self.assertEqual(json.loads(frames[1]["body"])["state"], "seen")
                self.assertEqual(frames[-1]["body"], "pong")
            await x.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
