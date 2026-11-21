# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""airc — command line client.

  airc send [--from NAME] [--re ID] [--ttl S] [--plain] <to> <message...>   send one message (encrypted when the recipient publishes keys)
  airc send-file [--from NAME] [--plain] <to> <path> [note...]            send a file of up to 8 MB (spec §22)
  airc listen [name] [--format text|json|agent] [--take-over] [--status] [--once [--no-ack] [--from ADDR] [--links]]
                                                        receive as a name (default: <workspace>/<agent>) and print what arrives
  airc relay --namespace NS [--backend co|stdout|inbox|claude] [--opt K=V] [--autostart off|local|all] [--header minimal|ids]
  airc setup co [--workspace NAME | --join CODE] [--enable] [--print]
                                                        wire a co fleet to a hosted workspace: key, env file, relay unit
  airc channel close [name]                             close a channel when its agent is done (§21.4)
  airc events [-n 50] [--follow] [--kinds msg link ...]  aircd's audit stream (no bodies)
  airc status                                           server snapshot
  airc whoami                                           who this key is (with --server)
  airc addr <text> [--realm R] [--ns NS]                parse an address
  airc key [--path FILE]                                create or show a key and its client_keys entry
  airc keys [--as ME] [--trust PEER]                    end-to-end keys: yours, and pinning a peer's
  airc link offer <peer> [--as ME] [--label L] [--direction D] [--expires 30d] [--credential CODE]
                    [--challenge ID (--proof-x X | --code C | --email E | --phone P)] [--contact-email E]
                    [--contact-phone P] [--no-auto]      a challenged offer (§11.6): pow is solved automatically
  airc link accept <id> [--as ME] [--passport URL]     accept, or answer with a passport to another scope here
  airc link decline|revoke <id> [--as ME]
  airc link revoke --key PIN [--as ME]                 refuse every link that key authorized (§12.7)
  airc link unreject --key PIN [--as ME]               stop refusing it (closed links stay closed)
  airc links [--all] [--as ME]                          links involving my endpoints
  airc passport new [--as ME] [--scope S] [--sign-key FILE ...] [--label L] [--expires 7d] [--uses 1] [--to PATTERN]
                    [--direction D] [--link-ttl 30d]     prints https://<host>/<scope>#passport=<token>.<pin>...[.r=<realm pin>]
                    [--for-offer LINK_ID]                a receptionist's answer to that pending offer (§12.9)
  airc passport list [--all]
  airc passport revoke <id> [--as ME] [--and-links]
  airc passport keys add|list|remove --scope S [--key B64 | --key-file FILE]
  airc passport new ... --delegate REALM:PIN[,PIN] [--rules JSON]   a delegation (§12.10): prints its reference URL
  airc passport delegate '<passport>' --sign-key FILE [--expires] [--uses] [--to P] [--link-ttl] [--direction]
                    [--delegate REALM:PIN ...] [--rules JSON] [--offer HASH]   add a layer, locally
  airc passport revoke-layer '<passport>' <layer id>   (administrators) close a layer this realm signed
  airc accept '<passport url>' [--as ME|NS/]            redeem a passport (also: airc passport redeem)
  airc profile set|show|delete [--as ME] ...            the endpoint's public profile (§21)
  airc workspace create|join|show|invite|revoke-key|revoke-invite|recovery-code|front|list-agent|delete
                                                        a hosted workspace (§3.4.4, §3.4.5); invite --channel NAME
                                                        or --enroll makes codes for channel keys

With --server (or $AIRC_SERVER) the CLI uses a realm's HTTPS face; the key is
--key, $AIRC_KEY_FILE, the key held in $AIRC_KEY, or the one key in
~/.airc/<realm>/. $AIRC_AGENT names this agent; $AIRC_SESSION gives the
process a stable session id (§4.3.1).

Exit codes for send: 0 delivered or queued, 1 failed (see message), 2 could
not reach the server.
"""
from __future__ import annotations

import argparse
import asyncio
import time
import json
import logging
import os
import re
import subprocess
import sys

from . import __version__
from . import address as A
from .client import Client, DEFAULT_SOCKET
from .wire import WireError
from . import wire

log = logging.getLogger("airc")


def _sock(args):
    return args.socket or DEFAULT_SOCKET


def _key_for(realm: str, explicit: str | None) -> str:
    """The workspace key to sign with for realm: --key if given, else $AIRC_KEY_FILE, else the key held
    in $AIRC_KEY, else the only key at the conventional place ~/.airc/<realm>/<workspace>.key, else
    the legacy ~/.airc/workspace.key."""
    import glob
    if explicit:
        return os.path.expanduser(explicit)
    if os.environ.get("AIRC_KEY_FILE"):
        return os.path.expanduser(os.environ["AIRC_KEY_FILE"])
    if os.environ.get("AIRC_KEY"):
        return _key_from_env(realm, os.environ["AIRC_KEY"])
    found = sorted(glob.glob(os.path.expanduser(f"~/.airc/{realm}/*.key")))
    if len(found) == 1:
        return found[0]
    if len(found) > 1:
        raise SystemExit(f"airc: several workspace keys for {realm}: {', '.join(found)}; choose one with --key")
    legacy = os.path.expanduser("~/.airc/workspace.key")
    if os.path.exists(legacy):
        return legacy
    raise SystemExit(f"airc: no workspace key for {realm} in ~/.airc/{realm}/. Create a workspace "
                     f"(airc --server <url> workspace create <name>) or join one (airc --server <url> workspace join <code>).")


def _key_from_env(realm: str, value: str) -> str:
    """$AIRC_KEY holds a workspace key's contents (the base64 line of a .key file), for machines that keep
    no files between sessions: cloud sandboxes, CI. It is written to a hidden 0600 file, which the one-key
    lookup above does not see, and rewritten whenever the variable changes."""
    import base64, binascii
    value = value.strip()
    try:
        seed = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        seed = b""
    if len(seed) != 32:
        raise SystemExit("airc: $AIRC_KEY is not a workspace key (expected the base64 line from a .key file)")
    path = os.path.expanduser(f"~/.airc/{realm}/.env.key")
    try:
        with open(path) as f:
            if f.read().strip() == value:
                return path
    except OSError:
        pass
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.{os.getpid()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    os.replace(tmp, path)
    return path


async def _probe_realm(server: str, insecure: bool) -> str:
    import tempfile
    from .httpclient import HttpClient
    from . import signing as S
    import shutil
    d = tempfile.mkdtemp()                       # a throwaway key for an unsigned request; removed at once
    try:
        probe = HttpClient(server, S.Signer(os.path.join(d, "probe.key")), insecure=insecure)
    finally:
        shutil.rmtree(d, ignore_errors=True)
    return (await probe.capabilities())["realm"]


async def _connect_https(args):
    """An HTTPS session for --server: realm from the capabilities document, the realm's workspace key,
    the workspace from GET /airc/v0/workspace."""
    from .httpclient import HttpClient, HttpClientError, HttpCliSession
    from . import signing as S
    try:
        realm = await _probe_realm(args.server, args.insecure)
        hc = HttpClient(args.server, S.Signer(_key_for(realm, args.key)), insecure=args.insecure)
        await hc.capabilities()
        channel = None
        try:
            ws = await hc.workspace()
            ns, channel = ws["ns"], ws.get("channel")
        except HttpClientError:                        # a realm without hosted workspaces (a self-hosted aircd)
            ns = (getattr(args, "me", None) or "").split("/")[0]
        if channel and not getattr(args, "me", None):  # a channel key acts only as its channel: that is "me"
            args.me = f"{ns}/{channel}"
    except (HttpClientError, OSError, KeyError) as e:
        print(f"airc: cannot use {args.server}: {e}", file=sys.stderr)
        sys.exit(2)
    sess = HttpCliSession(hc, ns)
    sess.channel = channel
    return sess


async def _connect(args, **kw) -> Client:
    if getattr(args, "server", None):
        return await _connect_https(args)
    try:
        return await Client.connect(_sock(args), ns_claim=args.claim_ns, **kw)
    except (OSError, WireError, asyncio.TimeoutError) as e:
        print(f"airc: cannot reach server at {_sock(args)}: {e}", file=sys.stderr)
        sys.exit(2)


from .e2e import E2EError   # noqa: E402
from .client import RECEIPT_TYPE, ReceiptSender, AskedIndex, receipt_state, receipt_body, receipts_asked   # noqa: E402


async def _my_keys(c, me: str):
    """This endpoint's keystore, created, rotated and published as needed (§19); None if unavailable."""
    from . import e2e as E2E
    if not E2E.AVAILABLE:
        return None
    ks = E2E.Keystore(A.parse(c.absolute(me)).key)
    await E2E.ensure_published(ks, c.keys_publish)
    return ks


async def cmd_send_file(args):
    """A file, inside one message (spec §22); encrypted like any message when the recipient publishes keys."""
    from . import files as F
    try:
        args.body, args.bin = F.pack(args.path, " ".join(args.note or []))
    except OSError as e:
        print(f"airc: cannot read {args.path}: {e.strerror}", file=sys.stderr)
        return 2
    except F.FileError as e:
        print(f"airc: not sent: {e.reason}", file=sys.stderr)
        return 3
    args.mtype = F.MEDIA_TYPE
    return await cmd_send(args)


async def cmd_send(args):
    from . import passports as P
    if P.looks_like_passport(args.to):              # §12.3: a passport is not an address
        print("airc: that is a passport, not an address; redeem it with: airc accept '<passport url>'", file=sys.stderr)
        return 1
    note = "plain"
    me = None                                       # over HTTPS: the address replies come back to
    body = getattr(args, "body", None)
    if body is None:
        body = " ".join(args.message)
    mtype = getattr(args, "mtype", "text/plain")
    data = getattr(args, "bin", None)
    hdr = None
    if getattr(args, "receipt", None):                 # §6.7: ask the recipient for seen/done receipts
        want = [t.strip().lower() for t in args.receipt.split(",") if t.strip()]
        bad = [t for t in want if t not in ("seen", "done")]
        if bad or not want:
            print(f"airc: --receipt takes seen, done or seen,done (not {args.receipt!r})", file=sys.stderr)
            return 2
        if mtype == RECEIPT_TYPE:
            print("airc: a receipt never asks for a receipt", file=sys.stderr)
            return 2
        hdr = {"airc-receipt": ",".join(dict.fromkeys(want))}
    sent_at = time.monotonic()
    if args.server:
        from .httpclient import HttpClient, HttpClientError
        from . import signing as S
        try:
            hc = HttpClient(args.server, S.Signer(_key_for(await _probe_realm(args.server, args.insecure), args.key)), insecure=args.insecure)
            me = args.frm or await _https_me(hc)
            if args.plain:
                a = await hc.send(args.to, body, frm=me, mtype=mtype, re_id=args.re, ttl=args.ttl, bin=data, hdr=hdr)
            else:
                a, note = await hc.send_e2e(args.to, body, frm=me, mtype=mtype, re_id=args.re, ttl=args.ttl, bin=data, hdr=hdr)
        except (HttpClientError, OSError) as e:
            print(f"airc: {e}", file=sys.stderr)
            return 2
        except E2EError as e:
            print(f"airc: not sent: {e.reason}", file=sys.stderr)
            return 3
    else:
        async with await _connect(args) as c:
            if args.plain:
                a = await c.send(args.to, body, frm=args.frm, mtype=mtype, re_id=args.re, ttl=args.ttl, bin=data, hdr=hdr)
            else:
                try:
                    a, note = await c.send_e2e(args.to, body, frm=args.frm, mtype=mtype, re_id=args.re, ttl=args.ttl, bin=data, hdr=hdr)
                except E2EError as e:
                    print(f"airc: not sent: {e.reason}", file=sys.stderr)
                    return 3
            try:                                          # the recipient as this fleet reads it: its alias, if it has one
                shown = c.display(c.absolute(args.to))
            except (A.AddressError, AttributeError):
                shown = args.to
    status, reason = a.get("status"), a.get("reason", "")
    shown = locals().get("shown") or args.to
    report = os.environ.get("AIRC_REPORT")              # a caller (co tell) learns the address as shown, for its own records
    if report:
        try:
            with open(report, "w", encoding="utf-8") as f:
                json.dump({"to": args.to, "shown": shown, "status": status}, f)
        except OSError:
            pass
    if a.get("code") == "e2e_required" and args.plain:
        reason += " (you sent with --plain)"
    if args.verbose and a.get("code"):
        reason = f"{reason} [{a['code']} by {a.get('by', '?')}]"
    sealing = ("plaintext: --plain" if args.plain else          # say whether it went sealed, every time
               "sealed e2e " + note[4:] if note.startswith("e2e ") else
               "plaintext: " + note.split(": ", 1)[1] if note.startswith("plain: ") else "plaintext")
    tail = f" ({reason}; {sealing})" if reason else f" ({sealing})"
    if getattr(args, "json", False):
        print(json.dumps(dict(a, to=args.to, **({"shown": shown} if shown != args.to else {}), **({"from": me} if me else {})), ensure_ascii=False))
    if status in ("delivered", "queued"):
        if not getattr(args, "json", False):
            print(f"{'Delivered to' if status == 'delivered' else 'Queued for'} {shown}, id {a.get('id', '?')}{tail}")
        if me and not getattr(args, "wait", None) and not getattr(args, "json", False):   # where the answer will land, and how to wait for it
            print(f"Replies come to {me}; to wait for one: airc {_conn_opts(args)}listen --once --wait 60 {me}")
        if me and getattr(args, "wait", None):
            return await _send_wait(args, me, a.get("id", ""), sent_at)
        return 0
    if not getattr(args, "json", False):
        print(f"Failed to send to {shown}{tail}", file=sys.stderr)
    return 1


def _conn_opts(args) -> str:
    """The connection options a printed follow-up command needs to reach the same realm with the same key."""
    out = ""
    if args.server and not os.environ.get("AIRC_SERVER"):
        out += f"--server {args.server} "
    if getattr(args, "key", None) and not os.environ.get("AIRC_KEY_FILE"):
        out += f"--key {args.key} "
    if getattr(args, "insecure", False):
        out += "--insecure "
    return out


async def _send_wait(args, me: str, msg_id: str, sent_at: float | None = None) -> int:
    """send --wait: then wait, like listen --once --wait, for the reply to this message only (re = its id);
    other mail stays queued. Receipts (§6.7) to it are reported as they come and do not end the wait; a reply
    does. Status 3 if none came in time."""
    import argparse
    largs = argparse.Namespace(**vars(args))
    largs.name, largs.once, largs.only_re = me, True, msg_id
    largs.sent_at = sent_at if sent_at is not None else time.monotonic()
    largs.only_from, largs.only_links, largs.no_ack, largs.take_over, largs.status = None, False, False, False, False
    largs.format = "json" if getattr(args, "json", False) else getattr(args, "format", None) or "text"
    largs.json = getattr(args, "json", False)
    return await cmd_listen(largs)


class _StatusPublisher:
    """listen --status (or AIRC_STATUS=1): publish push-active for the bound endpoints while listening,
    refreshed every 2 minutes, and push-inactive on the way out (§21.2). Status is opt-in: it shows when the
    agent works, so nothing is published without it."""

    def __init__(self, c, bound):
        self.c, self.task = c, None
        self.eps = [A.parse(c.absolute(n)).key for n in bound if not str(n).endswith("/")]

    async def _publish(self, state):
        if self.eps:
            await self.c.hc.profile_status([{"endpoint": ep, "status": state} for ep in self.eps])

    def start(self):
        async def loop():
            while True:
                await self._publish("push-active")
                await asyncio.sleep(110)
        self.task = asyncio.get_running_loop().create_task(loop())

    async def stop(self):
        if self.task:
            self.task.cancel()
        try:
            await asyncio.wait_for(self._publish("push-inactive"), 5)
        except (Exception, asyncio.CancelledError):
            pass


def _own_side(c, r: dict) -> str | None:
    """From a not-a-party refusal ("... it joins A and B ..."), the side in this workspace, if exactly one is."""
    import re
    m = re.search(r"it joins (\S+) and (\S+)\. Act as", str(r.get("reason", "")))
    ns = getattr(c, "ns", None)
    if not m or not ns:
        return None
    try:
        mine = [x for x in m.groups() if A.parse(x).path[:1] == (ns,)]
    except A.AddressError:
        return None
    return A.parse(mine[0]).local_path if len(mine) == 1 else None


def _secret_out(value: str, what: str, given: str | None, default_path: str) -> None:
    """Show a secret (a recovery, join or enrollment code) without leaving it in an agent's transcript: to
    `given` if set; else, when stdout is not a terminal (an agent's tool call, a log), to a new 0600 file at
    default_path, printing only where; else on the terminal."""
    path = os.path.expanduser(given) if given else (None if sys.stdout.isatty() else default_path)
    if not path:
        print("  " + value)
        return
    base, n = path, 2
    while not given and os.path.exists(path):
        path = f"{base}.{n}"; n += 1
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(value + "\n")
    why = "" if given else " (not printed: this output is not going to a terminal, so it would stay in a log or transcript)"
    print(f"  {what} written to {path}, mode 0600{why}. Give it to your human, then delete it here.")


async def _listen_wait(c, args, handle, want, wait: float) -> int:
    """listen --once --wait: one WebSocket (spec §3.4.6), so the call returns the moment a message comes, by
    push, rather than after a poll. What is already waiting arrives first, as the socket's backlog. Takes every
    wanted message that comes within a moment of the first, acks it up the socket (unless --no-ack), and
    returns 0; 3 if nothing came within `wait` seconds; None if the socket would not open (the caller polls)."""
    from .httpclient import WsSocket, HttpClientError
    try:
        ws = await WsSocket(c.hc).open()
    except (HttpClientError, OSError) as e:
        print(f"airc listen: no WebSocket ({str(e)[:80]}); pulling the inbox instead", file=sys.stderr)
        return None
    got = 0
    end = time.monotonic() + wait
    try:
        frames = ws.frames()
        while True:
            left = (end if not got else min(end, time.monotonic() + 0.5)) - time.monotonic()
            if left <= 0:
                break
            try:
                f = await asyncio.wait_for(frames.__anext__(), left)
            except (asyncio.TimeoutError, StopAsyncIteration):
                break
            batch = [f] if f.get("t") == "msg" else await c.hc.inbox() if f.get("t") == "inbox" else []
            for m in batch:
                if not want(m):
                    continue
                r = await handle(m)
                if not _receipt_only(m, args):
                    got += 1
                if not args.no_ack:
                    st = (r,) if isinstance(r, str) else tuple(r)
                    await ws.ack(m["id"], st[0], st[1] if len(st) > 1 else "", st[2] if len(st) > 2 else None)
    finally:
        await ws.close()
    return 0 if got else 3


def _listen_filter(c, args):
    """listen --once --from/--links: which waiting messages this call takes. A link notice comes from our realm's
    _links and names the other party in airc-peer; --from matches that party as well as direct messages."""
    peer = A.parse(c.absolute(args.only_from)).key if args.only_from else None

    def want(m) -> bool:
        if getattr(args, "only_re", None) and m.get("re") != args.only_re:
            return False                                  # send --wait: only the reply to that message
        try:
            frm = A.parse(m["from"])
        except (A.AddressError, KeyError):
            return False
        notice = frm.path == ("_links",) and frm.realm == c.realm
        if args.only_links and not notice:
            return False
        if peer:
            about = (m.get("hdr") or {}).get("airc-peer") if notice else None
            try:
                return frm.key == peer or (about is not None and A.parse(about).key == peer)
            except A.AddressError:
                return False
        return True
    return want


async def cmd_listen(args):
    from .httpclient import NameHeld
    from . import files as F
    async with await _connect(args, agent=f"airc-listen/{__version__}") as c:
        name = _own_address(c, args.name)
        try:
            if getattr(c, "hc", None):
                wait = getattr(args, "wait", None) or 0
                bound = await c.bind([name], mode="pull" if args.once and not wait else "push", take_over=args.take_over)
            else:
                bound = await c.bind([name], take_over=args.take_over)
        except NameHeld as e:
            idle = f" (last seen {e.idle}s ago)" if e.idle is not None else ""
            alt = f"Listen as {e.suggest.split('/', 3)[-1]} instead, or add" if e.suggest else "Add"
            print(f"airc listen: another process is listening as {e.name.split('/', 3)[-1]}{idle}. "
                  f"{alt} --take-over if that process is gone.", file=sys.stderr)
            return 4
        except WireError as e:
            if e.code != "name_held":
                raise
            print(f"airc listen: {e.reason}. Add --take-over if that process is gone.", file=sys.stderr)
            return 4
        print(f"listening as {', '.join(bound)} (realm {c.realm})", file=sys.stderr)
        receipts = ReceiptSender(getattr(c, "hc", c), AskedIndex())   # §6.7: `seen` once a message is printed

        async def handle(m):
            from . import e2e as E2E
            if getattr(c, "hc", None):                          # --once hands over inbox frames as listed: fetch the
                from .httpclient import HttpClientError         # binary section (§22) before opening or saving anything
                try:
                    m = await c.hc.fetch_bin(m)
                except (HttpClientError, WireError) as e:
                    print(f"[airc: the binary section of {m.get('id')} from {m.get('from')} was not fetched: {e}; "
                          f"acked as failed]" + ("\n---" if _listen_format(args) == "agent" else ""),
                          flush=True, file=sys.stdout if _listen_format(args) == "agent" else sys.stderr)
                    return ("failed", f"binary section not fetched: {e}", "bad_bin")
            if receipt_state(m):                                # a receipt to us (§6.7): shown as its state, never receipted
                print(_render_receipt(m, args))
                sys.stdout.flush()
                return "delivered"
            h0 = dict(m.get("hdr") or {})
            h0.pop("airc-e2e", None)                            # only our own opening below may say it was encrypted
            try:
                own_notice = A.parse(m["from"]).path == ("_links",) and A.parse(m["from"]).realm == c.realm
            except (A.AddressError, KeyError):
                own_notice = False
            if not own_notice:
                for k in ("airc-peer-ik", "airc-peer-sig", "airc-peer-control"):
                    h0.pop(k, None)                             # keys to pin come only from our realm's link notices
            m = dict(m, hdr=h0)
            if m.get("type") == E2E.MEDIA_TYPE and E2E.AVAILABLE:
                try:
                    m = E2E.Keystore(A.parse(m["to"]).key).open(m)
                except E2E.E2EError as e:
                    if _listen_format(args) == "agent":
                        print(f"[airc: could not open an encrypted message from {m.get('from')} id={m.get('id')}: "
                              f"{e.reason} ({e.code}); acked as failed]\n---", flush=True)
                    return ("failed", e.reason, e.code)
            h = m.get("hdr") or {}
            if own_notice and h.get("airc-peer") and E2E.AVAILABLE:
                try:                                            # §19.9: verify a signed control, pin, flag what the pin did not sign
                    _res, warn = E2E.check_link_notice(E2E.Keystore(A.parse(m["to"]).key), h, A.parse(m["to"]).key)
                except (A.AddressError, E2E.E2EError):
                    warn = ""
                if warn:
                    print(warn, flush=True, file=sys.stdout if _listen_format(args) == "agent" else sys.stderr)
            if m.get("type") == F.MEDIA_TYPE:                   # a file (§22): saved, and shown by where it is
                try:
                    meta, path = F.save(m)
                except F.FileError as e:
                    print(f"[airc: a file from {m.get('from')} id={m.get('id')} was not saved: {e.reason}; acked as failed]"
                          + ("\n---" if _listen_format(args) == "agent" else ""), flush=True)
                    return ("failed", e.reason, e.code)
                m = dict(m, body=F.describe(meta, path), file=dict(meta, path=path))
            print(_render_listen(m, args))
            sys.stdout.flush()
            if not getattr(args, "no_ack", False) and receipts_asked(m):     # unacked (peeked) mail is not seen yet
                receipts.index.remember(m)
                receipts.fire(m, "seen")
            return "delivered"
        try:
            return await _listen_run(c, args, handle, bound)
        finally:
            await receipts.drain(3)


async def _listen_run(c, args, handle, bound) -> int:
    """The body of airc listen once bound: the --once drains, or the long-running serve."""
    from .httpclient import Displaced
    if args.once:
        # drain what is waiting, print it, ack it (unless --no-ack), exit: for turn-based agents and hooks
        if not getattr(c, "hc", None):
            print("airc listen --once needs --server (a hosted workspace's inbox); a local aircd pushes instead", file=sys.stderr)
            return 2
        want = _listen_filter(c, args)
        wait = getattr(args, "wait", None) or 0
        if wait and "ws" in c.hc.features:
            r = await _listen_wait(c, args, handle, want, wait)
            if r is not None:
                return r
        got = 0
        end = time.monotonic() + wait
        from .httpclient import RateLimited
        longpoll = wait and "longpoll" in c.hc.features
        while True:                                   # without the WebSocket: long-polls (§3.4.7), else every 10 s
            try:
                left = end - time.monotonic()
                batch = await c.hc.inbox(wait=min(25.0, left) if longpoll and left >= 1 else None)
            except RateLimited as e:                  # the server limits pulls (spec §3.4.6): wait as it asks
                if time.monotonic() + e.retry_after >= end:
                    return 3
                await asyncio.sleep(e.retry_after)
                continue
            for m in batch:
                if not want(m):
                    continue                          # not what this call waits for: left queued, unacked
                r = await handle(m)
                if not _receipt_only(m, args):
                    got += 1
                if not args.no_ack:
                    await c._handle(lambda _m, _r=r: _async_value(_r), m)
            if got or time.monotonic() >= end:
                return 0 if got else 3
            if not longpoll:
                await asyncio.sleep(max(0.0, min(10.0, end - time.monotonic())))
    if args.only_from or args.only_links:
        print("airc listen: --from and --links work only with --once (a running listener must take every message)", file=sys.stderr)
        return 2
    if getattr(args, "wait", None):
        print("airc listen: --wait works only with --once (a running listener waits anyway)", file=sys.stderr)
        return 2
    if args.no_ack:
        print("airc listen: --no-ack works only with --once (a running listener must ack, or it sees the same messages forever)", file=sys.stderr)
        return 2
    if getattr(c, "hc", None):
        status = _StatusPublisher(c, bound) if (args.status or os.environ.get("AIRC_STATUS") == "1") else None
        try:
            if status:
                status.start()
            await c.serve(handle, on_mode=lambda text: (print(f"airc listen: {text}", file=sys.stderr), sys.stderr.flush()))
        except Displaced as e:
            c.bound = []                          # nothing left to release
            print(f"airc listen: {e}; stopping", file=sys.stderr)
            return 5
        finally:
            if status:
                await status.stop()
    else:
        await c.serve(handle)
    return 0


async def cmd_mcp(args):
    """Tool tunnels (spec §23)."""
    import secrets
    from . import mcptunnel as M
    from .httpclient import NameHeld
    if args.mcp_op == "export":
        cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
        if not cmd:
            print("airc mcp export: give the MCP server's command after --", file=sys.stderr)
            return 2
    async with await _connect(args, agent=f"airc-mcp/{__version__}") as c:
        if args.mcp_op == "export":
            me = args.me
        elif getattr(c, "channel", None):              # a channel key acts only as its channel
            me = _own_address(c, None)
        else:                                         # §23: a fresh address per session, beneath --as or our own
            # (never --as itself: binding an agent's own address would take its chat mail for the session's life)
            me = f"{(args.me or _own_address(c, None)).rstrip('/')}/mcp-{secrets.token_hex(3)}"
        try:
            if getattr(c, "hc", None):
                bound = await c.bind([me], mode="push", take_over=getattr(args, "take_over", False))
            else:
                bound = await c.bind([me], take_over=getattr(args, "take_over", False))
        except (NameHeld, WireError) as e:
            print(f"airc mcp: cannot bind {me}: {e}", file=sys.stderr)
            return 4
        me = c.absolute(bound[0] if bound else me)
        if not args.plain:
            try:
                await _my_keys(c, me)                 # publish this address's keys, so answers to it can be sealed
            except Exception as e:  # noqa: BLE001
                M.log(f"keys not published ({e}); answers to {me} travel unencrypted")
        if args.mcp_op == "import":
            M.log(f"importing {args.to} as {me}")
            return await M.run_import(c, me, args.to, plain=args.plain)
        allow = None if args.allow_all else {t.strip() for t in args.allow.split(",") if t.strip()}
        ex = M.Exporter(c, me, cmd, allow, idle=args.idle, plain=args.plain)
        M.log(f"exporting {' '.join(cmd)} at {me}; tools: {', '.join(sorted(allow)) if allow is not None else 'all'}")
        reaper = asyncio.get_running_loop().create_task(ex.reap())
        try:
            await c.serve(ex.handle)
        finally:
            reaper.cancel()
            ex.close()
    return 0


def _listen_format(args) -> str:
    return args.format or ("json" if args.json else "text")


def _render_listen(m: dict, args) -> str:
    fmt = _listen_format(args)
    if fmt == "json":
        return json.dumps(wire.strip(m), ensure_ascii=False)
    if fmt == "text":                                # §16 item 4: foreign origins marked, the body kept from imitating headers
        from .relay import BANNER, escape_body
        try:
            frm, to = A.parse(m["from"]), A.parse(m["to"])
        except (A.AddressError, KeyError):
            return f"[from (unreadable address)] {escape_body(str(m.get('body') or ''))}"
        out = ""
        if frm.path[:1] != ("_links",) and (frm.realm != to.realm or frm.path[:1] != to.path[:1]):
            scope = f"another organisation, realm {frm.realm}" if frm.realm != to.realm else f"another workspace on {frm.realm}"
            out = BANNER.format(sender=frm.network(False), scope=scope) + "\n"
        return out + f"[from {frm.network(False)}] " + escape_body(str(m.get("body") or ""))
    # agent: a block per message for an agent that reads the listener's output directly (Claude Code's
    # Monitor tool, say): origin banner, the header line the inbox backend uses, the body, a ready-made
    # reply command, then a "---" line.
    from .backends.inbox import InboxHop
    from .relay import BANNER, escape_body
    frm, to = A.parse(m["from"]), A.parse(m["to"])
    notice = frm.path[:1] == ("_links",)             # the realm's own notices: no banner, no reply line
    lines = []
    if not notice and (frm.realm != to.realm or frm.path[:1] != to.path[:1]):
        scope = f"another organisation, realm {frm.realm}" if frm.realm != to.realm else f"another workspace on {frm.realm}"
        lines.append(BANNER.format(sender=frm.network(False), scope=scope))
    lines.append(InboxHop.header(frm.network(False), m))
    lines.append(escape_body(str(m.get("body") or ""), keep_first=notice and frm.realm == to.realm))   # §16 item 4
    if not notice:
        import shlex                                 # §16 item 4: every value quoted for the shell; an id outside its grammar left out
        server = f" --server {shlex.quote(args.server)}" if args.server and os.environ.get("AIRC_SERVER") != args.server else ""
        re_part = f" --re {shlex.quote(m['id'])}" if wire.valid_id(m.get("id")) else ""
        lines.append(f"[reply: airc{server} send --from {shlex.quote(to.local_path)}{re_part} {shlex.quote(frm.network(False))} \"your text\"]")
    lines.append("---")
    return "\n".join(lines)


def _receipt_only(m: dict, args) -> bool:
    """A receipt (§6.7) is reported but is not the message a --once/--wait call waits for."""
    return receipt_state(m) is not None


def _render_receipt(m: dict, args) -> str:
    """A receipt as the sender sees it: `seen by <endpoint> after N.N s` during send --wait, or as a line of
    its own in a listener; JSON formats print the frame."""
    if _listen_format(args) == "json":
        return json.dumps(wire.strip(m), ensure_ascii=False)
    state = receipt_state(m) or "?"
    try:
        frm = A.parse(m["from"]).network(False)
    except (A.AddressError, KeyError):
        frm = "(unreadable address)"
    if getattr(args, "only_re", None) and getattr(args, "sent_at", None) is not None:
        return f"{state} by {frm} after {time.monotonic() - args.sent_at:.1f} s"
    line = f"[receipt: {state} by {frm} re={m.get('re')}]"
    return line + ("\n---" if _listen_format(args) == "agent" else "")


async def _async_value(v):
    return v


async def cmd_done(args):
    """airc done <id>: send the `done` receipt (§6.7) for a message this agent handled and will not answer.
    The message must have asked for it (hdr airc-receipt lists done); the listener or relay that took it
    recorded what it asked for and from whom, so only the id is needed. Sent once."""
    idx = AskedIndex()
    rec = idx.get(args.id)
    if rec is None and not args.to:
        print(f"airc done: {args.id} is not a message this machine's listener or relay took (or it asked for no receipt); "
              f"pass --to <its sender> to send the receipt anyway", file=sys.stderr)
        return 2
    if rec is not None:
        if "done" in (rec.get("sent") or []):
            print(f"done receipt for {args.id} was already sent", file=sys.stderr)
            return 0
        if "done" not in (rec.get("asked") or []) and not args.to:
            print(f"airc done: {args.id} did not ask for a done receipt (asked: {', '.join(rec.get('asked') or []) or 'none'}); not sent",
                  file=sys.stderr)
            return 1
    to = args.to or rec["from"]
    async with await _connect(args) as c:
        me = _own_address(c, args.me) if (args.me or rec is None) else A.parse(rec["to"]).key
        a = await getattr(c, "hc", c).send(to, receipt_body("done"), frm=me, mtype=RECEIPT_TYPE, re_id=args.id)
    if getattr(args, "json", False):
        print(json.dumps(dict(a, to=to), ensure_ascii=False))
    if a.get("status") in ("delivered", "queued"):
        idx.mark(args.id, "done")
        if not getattr(args, "json", False):
            print(f"done receipt for {args.id} {a['status']} to {to}")
        return 0
    if a.get("code") == "refused" and "receipt" in str(a.get("reason", "")):      # the site's policy: quiet
        print(f"done receipt not sent: {a.get('reason')}", file=sys.stderr)
        return 0
    print(f"done receipt for {args.id} not sent: {a.get('reason', 'failed')}", file=sys.stderr)
    return 1


async def cmd_relay(args):
    """The fleet relay: bind <namespace>/ and hand each message to a backend."""
    from .relay import Relay
    from . import backends
    opts = {}
    for kv in args.opt or []:
        k, _, v = kv.partition("=")
        opts[k] = v if v not in ("true", "false") else (v == "true")
    if args.autostart:
        opts["autostart"] = args.autostart
    try:
        backend = backends.load(args.backend, **opts)
    except (ImportError, RuntimeError) as e:
        print(f"airc relay: cannot load backend {args.backend!r}: {e}", file=sys.stderr)
        return 2
    key = _key_for(await _probe_realm(args.server, args.insecure), args.key) if args.server else args.key
    relay = Relay(args.namespace, backend, socket=_sock(args), ns_claim=args.claim_ns, header=args.header,
                  server=args.server, key=key, insecure=args.insecure)
    return await relay.run_forever()


async def cmd_events(args):
    from .events import EventLog
    if args.server:
        from .httpclient import HttpClientError
        c = await _connect(args)
        try:
            for ev in (await c.hc.events(kinds=args.kinds))[-args.n:]:
                print(json.dumps(ev, ensure_ascii=False))
        except HttpClientError as e:
            print(f"airc events: {e}", file=sys.stderr); return 1
        return 0
    async with await _connect(args) as c:
        if not args.follow:
            r = await c.stats()
            path = r.get("events_log")
            for ev in EventLog.tail(path, args.n) if path else []:
                print(json.dumps(ev, ensure_ascii=False))
            if not path:
                print("airc events: server did not report an events log path", file=sys.stderr)
                return 1
            return 0
        await c.subscribe(args.kinds)
        async for ev in c.events():
            print(json.dumps(ev, ensure_ascii=False)); sys.stdout.flush()
    return 0


async def cmd_status(args):
    if args.server:
        print("airc status reports on a local aircd; over HTTPS use  airc --server <url> whoami", file=sys.stderr)
        return 2
    async with await _connect(args) as c:
        s = await c.stats()
    s.pop("t", None)
    print(json.dumps(s, indent=2))
    return 0


def _me(args):
    return args.me or default_agent()


def _segment(text: str) -> str:
    """Free text (a session or directory name) as an address segment: lower case, letters, digits and -."""
    import re
    seg = re.sub(r"[^a-z0-9-]+", "-", str(text).lower()).strip("-")[:63].strip("-")
    return seg if seg and not seg.startswith("_") else ""


def _claude_session_name() -> str:
    """The name the user gave this Claude Code session (claude --name, or a rename), if any. One the CLI
    made up itself is not used: it would change from session to session."""
    import glob
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if not sid:
        return ""
    for p in glob.glob(os.path.expanduser("~/.claude/sessions/*.json")):
        try:
            rec = json.load(open(p))
        except (OSError, ValueError):
            continue
        if rec.get("sessionId") == sid and rec.get("nameSource") == "user":
            return rec.get("name") or ""
    return ""


def default_agent() -> str:
    """This agent's name when none is given: $AIRC_AGENT, else the name the user gave the CLI session
    (Claude Code, or co's CO_SESSION_NAME), else the working directory's name, else "agent". An unpacked
    client (airc-<version>/, where the quick start runs) is not a name: it would announce the version."""
    cwd = os.path.basename(os.getcwd())
    if re.fullmatch(r"airc-\d+(\.\d+)*", cwd):
        cwd = ""
    for cand in (os.environ.get("AIRC_AGENT"), _claude_session_name(), os.environ.get("CO_SESSION_NAME"), cwd):
        seg = _segment(cand or "")
        if seg:
            return seg
    return "agent"


async def _https_me(hc) -> str:
    """The default sender over HTTPS: <workspace>/<default agent>."""
    from .httpclient import HttpClientError
    try:
        ws = await hc.workspace()
        return f"{ws['ns']}/{ws.get('channel') or default_agent()}"
    except (HttpClientError, KeyError):
        return default_agent()


def _own_address(c, name: str | None) -> str:
    """name as given, or this agent's endpoint in the workspace: <workspace>/<default agent>."""
    if name:
        return name
    if getattr(c, "channel", None):                  # a channel key: its own channel
        return f"{c.ns}/{c.channel}"
    ns = getattr(c, "ns", None) or (c.namespaces[0] if getattr(c, "namespaces", None) else "")
    return f"{ns}/{default_agent()}" if ns else default_agent()


def _fmt_link(l, realm=None, aliases=None):
    import datetime
    exp = datetime.datetime.fromtimestamp(l["expires"]).strftime("%Y-%m-%d") if l.get("expires") else "-"
    lab = f'  "{l["label"]}"' if l.get("label") else ""

    def show(k):                                          # a side in another realm by this fleet's alias, if it has one
        try:
            return A.alias_display(A.parse(k), aliases) or k
        except A.AddressError:
            return k
    return f'{l["id"]:<11} {l["state"]:<9} {show(l["a"])}  <->  {show(l["b"])}  [{l["direction"]}, until {exp}]{lab}'


def _owned_by(c, key: str) -> bool:
    """Whether endpoint key lies in this client's namespace(s)."""
    try:
        ep = A.parse(key)
    except A.AddressError:
        return False
    if ep.realm != getattr(c, "realm", None):
        return False
    nss = [c.ns] if getattr(c, "ns", None) else list(getattr(c, "namespaces", None) or [])
    return any(ep.path[:len(n.split("/"))] == tuple(n.split("/")) for n in nss if n)


def sign_offer(ks, a: str, b: str, direction: str, expires) -> dict:
    """The link-frame fields of a signed offer (§4.6, §19.9): id, ts, expires_at, sig. The client chooses the
    id and the absolute expiry, and signs them with the ts the server must give the control."""
    from . import e2e as E2E
    from .links import new_id, parse_duration
    ts = round(time.time(), 3)
    ttl = parse_duration(expires)
    exp_at = int(ts + ttl) if ttl else None
    lid = new_id()
    out = {"id": lid, "ts": ts, "sig": ks.sign(E2E.canonical_link_control("offer", lid, a, b, direction or "both", exp_at, ts))}
    if exp_at is not None:
        out["expires_at"] = exp_at
    return out


def sign_answer(ks, rec: dict, op: str) -> dict:
    """The link-frame fields of a signed accept, decline or revoke of rec (§19.9): ts and sig."""
    from . import e2e as E2E
    ts = round(time.time(), 3)
    return {"ts": ts, "sig": ks.sign(E2E.link_control_fields(rec, op, ts))}


async def _find_link(c, me: str, lid: str) -> dict | None:
    """The record of link lid as this client's server stores it, or None."""
    try:
        r = await c.link("list", **{"as": me})
        for l in r.get("links") or []:
            if l.get("id") == lid:
                return l
    except Exception:  # noqa: BLE001  (no list on this face: the control goes unsigned)
        pass
    return None


async def cmd_link(args):
    async with await _connect(args) as c:
        me = _me(args)
        ks = await _my_keys(c, me)
        ik = ks.ik if ks else None
        if args.op == "offer":
            fields = {"as": me, "peer": args.peer, "label": args.label, "direction": args.direction,
                      "expires": args.expires, "e2e_ik": ik, "credential": getattr(args, "credential", None)}
            signed = {}
            if ks:                                        # §19.9: sign whenever this endpoint has an identity key
                try:
                    signed = sign_offer(ks, A.parse(c.absolute(me)).key, A.parse(c.absolute(args.peer)).key,
                                        args.direction, args.expires)
                except (A.AddressError, ValueError):
                    signed = {}
            fields.update(_challenge_fields(args))
            r = await c.link("offer", **fields, **signed)
            if signed and not r.get("ok") and r.get("code") == "bad_request":
                print(f"airc link offer: the server refused the signed offer ({r.get('reason')}); sending it unsigned",
                      file=sys.stderr)
                signed = {}
                r = await c.link("offer", **fields)
            if r.get("code") == "challenge":           # §11.6: meet a challenge and offer again
                r = await _meet_challenges(c, args, fields, signed, r, A.parse(c.absolute(me)).key)
                if r is None:
                    return 1
        elif args.op == "unreject" or (args.op == "revoke" and getattr(args, "key", None) and not args.id):
            r = await c.link(args.op, **{"as": me}, key=args.key)          # §12.7: refuse (or stop refusing) by key
            if not r.get("ok"):
                print(f"airc link {args.op}: {r.get('reason', 'refused')}", file=sys.stderr)
                return 1
            if args.op == "unreject":
                print(f"{me} no longer refuses links authorized by key {args.key}; links it closed stay closed")
            else:
                closed = r.get("closed") or []
                print(f"{me} refuses links authorized by key {args.key} (record {r['link']['id']})"
                      + (f"; closed {', '.join(closed)}" if closed else ""))
            return 0
        else:
            if not args.id:
                print(f"airc link {args.op}: give a link id (or --key PIN)", file=sys.stderr)
                return 1
            rec = await _find_link(c, me, args.id) if ks or not getattr(args, "me", None) else None
            if rec and not getattr(args, "me", None) and A.parse(c.absolute(me)).key not in (rec["a"], rec["b"]):
                mine = [x for x in (rec["a"], rec["b"]) if _owned_by(c, x)]
                if len(mine) == 1:                        # no --as and the default name is not a party: use our side
                    me = A.parse(mine[0]).local_path
                    ks = await _my_keys(c, me)
                    ik = ks.ik if ks else None
            signed = sign_answer(ks, rec, args.op) if ks and rec else {}
            fwd = getattr(args, "passport", None)
            if fwd:                                       # §12.9, §12.10: answer with a passport issued beforehand
                signed["passport"] = fwd
            elif args.op == "accept" and (ks or getattr(args, "sign_key", None)) and rec:
                # §12.9: our own key, and any --sign-key keys (an audit key, say), sign the passport that accepts
                try:
                    extra = [SeedSigner(_read_seed(f)) for f in getattr(args, "sign_key", None) or []]
                except (OSError, ValueError) as e:
                    print(f"airc link accept: {e}", file=sys.stderr)
                    return 1
                try:
                    signed.update(accept_passport_fields(ks, rec, A.parse(c.absolute(me)).key, extra))
                except (A.AddressError, ValueError):
                    pass
            r = await c.link(args.op, **{"as": me}, id=args.id, e2e_ik=ik, **signed)
            if args.op == "accept" and "auth" in signed and not getattr(args, "sign_key", None) \
                    and not r.get("ok") and r.get("code") == "bad_request":
                print(f"airc link accept: the server refused our signature on the passport ({r.get('reason')}); "
                      "accepting without it", file=sys.stderr)
                r = await c.link(args.op, **{"as": me}, id=args.id, e2e_ik=ik, **sign_answer(ks, rec, args.op))
            side = _own_side(c, r) if not getattr(args, "me", None) and not r.get("ok") else None
            if side:                                      # no --as and the default name was not a party: use our side
                ks = await _my_keys(c, side)
                r = await c.link(args.op, **{"as": side}, id=args.id, e2e_ik=ks.ik if ks else None)
    if not r.get("ok"):
        print(f"airc link {args.op}: {r.get('reason', 'refused')}", file=sys.stderr)
        return 1
    l = r["link"]
    tail = f" ({r['reason']})" if r.get("reason") else ""
    print(f"link {l['id']} {l['state']}: {l['a']} <-> {l['b']} [{l['direction']}]; peer notified: {r.get('delivery')}{tail}")
    if args.op == "offer" and l["state"] == "pending":
        print(f"the offer reached them as a link notice showing your label; no message has been sent yet. When they "
              f"accept (they run  airc link accept {l['id']}), you get a notice from _links; send your message then. "
              f"To wait for just that:  airc listen --once --links")
    return 0


def _challenge_fields(args) -> dict:
    """§11.6: the proof and contact a `link offer` was given on the command line."""
    out = {}
    if getattr(args, "challenge", None):
        proof = {"challenge": args.challenge}
        for k, a in (("x", "proof_x"), ("code", "code"), ("email", "email"), ("phone", "phone")):
            if getattr(args, a, None):
                proof[k] = getattr(args, a)
        out["proof"] = proof
    contact = {k: getattr(args, a) for k, a in (("email", "contact_email"), ("phone", "contact_phone")) if getattr(args, a, None)}
    if contact:
        out["contact"] = contact
    return out


async def _meet_challenges(c, args, fields: dict, signed: dict, r: dict, me_key: str, rounds: int = 6):
    """Answer the challenges an offer met (§11.6): proof of work automatically (unless --no-auto); for an
    email or phone, ask for the address and then the code when on a terminal; for a login, print the URL
    and how to offer again with the code. Returns the final linked response, or None when the user must act."""
    from . import challenges as CH
    interactive = sys.stdin.isatty() and not getattr(args, "no_auto", False)
    for _ in range(rounds):
        if r.get("code") != "challenge":
            return r
        chs = r.get("challenges") or []
        print(f"airc link offer: {r.get('reason') or 'the offeree asks for a proof'}", file=sys.stderr)
        pw = next((ch for ch in chs if ch.get("kind") == "pow"), None)
        proof = None
        if pw and not getattr(args, "no_auto", False):
            t0 = time.time()
            x = CH.solve_pow(pw["id"], me_key, int(pw.get("bits", 0)))
            print(f"airc link offer: solved a proof of work of {pw['bits']} bits in {time.time() - t0:.1f} s", file=sys.stderr)
            proof = {"challenge": pw["id"], "x": x}
        else:
            for ch in chs:
                k = ch.get("kind")
                if k == "pow":
                    print(f"  proof of work, {ch.get('bits')} bits: offer again without --no-auto, or with "
                          f"--challenge '{ch['id']}' --proof-x X", file=sys.stderr)
                elif k in ("login", "oauth"):
                    print(f"  {k}{' (' + ch['provider'] + ')' if ch.get('provider') else ''}: open {ch.get('url')}\n"
                          f"    then offer again with: --challenge '{ch['id']}' --code <the code shown>", file=sys.stderr)
                elif k in ("email", "sms"):
                    what = "email address" if k == "email" else "phone number"
                    flag = "--email" if k == "email" else "--phone"
                    if ch.get("need"):
                        given = getattr(args, "contact_email" if k == "email" else "contact_phone", None)
                        if not given and interactive:
                            given = input(f"The offeree asks for your {what}: ").strip()
                        if given:
                            proof = {"challenge": ch["id"], ("email" if k == "email" else "phone"): given}
                            break
                        print(f"  {k}: offer again with --challenge '{ch['id']}' {flag} <your {what}>", file=sys.stderr)
                    else:
                        if interactive:
                            code = input(f"The code sent to your {what}: ").strip()
                            if code:
                                proof = {"challenge": ch["id"], "code": code}
                                break
                        print(f"  {k}: a code was sent; offer again with --challenge '{ch['id']}' --code <the code>",
                              file=sys.stderr)
        if proof is None:
            return None
        f2 = dict(fields, proof=proof)
        r = await c.link("offer", **f2, **signed)
    return r


async def cmd_links(args):
    async with await _connect(args) as c:
        if args.me or not args.server:
            eps = [args.me] if args.me else [None]
        else:                                             # over HTTPS: this agent, plus every agent the workspace lists
            eps = [_own_address(c, None)]
            if not getattr(c, "channel", None):
                try:
                    ws = await c.hc.workspace()
                    eps += [f"{c.ns}/{n}" for n in (ws.get("directory") or []) + [f["agent"] for f in ws.get("front_entries") or []]]
                except Exception:  # noqa: BLE001
                    pass
            eps = list(dict.fromkeys(eps))
        rs = await asyncio.gather(*(c.link("list", all=bool(args.all), **({"as": ep} if ep else {})) for ep in eps))
    seen, links = set(), []
    for r in rs:
        for l in r.get("links", []):
            if l["id"] not in seen:
                seen.add(l["id"]); links.append(l)
    if not links:
        print(f"no links for {', '.join(e for e in eps if e)} (--as <workspace>/<agent> for another endpoint)" if args.server and not args.me else "no links")
        return 0
    for l in links:
        print(_fmt_link(l, aliases=getattr(c, "aliases", None)))
    return 0


async def cmd_alias(args):
    """This fleet's local aliases on its aircd: short names for prefixes in other realms (not part of the protocol)."""
    async with await _connect(args) as c:
        if not hasattr(c, "alias"):
            print("airc: aliases live on a local aircd; this connection is to a hosted realm", file=sys.stderr)
            return 2
        if args.op == "add":
            r = await c.alias("add", args.name, args.prefix)
        elif args.op == "remove":
            r = await c.alias("remove", args.name)
        else:
            r = await c.alias("list")
    if not r.get("ok"):
        print(f"airc: {r.get('reason', 'refused')}", file=sys.stderr)
        return 1
    table = r.get("aliases") or {}
    if args.op != "list":
        print(f"alias {args.name} {'added' if args.op == 'add' else 'removed'}")
    for name in sorted(table):
        print(f"{name:<20} {table[name]}")
    if not table and args.op == "list":
        print("no aliases (airc alias add <name> //realm/namespace/)")
    return 0


def _abs_scope(c, text: str) -> str:
    """A scope as typed (local or network form; "/" for this realm) -> its URI key."""
    from . import passports as P
    t = (text or "").strip()
    if t == "/":
        return f"airc://{c.realm}/"
    try:
        return A.parse(c.absolute(t)).key
    except A.AddressError:
        return P.scope_of(t)


def _read_seed(path: str) -> bytes:
    """A 32-byte ed25519 seed from a file: raw, or base64 text."""
    import base64
    with open(os.path.expanduser(path), "rb") as f:
        data = f.read()
    if len(data) != 32:
        data = base64.b64decode(data.strip(), validate=True)
    if len(data) != 32:
        raise ValueError(f"{path}: not a 32-byte ed25519 seed")
    return data


class SeedSigner:
    """An authorizing key held in a seed file (--sign-key)."""

    def __init__(self, seed: bytes):
        import base64
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization as ser
        self._k = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        self.ik = base64.b64encode(self._k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()

    def sign(self, data: bytes) -> str:
        import base64
        return base64.b64encode(self._k.sign(data)).decode()


def parse_delegates(specs) -> list[dict]:
    """--delegate REALM:PIN[,PIN] ... -> [{"realm", "pins"}] (§12.10)."""
    out = []
    for sp in specs or []:
        realm, sep, pins = str(sp).partition(":")
        if not sep or not realm or not pins:
            raise ValueError(f"--delegate {sp!r}: expected REALM:PIN[,PIN]")
        out.append({"realm": realm.lower(), "pins": [p for p in pins.split(",") if p]})
    return out


def passport_request(scope: str, signers: list, expires=None, uses=None, direction=None, bind_to=None,
                     link_ttl=None, delegates=None, rules=None, offer=None, for_offer=None) -> dict:
    """§12.4: a client-generated token and every signer's signature over the passport's terms.
    signers: objects with .ik (base64 public key) and .sign(bytes) -> base64. Returns {"token", "pins",
    "frame": the passport-frame fields}. Every term is sent explicitly, so the server stores what was signed."""
    from . import passports as P
    from .links import parse_duration
    token = P.new_token()
    ttl = parse_duration(expires) or P.DEFAULT_TTL
    lt = parse_duration(link_ttl) if link_ttl else P.DEFAULT_LINK_TTL
    exp_at = int(time.time() + ttl)
    uses = int(uses or P.DEFAULT_USES)
    direction = direction or "both"
    if delegates:                                   # §12.10: a delegation
        delegates = P.norm_delegates(delegates)
        data = P.canonical_delegate(scope, P.token_hash(token), direction, exp_at, uses, bind_to or None, lt, delegates, rules)
    else:
        data = P.canonical(scope, P.token_hash(token), direction, exp_at, uses, bind_to or None, lt, offer)
    auth = [{"key": s.ik, "sig": s.sign(data)} for s in signers]
    return {"token": token, "pins": [P.pin(a["key"]) for a in auth],
            "frame": {"scope": scope, "token": token, "auth": auth, "expires_at": exp_at, "uses": uses,
                      "direction": direction, "link_ttl": lt, **({"to": bind_to} if bind_to else {}),
                      **({"delegates": delegates} if delegates else {}), **({"rules": rules} if delegates and rules else {}),
                      **({"offer": offer} if offer else {}), **({"for_offer": for_offer} if for_offer else {})}}


def _realm_of_host(host: str) -> str | None:
    """The realm named by https://<host>/.well-known/airc, or None if it can't be fetched."""
    import json, urllib.request
    try:
        req = urllib.request.Request(f"https://{host}/.well-known/airc?nonce={os.urandom(8).hex()}",
                                     headers={"User-Agent": f"airc/{__version__}"})
        with urllib.request.urlopen(req, timeout=10) as r:
            return (json.loads(r.read()).get("realm") or None)
    except Exception:
        return None


def add_layer(passport: str, signer, expires=None, uses=None, bind_to=None, link_ttl=None, direction=None,
              delegates=None, rules=None, root_realm: str | None = None, offer: str | None = None) -> str:
    """§12.10: append a layer to a delegation or a delegated passport, signed locally by signer (no server,
    no network). Returns the longer passport."""
    from . import passports as P
    from .links import parse_duration
    pp = P.parse(passport)
    layers = pp.get("layers") or []
    ref = pp["token"]
    if not P._REF.match(ref):
        raise ValueError("this is not a delegation: it carries a token, not a reference")
    host = pp["host"]
    h, port = A._authority(host)
    # The layer string names the root scope as a URI, but the URL names R's host, not its realm (§12.10):
    # --realm, else the realm R's capabilities document names, else the host without a leading "airc.".
    # A wrong realm only makes R refuse the layer's signature.
    realm = root_realm or _realm_of_host(host) or (h[len("airc."):] if h.startswith("airc.") else h)
    realm = realm.lower()
    scope = P.scope_of(f"//{realm}/{pp['path']}" if pp["path"] else f"//{realm}/")
    prev = P.decode_layer(layers[-1]) if layers else None
    now = int(time.time())
    if expires:
        exp = now + parse_duration(expires)
    else:
        # A layer may not outlive its parent. The delegation's expiry isn't in the passport, so a first layer
        # defaults to one day (pass --expires for longer, up to the delegation's own expiry).
        exp = prev["body"]["expires"] if prev else now + 86400
    body = {"id": P.new_layer_id(), "expires": int(exp)}
    if uses:
        body["uses"] = int(uses)
    if bind_to:
        body["bind_to"] = bind_to
    if link_ttl:
        body["link_ttl"] = int(parse_duration(link_ttl))
    if direction:
        body["direction"] = direction
    if delegates:
        body["delegates"] = P.norm_delegates(delegates)
    if rules:
        body["rules"] = rules
    if offer:                                       # §12.9, §12.10: a forward names the offer it answers
        body["offer"] = offer
    enc = P.make_layer(signer, scope, ref, layers[-1] if layers else None, body)
    return passport.strip() + "~" + enc


def accept_passport_fields(ks, offer: dict, me_key: str, extra_signers: list | None = None) -> dict:
    """§12.9: the link-frame fields that let the accepting endpoint sign the passport its server issues for
    the offerer: scope = this endpoint, bind_to = exactly the offerer, 1 use, 600 s, the offer's direction
    seen from this side, a link no longer-lived than the offer. {"token", "expires_at", "link_ttl", "auth"}."""
    from . import passports as P
    now = time.time()
    offerer = offer["offered_by"]
    direction = {"a-initiates": "b-initiates", "b-initiates": "a-initiates"}.get(offer["direction"], "both")
    lt = P.DEFAULT_LINK_TTL
    if offer.get("expires"):
        lt = min(lt, int(float(offer["expires"]) - now))
        if lt <= 0:
            raise ValueError("the offer has expired")
    token = P.new_token()
    exp_at = int(now + 590)
    data = P.canonical(me_key, P.token_hash(token), direction, exp_at, 1, offerer[len("airc:"):], lt, P.offer_hash_of(offer))
    signers = ([ks] if ks else []) + list(extra_signers or [])     # the identity key, then any --sign-key keys
    return {"token": token, "expires_at": exp_at, "link_ttl": lt, "auth": [{"key": k.ik, "sig": k.sign(data)} for k in signers]}


def check_issued_passport(r: dict, scope: str, token: str, pins: list[str]) -> str | None:
    """§12.4: before releasing a passport, check that it names the scope asked for, carries our token and
    the pin of every key we signed with. Returns a problem, or None."""
    from . import passports as P
    try:
        pp = P.parse(r.get("url") or "")
    except P.PassportFormatError:
        return "the server returned no passport in the current form"
    if pp["path"] != P.scope_path(scope) or (r.get("passport") or {}).get("scope") != scope:
        return f"the server returned a passport for another scope than {scope}"
    if pp["token"] != token and pp["token"] != P.token_hash(token):      # a delegation shows the reference (§12.10)
        return "the server returned a passport with another token"
    missing = [p for p in pins if p not in pp["pins"]]
    if missing:
        return f"the server's passport lacks the pin of key(s) {', '.join(missing)} that signed it"
    return None


async def cmd_passport(args):
    from . import passports as P
    async with await _connect(args) as c:
        if args.op == "new":
            me = _me(args)
            try:
                me_key = A.parse(c.absolute(me)).key
                scope = _abs_scope(c, args.scope) if args.scope else me_key
            except (A.AddressError, ValueError) as e:
                print(f"airc passport new: {e}", file=sys.stderr)
                return 1
            signers = []
            try:
                for f in args.sign_key or []:
                    signers.append(SeedSigner(_read_seed(f)))
            except (OSError, ValueError) as e:
                print(f"airc passport new: {e}", file=sys.stderr)
                return 1
            if P.entitles(me_key, scope) and not args.no_identity_key:
                ks = await _my_keys(c, me)           # the acting endpoint's identity key authorizes itself and beneath
                if ks is not None:
                    signers.insert(0, ks)
            try:
                delegates = parse_delegates(args.delegate)
                rules = json.loads(args.rules) if args.rules else None
            except ValueError as e:
                print(f"airc passport new: {e}", file=sys.stderr)
                return 1
            offer = None
            if getattr(args, "for_offer", None):        # §12.9: a receptionist's answer to a pending offer to --as
                o = await _find_link(c, me, args.for_offer)
                if not o or o.get("state") != "pending" or o.get("offered_by") == me_key:
                    print(f"airc passport new: no pending offer {args.for_offer} to {me}", file=sys.stderr)
                    return 1
                offer = P.offer_hash_of(o)
            req = passport_request(scope, signers, args.expires, args.uses, args.direction, args.to, args.link_ttl,
                                   delegates or None, rules, offer=offer, for_offer=getattr(args, "for_offer", None))
            r = await c.passport("new", **{"as": me, "label": args.label}, **req["frame"])
            if r.get("ok"):
                problem = check_issued_passport(r, scope, req["token"], req["pins"])
                if problem:
                    await c.passport("revoke", **{"as": me}, id=(r.get("passport") or {}).get("id"))
                    print(f"airc passport new: {problem}; the passport was revoked, not released", file=sys.stderr)
                    return 1
        elif args.op == "keys":
            fields = {"as": _me(args)}
            if args.kop != "list":
                if not args.scope:
                    print("airc passport keys: --scope is required", file=sys.stderr)
                    return 1
                try:
                    key = args.key or (SeedSigner(_read_seed(args.key_file)).ik if args.key_file else None)
                except (OSError, ValueError) as e:
                    print(f"airc passport keys: {e}", file=sys.stderr)
                    return 1
                if not key:
                    print("airc passport keys: give --key B64 or --key-file FILE", file=sys.stderr)
                    return 1
                fields.update(scope=_abs_scope(c, args.scope), key=key)
            r = await c.passport("key-" + args.kop, **fields)
            if r.get("ok"):
                ks = r.get("keys") or []
                if args.kop == "list" and args.scope:
                    sc = _abs_scope(c, args.scope)
                    ks = [k for k in ks if P.entitles(k["scope"], sc) or k["scope"].startswith(sc)]
                if args.kop == "remove":
                    print("key removed")
                for k in ks:
                    print(f"{k['scope']}  {k['pin']}  {k['key']}  set by {k['set_by']}")
                if args.kop == "list" and not ks:
                    print("no passport keys")
                return 0
        elif args.op == "redeem":
            return await _redeem(c, args)
        elif args.op == "revoke-layer":
            r = await c.passport("revoke-layer", passport=args.passport, layer=args.layer)
            if r.get("ok"):
                print(r.get("reason") or "layer revoked")
                return 0
        elif args.op == "list":
            r = await c.passport("list", all=bool(args.all))
        else:
            r = await c.passport("revoke", **{"as": _me(args)}, id=args.id, and_links=bool(args.and_links))
    if not r.get("ok"):
        print(f"airc passport {args.op}: {r.get('reason', 'refused')}", file=sys.stderr)
        return 1
    if args.op == "new":
        p = r["passport"]
        import datetime
        exp = datetime.datetime.fromtimestamp(p["expires"]).strftime("%Y-%m-%d %H:%M") if p.get("expires") else "never"
        print(r["url"])
        print(f"passport {p['id']} for {p['scope']}: {p['uses']} use(s), expires {exp}, direction {p['direction']}"
              + (f", only for {p['bind_to']}" if p.get("bind_to") else "")
              + f"; authorized by {len(p.get('auth') or [])} key(s)", file=sys.stderr)
        print("Give the recipient the URL above; they run: airc accept '<url>'. It is shown once; revoke with: "
              "airc passport revoke " + p["id"], file=sys.stderr)
        return 0
    if args.op == "list":
        ps = r.get("passports", [])
        if not ps:
            print("no passports")
        import datetime
        for p in ps:
            exp = datetime.datetime.fromtimestamp(p["expires"]).strftime("%Y-%m-%d") if p.get("expires") else "-"
            used = ", ".join(u["redeemer"] for u in p.get("used", [])) or "-"
            lab = f'  "{p["label"]}"' if p.get("label") else ""
            print(f'{p["id"]:<11} {p["state"]:<10} {p.get("scope")}  uses {len(p.get("used", []))}/{p["uses"]}  until {exp}  redeemed by: {used}{lab}')
        return 0
    print(f"passport {r['passport']['id']} revoked" + (f"; links revoked: {', '.join(r['revoked_links'])}" if r.get("revoked_links") else ""))
    return 0


async def _redeem(c, args) -> int:
    from . import passports as P
    try:
        P.parse(args.passport)
    except P.PassportFormatError as e:
        print(f"airc accept: {e}", file=sys.stderr)
        return 1
    r = await c.passport("redeem", **{"as": _me(args)}, passport=args.passport.strip())
    if not r.get("ok"):
        print(f"airc accept: {r.get('reason', 'refused')}" + (f" [{r['code']}]" if r.get("code") else ""), file=sys.stderr)
        return 1
    l = r.get("link")
    if l:
        print(f"link {l['id']} open: {l['a']} <-> {l['b']} [{l['direction']}]")
    else:
        print(f"accepted: {r.get('reason', '')}")
    return 0


def cmd_passport_delegate(args):
    """airc passport delegate '<passport>' --sign-key FILE ...: add a layer locally (§12.10)."""
    try:
        signer = SeedSigner(_read_seed(args.sign_key))
        out = add_layer(args.passport, signer, args.expires, args.uses, args.to, args.link_ttl, args.direction,
                        parse_delegates(args.delegate) or None, json.loads(args.rules) if args.rules else None,
                        root_realm=args.realm, offer=getattr(args, "offer", None))
    except (OSError, ValueError) as e:
        print(f"airc passport delegate: {e}", file=sys.stderr)
        return 1
    print(out)
    return 0


async def cmd_accept(args):
    from . import passports as P
    try:
        P.parse(args.passport)                       # refuse an old form before connecting
    except P.PassportFormatError as e:
        print(f"airc accept: {e}", file=sys.stderr)
        return 1
    async with await _connect(args) as c:
        return await _redeem(c, args)


async def cmd_keys(args):
    """Show this endpoint's end-to-end fingerprint and pins; trust a peer's current key after a change."""
    from . import e2e as E2E
    async with await _connect(args) as c:
        ks = await _my_keys(c, _me(args))
        if ks is None:
            print("airc keys: end-to-end encryption needs the python package cryptography", file=sys.stderr)
            return 1
        if args.trust:
            peer = A.parse(c.absolute(args.trust)).key
            rec = await c.keys_get(peer)
            if not rec or not E2E.verify_record(rec, peer)[0]:
                print(f"airc keys: {peer} publishes no valid key record", file=sys.stderr)
                return 1
            ks.repin(peer, rec["ik"], "verified")
            print(f"trusted {peer}: {E2E.show_fingerprint(E2E.fingerprint(rec['ik']))} (verified)")
            return 0
    print(f"{ks.endpoint}\n  fingerprint {E2E.show_fingerprint(ks.ifp)}")
    for peer, p in sorted(ks.data["pins"].items()):
        print(f"  {peer:<50} {E2E.show_fingerprint(E2E.fingerprint(p['ik']))}  ({p['source']})")
    return 0


async def cmd_channel(args):
    """Close a channel (§21.4): its profile, page, E2E keys and status go, what waits for it is dropped,
    and a message to it fails with path_gone until it is used again."""
    c = await _connect(args)
    try:
        ep = A.parse(c.absolute(_own_address(c, args.name))).key
        ok, why = await c.channel_close(ep)
        print(f"{ep}: {'closed' if ok else 'not closed: ' + str(why)}")
        return 0 if ok else 1
    finally:
        await c.close()


async def cmd_profile(args):
    """Publish or show an endpoint's public profile (spec §21): what its web page and directory entry say."""
    import time as _t
    from . import profile as PR
    c = await _connect(args); absolute = c.absolute; close = c.close
    try:
        if args.op == "show":
            rec = await c.profile_get(A.parse(absolute(args.addr or _me(args))).key)
            if not rec:
                print("no profile"); return 1
            for k in ("endpoint", "name", "about", "icon", "text", "status"):
                if rec.get(k):
                    print(f"{k}: {rec[k]}")
            for sk in rec.get("skills") or []:
                print(f"skill: {sk['id']}: {sk.get('name', '')}" + (f" — {sk['description']}" if sk.get("description") else "")
                      + (" [" + ", ".join(sk["tags"]) + "]" if sk.get("tags") else ""))
            if rec.get("image"):
                print(f"image: {PR.image_bytes(rec['image'])[0] if PR.image_bytes(rec['image']) else 'yes'}")
            return 0
        me = args.me or _me(args)
        if args.op == "delete":
            ep = A.parse(absolute(me)).key
            ok, why = await c.profile_delete(ep)
            if not ok:
                print(f"airc profile delete: {why}", file=sys.stderr); return 1
            print(f"profile of {ep} deleted; its page and directory entry are gone unless it publishes keys")
            return 0
        rec = {"endpoint": A.parse(absolute(me)).key, "ts": int(_t.time())}
        for k in ("name", "about", "icon", "text"):
            if getattr(args, k):
                rec[k] = getattr(args, k)
        if args.skill or args.skills_file:
            skills = []
            if args.skills_file:
                with open(os.path.expanduser(args.skills_file), encoding="utf-8") as f:
                    skills = json.load(f)
                if isinstance(skills, dict) and "skills" in skills:
                    skills = skills["skills"]
            for spec in args.skill or []:                    # id|name|description|tag,tag
                parts = [x.strip() for x in spec.split("|")]
                sk = {"id": parts[0], "name": parts[1] if len(parts) > 1 and parts[1] else parts[0]}
                if len(parts) > 2 and parts[2]:
                    sk["description"] = parts[2]
                if len(parts) > 3 and parts[3]:
                    sk["tags"] = [t.strip() for t in parts[3].split(",") if t.strip()]
                skills.append(sk)
            rec["skills"] = skills
        if args.image:
            img = PR.thumbnail(os.path.expanduser(args.image))
            if not img:
                print("airc profile: could not read that picture (it needs Pillow: pip install pillow)", file=sys.stderr); return 1
            rec["image"] = img
        ok, why = PR.validate(rec)
        if ok:
            ok, why = await c.profile_publish(rec)
        if not ok:
            print(f"airc profile: {why}", file=sys.stderr); return 1
        page = f"/{'/'.join(A.parse(rec['endpoint']).path)}"
        print(f"profile of {rec['endpoint']} published; its page: {args.server.rstrip('/') + page if args.server else page}")
        return 0
    finally:
        if close:
            await close()


DEFAULT_HOSTED = "https://airc.dev"


def _ws_key_path(realm: str, ns: str) -> str:
    """The conventional place for a workspace key, so the next agent on this machine finds it."""
    return os.path.expanduser(f"~/.airc/{realm}/{ns}.key")


def _print_front(r: dict):
    base = f"//{r['realm']}/{r['ns']}"
    mode = r.get("front", "directory")
    if r.get("front_about"):
        print(f"about: {r['front_about']}")
    if mode == "agent":
        print(f"front door: messages to {base} go to {base}/{r.get('front_agent')}")
    elif mode == "off":
        print(f"front door: off (messages to {base} are refused)")
    else:
        names = r.get("directory") or []
        print(f"front door: directory; a message to {base} is answered with {len(names)} agent(s): "
              + (", ".join(names) or "none listed"))
    for f in r.get("front_entries") or []:
        print(f"  entry {f['agent']}" + ("  hidden" if f.get("hidden") else "") + (f"  note: {f['note']}" if f.get("note") else ""))


async def cmd_workspace(args):
    """Workspaces on a hosted realm (spec §3.4.4, §3.4.5): create, join, show, invite, revoke, recovery."""
    import re
    import tempfile
    from .httpclient import HttpClient, HttpClientError
    from . import signing as S
    base = args.server or DEFAULT_HOSTED
    try:
        if args.op in ("create", "join"):
            probe = HttpClient(base, S.Signer(os.path.join(tempfile.mkdtemp(), "probe.key")), insecure=args.insecure)
            realm = (await probe.capabilities())["realm"]
            if args.op == "create":
                if getattr(args, "temp", False) and not args.name:
                    args.name = "tmp-" + os.urandom(4).hex()    # a test workspace: no name to choose
                if not args.name:
                    print("airc workspace create: give a name (ask your human: it is public), or --temp for a test workspace", file=sys.stderr)
                    return 2
                ns = args.name.lower()
                if ns.startswith("tmp-"):
                    args.recovery = False                        # nothing to keep: it is gone a day after its last use
            else:
                m = re.search(r";w=([^;]+);", args.code + ";")
                if not m:
                    print("airc workspace join: that is not a join or recovery code", file=sys.stderr)
                    return 1
                ns = m.group(1)
            path = os.path.expanduser(args.key) if args.key else _ws_key_path(realm, ns)
            rfile = getattr(args, "recovery_file", None)
            if args.op == "create" and rfile and os.path.exists(os.path.expanduser(rfile)):
                print(f"airc workspace create: {rfile} already exists; the recovery code is written only to a new file", file=sys.stderr)
                return 1
            if os.path.exists(path) and args.op == "create":
                print(f"airc workspace create: {path} already exists; is the workspace already yours? (use --key for another path)", file=sys.stderr)
                return 1
            os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
            signer = S.Signer(path)          # created, mode 0600
            hc = HttpClient(base, signer, insecure=args.insecure)
            if args.op == "create":
                print(f"Creating a workspace on {realm} means accepting its terms of use ({base}/terms) and privacy statement ({base}/privacy).")
                r = await hc.register(ns, label=args.label or "", recovery=args.recovery)
            else:
                r = await hc.join(args.code, label=args.label or "", revoke_others=args.revoke_others,
                                  channel=getattr(args, "channel", None))
            if r.get("t") != "workspace":
                os.remove(path) if args.op == "create" or not r.get("kid") else None
                print(f"airc workspace {args.op}: {r.get('reason') or r}", file=sys.stderr)
                return 1
            print(f"workspace {r['uri']}  key {r['kid']}  saved at {path}")
            if r.get("temporary") or (args.op == "create" and ns.startswith("tmp-")):
                print(f"temporary: it and its key expire a day after their last use; delete it when done:  "
                      f"airc --server {base} --key {path} workspace delete --confirm {ns}")
                print(f"use it:  airc --server {base} --key {path} send --from {ns}/{default_agent()} --wait 60 //{r['realm']}/eliza \"hello\"")
                if os.path.dirname(os.path.abspath(path)) == os.path.expanduser(f"~/.airc/{r['realm']}"):
                    print(f"while this is the only workspace key on this machine (~/.airc/{r['realm']}/), later sends need neither "
                          f"--key nor --from: they come from {ns}/{default_agent()}")
                return 0
            if r.get("recovery"):
                print("recovery code (shown once; keep it somewhere safe, apart from this machine):")
                _secret_out(r["recovery"], "recovery code", getattr(args, "recovery_file", None),
                            os.path.join(os.path.dirname(path), f"{ns}.recovery"))
            agent = r.get("channel") or "<agent>"
            print(f"use it:  airc --server {base} --key {path} send --from {ns}/{agent} //realm/path \"message\"")
            if args.op == "create":
                print("tell your human: the workspace name, the recovery code, and that this machine's key is at the "
                      "path above. If this machine is thrown away when the session ends (a cloud sandbox), also run  "
                      "airc workspace invite --enroll  and give them that code for the environment's settings: later "
                      "sessions join with it, and the recovery code gets a full key back once this machine is gone.")
            return 0
        path = os.path.expanduser(args.key) if args.key else None
        if not path:
            probe = HttpClient(base, S.Signer(os.path.join(tempfile.mkdtemp(), "probe.key")), insecure=args.insecure)
            realm = (await probe.capabilities())["realm"]
            if args.workspace:
                path = _ws_key_path(realm, args.workspace.lower())
            else:
                try:
                    path = _key_for(realm, None)                 # the one key in ~/.airc/<realm>/, as elsewhere
                except SystemExit as e:
                    print(str(e).replace("airc:", "airc workspace:", 1) + " (or give --workspace NAME)", file=sys.stderr)
                    return 1
        if not os.path.exists(path):
            print(f"airc workspace: no key at {path}. Knowing a workspace's name is not enough: ask a member for a "
                  f"join code and run  airc workspace join <code>", file=sys.stderr)
            return 1
        hc = HttpClient(base, S.Signer(path), insecure=args.insecure)
        if args.op == "show":
            r = await hc.workspace()
            print(f"workspace //{r['realm']}/{r['ns']}/   recovery code: {'set' if r.get('recovery') else 'none'}")
            for k in r.get("keys", []):
                me = "  (this key)" if k["kid"] == hc.signer.kid else ""
                ch = f"  channel {k['channel']}" if k.get("channel") else ""
                print(f"  key {k['kid']}  {k.get('label') or '-':<20} added by {k.get('added_by')}{ch}{me}")
            for j in r.get("joins", []):
                kind = ("enrollment code" if j.get("kind") == "enroll"
                        else f"channel code for {j['channel']}" if j.get("kind") == "channel" else "join code")
                uses = f"{j['used']} used" if not j.get("uses") else f"{j['used']}/{j['uses']} used"
                print(f"  {kind} {j['id']}  {j.get('label') or '-':<20} {uses}")
            _print_front(r)
            return 0
        if args.op == "front":
            if args.about is not None:
                await hc.workspace("front", about=args.about)
            if args.mode:
                if args.mode == "agent" and not args.agent:
                    print("airc workspace front agent: name the agent, e.g.  airc workspace front agent desk", file=sys.stderr)
                    return 1
                await hc.workspace("front", mode=args.mode, agent=args.agent if args.mode == "agent" else None)
            _print_front(await hc.workspace())
            return 0
        if args.op == "receipts":
            if args.value:
                r = await hc.workspace("receipts", value=args.value)
            else:
                r = await hc.workspace()
            v = r.get("receipts", "default")
            print(f"receipts: {v}" + (" (on within this realm, off to other realms)" if v == "default" else ""))
            return 0
        if args.op == "list-agent":
            entry = {"agent": args.agent}
            if args.remove:
                entry["remove"] = True
            else:
                if args.note:
                    entry["note"] = args.note
                if args.hide:
                    entry["hidden"] = True
            await hc.workspace("front", entry=entry)
            _print_front(await hc.workspace())
            return 0
        if args.op == "invite":
            r = await hc.workspace("join-code", label=args.label, uses=args.uses, expires=args.expires,
                                   channel=args.channel, enroll=True if args.enroll else None)
            if r.get("kind") == "enroll":
                print(f"enrollment code {r['id']}: each session joins with it and names its channel "
                      f"(airc workspace join <code> --channel <name>), getting a key for that channel only.")
                print(f"It does not expire{'' if not r.get('expires') else ' until ' + str(r['expires'])}; "
                      f"airc workspace revoke-invite {r['id']} revokes it and every key it made.")
            elif r.get("kind") == "channel":
                print(f"channel code {r['id']}: one use; whoever joins with it gets a key for {r['channel']} only:")
            else:
                print(f"join code {r['id']} ({r['uses']} use(s)); give it to the new member, who runs  airc workspace join <code>:")
            _secret_out(r["code"], {"enroll": "enrollment code", "channel": "channel code"}.get(r.get("kind"), "join code"),
                        getattr(args, "output", None),
                        os.path.join(os.path.dirname(path), f"{os.path.splitext(os.path.basename(path))[0]}.{r['id']}.code"))
            return 0
        if args.op == "revoke-key":
            await hc.workspace("revoke-key", kid=args.kid); print(f"key {args.kid} revoked"); return 0
        if args.op == "revoke-invite":
            await hc.workspace("revoke-join", id=args.id); print(f"join code {args.id} revoked"); return 0
        if args.op == "delete":
            r = await hc.workspace()
            if args.confirm != r["ns"]:
                print(f"airc workspace delete: this deletes //{r['realm']}/{r['ns']}/ for good (keys, profiles, pages, queued "
                      f"messages; links revoked). Confirm with  --confirm {r['ns']}", file=sys.stderr)
                return 1
            d = await hc.workspace("delete", confirm=args.confirm, recovery=args.recovery)
            print(f"workspace {d['deleted']} deleted: {d.get('endpoints', 0)} endpoints, {d.get('links_revoked', 0)} links revoked, "
                  f"{d.get('queued_dropped', 0)} queued messages dropped. The name is free again.")
            return 0
        if args.op == "recovery-code":
            r = await hc.workspace("recovery-code", recovery=getattr(args, "recovery", None))
            print("new recovery code (shown once; any earlier one no longer works):")
            _secret_out(r["recovery"], "recovery code", getattr(args, "output", None),
                        os.path.join(os.path.dirname(path), f"{os.path.splitext(os.path.basename(path))[0]}.recovery"))
            return 0
    except HttpClientError as e:
        print(f"airc workspace {args.op}: {e}", file=sys.stderr)
        return 1
    return 1


async def cmd_whoami(args):
    """Which realm, workspace and key this machine would use, as the realm itself reports it."""
    if not args.server:
        print("airc whoami: give --server <url> (a hosted realm); a local aircd identifies you by your Unix user", file=sys.stderr)
        return 2
    c = await _connect(args)
    r = await c.hc.workspace()
    print(f"realm {r['realm']}  workspace //{r['realm']}/{r['ns']}/  key {c.hc.signer.kid} ({_key_for(r['realm'], args.key)})")
    if r.get("channel"):
        print(f"a channel key: it acts only as //{r['realm']}/{r['ns']}/{r['channel']}")
        return 0
    print(f"this agent: //{r['realm']}/{_own_address(c, None)}  (its default name; --as or AIRC_AGENT for another)")
    print(f"keys in this workspace: {len(r.get('keys', []))}; recovery code: {'set' if r.get('recovery') else 'none (airc workspace recovery-code)'}")
    if getattr(args, "did", False):
        _print_dids(c, r)
    return 0


def _print_dids(c, r):
    """airc whoami --did: this endpoint's did:key and did:web (spec §24.2), when it holds end-to-end keys."""
    import urllib.parse
    from . import did as DID, e2e as E2E
    me = c.absolute(_own_address(c, None))
    ks = E2E.Keystore(A.parse(me).key) if E2E.AVAILABLE else None
    if not ks or not ks.data.get("identity"):
        print("did: none; this endpoint has no end-to-end keys yet (they are made when it first sends or listens)")
        return
    a = A.parse(me)
    host = urllib.parse.urlsplit(c.hc.base).hostname or r["realm"]
    print(f"did:key  {DID.did_key(ks.ik)}")
    print(f"did:web  {DID.web_did(host, *a.path)}  (https://{host}/{'/'.join(a.path)}/did.json, once the keys are published)")


def cmd_key(args):
    from . import signing as S
    k = S.Signer(os.path.expanduser(args.path))
    print(json.dumps({"path": os.path.expanduser(args.path), "kid": k.kid, "pub": k.public_b64,
                      "register_as": {k.kid: {"pub": k.public_b64, "ns": ["<namespace>"]}}}, indent=2))
    return 0


def cmd_addr(args):
    try:
        a = A.parse(args.text, args.realm, args.ns or "")
    except A.AddressError as e:
        print(f"invalid: {e}", file=sys.stderr)
        return 1
    print(json.dumps({"canonical": str(a), "realm": a.realm, "namespace": a.namespace, "name": a.name}))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="airc", description="AIRC client")
    ap.add_argument("--socket", help=f"server socket path or host:port (default $AIRC_SOCKET or {DEFAULT_SOCKET})")
    ap.add_argument("--claim-ns", action="append", help="namespace claim (only honoured by test servers)")
    ap.add_argument("--server", default=os.environ.get("AIRC_SERVER") or None,
                    help="use a realm's HTTPS face instead of the local socket, e.g. https://www.airc.dev (default $AIRC_SERVER)")
    ap.add_argument("--key", help="workspace key file for --server (default: $AIRC_KEY_FILE, else the key held in $AIRC_KEY, "
                                  "else the one key in ~/.airc/<realm>/, else ~/.airc/workspace.key)")
    ap.add_argument("--insecure", action="store_true", help="do not verify the server's TLS certificate (tests)")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("send"); p.add_argument("--from", dest="frm"); p.add_argument("--re"); p.add_argument("--ttl", type=int)
    p.add_argument("--plain", action="store_true", help="do not encrypt end to end, even when the recipient publishes keys")
    p.add_argument("--wait", type=float, metavar="SECONDS", help="with --server: then wait up to this long for the reply to this message "
                   "and print it (over the realm's WebSocket: it returns the moment the reply comes); status 3 if none came")
    p.add_argument("--json", action="store_true", help="print the result (the ack, with the message id) as one JSON line, and a reply "
                   "(and any receipt) as JSON")
    p.add_argument("--receipt", metavar="TYPES", help="ask the recipient for receipts (spec 6.7): seen (its agent took the message), "
                   "done (it finished with it and will not reply), or seen,done. With --wait each receipt is reported as it comes "
                   "(`seen by <endpoint> after N s`) without ending the wait. Sent only if the recipient's site allows it")
    p.add_argument("to"); p.add_argument("message", nargs="+"); p.set_defaults(fn=cmd_send)
    p = sub.add_parser("done", help="send the done receipt for a message you handled without replying (spec 6.7)",
                       description="Tell a message's sender you are done with it and will send no reply. Only for a message that asked "
                                   "(its header asks for done); the listener or relay that took it recorded the sender, so the id is "
                                   "enough. If you answer a message, reply instead: a reply says done. Sent at most once, and only "
                                   "where this site's receipt policy allows.")
    p.add_argument("id", help="the message id (the id= in its [airc ...] header)")
    p.add_argument("--to", help="its sender, when this machine's listener or relay did not take the message")
    p.add_argument("--as", dest="me", help="send as this endpoint (default: the one the message was addressed to)")
    p.add_argument("--json", action="store_true"); p.set_defaults(fn=cmd_done)
    p = sub.add_parser("send-file", help="send a file (up to 8 MB) as one message",
                       description="Send a file as one message's binary section (spec §22), compressed when that helps and encrypted end to end "
                                   "when the recipient publishes keys. The recipient's client saves it and shows where.")
    p.add_argument("--from", dest="frm"); p.add_argument("--re"); p.add_argument("--ttl", type=int)
    p.add_argument("--plain", action="store_true", help="do not encrypt end to end")
    p.add_argument("to"); p.add_argument("path"); p.add_argument("note", nargs="*", help="a line of text to go with it")
    p.set_defaults(fn=cmd_send_file)
    p = sub.add_parser("listen", help="receive messages for a name and print them; each printed message is acked as delivered",
                       description="Receive messages for NAME and print them. Each message is acknowledged as delivered once it is "
                                   "printed, which removes it from the queue. Only one process may listen as a name at a time (see /docs/receive).")
    p.add_argument("name", nargs="?", help="the address to receive for: <workspace>/<agent>, or <workspace>/ for the whole "
                   "workspace (a relay). Default: this agent's own address, <workspace>/<name>, the name coming from "
                   "$AIRC_AGENT, the CLI session's name, or the directory's")
    p.add_argument("--json", action="store_true")
    p.add_argument("--take-over", dest="take_over", action="store_true",
                   help="take the name from another process that holds it (for a restarted listener whose predecessor is gone)")
    p.add_argument("--format", choices=["text", "json", "agent"],
                   help="text: [from X] body (default); json: one frame per line (same as --json); agent: a block per message "
                        "for an agent to read, with an origin banner, the full id and a ready-made reply command, ending in ---")
    p.add_argument("--once", action="store_true", help="with --server: print what is waiting and exit (status 3 if nothing was)")
    p.add_argument("--wait", type=float, metavar="SECONDS", help="with --once: if nothing is waiting, wait up to this long for a message "
                   "and return the moment one comes (over the realm's WebSocket: no polling); status 3 if none came")
    p.add_argument("--no-ack", dest="no_ack", action="store_true", help="with --once: print without acknowledging, so the messages stay "
                   "queued (and no seen receipt goes: the message was not taken)")
    p.add_argument("--from", dest="only_from", metavar="ADDRESS",
                   help="with --once: only messages from ADDRESS, and link notices about it; the rest stay queued")
    p.add_argument("--status", action="store_true",
                   help="publish this agent's status (running / not running) on its page while listening; off by "
                        "default, since it shows when the agent works (AIRC_STATUS=1 does the same)")
    p.add_argument("--links", dest="only_links", action="store_true",
                   help="with --once: only link notices (offers, acceptances, revocations); the rest stay queued")
    p.set_defaults(fn=cmd_listen)
    p = sub.add_parser("relay"); p.add_argument("--namespace", required=True)
    p.add_argument("--autostart", nargs="?", const="all", choices=["off", "local", "all"],
                   help="start a stopped agent on an inbound message: off, local (senders of this fleet; the co default), all")
    p.add_argument("--backend", default="co", help="delivery backend module under airc.backends (co, stdout)")
    p.add_argument("--opt", action="append", help="backend option key=value (repeatable)")
    p.add_argument("--header", choices=["minimal", "ids"], default="minimal", help="when to prefix an [airc id=...] line")
    p.set_defaults(fn=cmd_relay)
    p = sub.add_parser("mcp", help="tool tunnels: share an MCP server's tools with other endpoints, or use theirs (spec §23)",
                       description="Tool tunnels (spec §23): MCP carried over AIRC. 'export' serves a local stdio MCP server's "
                                   "tools at an address; 'import' is a stdio MCP server for your agent that reaches an exported "
                                   "address, so the agent calls those tools as its own.")
    msub = p.add_subparsers(dest="mcp_op", required=True)
    q = msub.add_parser("export", help="serve a local stdio MCP server at an address",
                        description="Serve a local stdio MCP server at ADDRESS. Only the tools named with --allow are "
                                    "exported (or every tool, with --allow-all); they run with your privileges, for whoever "
                                    "can reach ADDRESS under your realm's rules, links and passports.")
    q.add_argument("--as", dest="me", required=True, metavar="ADDRESS", help="the exported address, e.g. <workspace>/<agent>/mcp/files")
    g = q.add_mutually_exclusive_group(required=True)
    g.add_argument("--allow", help="comma-separated names of the tools to export")
    g.add_argument("--allow-all", dest="allow_all", action="store_true", help="export every tool the server lists")
    q.add_argument("--idle", type=int, default=600, help="end an importer's session after this many idle seconds (default 600)")
    q.add_argument("--take-over", dest="take_over", action="store_true")
    q.add_argument("--plain", action="store_true", help="do not encrypt answers even when the importer publishes keys")
    q.add_argument("cmd", nargs=argparse.REMAINDER, help="-- then the MCP server's command line")
    q.set_defaults(fn=cmd_mcp)
    q = msub.add_parser("import", help="a stdio MCP server for your agent that reaches an exported address",
                        description="Run as an MCP server over stdin/stdout (add it to your agent like any MCP server) that "
                                    "forwards every MCP message to ADDRESS over AIRC. Example: claude mcp add demo -- "
                                    "airc --server https://airc.dev mcp import --to //airc.dev/mcp")
    q.add_argument("--to", required=True, metavar="ADDRESS", help="the exported address")
    q.add_argument("--as", dest="me", help="the agent this session acts beneath (default: your own); the session itself binds a fresh sub-address, <agent>/mcp-<id>, so the agent's own mail keeps flowing")
    q.add_argument("--plain", action="store_true", help="do not encrypt even when the exporter publishes keys")
    q.set_defaults(fn=cmd_mcp)
    p = sub.add_parser("events"); p.add_argument("--follow", "-f", action="store_true"); p.add_argument("-n", type=int, default=50)
    p.add_argument("--kinds", nargs="*"); p.set_defaults(fn=cmd_events)
    p = sub.add_parser("status"); p.set_defaults(fn=cmd_status)
    p = sub.add_parser("whoami", help="with --server: the realm, workspace and key this machine uses"); p.set_defaults(fn=cmd_whoami)
    p.add_argument("--did", action="store_true", help="also print this endpoint's did:key and did:web (spec §24), when it has end-to-end keys")
    from . import setup as SETUP
    SETUP.add_parser(sub)
    p = sub.add_parser("addr"); p.add_argument("text"); p.add_argument("--realm"); p.add_argument("--ns"); p.set_defaults(fn=cmd_addr)
    p = sub.add_parser("workspace", help="workspaces on a hosted realm (default https://www.airc.dev)")
    wsub = p.add_subparsers(dest="op", required=True)
    q = wsub.add_parser("create"); q.add_argument("name", nargs="?", help="the workspace name: public, so your human picks it; "
                                                      "with --temp, leave it out"); q.add_argument("--label")
    q.add_argument("--temp", action="store_true", help="a temporary test workspace named tmp-<random>: no recovery code, and it expires "
                   "a day after its last use (names starting tmp- are temporary on airc.dev; an agent may create one without asking)")
    q.add_argument("--recovery-file", dest="recovery_file", metavar="PATH",
                   help="write the recovery code to PATH (mode 0600) instead of printing it, so it stays out of logs; "
                        "the default when output is not a terminal is a file beside the workspace key")
    q.add_argument("--no-recovery", dest="recovery", action="store_false", help="skip the recovery code (the only way back if every key is lost)")
    q.add_argument("--key", default=argparse.SUPPRESS, help="key file (default ~/.airc/<realm>/<name>.key)"); q.set_defaults(fn=cmd_workspace)
    q = wsub.add_parser("join"); q.add_argument("code"); q.add_argument("--label"); q.add_argument("--revoke-others", dest="revoke_others", action="store_true")
    q.add_argument("--channel", help="with an enrollment code: the one channel this key will act as")
    q.add_argument("--key", default=argparse.SUPPRESS); q.set_defaults(fn=cmd_workspace)
    aliases = {"invite": ["join-code"], "revoke-invite": ["revoke-join"]}      # the spec's names (§3.4.5)
    for op in ("show", "invite", "revoke-key", "revoke-invite", "recovery-code", "front", "list-agent", "receipts", "delete"):
        q = wsub.add_parser(op, aliases=aliases.get(op, [])); q.add_argument("--workspace"); q.add_argument("--key", default=argparse.SUPPRESS)
        q.set_defaults(op=op)
        if op in ("invite", "recovery-code"):     # a secret: to a file rather than a transcript
            q.add_argument("--output", metavar="PATH", help="write the code to PATH (mode 0600) instead of printing it; "
                           "the default when output is not a terminal is a file beside the workspace key")
        if op == "front":                        # what a message to the bare workspace address gets (spec §20)
            q.add_argument("mode", nargs="?", choices=["directory", "agent", "off"])
            q.add_argument("agent", nargs="?", help="with mode agent: the agent that receives it")
            q.add_argument("--about", help="one line saying who runs this workspace and what it is for")
        if op == "delete":                       # the whole workspace, for good
            q.add_argument("--confirm", help="the workspace's name, to confirm")
            q.add_argument("--recovery", help="the recovery code, if the workspace has one")
        if op == "receipts":                     # §6.7: whether this workspace's agents send receipts
            q.add_argument("value", nargs="?", choices=("on", "off", "default"), help="on | off | default (on within this realm, off to other realms); omit to show")
        if op == "list-agent":                   # an entry in the workspace's directory
            q.add_argument("agent"); q.add_argument("--note", help="what to ask this agent about")
            q.add_argument("--hide", action="store_true", help="leave it out of the directory")
            q.add_argument("--remove", action="store_true", help="drop the entry (back to the default listing)")
        if op == "recovery-code":                 # replacing an existing code needs it (§3.4.5)
            q.add_argument("--recovery", help="the current recovery code, when the workspace has one")
        if op == "invite":
            q.add_argument("--channel", help="a one-use code for a key that acts only as this channel (§3.4.5)")
            q.add_argument("--enroll", action="store_true",
                           help="a long-lived code for an environment: each session joins with it, names its channel, and gets a key for that channel only")
            q.add_argument("--label"); q.add_argument("--uses", type=int); q.add_argument("--expires", help="e.g. 1h, 2d (max 7d)")
        if op == "revoke-key":
            q.add_argument("kid")
        if op == "revoke-invite":
            q.add_argument("id")
        q.set_defaults(fn=cmd_workspace)
    p = sub.add_parser("profile", help="an endpoint's public profile: what its web page and directory entry say (spec §21)")
    psub = p.add_subparsers(dest="op", required=True)
    q = psub.add_parser("set"); q.add_argument("--as", dest="me", help="the endpoint (workspace/agent)")
    q.add_argument("--name"); q.add_argument("--about", help="one line: what this agent does")
    q.add_argument("--icon", help="one emoji"); q.add_argument("--text", help="a longer description")
    q.add_argument("--image", help="a picture file, shrunk to a small thumbnail")
    q.add_argument("--skill", action="append", help="a skill, 'id|name|description|tag,tag' (repeatable; §21.1)")
    q.add_argument("--skills-file", help="a JSON file: a list of {id, name, description, tags, examples}, or {\"skills\": [...]}")
    q.set_defaults(fn=cmd_profile)
    q = psub.add_parser("show"); q.add_argument("addr", nargs="?"); q.add_argument("--as", dest="me"); q.set_defaults(fn=cmd_profile)
    q = psub.add_parser("delete", help="take the profile and its page down"); q.add_argument("--as", dest="me"); q.set_defaults(fn=cmd_profile)
    p = sub.add_parser("keys", help="end-to-end keys: this endpoint's fingerprint and pins")
    p.add_argument("--as", dest="me"); p.add_argument("--trust", metavar="PEER", help="pin PEER's current key after verifying it")
    p.set_defaults(fn=cmd_keys)
    p = sub.add_parser("key", help="create or show a workspace key for --server"); p.add_argument("--path", default="~/.airc/workspace.key"); p.set_defaults(fn=cmd_key)
    p = sub.add_parser("link", help="link offers and answers (list them with: airc link list, or airc links)")
    lsub = p.add_subparsers(dest="op", required=True)
    q = lsub.add_parser("list", help="the links of an endpoint (same as airc links)"); q.add_argument("--all", action="store_true")
    q.add_argument("--as", dest="me"); q.set_defaults(fn=cmd_links)
    q = lsub.add_parser("offer"); q.add_argument("peer"); q.add_argument("--as", dest="me"); q.add_argument("--label")
    q.add_argument("--direction", choices=["both", "a-initiates", "b-initiates"], default="both"); q.add_argument("--expires", default="30d")
    q.add_argument("--credential", help="a code the offeree asked callers to bring (opaque, at most 1000 characters; not secret)")
    q.add_argument("--challenge", metavar="ID", help="the challenge this offer answers (§11.6)")
    q.add_argument("--proof-x", dest="proof_x", metavar="X", help="a proof of work for --challenge")
    q.add_argument("--code", help="the code a login page, OAuth login, email or SMS gave you, for --challenge")
    q.add_argument("--email", help="your email address, for an email --challenge"); q.add_argument("--phone", help="your phone number, for an sms --challenge")
    q.add_argument("--contact-email", dest="contact_email", help="give an email address up front, to a realm known to ask")
    q.add_argument("--contact-phone", dest="contact_phone", help="give a phone number up front")
    q.add_argument("--no-auto", dest="no_auto", action="store_true", help="do not solve a proof of work automatically")
    q.set_defaults(fn=cmd_link)
    for op in ("accept", "decline", "revoke"):
        q = lsub.add_parser(op); q.add_argument("id", nargs="?" if op == "revoke" else None); q.add_argument("--as", dest="me")
        q.set_defaults(fn=cmd_link)
        if op == "revoke":
            q.add_argument("--key", metavar="PIN", help="instead of a link id: refuse every link that key authorized, "
                                                       "for --as (§12.7)")
        if op == "accept":
            q.add_argument("--sign-key", dest="sign_key", action="append", metavar="FILE",
                           help="also sign the accepting passport with the ed25519 seed in FILE (an audit key, say)")
            q.add_argument("--passport", help="answer the offer with this passport instead: one to another scope in this "
                                              "realm (a receptionist, §12.9) or a delegated passport (§12.10)")
    q = lsub.add_parser("unreject", help="stop refusing links authorized by a key (§12.7); closed links stay closed")
    q.add_argument("--key", metavar="PIN", required=True); q.add_argument("--as", dest="me"); q.set_defaults(fn=cmd_link)
    p = sub.add_parser("channel", help="close a channel when its agent is done (§21.4)")
    csub = p.add_subparsers(dest="op", required=True)
    q = csub.add_parser("close", help="take down the channel's profile, page, keys and status; messages to it then fail")
    q.add_argument("name", nargs="?", help="<workspace>/<agent>; default: this agent's own channel")
    q.set_defaults(fn=cmd_channel)
    p = sub.add_parser("links"); p.add_argument("--all", action="store_true"); p.add_argument("--as", dest="me"); p.set_defaults(fn=cmd_links)
    p = sub.add_parser("alias", help="short local names for prefixes in other realms: 'airc alias add tr-x //realm/ns/' makes //realm/ns/agent read and type as tr-x/agent (this fleet only; never sent on the wire)")
    asub = p.add_subparsers(dest="op")
    asub.add_parser("list")
    a = asub.add_parser("add"); a.add_argument("name"); a.add_argument("prefix", help="a realm or namespace in another realm, ending in /: //realm/ or //realm/ns/")
    a = asub.add_parser("remove"); a.add_argument("name")
    p.set_defaults(fn=cmd_alias, op="list")
    p = sub.add_parser("passport", help="passports: invitations that open a link when redeemed (spec §12)")
    psub = p.add_subparsers(dest="op", required=True)
    q = psub.add_parser("new"); q.add_argument("--as", dest="me"); q.add_argument("--label"); q.add_argument("--expires")
    q.add_argument("--scope", help="endpoint, namespace (trailing /) or / for the realm; default: --as")
    q.add_argument("--sign-key", dest="sign_key", action="append", metavar="FILE", help="also sign with the ed25519 seed in FILE")
    q.add_argument("--no-identity-key", dest="no_identity_key", action="store_true", help="do not sign with the endpoint's identity key")
    q.add_argument("--uses", type=int); q.add_argument("--to", help="pattern the redeemer must match, e.g. //partner.example/**")
    q.add_argument("--direction", choices=["both", "a-initiates", "b-initiates"]); q.add_argument("--link-ttl", dest="link_ttl")
    q.add_argument("--delegate", action="append", metavar="REALM:PIN[,PIN]", help="make a delegation to this realm's keys (§12.10)")
    q.add_argument("--rules", help='rules for the delegates, JSON, e.g. {"depth":1,"to":["b.example"]}')
    q.add_argument("--for-offer", dest="for_offer", metavar="LINK_ID",
                   help="answer this pending offer to --as (a receptionist, §12.9): signs its offer hash; "
                        "use with --to <the offerer> --uses 1 --expires 10m")
    q.set_defaults(fn=cmd_passport)
    q = psub.add_parser("delegate", help="add a layer to a delegation or delegated passport, signed locally (§12.10)")
    q.add_argument("passport"); q.add_argument("--sign-key", dest="sign_key", required=True, metavar="FILE")
    q.add_argument("--expires"); q.add_argument("--uses", type=int); q.add_argument("--to", help="bind_to pattern")
    q.add_argument("--link-ttl", dest="link_ttl"); q.add_argument("--direction", choices=["both", "a-initiates", "b-initiates"])
    q.add_argument("--delegate", action="append", metavar="REALM:PIN[,PIN]", help="let these keys add a further layer")
    q.add_argument("--rules"); q.add_argument("--realm", help="the root realm, when its host is not airc.<realm> or <realm>")
    q.add_argument("--offer", metavar="HASH", help="the offer hash (§12.9) of the knock this forward answers")
    q.set_defaults(fn=cmd_passport_delegate)
    q = psub.add_parser("revoke-layer", help="as this realm's administrator, close a layer it signed (§12.10)")
    q.add_argument("passport"); q.add_argument("layer"); q.set_defaults(fn=cmd_passport)
    q = psub.add_parser("list"); q.add_argument("--all", action="store_true"); q.set_defaults(fn=cmd_passport)
    q = psub.add_parser("revoke"); q.add_argument("id"); q.add_argument("--as", dest="me"); q.add_argument("--and-links", dest="and_links", action="store_true"); q.set_defaults(fn=cmd_passport)
    q = psub.add_parser("redeem"); q.add_argument("passport"); q.add_argument("--as", dest="me", help="an endpoint, or a namespace (trailing /)")
    q.set_defaults(fn=cmd_passport)
    q = psub.add_parser("keys", help="keys entitled to authorize passports for a scope (§4.7)")
    q.add_argument("kop", choices=["add", "list", "remove"]); q.add_argument("--as", dest="me"); q.add_argument("--scope")
    q.add_argument("--key", help="base64 ed25519 public key"); q.add_argument("--key-file", dest="key_file", help="a seed file whose public key to use")
    q.set_defaults(fn=cmd_passport)
    p = sub.add_parser("accept", help="redeem a passport URL"); p.add_argument("passport"); p.add_argument("--as", dest="me", help="an endpoint, or a namespace (trailing /)")
    p.set_defaults(fn=cmd_accept)
    args = ap.parse_args(argv)
    try:                                         # piped into a file or a watcher, every line goes out as it is printed
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, ValueError):
        pass
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s %(message)s")
    from .signing import SigningUnavailable
    from . import cryptolib
    try:
        r = args.fn(args)
        if asyncio.iscoroutine(r):
            r = asyncio.run(_until_terminated(r))
    except SigningUnavailable as e:              # one line, not a traceback; -v adds what the import said
        print(f"airc: {e}", file=sys.stderr)
        if args.verbose and cryptolib.detail():
            print(cryptolib.detail(), file=sys.stderr)
        sys.exit(2)
    sys.exit(r or 0)


async def _until_terminated(coro):
    """Run a command so that SIGTERM (timeout, a Monitor tool, systemd) ends it like Ctrl-C does:
    cancelled, so a listener still releases its names on the way out (§4.3.1)."""
    import signal
    task = asyncio.current_task()
    try:
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    except (NotImplementedError, RuntimeError):
        pass
    try:
        return await coro
    except asyncio.CancelledError:
        return 143


if __name__ == "__main__":
    main()
