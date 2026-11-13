# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Challenges (spec §11.6): proofs a realm may require of a link offer.

This module is self-contained; the server calls it only when its config has `offers.challenge` rules,
and the HTTPS face routes /airc/v0/login/oauth* to it. Removing it (and the few calls that check
`server.challenges`) removes the feature.

Config:
  "offers": {"challenge": [{"from": "<pattern>", "to"?: "<pattern>",
                            "any": ["pow:20", "login", "oauth", "email", "sms", "email+sms"],
                            "then": "pending" | "accept"}]}          first match wins; no match, no challenge
  "challenges": {"login_url": "https://site/login", "login_secret": "...",
                 "oauth": {"provider", "authorize_url", "token_url", "userinfo_url"?, "client_id",
                           "client_secret", "scope", "allow": ["*", "bob@example.com", "*@example.com", "example.com", "*.example.org"], "secret"?},
                 "contact_secret": "...",
                 "send": {"http": "<url>"} | {"command": ["prog", "arg", ...]}}
Secrets not configured are derived from the realm key, one label each.

A challenge id is <b64url(body)>.<b64url(sig)>: body the canonical JSON {"kind","from","to","exp","n",...},
sig the realm key's signature over "airc-challenge\\n<body>". No state is kept for an open challenge; only
the tries at a sent email/SMS code are counted, in memory.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import subprocess
import time
import urllib.parse
import urllib.request

from . import address as A
from . import passports as P
from . import wire

log = logging.getLogger("aircd.challenges")

TTL = 600
MAX_TRIES = 5
KINDS = ("pow", "login", "oauth", "email", "sms", "email+sms")
_EMAIL = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}\Z")
_PHONE = re.compile(r"^\+?[0-9]{6,15}\Z")


class ChallengeConfigError(ValueError):
    pass


def norm_email(e) -> str | None:
    e = str(e or "").strip().lower()
    return e if _EMAIL.match(e) else None


def norm_phone(p) -> str | None:
    p = re.sub(r"[\s().-]", "", str(p or ""))
    return p if _PHONE.match(p) else None


def sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def code10(secret: bytes, cid: str) -> str:
    """login/oauth: first 10 characters of base32(HMAC-SHA-256(secret, "airc-login\\n<id>"))."""
    mac = hmac.new(secret, f"airc-login\n{cid}".encode(), hashlib.sha256).digest()
    return base64.b32encode(mac).decode().rstrip("=")[:10]


def code8(secret: bytes, sent_id: str) -> str:
    """email/sms: 8 decimal digits of HMAC-SHA-256(secret, "airc-contact\\n<sent id>") (first 4 bytes, u32)."""
    mac = hmac.new(secret, f"airc-contact\n{sent_id}".encode(), hashlib.sha256).digest()
    return f"{int.from_bytes(mac[:4], 'big') % 100_000_000:08d}"


def pow_ok(cid: str, offerer: str, x: str, bits: int) -> bool:
    if not isinstance(x, str) or not 0 < len(x) <= 64:
        return False
    h = int.from_bytes(hashlib.sha256(f"airc-pow\n{cid}\n{offerer}\n{x}".encode()).digest(), "big")
    return h >> (256 - bits) == 0 if bits > 0 else True


def solve_pow(cid: str, offerer: str, bits: int) -> str:
    """The client side: find x (decimal counter) meeting the challenge."""
    n = 0
    while not pow_ok(cid, offerer, str(n), bits):
        n += 1
    return str(n)


def domain_allowed(patterns, email: str) -> bool:
    """oauth.allow: "*", a full address (bob@example.com), "*@domain", a bare domain (example.com),
    or "*.domain" (any subdomain of it). Case-insensitive."""
    email = email.strip().lower()
    dom = email.rsplit("@", 1)[-1]
    for p in patterns or []:
        p = str(p).strip().lower()
        if p == "*":
            return True
        if "@" in p:
            local, _, pdom = p.rpartition("@")
            if (local == "*" and pdom == dom) or p == email:
                return True
        elif p == dom or (p.startswith("*.") and dom.endswith(p[1:])):
            return True
    return False


class Challenges:
    def __init__(self, server, offers_cfg: dict, cfg: dict):
        self.srv = server
        self.rules = []
        for r in offers_cfg.get("challenge") or []:
            kinds = []
            for k in r.get("any") or []:
                name, _, arg = str(k).partition(":")
                if name not in KINDS:
                    raise ChallengeConfigError(f"offers.challenge: unknown kind {k!r}")
                kinds.append((name, int(arg) if name == "pow" else None))
            if r.get("then", "pending") not in ("pending", "accept"):
                raise ChallengeConfigError("offers.challenge: then is pending or accept")
            self.rules.append({"from": r.get("from", "*"), "to": r.get("to"), "any": kinds, "then": r.get("then", "pending")})
        self.cfg = cfg
        self.login_url = cfg.get("login_url")
        self.oauth = cfg.get("oauth") or None
        self.send_hook = cfg.get("send") or None
        self._secrets = {"login": cfg.get("login_secret"), "oauth": (self.oauth or {}).get("secret"),
                         "contact": cfg.get("contact_secret")}
        self.tries: dict[str, int] = {}

    # --- keys -------------------------------------------------------------------------------------
    def secret(self, label: str) -> bytes:
        v = self._secrets.get(label)
        if v:
            return str(v).encode()
        if not self.srv.signer:
            raise ChallengeConfigError(f"no challenges.{label}_secret and no realm key to derive one from")
        return hashlib.sha256(base64.b64decode(self.srv.signer.sign(f"airc-secret\n{label}".encode()))).digest()

    def make_id(self, body: dict) -> str:
        raw = P.cjson(body)
        sig = base64.b64decode(self.srv.signer.sign(f"airc-challenge\n{raw}".encode()))
        return f"{P.b64u(raw.encode())}.{P.b64u(sig)}"

    def read_id(self, cid) -> dict | None:
        """The body of a challenge id this realm made and that has not expired, or None."""
        from . import e2e as E2E
        try:
            b64body, b64sig = str(cid).split(".")
            raw = P.unb64u(b64body).decode()
            sig = base64.b64encode(P.unb64u(b64sig)).decode()
            if not E2E.verify_sig(self.srv.signer.public_b64, sig, f"airc-challenge\n{raw}".encode()):
                return None
            body = json.loads(raw)
        except (ValueError, UnicodeDecodeError, AttributeError):
            return None
        if not isinstance(body, dict) or not isinstance(body.get("exp"), int) or body["exp"] < time.time():
            return None
        return body

    def _new(self, kind: str, frm: str, to: str, **params) -> tuple[str, dict]:
        body = {"kind": kind, "from": frm, "to": to, "exp": int(time.time()) + TTL, "n": secrets.token_hex(4), **params}
        return self.make_id(body), body

    # --- policy -----------------------------------------------------------------------------------
    def rule_for(self, frm: A.Address, to: A.Address) -> dict | None:
        for r in self.rules:
            try:
                if A.pattern_match(r["from"], frm) and (not r["to"] or A.pattern_match(r["to"], to)):
                    return r
            except A.AddressError:
                continue
        return None

    # --- challenges offered -------------------------------------------------------------------------
    async def offered(self, rule: dict, frm: str, to: str, contact: dict | None, ctx: dict | None = None) -> list[dict]:
        out = []
        contact = contact if isinstance(contact, dict) else {}
        for kind, bits in rule["any"]:
            if kind == "pow":
                cid, _ = self._new("pow", frm, to, bits=bits)
                out.append({"id": cid, "kind": "pow", "bits": bits})
            elif kind == "login":
                if not self.login_url:
                    continue
                cid, _ = self._new("login", frm, to)
                sep = "&" if "?" in self.login_url else "?"
                out.append({"id": cid, "kind": "login", "url": f"{self.login_url}{sep}c={urllib.parse.quote(cid)}"})
            elif kind == "oauth":
                if not self.oauth:
                    continue
                prov = self.oauth.get("provider", "oauth")
                cid, _ = self._new("oauth", frm, to, provider=prov)
                host = self.srv.passports_cfg["host"]
                out.append({"id": cid, "kind": "oauth", "provider": prov,
                            "url": f"https://{host}/airc/v0/login/oauth?c={urllib.parse.quote(cid)}"})
            elif self.send_hook:                        # email, sms, email+sms
                first = "sms" if kind == "sms" else "email"
                extra = {"chain": "sms"} if kind == "email+sms" else {}
                addr = norm_email(contact.get("email")) if first == "email" else norm_phone(contact.get("phone"))
                if addr:                                # given up front: send at once (§11.6)
                    out.append(await self._send(first, addr, frm, to, extra, dict(ctx or {}, challenge=None, source="contact")))
                else:
                    cid, _ = self._new(first, frm, to, need="address", **extra)
                    out.append({"id": cid, "kind": first, "need": "address"})
        return out

    async def _send(self, channel: str, addr: str, frm: str, to: str, extra: dict, ctx: dict) -> dict:
        cid, _ = self._new(channel, frm, to, sent=sha(addr), **extra)
        code = code8(self.secret("contact"), cid)
        await self.send_code(channel, addr, code, frm, to, ctx)
        return {"id": cid, "kind": channel, "sent": True}

    async def send_code(self, channel: str, addr: str, code: str, frm: str, to: str, ctx: dict | None = None):
        """The site's hook does the sending, and the metering (§11.6): it gets the offer's realm, the client
        address of a local offer, the challenge being answered and where the address came from."""
        ctx = ctx or {}
        try:
            origin_realm = A.parse(frm).authority
        except A.AddressError:
            origin_realm = None
        payload = json.dumps({"channel": channel, "to": addr, "code": code, "offerer": frm, "offeree": to,
                              "origin_realm": origin_realm, "client_ip": ctx.get("client_ip"),
                              "challenge": ctx.get("challenge"), "source": ctx.get("source")}).encode()
        hook = self.send_hook or {}
        loop = asyncio.get_running_loop()

        def run():
            if hook.get("http"):
                req = urllib.request.Request(hook["http"], data=payload, method="POST",
                                             headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=10) as r:
                    r.read(65536)                      # S7: the hook's answer is not used; read a bounded amount
            elif hook.get("command"):
                subprocess.run(list(hook["command"]), input=payload, timeout=20, check=True, capture_output=True)
        try:
            await loop.run_in_executor(None, run)
        except Exception as e:                          # noqa: BLE001 the challenge still stands; the code may arrive late
            log.warning("challenge %s code to %s not sent: %s", channel, sha(addr)[:12], e)

    # --- checking ---------------------------------------------------------------------------------
    async def check(self, frm: A.Address, to: A.Address, proof, contact, client_ip: str | None = None) -> tuple[bool, str, list[dict]]:
        """(admitted, reason, challenges). admitted: a valid proof for the rule that matches; otherwise the
        challenges to answer (a follow-up one for a need/chain step, or fresh ones)."""
        rule = self.rule_for(frm, to)
        if rule is None or not rule["any"]:            # no rule, or a matching rule with "any": [] exempts the offer
            return True, "", []
        why = "a proof is required (spec §11.6)"
        if isinstance(proof, dict) and proof.get("challenge"):
            ok, why2, follow = await self._check_proof(rule, frm.key, to.key, proof, contact if isinstance(contact, dict) else {},
                                                       {"client_ip": client_ip})
            if ok:
                return True, "", []
            if follow:
                return False, why2, follow
            why = f"a proof is required: {why2}"
        return False, why, await self.offered(rule, frm.key, to.key, contact, {"client_ip": client_ip})

    async def _check_proof(self, rule, frm: str, to: str, proof: dict, contact: dict, ctx: dict) -> tuple[bool, str, list[dict]]:
        cid = proof["challenge"]
        b = self.read_id(cid)
        if b is None:
            return False, "the challenge is invalid or expired", []
        if b.get("from") != frm or b.get("to") != to:
            return False, "the challenge was made for another offer", []
        allowed = dict(rule["any"])
        kind = b.get("kind")
        if kind == "pow":
            if "pow" not in allowed or int(b.get("bits", 0)) < allowed["pow"]:
                return False, "this proof of work is no longer enough", []
            return (pow_ok(cid, frm, proof.get("x"), int(b["bits"])), "the proof of work does not hold", [])
        if kind in ("login", "oauth"):
            if kind not in allowed:
                return False, f"{kind} is not accepted here", []
            code = str(proof.get("code") or "").strip().upper()
            return (hmac.compare_digest(code, code10(self.secret(kind), cid)), f"the {kind} code is wrong", [])
        if kind not in ("email", "sms"):
            return False, "unknown challenge", []
        chain, after = b.get("chain"), b.get("after")
        need_rule = "email+sms" if (chain or after) else kind
        if need_rule not in allowed:
            return False, f"{need_rule} is not accepted here", []
        if b.get("need"):                               # the address, then a code is sent
            addr = norm_email(proof.get("email")) if kind == "email" else norm_phone(proof.get("phone"))
            if not addr:
                return False, f"a valid {'email address' if kind == 'email' else 'phone number'} is needed", []
            extra = {k: b[k] for k in ("chain", "after") if b.get(k)}
            return False, "a code was sent; answer with it", [await self._send(kind, addr, frm, to, extra,
                                                                                dict(ctx, challenge=cid, source="proof"))]
        if not b.get("sent"):
            return False, "unknown challenge", []
        n = self.tries.get(cid, 0)
        if n >= MAX_TRIES:
            return False, "too many tries", []
        self.tries[cid] = n + 1
        if len(self.tries) > 10000:                     # forget the oldest
            for k in list(self.tries)[:5000]:
                self.tries.pop(k, None)
        if not hmac.compare_digest(str(proof.get("code") or "").strip(), code8(self.secret("contact"), cid)):
            return False, f"the code is wrong ({MAX_TRIES - n - 1} tries left)", []
        if chain == "sms":                              # email+sms: the email is verified; now the phone
            extra = {"after": sha(cid)}
            phone = norm_phone(proof.get("phone") or contact.get("phone"))
            if phone:
                src = "proof" if norm_phone(proof.get("phone")) else "contact"
                return False, "email verified; a code was sent by SMS", [await self._send("sms", phone, frm, to, extra,
                                                                                         dict(ctx, challenge=cid, source=src))]
            nid, _ = self._new("sms", frm, to, need="address", **extra)
            return False, "email verified; now a phone number", [{"id": nid, "kind": "sms", "need": "address"}]
        return True, "", []

    # --- OAuth on the HTTPS face (§11.6) -----------------------------------------------------------
    def _verifier(self, cid: str) -> str:
        return P.b64u(hmac.new(self.secret("oauth"), f"airc-pkce\n{cid}".encode(), hashlib.sha256).digest())

    def _redirect_uri(self) -> str:
        return self.oauth.get("redirect_uri") or f"https://{self.srv.passports_cfg['host']}/airc/v0/login/oauth/callback"

    def oauth_start(self, cid: str) -> tuple[int, str]:
        """(302, location) or (400, message)."""
        if not self.oauth:
            return 404, "no OAuth login here"
        b = self.read_id(cid)
        if b is None or b.get("kind") != "oauth":
            return 400, "this login link is invalid or has expired; send the offer again for a new one"
        challenge = P.b64u(hashlib.sha256(self._verifier(cid).encode()).digest())
        q = {"response_type": "code", "client_id": self.oauth["client_id"], "redirect_uri": self._redirect_uri(),
             "scope": self.oauth.get("scope", "openid email"), "state": cid,
             "code_challenge": challenge, "code_challenge_method": "S256"}
        url = self.oauth["authorize_url"]
        return 302, url + ("&" if "?" in url else "?") + urllib.parse.urlencode(q)

    async def oauth_callback(self, query: dict) -> tuple[int, str]:
        """Exchange the code, read the account's email, check allow, and show the code. (status, html)."""
        def page(title, text, status=200):
            return status, (f"<!doctype html><meta charset=utf-8><title>{html.escape(title)}</title>"
                            f"<h1>{html.escape(title)}</h1><p>{text}</p>")
        if not self.oauth:
            return page("Not available", "No OAuth login here.", 404)
        cid = (query.get("state") or [""])[0]
        code = (query.get("code") or [""])[0]
        b = self.read_id(cid)
        if b is None or b.get("kind") != "oauth" or not code:
            return page("Login failed", "This login has expired or is incomplete. Send the offer again.", 400)
        o = self.oauth
        form = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": self._redirect_uri(),
                                       "client_id": o["client_id"], "client_secret": o.get("client_secret", ""),
                                       "code_verifier": self._verifier(cid)}).encode()
        loop = asyncio.get_running_loop()

        def fetch(req):
            with urllib.request.urlopen(req, timeout=15) as r:
                data = r.read(65537)                   # S7: a token or userinfo document is small
                if len(data) > 65536:
                    raise OSError("provider response too large")
                return wire.loads(data.decode() or "{}")
        try:
            tok = await loop.run_in_executor(None, fetch, urllib.request.Request(
                o["token_url"], data=form, method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}))
            claims = {}
            if isinstance(tok.get("id_token"), str) and tok["id_token"].count(".") == 2:
                # the id_token came straight from the token endpoint over TLS (OIDC §3.1.3.7): its claims are read
                claims = json.loads(P.unb64u(tok["id_token"].split(".")[1]).decode())
            if not claims.get("email") and o.get("userinfo_url") and tok.get("access_token"):
                claims = await loop.run_in_executor(None, fetch, urllib.request.Request(
                    o["userinfo_url"], headers={"Authorization": f"Bearer {tok['access_token']}", "Accept": "application/json"}))
        except Exception as e:                          # noqa: BLE001
            log.warning("oauth callback: %s", e)
            return page("Login failed", "The login provider did not complete the login.", 502)
        email = norm_email(claims.get("email"))
        if not email or claims.get("email_verified") is False:
            return page("Login failed", "The provider gave no verified email address.", 403)
        if not domain_allowed(o.get("allow") or ["*"], email):
            return page("Not allowed", "This account is not one this site accepts.", 403)
        c = code10(self.secret("oauth"), cid)
        return page("Your code", f"Give your agent this code: <code style='font-size:1.6em'>{c}</code>")
