#!/usr/bin/env python3
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Cross-realm link interop: the edge realm (airc.wasm under viceroy, realm airc.test) against the
Python reference realm (home.test), both default-deny for strangers. Links: offers in both
directions, accept, messages over the link, revoke, refusal afterwards (spec §11). Passports: issued
on each side and redeemed from the other, same-realm redemption on the edge, a spent passport
refused, revocation cascading to the link (spec §12). End-to-end encryption: keys exchanged through a
link, sealed messages both ways, passport fingerprints, no open key proxy (spec §19). A company realm
requiring encryption to and from an employee's hosted workspace, and a workspace requiring it (§19.7).
The built-in echo answering another realm, opened with its public passport. Each realm's workspace
front door answering the other with its directory (§20).

    tests/edge_interop.py        (needs viceroy and a wasi debug build: wkjam -s PLATFORM=wasi)
"""
import asyncio, json, os, re, secrets, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
APP = os.path.dirname(os.path.dirname(os.path.abspath(__file__))); sys.path.insert(0, APP + "/scripts")
VICEROY = os.environ.get("VICEROY", os.path.expanduser("~/.config/fastly/viceroy"))
from airc.httpclient import HttpClient
from airc import signing as S
from airc import passports as P
T = tempfile.mkdtemp(prefix="airc-interop-"); EDGE = "http://127.0.0.1:7473"; SOCK = f"{T}/py.sock"
EDGE_PUB = "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="
fails = 0
def check(c, what):
    global fails; print(("  ok    " if c else "  FAIL  ") + what); fails += (not c)
def airc(*a):
    r = subprocess.run([f"{APP}/airc", "--socket", SOCK, *a], capture_output=True, text=True, timeout=60); return (r.stdout + r.stderr).strip()
def lines(path):
    out = []
    for l in open(path):
        try: out.append(json.loads(l))
        except Exception: pass
    return out
B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
def pin(ik_b64):
    """§12.1: base62 of the first 128 bits of sha256(raw key), 22 characters."""
    import base64, hashlib
    n = int.from_bytes(hashlib.sha256(base64.b64decode(ik_b64)).digest()[:16], "big"); out = ""
    while n: n, r = divmod(n, 62); out = B62[r] + out
    return out.rjust(22, "0")
def terms(scope, token, exp, uses=1, bind_to="", link_ttl=86400, direction="both", offer=""):
    """§12.4's airc-passport-auth string; offer: the offer hash (§12.9) of a passport answering an offer, else empty."""
    import hashlib
    return "\n".join(["airc-passport-auth", scope, hashlib.sha256(token.encode()).hexdigest(), direction, str(exp), str(uses), bind_to,
                      str(link_ttl), offer]).encode()
async def edge_passport(c, as_, scope, signers, uses=1, label="interop", scope_arg=None):
    """passport op=new on the edge with a client token and every signer's signature (§4.7, §12.4)."""
    token, exp = "".join(secrets.choice(B62) for _ in range(32)), int(time.time()) + 3600
    canon = terms(scope, token, exp, uses)
    args = {"as": as_, "label": label, "token": token, "expires_at": exp, "uses": uses, "link_ttl": 86400,
            "auth": [{"key": k.ik, "sig": k.sign(canon)} for k in signers]}
    if scope_arg: args["scope"] = scope_arg
    return await c.passport("new", **args)
class SeedKey:
    """An authorizing key held by the test (an audit key, §12.8)."""
    def __init__(self):
        import base64
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization as ser
        self._k = Ed25519PrivateKey.generate()
        self.ik = base64.b64encode(self._k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
    def sign(self, data):
        import base64
        return base64.b64encode(self._k.sign(data)).decode()
REQ = SeedKey()
URL_RE = re.compile(r"https://\S+#passport=[0-9A-Za-z._~=-]+")


def no_rpin(url):
    """A passport without its realm pin (§12.3: .r=<pin> after the pins, before any layer)."""
    return re.sub(r"\.r=[0-9A-Za-z]{22}(?=~|$)", "", url or "")


def rpin_of(url):
    m = re.search(r"#passport=[^~]*?\.r=([0-9A-Za-z]{22})(?:~|$)", url or "")
    return m.group(1) if m else None
async def edge_ws(name):
    k = S.Signer(f"{T}/{name}.key")
    req = urllib.request.Request(EDGE + "/airc/v0/workspaces", data=json.dumps({"name": name, "pub": k.public_b64}).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    urllib.request.urlopen(req, timeout=30).read(); c = HttpClient(EDGE, k); await c.bind([name + "/"], mode="pull"); return c
async def wait_inbox(c, pred, secs=8):
    for _ in range(secs * 2):
        box = await c.inbox(); hit = [m for m in box if pred(m)]
        if hit: return hit[0]
        await asyncio.sleep(0.5)
    return None
async def main():
    os.environ["AIRC_E2E_DIR"] = f"{T}/e2e"          # private keys of every test endpoint (and of the CLI below)
    os.environ["AIRC_FILES_DIR"] = f"{T}/files"      # where the CLI listener saves files it receives
    from airc import e2e as E2E
    # --- the Python reference realm home.test, default-deny for foreign realms (links first)
    pk = S.Signer(f"{T}/py.key")
    cfg = {"realm": "home.test", "client_unix": SOCK, "http_listen": "127.0.0.1:28580",
           "uid_namespaces": {str(os.getuid()): ["alice"]}, "spool_dir": f"{T}/spool",
           "peers": {"airc.test": {"https": EDGE}}, "ack_timeout": 2.0, "retry_interval": 2.0,
           "signing": {"key": f"{T}/py.key", "known_keys": {"airc.test": [EDGE_PUB]}, "always": True, "require": True},
           "e2e": {"require": ["//airc.test/employee/**"]},    # the company insists on sealed traffic with the employee's workspace
           "policy": {"default_allow": False, "rules": [{"from": "//home.test/**", "to": "//home.test/**", "allow": True},
                                                          {"from": "//home.test/**", "to": "//airc.test/desk6", "allow": True, "note": "I: ask a front door"},
                                                          {"from": "//airc.test/desk6", "to": "//home.test/**", "allow": True, "mode": "reply", "note": "I: and hear its answer"},
                                                          {"from": "*", "to": "*", "allow": False, "note": "foreign realms need a link"}]}}
    cfg["offers"] = {"challenge": [{"from": "//airc.test/**", "to": "//home.test/alice/powgate", "any": ["pow:10"], "then": "pending"},
                                   {"from": "//airc.test/**", "to": "//home.test/alice/logingate", "any": ["login"], "then": "accept"}]}
    cfg["challenges"] = {"login_url": "https://login.home.test/", "login_secret": "py-login-secret"}   # §11.6
    json.dump(cfg, open(f"{T}/aircd.json", "w"))
    # --- the edge as airc.test: its own endpoints may send anywhere (as on airc.dev), strangers need a
    #     link or a passport; it knows the python realm's key
    toml = open(f"{APP}/scripts/build/fastly.dev.toml").read()
    toml = re.sub(r'"keys":\["[^"]+"\]', f'"keys":["{pk.public_b64}"]', toml)
    toml = toml.replace('"trusted":true', '"trusted":true,"passport_host":"airc.home.test"')   # the host in python's passports (§12.3)
    toml = toml.replace('default_allow = "true"', 'default_allow = "false"').replace("""rules = '[{"from":"*","to":"*","allow":true}]'""", """rules = '[{"from":"*","to":"*","allow":true,"mode":"reply"},{"from":"//airc.test/**","to":"//airc.test/**","allow":false,"note":"workspaces here need a link to each other"},{"from":"//airc.test/**","to":"*","allow":true}]'""")   # airc.dev's production rules, 2026-09-29
    toml = re.sub(r'(\[local_server\.config_stores\.airc_config\.contents\]\n)', r'\1channel_key_ttl = "30"\n', toml)   # scenario N waits one out
    # site policy (§12.8): an audit key that team9's grants and audit9's passports must carry; links team7 cannot refuse
    pol = (f"passport_accept_require = '[{{\"to\":\"//airc.test/team9/**\",\"key\":\"{REQ.ik}\"}}]'\n"
           f"passport_require = '[{{\"scope\":\"//airc.test/audit9/**\",\"key\":\"{REQ.ik}\",\"role\":\"audit\"}}]'\n"
           "links_must_accept = '[{\"peer\":\"//home.test/alice/boss\"}]'\n")
    toml = toml.replace("channel_key_ttl = \"30\"\n", "channel_key_ttl = \"30\"\n" + pol, 1)
    chal = ("offer_challenge = '[{\"from\":\"*\",\"to\":\"//airc.test/*/powgate\",\"any\":[\"pow:10\"],\"then\":\"pending\"},"
            "{\"from\":\"*\",\"to\":\"//airc.test/*/logingate\",\"any\":[\"login\"],\"then\":\"accept\"},"
            "{\"from\":\"*\",\"to\":\"//airc.test/*/oauthgate\",\"any\":[\"oauth\"],\"then\":\"pending\"}]'\n"
            "challenge_login_url = \"https://login.airc.test/\"\n"
            "challenge_oauth_provider = \"fake\"\nchallenge_oauth_authorize_url = \"https://provider.example/authorize\"\n"
            "challenge_oauth_token_url = \"http://127.0.0.1:28601/token\"\nchallenge_oauth_userinfo_url = \"http://127.0.0.1:28601/userinfo\"\n"
            "challenge_oauth_client_id = \"airc-interop\"\nchallenge_oauth_allow = \"*@example.com\"\n")
    toml = toml.replace("channel_key_ttl = \"30\"\n", "channel_key_ttl = \"30\"\n" + chal, 1)
    toml = toml.replace("""      key = "admin_token"\n      data = "dev-admin-token"\n""", """      key = "admin_token"\n      data = "dev-admin-token"\n"""
                        """    [[local_server.secret_stores.airc_secrets]]\n      key = "login_secret"\n      data = "interop-login-secret"\n"""
                        """    [[local_server.secret_stores.airc_secrets]]\n      key = "oauth_secret"\n      data = "interop-oauth-secret"\n""")
    open(f"{T}/fastly.interop.toml", "w").write(toml)
    vic = subprocess.Popen([VICEROY, "-C", f"{T}/fastly.interop.toml", "--addr=127.0.0.1:7473", "../../bin/wasi/debug/airc.wasm"],
                           cwd=f"{APP}/scripts/build", stdout=open(f"{T}/viceroy.log", "w"), stderr=subprocess.STDOUT)
    py = subprocess.Popen([sys.executable, f"{APP}/aircd", "-c", f"{T}/aircd.json"], stdout=open(f"{T}/aircd.log", "w"), stderr=subprocess.STDOUT)
    lst = None
    try:
        for _ in range(60):
            try: urllib.request.urlopen(EDGE + "/service_info", timeout=2); break
            except Exception: time.sleep(0.5)
        for _ in range(30):
            if os.path.exists(SOCK): break
            time.sleep(0.3)
        lst = subprocess.Popen([f"{APP}/airc", "--socket", SOCK, "listen", "--json", "alice/bot"], stdout=open(f"{T}/bot.jsonl", "w"), stderr=subprocess.STDOUT)
        await asyncio.sleep(1.5)
        BOT = "//home.test/alice/bot"
        print("A. edge endpoint offers, python endpoint accepts")
        d = await edge_ws("front")
        a0 = await d.send(BOT, "cold hello", frm="front/x")
        check(a0["status"] == "failed", f"cold message refused before a link: {a0.get('reason','')[:70]}")
        check("link offer" in a0.get("reason", ""), "the refusal says how to ask")
        off = await d.link("offer", **{"as": "front/x", "peer": BOT, "label": "interop at my user\u2019s request", "expires": "7d"})   # non-ASCII label: live bug 09-28
        lid = off["link"]["id"]
        check(off.get("ok") and re.fullmatch(r"L[0-9a-f]{8}", lid) is not None, f"edge offer {lid}, peer: {off.get('peer')}")
        check(off.get("delivery") == "delivered", "python realm stored the offer (linked.delivery)")
        await asyncio.sleep(1)
        check(off["link"].get("expires") and abs(off["link"]["expires"] - off["link"]["created"] - 7 * 86400) < 5, "expires 7d honoured")
        note = next((m for m in lines(f"{T}/bot.jsonl") if m.get("hdr", {}).get("airc-link") == lid), None)
        check(note is not None, "bot got the offer notice")
        check(note and note["from"] == "airc://home.test/_links" and note["hdr"].get("airc-peer") == "airc://airc.test/front/x",
              f"python notice comes from its _links, naming the peer ({note and note['from']})")
        check("pending" in airc("links", "--all"), "python lists the link pending")
        out = airc("link", "accept", lid, "--as", "alice/bot"); check("active" in out, f"python accept: {out[:90]}")
        check("did not verify" not in out, f"the accept of a non-ASCII-labelled link verifies at the edge: {out[-80:]}")
        n = await wait_inbox(d, lambda m: m.get("hdr", {}).get("airc-link") == lid and "accepted" in m["body"])
        check(n is not None, "edge endpoint told the link was accepted")
        check(n and n["from"] == "airc://airc.test/_links" and n["hdr"].get("airc-peer") == "airc://home.test/alice/bot",
              f"edge notice comes from its _links, naming the peer ({n and n['from']})")
        if n: await d.ack(n["id"])
        lk = [l for l in (await d.link("list", **{"as": "front/x"}))["links"] if l["id"] == lid]
        check(lk and lk[0]["state"] == "active", "edge record is active")
        check(lk and lk[0]["a"] == "airc://home.test/alice/bot" and lk[0]["b"] == "airc://airc.test/front/x" and lk[0].get("origin", {}).get("passport"),
              "§12.9: python's accept issued a passport the edge redeemed; the granted record keeps the offer's id, a = the offeree")
        a1 = await d.send(BOT, "hello over the link", frm="front/x"); check(a1["status"] == "delivered", f"edge -> python over the link: {a1['status']} {a1.get('reason','')}")
        out = airc("send", "--from", "alice/bot", "//airc.test/front/x", "reply over the link")
        def opened(m):                                    # the offer carried front/x's key, so python seals to it (§19.9)
            if m.get("type") == E2E.MEDIA_TYPE:
                try:
                    return E2E.Keystore("airc://airc.test/front/x").open(m)
                except E2E.E2EError:
                    return m
            return m
        m = await wait_inbox(d, lambda m: opened(m).get("body") == "reply over the link")
        check(m is not None and m.get("type") == E2E.MEDIA_TYPE, f"python -> edge over the link, sealed to the key the offer carried ({out[:60]})")
        print("B. python endpoint offers, edge endpoint accepts, then revokes")
        d2 = await edge_ws("desk2")
        out = airc("link", "offer", "//airc.test/desk2/y", "--as", "alice/bot", "--label", "reverse")
        m2 = re.search(r"link (L[0-9a-f]{8})", out); lid2 = m2.group(1) if m2 else ""
        check(bool(lid2) and "delivered" in out, f"python offer: {out[:110]}")
        n = await wait_inbox(d2, lambda m: m.get("hdr", {}).get("airc-link") == lid2)
        check(n is not None and "another realm" in n["body"], "edge endpoint got the offer notice")
        if n: await d2.ack(n["id"])
        acc = await d2.link("accept", **{"as": "desk2/y", "id": lid2})
        check(acc["link"]["state"] == "active" and acc.get("delivery") == "delivered", f"edge accept, peer: {acc.get('peer')}")
        check(acc["link"]["id"] == lid2 and acc["link"]["a"] == "airc://airc.test/desk2/y" and acc["link"].get("origin", {}).get("passport", "").startswith("P"),
              "§12.9: the edge's accept issued a passport python redeemed; the grant took the offer's id")
        await asyncio.sleep(1)
        check("active" in [l for l in airc("links", "--all").splitlines() if lid2 in l][0], "python record is active")
        a2 = await d2.send(BOT, "hi from desk2", frm="desk2/y"); check(a2["status"] == "delivered", "edge -> python over the reverse link")
        rv = await d2.link("revoke", **{"as": "desk2/y", "id": lid2})
        check(rv["link"]["state"] == "revoked" and rv.get("delivery") == "delivered", f"edge revoke, peer: {rv.get('peer')}")
        a3 = await d2.send(BOT, "after revoke", frm="desk2/y"); check(a3["status"] == "failed", f"edge -> python refused after revoke: {a3.get('reason','')[:70]}")
        out = airc("send", "--from", "alice/bot", "//airc.test/desk2/y", "python after revoke"); check("fail" in out.lower() or "not authorized" in out, f"python -> edge refused after revoke: {out[:80]}")
        print("C. python issues a passport, an edge endpoint redeems it, python revokes it with its links")
        out = airc("passport", "new", "--as", "alice/bot", "--label", "for the edge")
        line = (URL_RE.search(out) or [""])[0] if URL_RE.search(out) else ""
        pid = (re.search(r"(P[0-9a-f]{8})", out) or [None, ""])[1] if re.search(r"(P[0-9a-f]{8})", out) else ""
        check(line.startswith("https://airc.home.test/alice/bot#passport="), f"python passport issued {pid}: {line[:70]}")
        d3 = await edge_ws("desk3")
        r = await d3.passport("redeem", **{"as": "desk3/z"}, passport=line)
        lid3 = (r.get("link") or {}).get("id", "")
        check(r.get("ok") and lid3 and (r.get("link") or {}).get("state") == "active", f"edge redeem: {r.get('status')} {r.get('reason','')[:60]}")
        n = await wait_inbox(d3, lambda m: m.get("hdr", {}).get("airc-link") == lid3)
        check(n is not None and "redeemed a passport" in n["body"] and n["hdr"].get("airc-passport-scope") == "airc://home.test/alice/bot"
              and n["hdr"].get("airc-passport-pins") == line.split("#passport=")[1].split(".", 1)[1].split(".r=")[0] if n else False, "edge endpoint told the link is open, with the scope and the pins")
        check(n is not None and n["hdr"].get("airc-peer-ik") and pin(n["hdr"]["airc-peer-ik"]) in line, "the scope endpoint's own key is passed as its identity key")
        if n: await d3.ack(n["id"])
        await asyncio.sleep(1)
        check(any("redeemed" in m.get("body", "") and m.get("hdr", {}).get("airc-link") == lid3 for m in lines(f"{T}/bot.jsonl")), "bot told its passport was redeemed")
        a4 = await d3.send(BOT, "hi via passport", frm="desk3/z"); check(a4["status"] == "delivered", f"edge -> python over the passport link: {a4.get('reason','')[:50]}")
        r2 = await d3.passport("redeem", **{"as": "desk3/w"}, passport=line)
        check(not r2.get("ok") and "exhausted" in r2.get("reason", ""), f"spent passport refused: {r2.get('reason','')}")
        out = airc("passport", "revoke", pid, "--as", "alice/bot", "--and-links"); check("revoked" in out, f"python revoke --and-links: {out[:70]}")
        await asyncio.sleep(1)
        a5 = await d3.send(BOT, "after passport revoke", frm="desk3/z"); check(a5["status"] == "failed", f"edge -> python refused after cascade: {a5.get('reason','')[:60]}")
        print("D. an edge endpoint issues a passport, python redeems it, the edge revokes it with its links")
        d4 = await edge_ws("desk4")
        ks4 = E2E.Keystore("airc://airc.test/desk4/q"); await E2E.ensure_published(ks4, d4.keys_publish)
        pnew = await edge_passport(d4, "desk4/q", "airc://airc.test/desk4/q", [ks4], label="for python")
        check(pnew.get("ok") and pnew.get("url", "").startswith("https://airc.test/desk4/q#passport=") and no_rpin(pnew["url"]).endswith("." + pin(ks4.ik)),
              f"edge passport issued {pnew.get('passport',{}).get('id')}: {pnew.get('url', pnew.get('reason', ''))[:70]}")
        out = airc("accept", pnew.get("url", ""), "--as", "alice/bot")
        m4 = re.search(r"(L[0-9a-f]{8})", out); lid4 = m4.group(1) if m4 else ""
        check(bool(lid4) and "fail" not in out.lower(), f"python redeem: {out[:100]}")
        n = await wait_inbox(d4, lambda m: "redeemed the passport" in m["body"] and m["hdr"].get("airc-passport-scope") == "airc://airc.test/desk4/q")
        check(n is not None, "edge issuer told its passport was redeemed")
        if n: await d4.ack(n["id"])
        check("active" in "".join(l for l in airc("links", "--all").splitlines() if lid4 in l), "python records the granted link")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/desk4/q", "hi from python via passport")   # (it pinned desk4/q's key from the grant)
        m = await wait_inbox(d4, lambda m: m["body"] == "hi from python via passport")
        check(m is not None, f"python -> edge over the passport link ({out[:40]})")
        rv = await d4.passport("revoke", **{"as": "desk4/q", "id": pnew["passport"]["id"], "and_links": True})
        check(rv.get("ok") and rv.get("links_revoked") == 1, f"edge revoke and_links: {rv.get('links_revoked')}")
        await asyncio.sleep(1)
        out = airc("send", "--from", "alice/bot", "//airc.test/desk4/q", "after edge revoke")
        check("fail" in out.lower() or "not authorized" in out, f"python -> edge refused after cascade: {out[:80]}")
        bad = None
        try: await d4.link("offer", **{"as": "desk4/q", "peer": BOT, "expires": "7x"})
        except Exception as ex: bad = str(ex)
        check(bad and "duration" in bad, f"malformed expires refused: {bad and bad[:60]}")
        print("E. same-realm redemption on the edge")
        ksf = E2E.Keystore("airc://airc.test/front/x"); await E2E.ensure_published(ksf, d.keys_publish)
        pn = await edge_passport(d, "front/x", "airc://airc.test/front/x", [ksf], label="local")
        r = await d2.passport("redeem", **{"as": "desk2/y"}, passport=pn.get("url", ""))
        check(r.get("ok") and (r.get("link") or {}).get("state") == "active", f"edge-local redeem: {r.get('reason','')[:50]}")
        a6 = await d2.send("front/x", "local via passport", frm="desk2/y"); check(a6["status"] in ("delivered", "queued"), f"desk2 -> desk over it: {a6['status']}")
        r = await d2.passport("redeem", **{"as": "desk2/y"}, passport="https://airc.test/front/x#passport=nosuchtoken00000000000000." + pin(ksf.ik))
        check(not r.get("ok") and "unknown" in r.get("reason", ""), f"unknown token refused: {r.get('reason','')}")
        r = None
        try: await d2.passport("redeem", **{"as": "desk2/y"}, passport="airc-passport:1;i=airc.test;t=nosuchtoken0000000000")
        except Exception as ex: r = str(ex)
        check(r is not None and "old or unknown passport format" in r, f"the withdrawn line form is refused: {(r or '')[:60]}")
        print("E2. namespace passports across realms (§12.1, §11.3, §12.7)")
        d8 = await edge_ws("desk8")
        fleet = E2E.Keystore("airc://airc.test/desk8/fleet", f"{T}/fleet8"); fleet.ensure()
        ka = await d8.passport("key-add", **{"as": "desk8/", "scope": "desk8/", "key": fleet.ik})
        check(ka.get("ok"), f"edge key-add for desk8/: {ka.get('reason', '')[:50]}")
        p8 = await edge_passport(d8, "desk8/", "airc://airc.test/desk8/", [fleet], scope_arg="desk8/")
        check(p8.get("url", "").startswith("https://airc.test/desk8/#passport="), f"edge namespace passport: {p8.get('url', p8.get('reason', ''))[:70]}")
        out = airc("accept", p8.get("url", ""), "--as", "alice/bot")
        m8 = re.search(r"(L[0-9a-f]{8})", out); l8 = m8.group(1) if m8 else ""
        check(bool(l8) and "fail" not in out.lower(), f"python redeems the edge's namespace passport: {out[:90]}")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/desk8/later", "to an endpoint created later")
        m = await wait_inbox(d8, lambda m: m["body"] == "to an endpoint created later")
        check(m is not None, f"python -> an edge endpoint created after the passport, over the group link ({out[:50]})")
        oo = await d8.link("revoke", **{"as": "desk8/later", "id": l8})
        check(oo.get("ok") and (oo.get("link") or {}).get("origin", {}).get("opt_out_of") == l8 and oo.get("delivery") == "delivered",
              f"desk8/later opts out, python stores it ({oo.get('delivery')} {oo.get('reason', '')[:40]})")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/desk8/later", "after the opt-out")
        check("fail" in out.lower() or "not authorized" in out or "revoked" in out, f"python -> the endpoint that opted out is refused: {out[:80]}")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/desk8/other", "to the rest of desk8")
        m = await wait_inbox(d8, lambda m: m["body"] == "to the rest of desk8")
        check(m is not None, f"the rest of the namespace stays linked ({out[:50]})")
        import base64 as _b64
        open(f"{T}/fleet.seed", "w").write(_b64.b64encode(os.urandom(32)).decode())
        out = airc("passport", "keys", "add", "--as", "alice/bot", "--scope", "alice/", "--key-file", f"{T}/fleet.seed")
        check("fail" not in out.lower() and "refused" not in out.lower(), f"python passport keys add for alice/: {out[:70]}")
        out = airc("passport", "new", "--as", "alice/bot", "--scope", "alice/", "--sign-key", f"{T}/fleet.seed", "--no-identity-key", "--label", "fleet")
        u9 = (URL_RE.search(out) or [""])[0] if URL_RE.search(out) else ""
        check(u9.startswith("https://airc.home.test/alice/#passport="), f"python namespace passport: {out[:80]}")
        r9 = await d8.passport("redeem", **{"as": "desk8/z"}, passport=u9)
        check(r9.get("ok") and (r9.get("link") or {}).get("a") == "airc://home.test/alice/", f"the edge redeems python's namespace passport: {r9.get('reason', '')[:60]}")
        a9 = await d8.send("//home.test/alice/bot", "via the namespace passport", frm="desk8/z")
        check(a9["status"] == "delivered", f"edge -> an endpoint beneath python's namespace, over the group link ({a9.get('reason', '')[:50]})")
        print("F. end-to-end encryption between an edge workspace and a python endpoint")
        d5 = await edge_ws("desk5"); D5 = "airc://airc.test/desk5/x"
        ks5 = E2E.Keystore(D5); check(await E2E.ensure_published(ks5, d5.keys_publish), "edge workspace published its key record")
        out = airc("keys", "--as", "alice/bot"); check("fingerprint" in out, "python endpoint published its key record")
        bot_ik = json.loads(urllib.request.urlopen("http://127.0.0.1:28580/airc/v0/keys?endpoint=" + urllib.parse.quote("airc://home.test/alice/bot", safe=""), timeout=10).read())["ik"]
        off = await d5.link("offer", **{"as": "desk5/x", "peer": BOT, "label": "e2e", "e2e_ik": ks5.ik})
        l5 = off["link"]["id"]; await asyncio.sleep(1)
        note = next((m for m in lines(f"{T}/bot.jsonl") if m.get("hdr", {}).get("airc-link") == l5), None)
        check(note and note["hdr"].get("airc-peer-ik") == ks5.ik, "python notice carries the edge endpoint's identity key")
        out = airc("link", "accept", l5, "--as", "alice/bot"); check("active" in out, "python accepts")
        n = await wait_inbox(d5, lambda m: m.get("hdr", {}).get("airc-link") == l5)
        check(n and n["hdr"].get("airc-peer-ik") == bot_ik, "edge notice carries the python endpoint's identity key")
        if n:
            await d5.ack(n["id"]); ks5.pin(BOT.replace("//", "airc://", 1), n["hdr"]["airc-peer-ik"], "link")
        a7, note7 = await d5.send_e2e(BOT, "sealed from the edge", frm="desk5/x")
        check(a7["status"] == "delivered" and note7.startswith("e2e "), f"edge -> python sealed: {a7['status']} {note7}")
        await asyncio.sleep(1)
        got = next((m for m in lines(f"{T}/bot.jsonl") if m.get("body") == "sealed from the edge"), None)
        check(got is not None and got.get("hdr", {}).get("airc-e2e", {}).get("pin") == "link", f"python opened it, sender pinned from the link ({got and got.get('hdr', {}).get('airc-e2e')})")
        out = airc("send", "--from", "alice/bot", "-v", "//airc.test/desk5/x", "sealed from python") if False else airc("-v", "send", "--from", "alice/bot", "//airc.test/desk5/x", "sealed from python")
        m = await wait_inbox(d5, lambda m: m.get("type") == E2E.MEDIA_TYPE)
        check(m is not None and "sealed from python" not in json.dumps(m), "the edge stored only ciphertext")
        if m:
            o = ks5.open(m); await d5.ack(m["id"])
            check(o["body"] == "sealed from python" and o["hdr"]["airc-e2e"]["pin"] == "link", f"edge endpoint opened it ({o['hdr']['airc-e2e']})")
        pp5 = await edge_passport(d5, "desk5/x", D5, [ks5])
        check(no_rpin(pp5.get("url", "")).endswith("." + pin(ks5.ik)), "edge passport pins the issuer's identity key")
        try:
            urllib.request.urlopen(EDGE + "/airc/v0/keys?endpoint=" + urllib.parse.quote("airc://home.test/alice/bot", safe=""), timeout=10)
            check(False, "edge refuses to proxy key lookups for strangers")
        except urllib.error.HTTPError as ex:
            check(ex.code == 404, "edge refuses to proxy key lookups for strangers")
        print("G. a company realm that requires encryption with an employee's hosted workspace")
        emp = await edge_ws("employee"); EMP = "airc://airc.test/employee/home"
        eks = E2E.Keystore(EMP); await E2E.ensure_published(eks, emp.keys_publish)
        off = await emp.link("offer", **{"as": "employee/home", "peer": BOT, "label": "working from home", "e2e_ik": eks.ik})
        out = airc("link", "accept", off["link"]["id"], "--as", "alice/bot")
        check("active" in out, f"python accepts the employee's offer: {out[:120]}")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/employee/home", "plaintext out of the company")
        check("only end-to-end encrypted" in out, f"company egress refuses plaintext: {out[:90]}")
        out = airc("send", "--from", "alice/bot", "//airc.test/employee/home", "sealed out of the company")
        m = await wait_inbox(emp, lambda m: m.get("type") == E2E.MEDIA_TYPE)
        check(m is not None and eks.open(m)["body"] == "sealed out of the company", f"sealed message leaves and opens at home ({out[:40]})")
        if m: await emp.ack(m["id"])
        from airc import files as F
        with open(f"{T}/secret.bin", "wb") as f:
            f.write(os.urandom(50_000))
        out = airc("send-file", "--from", "alice/bot", "//airc.test/employee/home", f"{T}/secret.bin")
        m = await wait_inbox(emp, lambda m: m.get("type") == E2E.MEDIA_TYPE and m.get("bin"))
        ok = False
        if m:
            opened = eks.open(await emp.fetch_bin(m))
            ok = opened["type"] == F.MEDIA_TYPE and F.unpack(opened)[1] == open(f"{T}/secret.bin", "rb").read() and "ct" not in json.loads(m["body"])
            await emp.ack(m["id"])
        check(ok, f"a sealed file (envelope v2, ciphertext as the binary section) passes the edge's encryption rule and opens at home ({out[:40]})")
        a8 = await emp.send(BOT, "plaintext into the company", frm="employee/home")
        check(a8["status"] == "failed" and a8.get("code") == "e2e_required", f"company ingress refuses plaintext: {a8.get('reason','')[:70]}")
        a9, n9 = await emp.send_e2e(BOT, "sealed into the company", frm="employee/home")
        await asyncio.sleep(1)
        check(a9["status"] == "delivered" and any(m.get("body") == "sealed into the company" for m in lines(f"{T}/bot.jsonl")),
              f"sealed reply accepted and opened ({a9['status']} {n9})")
        ok, _ = await emp.keys_publish(eks.record(require=True))
        d6 = await edge_ws("desk6")                                    # used below
        a10 = await emp.send("employee/home", "local plaintext", frm="employee/desk")   # same workspace: past the link rules
        check(ok and a10.get("code") == "e2e_required", f"a workspace endpoint that requires encryption refuses plaintext: {a10.get('reason','')[:60]}")
        print("H. the built-in echo, from another realm")
        page = urllib.request.urlopen(EDGE + "/echo.md", timeout=10).read().decode()
        epp = (re.search(r"https://airc\.test/echo#passport=EchoTestPassportPublic\.[0-9A-Za-z]{22}", page) or [""])[0] if "EchoTestPassportPublic" in page else ""
        check(bool(epp), f"the echo's page shows its passport {epp[:60]}")
        out = airc("accept", epp, "--as", "alice/bot")
        check("open" in out or "granted" in out, f"python redeems the echo's public passport: {out[:70]}")
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/echo", "hello echo")
        await asyncio.sleep(1.5)
        er = next((m for m in lines(f"{T}/bot.jsonl") if m.get("from") == "airc://airc.test/echo" and "hello echo" in m.get("body", "")), None)
        check(er is not None and "signed by home.test" in er["body"] and er.get("re"), f"echo answered across realms with re ({out[:40]})")
        print("I. the workspace front door (§20), across realms")
        hk = E2E.Keystore("airc://airc.test/desk6/helper"); await E2E.ensure_published(hk, d6.keys_publish)
        await d6.workspace("front", entry={"agent": "intake", "note": "start here"})
        out = airc("send", "--plain", "--from", "alice/bot", "//airc.test/desk6", "who works here?")
        await asyncio.sleep(1.5)
        dr = next((m for m in lines(f"{T}/bot.jsonl") if m.get("from") == "airc://airc.test/desk6"), None)
        check(dr is not None and (dr.get("hdr") or {}).get("airc-directory") == "airc://airc.test/desk6/helper airc://airc.test/desk6/intake"
              and "start here" in dr.get("body", "") and dr.get("re"), f"edge front door answers another realm with its directory ({out[:50]})")
        a11 = await d6.send("//home.test/alice", "who is on your side?", frm="desk6/x")
        m = await wait_inbox(d6, lambda m: m.get("from") == "airc://home.test/alice")
        check(a11["status"] == "delivered" and m is not None and "airc://home.test/alice/bot" in m["hdr"].get("airc-directory", ""),
              f"python front door answers the edge with its directory ({a11.get('reason', '')[:50]})")

        print("J. sessions and leases on the edge (§4.3.1)")
        from airc.httpclient import NameHeld
        t7 = await edge_ws("team7")                                   # this session holds team7/ (the catch-all)
        k7 = S.Signer(f"{T}/team7.key")
        sa, sb = HttpClient(EDGE, k7), HttpClient(EDGE, k7)            # two more processes, same workspace key
        check("leases" in (await sa.capabilities()).get("features", []), "edge offers leases")
        await sa.bind(["team7/a"], mode="pull"); await sb.bind(["team7/b"], mode="pull")
        for to in ("team7/a", "team7/b", "team7/other"):
            await t7.send(to, f"for {to}", frm="team7/x")
        await asyncio.sleep(1)
        ia, ib, it = [m["body"] for m in await sa.inbox()], [m["body"] for m in await sb.inbox()], [m["body"] for m in await t7.inbox()]
        check(ia == ["for team7/a"] and ib == ["for team7/b"], f"each session gets its own endpoint's messages ({ia}, {ib})")
        check(it == ["for team7/other"], f"the catch-all gets only what no endpoint session wins ({it})")
        try:
            await sb.bind(["team7/b", "team7/a"], mode="pull"); held = None
        except NameHeld as e:
            held = e
        check(held is not None and held.suggest == "airc://airc.test/team7/a-2", f"a held name is refused, with a free one suggested ({held})")
        await sb.bind(["team7/b", "team7/a"], mode="pull", take_over=True)
        await sa.inbox()
        ib = sorted(m["body"] for m in await sb.inbox())
        check(ib == ["for team7/a", "for team7/b"] and sa.displaced == ["airc://airc.test/team7/a"], f"take-over moves the name and tells the old holder ({ib}, {sa.displaced})")
        await sb.release()
        it = sorted(m["body"] for m in await t7.inbox())
        check(it == ["for team7/a", "for team7/b", "for team7/other"], f"released names fall back to the catch-all ({it})")
        old = await edge_ws("oldclient"); await old.release(); old.session = None   # a client from before sessions
        await old.bind(["oldclient/"], mode="pull")
        await old.send("//airc.test/oldclient/agent", "to an old client", frm="oldclient/sender")   # same workspace: past the link rules
        await asyncio.sleep(1)
        check([m["body"] for m in await old.inbox()] == ["to an old client"], "a client without AIRC-Session still receives (legacy session)")

        print("K. files in binary sections (§22), across realms")
        from airc import files as F
        blob = os.urandom(200_000)
        body, data = F.pack_bytes(blob, "blob.bin", note="from the edge")
        k1 = await d.send(BOT, body, frm="front/x", mtype=F.MEDIA_TYPE, bin=data)
        await asyncio.sleep(1.5)
        fm = next((m for m in lines(f"{T}/bot.jsonl") if (m.get("file") or {}).get("name") == "blob.bin"), None)
        check(k1["status"] in ("delivered", "queued") and fm is not None and open(fm["file"]["path"], "rb").read() == blob,
              f"a file from the edge reaches the python realm's listener, saved intact ({k1.get('status')} {k1.get('reason', '')[:40]})")
        with open(f"{T}/notes.txt", "w") as f:
            f.write("note line\n" * 20000)
        out = airc("send-file", "--plain", "--from", "alice/bot", "//airc.test/front/x", f"{T}/notes.txt", "the notes")
        qm = await wait_inbox(d, lambda m: m.get("type") == F.MEDIA_TYPE and m.get("from") == "airc://home.test/alice/bot")
        ok = False
        if qm:
            qm = await d.fetch_bin(qm)
            meta, raw = F.unpack(qm)
            ok = raw == open(f"{T}/notes.txt", "rb").read() and meta["enc"] == "gzip" and meta["note"] == "the notes" and qm["bin"] < 10000
        check(ok, f"a file from the python realm is queued at the edge and fetched raw from /airc/v0/bin ({out[:50]})")
        if qm:
            await d.ack(qm["id"])
            st = None
            try:
                await d._request("GET", "/airc/v0/bin/" + qm["id"], raw=True)
            except Exception as ex:
                st = str(ex)
            check(st is not None and "404" in st, "an acked message's binary section is gone")

        print("L. forged link control from a federated realm (§11.4, §12.5)")
        from airc.links import LinkStore, MEDIA_TYPE as LT
        from airc import wire as W
        async def forged(action, rec):
            m = W.new_msg(rec["a"] if action == "grant" else "airc://home.test/alice/mallory", rec["b"] if action == "grant" else "airc://airc.test/team7/a",
                          json.dumps({"action": action, "link": rec, "redemption": "1999999999.forged"}), mtype=LT, hdr={"airc-link": rec["id"]})
            m["via"] = ["home.test"]; pk.sign_message(m)
            req = urllib.request.Request(EDGE + "/airc/v0/msg", data=json.dumps(m).encode(), headers={"Content-Type": "application/json"}, method="POST")
            return json.loads(urllib.request.urlopen(req, timeout=30).read())
        g = LinkStore.make("airc://home.test/alice/mallory", "airc://airc.test/team7/a", direction="both", offered_by="airc://home.test/alice/mallory")
        g["state"] = "active"
        fa = await forged("grant", g)
        check(fa["status"] == "failed" and "redemption" in fa.get("reason", ""), f"a forged grant opens no link at the edge ({fa.get('reason', '')[:60]})")
        lk = await t7.link("offer", **{"as": "team7/x", "peer": "team7/a"}); lid2 = lk["link"]["id"]
        rv = LinkStore.make("airc://home.test/alice/mallory", "airc://airc.test/team7/a", direction="both",
                            offered_by="airc://home.test/alice/mallory", link_id=lid2)
        rv["state"] = "revoked"
        fr = await forged("revoke", rv)
        lst2 = await t7.link("list", **{"as": "team7/x"}) if hasattr(t7, "link") else {}
        still = [l for l in (lst2.get("links") or []) if l.get("id") == lid2]
        check(fr["status"] == "failed" and still and still[0]["state"] != "revoked", f"a foreign realm cannot revoke a link between two edge endpoints ({fr.get('reason', '')[:50]})")
        # draft 0.9 (§12.4, §12.7, §19.9). The interop edge's realm key is the §18.2 test key, so this test can make
        # the redemption value only the edge should be able to: a grant may use one value once.
        import base64 as B64, hashlib as HL
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as EdK
        from cryptography.hazmat.primitives import serialization as Ser
        edge_key = EdK.from_private_bytes(bytes(range(1, 33)))
        def red_value(redeemer, scope, token, pins):
            """airc.dev's stateless redemption value (§12.5): <expiry>.<h>.<p>.<sig>."""
            exp = int(time.time()) + 300; h = HL.sha256(token.encode()).hexdigest()[:16]; p = HL.sha256(".".join(pins).encode()).hexdigest()[:16]
            canon = "\n".join(["airc-redeem", redeemer, scope, str(exp), h, p])
            return ".".join([str(exp), h, p, B64.b64encode(edge_key.sign(canon.encode())).decode()])
        async def control(frm, to, body, ts=None):
            m = W.new_msg(frm, to, json.dumps(body), mtype=LT, hdr={"airc-link": body["link"]["id"]})
            if ts is not None: m["ts"] = ts
            m["via"] = ["home.test"]; pk.sign_message(m)
            req = urllib.request.Request(EDGE + "/airc/v0/msg", data=json.dumps(m).encode(), headers={"Content-Type": "application/json"}, method="POST")
            return json.loads(urllib.request.urlopen(req, timeout=30).read())
        MAL, T7A = "airc://home.test/alice/mallory", "airc://airc.test/team7/a"
        mal_ik = B64.b64encode(edge_key.public_key().public_bytes(Ser.Encoding.Raw, Ser.PublicFormat.Raw)).decode()
        def grant(scope, uses_signed=1, uses_sent=None, pins=None, with_pa=True, to=T7A):
            """A grant for a redemption only the edge could have made, with passport_auth signed by mal_ik."""
            tok = "tok" + secrets.token_hex(12); exp = int(time.time()) + 86400
            g = LinkStore.make(scope, to, direction="both", offered_by=scope) if not scope.endswith("/") else dict(LinkStore.make(MAL, to, direction="both", offered_by=MAL), a=scope, offered_by=scope)
            g["state"] = "active"; g["expires"] = int(time.time()) + 3600
            body = {"action": "grant", "link": g, "redemption": red_value(to, scope, tok, pins or [pin(mal_ik)])}
            if with_pa:
                body["passport_auth"] = {"scope": scope, "token_sha256": HL.sha256(tok.encode()).hexdigest(), "direction": "both", "expires": exp,
                                         "uses": uses_sent or uses_signed, "bind_to": "", "link_ttl": 3600,
                                         "auth": [{"key": mal_ik, "sig": B64.b64encode(edge_key.sign(terms(scope, tok, exp, uses_signed, "", 3600))).decode()}]}
            return body
        b1 = grant(MAL)
        r1 = await control(MAL, T7A, b1)
        check(r1["status"] == "delivered", f"a grant with a valid redemption value and passport_auth is recorded ({r1.get('reason', '')[:60]})")
        b2 = dict(b1, link=dict(LinkStore.make(MAL, T7A, direction="both", offered_by=MAL), state="active", expires=int(time.time()) + 3600))
        await asyncio.sleep(1)
        r2 = await control(MAL, T7A, b2)
        check(r2["status"] == "failed" and "already answered" in r2.get("reason", ""), f"a second grant on the same redemption value is refused ({r2.get('reason', '')[:60]})")
        r3 = await control(MAL, T7A, grant(MAL, with_pa=False))
        check(r3["status"] == "failed" and r3.get("reason") == "passport not authorized", f"a grant without passport_auth is refused ({r3.get('reason', '')[:60]})")
        r4 = await control(MAL, T7A, grant(MAL, pins=[pin(mal_ik), "0" * 22]))
        check(r4["status"] == "failed" and r4.get("reason") == "passport not authorized", f"a grant missing one of the passport's keys is refused ({r4.get('reason', '')[:60]})")
        r5 = await control(MAL, T7A, grant(MAL, uses_signed=1, uses_sent=2))
        check(r5["status"] == "failed" and r5.get("reason") == "passport not authorized", f"a passport_auth that does not verify is refused ({r5.get('reason', '')[:70]})")
        NS = "airc://home.test/alice/"
        r5b = await control(NS, T7A, grant(NS))
        check(r5b["status"] == "delivered", f"a namespace-scope grant (from = the namespace) is recorded ({r5b.get('reason', '')[:60]})")
        RL = "airc://home.test/"
        r5c = await control(RL, T7A, grant(RL))
        check(r5c["status"] == "delivered", f"a realm-scope grant (from = airc://home.test/) is recorded ({r5c.get('reason', '')[:60]})")
        await edge_ws("team9"); T9A = "airc://airc.test/team9/a"
        r5d = await control(MAL, T9A, grant(MAL, to=T9A))
        check(r5d["status"] == "failed" and r5d.get("reason") == "passport lacks a key required here", f"passport_accept_require: a grant without the audit key is refused ({r5d.get('reason', '')[:60]})")
        T7X = "airc://airc.test/team7/x"
        o12 = await t7.link("offer", **{"as": "team7/x", "peer": MAL, "label": "knock"})       # an edge offer to python (mallory never answers)
        rec12 = o12["link"]
        r12 = await control(MAL, T7X, {"action": "accept", "link": rec12})
        check(r12["status"] == "failed" and "must carry a passport" in r12.get("reason", ""), f"§12.9: an accept without a passport is refused ({r12.get('reason', '')[:60]})")
        r13 = await control(MAL, T7X, {"action": "accept", "link": rec12, "passport": "https://airc.home.test/alice/other#passport=" + "A" * 32 + "." + pin(mal_ik)})
        check(r13["status"] == "failed" and "did not redeem" in r13.get("reason", ""), f"§12.9: an accept answering with another endpoint's passport that does not redeem is refused ({r13.get('reason', '')[:60]})")
        st12 = [l for l in (await t7.link("list", **{"as": "team7/x"})).get("links", []) if l["id"] == rec12["id"]]
        check(st12 and st12[0]["state"] == "pending", "the offer stays pending")
        BOSS = "airc://home.test/alice/boss"
        ob = LinkStore.make(BOSS, T7A, direction="both", offered_by=BOSS)
        rb = await control(BOSS, T7A, {"action": "offer", "link": ob})
        acc = {"ok": True}                                             # (accepting would have python redeem a passport for an offer it never made)
        why = None
        try: await t7.link("revoke", **{"as": "team7/a", "id": ob["id"]})
        except Exception as ex: why = str(ex)
        check(rb["status"] == "delivered" and acc.get("ok") and why is not None and "required by site policy" in why,
              f"links_must_accept: the endpoint cannot revoke a link with //home.test/alice/boss ({(why or '')[:60]})")
        a9w = await edge_ws("audit9")
        ka9 = E2E.Keystore("airc://airc.test/audit9/x"); await E2E.ensure_published(ka9, a9w.keys_publish)
        why = None
        try: await edge_passport(a9w, "audit9/x", "airc://airc.test/audit9/x", [ka9])
        except Exception as ex: why = str(ex)
        check(why is not None and "requires" in why and pin(REQ.ik) in why, f"passport_require: a passport without the audit key is refused ({(why or '')[:70]})")
        await a9w.passport("key-add", **{"as": "audit9/", "scope": "audit9/", "key": REQ.ik})
        pa9 = await edge_passport(a9w, "audit9/x", "airc://airc.test/audit9/x", [ka9, REQ])
        check(pa9.get("ok") and no_rpin(pa9.get("url", "")).endswith("." + pin(ka9.ik) + "." + pin(REQ.ik)), f"with the audit key it is issued, both pinned ({pa9.get('url', '')[-50:]})")
        o6 = LinkStore.make(MAL, T7A, direction="both", offered_by=MAL)
        ts6 = round(time.time(), 3)
        lc = "\n".join(["airc-link-control", "offer", o6["id"], MAL, T7A, "both", "", str(int(round(ts6 * 1000)))])
        sig6 = B64.b64encode(edge_key.sign(lc.encode())).decode()
        r6 = await control(MAL, T7A, {"action": "offer", "link": o6, "e2e": {"ik": mal_ik, "sig": sig6}}, ts=ts6)
        check(r6["status"] == "delivered", f"a peer's signed offer is accepted ({r6.get('reason', '')[:60]})")
        o7 = LinkStore.make(MAL, T7A, direction="both", offered_by=MAL)
        r7 = await control(MAL, T7A, {"action": "offer", "link": o7, "e2e": {"ik": mal_ik, "sig": sig6}}, ts=ts6)
        check(r7["status"] == "failed" and r7.get("reason") == "link control signature invalid", f"a peer's offer with a signature for another link is refused ({r7.get('reason', '')[:60]})")
        print("M. workspace keys and recovery codes (§3.4.4, §3.4.5)")
        try:
            await HttpClient(EDGE, k7).register("thief9"); stolen = True
        except Exception as ex:
            stolen = "409" in str(ex) or "key_in_use" in str(ex)
            stolen = not stolen
        check(not stolen, "registering a new workspace with another workspace's public key is refused")
        rk = S.Signer(f"{T}/recov.key"); rc = HttpClient(EDGE, rk)
        reg = await rc.register("recovws", recovery=True)
        try:
            await rc.workspace("recovery-code"); minted = True
        except Exception as ex:
            minted = "recovery" not in str(ex)
        check(not minted and reg.get("recovery"), "a recovery code cannot be replaced without the current one")
        r2 = await rc.workspace("recovery-code", recovery=reg["recovery"])
        check(bool(r2.get("recovery")) and r2["recovery"] != reg["recovery"], "with the current code it is replaced")
        print("N. channel keys, enrollment codes and closing channels (§3.4.5, §21.4)")
        from airc.httpclient import HttpClientError
        async def refused(coro):
            try:
                r = await coro
                if isinstance(r, tuple):
                    return r[0] is False
                return isinstance(r, dict) and (r.get("status") == "failed" or r.get("ok") is False)
            except HttpClientError:
                return True
        inv = await t7.workspace("join-code", channel="reviewer2")
        ck = HttpClient(EDGE, S.Signer(f"{T}/chan.key")); j = await ck.join(inv["code"])
        check(inv.get("kind") == "channel" and j.get("channel") == "reviewer2", "a channel code makes a key for exactly one channel")
        ok_send = await ck.send("team7/x", "from my channel", frm="team7/reviewer2")
        check(ok_send["status"] in ("queued", "delivered"), "a channel key sends as its channel")
        check(await refused(ck.send("team7/x", "pretending", frm="team7/a")), "a channel key cannot send as another channel")
        check(await refused(ck.bind(["team7/"], mode="pull")), "a channel key cannot listen for the whole workspace")
        check(await refused(ck.workspace("join-code")), "a channel key cannot change the workspace")
        check(await refused(ck.channel_close("airc://airc.test/team7/a")), "a channel key cannot close another channel")
        check((await ck.workspace()).get("channel") == "reviewer2", "a channel key sees only its own channel")
        enr = await t7.workspace("join-code", enroll=True, label="cloud env")
        s1 = HttpClient(EDGE, S.Signer(f"{T}/s1.key")); s2 = HttpClient(EDGE, S.Signer(f"{T}/s2.key"))
        j1 = await s1.join(enr["code"], channel="s-one")
        try:
            await s2.join(enr["code"], channel="s-one"); clash = None
        except HttpClientError as ex:
            clash = str(ex)
        check(enr.get("kind") == "enroll" and not enr.get("expires") and j1.get("channel") == "s-one" and clash and "s-one-2" in clash,
              f"an enrollment code lets each session claim a free channel; a taken one is refused with a free name ({(clash or '')[:50]})")
        await s2.join(enr["code"], channel="s-two")
        check(await refused(s2.send("team7/x", "as s-one", frm="team7/s-one")), "sessions from one environment cannot act as each other")
        pb = await t7.profile_publish({"t": "profile", "endpoint": "airc://airc.test/team7/busy", "about": "in use", "ts": int(__import__("time").time())})
        check(pb[0], f"a full key publishes a profile for team7/busy ({pb[1][:50]})")
        s3 = HttpClient(EDGE, S.Signer(f"{T}/s3.key"))
        check(await refused(s3.join(enr["code"], channel="busy")), "a channel already in use by someone else cannot be claimed")
        # closing: a message to a closed channel fails at once; listening as it again opens it
        await s1.bind(["team7/s-one"], mode="pull")
        cl = await s1.channel_close("airc://airc.test/team7/s-one")
        m1 = await t7.send("team7/s-one", "anyone there?", frm="team7/x")
        check(cl[0] and m1["status"] == "failed" and m1.get("code") == "path_gone", f"a closed channel says so to senders ({m1.get('reason', '')[:50]})")
        await s1.bind(["team7/s-one"], mode="pull")
        m2 = await t7.send("team7/s-one", "back?", frm="team7/x")
        check(m2["status"] == "queued", "listening as it again opens it")
        # revoking the enrollment code revokes every key it made
        rv = await t7.workspace("revoke-join", id=enr["id"])
        check(rv.get("keys_revoked") == 2 and await refused(s1.inbox()) and await refused(s2.inbox()),
              f"revoking the enrollment code revokes its keys ({rv.get('keys_revoked')})")
        # a channel key unused for its lifetime lapses, and its channel is closed (30 s here; 7 days for real)
        inv2 = await t7.workspace("join-code", channel="lapser")
        lk2 = HttpClient(EDGE, S.Signer(f"{T}/lapse.key")); await lk2.join(inv2["code"])
        await lk2.profile_publish({"t": "profile", "endpoint": "airc://airc.test/team7/lapser", "about": "short-lived", "ts": int(__import__("time").time())})
        await asyncio.sleep(35)
        await t7.workspace()                                          # any look at the workspace sweeps lapsed keys
        m3 = await t7.send("team7/lapser", "still there?", frm="team7/x")
        check(await refused(lk2.inbox()) and m3.get("code") == "path_gone", f"an unused channel key lapses and its channel closes ({m3.get('reason', '')[:40]})")

        print("P. links enforced, as on airc.dev: one workspace talks freely, other workspaces need a link, replies pass")
        pa = await edge_ws("polia"); pb = await edge_ws("polib")
        r1 = await pa.send("polia/two", "sibling", frm="polia/one")
        check(r1["status"] in ("queued", "delivered"), f"endpoints of one workspace message each other ({r1['status']} {r1.get('reason','')[:50]})")
        r2 = await pa.send("//airc.test/polib/x", "cold", frm="polia/one")
        check(r2["status"] == "failed" and "link" in r2.get("reason", ""), f"another workspace on the realm needs a link ({r2.get('reason','')[:60]})")
        r3 = await pb.send("//airc.test/polia/one", "unasked", frm="polib/x")
        check(r3["status"] == "failed", "and so does the other direction")
        e1 = await pa.send("//airc.test/echo", "hello", frm="polia/one")
        check(e1["status"] in ("queued", "delivered"), f"the echo answers without a link ({e1['status']})")
        off = await pb.link("offer", **{"as": "polib/x", "peer": "//airc.test/polia/one", "label": "policy test"})
        check(off.get("ok"), f"a stranger may still ask: link offer {off.get('link', {}).get('id')}")
        await pa.link("accept", **{"as": "polia/one", "id": off["link"]["id"]})
        r4 = await pb.send("//airc.test/polia/one", "now linked", frm="polib/x")
        check(r4["status"] in ("queued", "delivered"), f"over the link it goes through ({r4['status']} {r4.get('reason','')[:50]})")
        off2 = await pb.link("offer", **{"as": "polib/y", "peer": "//airc.test/polia/two", "label": "no as"})
        acc2 = await pa.link("accept", id=off2["link"]["id"])        # no "as": the edge takes this key's side of the link
        check(acc2.get("ok") and acc2["link"]["state"] == "active", "accept without as acts as this key's side of the link")
        try:
            await pa.link("accept", **{"as": "polia/nobody", "id": off2["link"]["id"]}); check(False, "a wrong as is refused, naming the sides")
        except HttpClientError as ex:
            check("it joins" in str(ex) and "polia/two" in str(ex), f"a wrong as is refused, naming the sides ({str(ex)[:60]})")
        await pa.bind(["polia/"], mode="pull")
        for i in range(3):
            await pa.send("polia/one", f"order {i}", frm="polia/two"); await asyncio.sleep(0.05)
        got = [m["body"] for m in await pa.inbox() if m.get("body", "").startswith("order ")]
        check(got == ["order 0", "order 1", "order 2"], f"the inbox hands messages out oldest first ({got})")

        print("Q. delegated passports across realms (§12.10)")
        import hashlib as _hl, base64 as _b
        def cj(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        def b64u(x): return _b.urlsafe_b64encode(x).decode().rstrip("=")
        def layer(key, scope, ref, body, prev=None):
            """§12.10 layer, made here (independent of the Python library): body with "key", signed over airc-passport-layer."""
            body = dict(body, key=key.ik); bt = cj(body)
            ls = "\n".join(["airc-passport-layer", scope, ref, _hl.sha256(prev.encode()).hexdigest() if prev else "", bt])
            return b64u(bt.encode()) + "." + b64u(key._k.sign(ls.encode())) + "." + pin(key.ik)
        def seed_file(name):
            path = f"{T}/{name}.seed"; raw = os.urandom(32); open(path, "w").write(_b.b64encode(raw).decode())
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization as ser
            ik = _b.b64encode(Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)).decode()
            return path, ik
        async def edge_delegation(c, as_, scope, signers, delegates, uses=3):
            token, exp = "".join(secrets.choice(B62) for _ in range(32)), int(time.time()) + 3600
            canon = "\n".join(["airc-passport-delegate", scope, _hl.sha256(token.encode()).hexdigest(), "both", str(exp), str(uses), "", "86400", cj(delegates), ""]).encode()
            return await c.passport("new", **{"as": as_, "label": "interop delegation", "token": token, "expires_at": exp, "uses": uses, "link_ttl": 86400,
                                             "delegates": delegates, "auth": [{"key": k.ik, "sig": k.sign(canon)} for k in signers]})
        def py_url(out): return (URL_RE.search(out) or [""])[0] if URL_RE.search(out) else ""
        # Q1: an edge root, a python delegate's layer, redeemed by python
        dq1 = await edge_ws("deleg1"); kq1 = E2E.Keystore("airc://airc.test/deleg1/x"); await E2E.ensure_published(kq1, dq1.keys_publish)
        pyd_path, pyd_ik = seed_file("pydelegate")
        g1 = await edge_delegation(dq1, "deleg1/x", "airc://airc.test/deleg1/x", [kq1], [{"realm": "home.test", "pins": [pin(pyd_ik)]}])
        check(g1.get("ok") and len(g1.get("reference", "")) == 64, f"edge root issues a delegation to home.test ({g1.get('reason', '')[:50]})")
        out = airc("passport", "delegate", g1.get("url", ""), "--sign-key", pyd_path, "--to", "//home.test/alice/bot", "--expires", "50m", "--realm", "airc.test")
        u1 = py_url(out)
        check(u1.count("~") == 1, f"python adds its layer: {out[:60]}")
        out = airc("accept", u1, "--as", "alice/bot")
        check("open" in out or "granted" in out, f"python redeems the edge's delegated passport: {out[:90]}")
        l1 = [l for l in (await dq1.link("list", **{"as": "deleg1/x"})).get("links", []) if l.get("origin", {}).get("chain")]
        check(l1 and l1[0]["state"] == "active" and l1[0]["origin"]["chain"][0]["realm"] == "home.test", "the edge records the link with origin.chain naming home.test")
        # Q4a: python, as the delegate, closes its layer at the edge root
        if l1:
            out = airc("passport", "revoke-layer", u1, l1[0]["origin"]["chain"][0]["id"])
            await asyncio.sleep(1)
            st = [l for l in (await dq1.link("list", **{"as": "deleg1/x"})).get("links", []) if l["id"] == l1[0]["id"]]
            check(st and st[0]["state"] == "revoked", f"revoke-layer from home.test closes the edge's link: {out[:70]}")
        # Q2: a python root, an edge delegate's layer, redeemed at the edge
        dq2 = await edge_ws("deleg2"); ek2 = SeedKey()
        out = airc("passport", "new", "--as", "alice/bot", "--delegate", f"airc.test:{pin(ek2.ik)}", "--uses", "3")
        r2url = py_url(out); ref2 = r2url.split("#passport=")[1].split(".")[0] if r2url else ""
        check(len(ref2) == 64, f"python root issues a delegation to airc.test: {out[:70]}")
        lid2 = "Q" + secrets.token_hex(8)
        ly2 = layer(ek2, "airc://home.test/alice/bot", ref2, {"id": lid2, "expires": int(time.time()) + 1800, "bind_to": "//airc.test/deleg2/**"})
        rq2 = await dq2.passport("redeem", **{"as": "deleg2/a"}, passport=r2url + "~" + ly2)
        check(rq2.get("ok") and (rq2.get("link") or {}).get("a") == "airc://home.test/alice/bot", f"the edge redeems python's delegated passport ({rq2.get('reason', '')[:60]})")
        # Q4b: the edge, as the delegate, closes its layer at the python root
        await dq2.passport("key-add", **{"as": "deleg2/", "scope": "deleg2/", "key": ek2.ik})   # the layer's key is this workspace's (S12)
        rl2 = await dq2.passport("revoke-layer", **{"as": "deleg2/", "passport": r2url + "~" + ly2, "layer": lid2})
        check(rl2.get("ok") and rl2.get("reason", "").startswith(f"layer {lid2} revoked; 1 link"), f"revoke-layer from airc.test closes python's link ({rl2.get('reason', '')[:60]})")
        rq2b = await dq2.passport("redeem", **{"as": "deleg2/b"}, passport=r2url + "~" + ly2)
        check(not rq2b.get("ok") and "delegation refused" in rq2b.get("reason", ""), f"python refuses the revoked layer ({rq2b.get('reason', '')[:60]})")
        # Q3: three levels: python root -> airc.test key -> home.test key -> airc.test key (final)
        dq3 = await edge_ws("deleg3"); ek3a, ek3c = SeedKey(), SeedKey()
        py3_path, py3_ik = seed_file("pymiddle")
        out = airc("passport", "new", "--as", "alice/bot", "--delegate", f"airc.test:{pin(ek3a.ik)}", "--rules", '{"depth":3}')
        r3url = py_url(out); ref3 = r3url.split("#passport=")[1].split(".")[0] if r3url else ""
        la3 = layer(ek3a, "airc://home.test/alice/bot", ref3, {"id": "Q" + secrets.token_hex(8), "expires": int(time.time()) + 3000,
                                                                     "delegates": [{"realm": "home.test", "pins": [pin(py3_ik)]}]})
        out = airc("passport", "delegate", r3url + "~" + la3, "--sign-key", py3_path, "--expires", "40m", "--delegate", f"airc.test:{pin(ek3c.ik)}")
        u3 = py_url(out)
        lc3 = layer(ek3c, "airc://home.test/alice/bot", ref3, {"id": "Q" + secrets.token_hex(8), "expires": int(time.time()) + 1200,
                                                                     "bind_to": "//airc.test/deleg3/**"}, u3.split("~")[-1] if u3 else None)
        rq3 = await dq3.passport("redeem", **{"as": "deleg3/a"}, passport=u3 + "~" + lc3)
        ch3 = ((rq3.get("link") or {}).get("origin") or {}).get("chain", [])
        check(rq3.get("ok") and [c.get("realm") for c in ch3] == ["airc.test", "home.test", "airc.test"], f"a three-level chain across both realms redeems ({rq3.get('reason', '')[:60]} {ch3})")
        # Q5: forwarding a knock, the edge answering python's offer with a delegated passport rooted at the edge
        fq = await edge_ws("fwdone"); kf = E2E.Keystore("airc://airc.test/fwdone/desk"); await E2E.ensure_published(kf, fq.keys_publish)
        fk1 = SeedKey()
        out = airc("link", "offer", "//airc.test/fwdone/x", "--as", "alice/bot", "--label", "knock to forward")
        mo = re.search(r"link (L[0-9a-f]{8})", out); loff = mo.group(1) if mo else ""
        gf = await edge_delegation(fq, "fwdone/desk", "airc://airc.test/fwdone/desk", [kf], [{"realm": "airc.test", "pins": [pin(fk1.ik)]}], uses=2)
        orec = next((l for l in (await fq.link("list", **{"as": "fwdone/x"})).get("links", []) if l["id"] == loff), None)
        ohash = P.offer_hash_of(orec) if orec else ""                  # §12.9, §12.10: the forward's last layer names the offer
        def fwd_layer(offer):
            body = {"id": "Q" + secrets.token_hex(8), "expires": int(time.time()) + 1800, "bind_to": "//home.test/alice/bot"}
            if offer:
                body["offer"] = offer
            return layer(fk1, "airc://airc.test/fwdone/desk", gf.get("reference", ""), body)
        abad = await fq.link("accept", **{"as": "fwdone/x", "id": loff, "passport": gf.get("url", "") + "~" + fwd_layer("0" * 64)})
        check(not abad.get("ok") and "passport does not answer this offer" in abad.get("reason", ""),
              f"python refuses a forward whose last layer names another offer hash ({abad.get('reason', '')[:70]})")
        lf = fwd_layer(ohash)
        af = await fq.link("accept", **{"as": "fwdone/x", "id": loff, "passport": gf.get("url", "") + "~" + lf})
        check(af.get("ok") and af.get("delivery") == "delivered" and af.get("forwarded"), f"the edge forwards python's knock; python redeems it ({af.get('reason', '')[:70]})")
        await asyncio.sleep(1)
        st = [l for l in (await fq.link("list", **{"as": "fwdone/desk"})).get("links", []) if l["state"] == "active"]
        check(st and st[0]["b"] == "airc://home.test/alice/bot", "the forwarded link joins fwdone/desk and the bot")
        po = [l for l in (await fq.link("list", **{"as": "fwdone/x"})).get("links", []) if l["id"] == loff]
        check(po and po[0]["state"] == "pending", "the offer stays pending at the edge")
        # Q6: forwarding the other way: python answers an edge endpoint's offer with a delegated passport rooted at python
        fq2 = await edge_ws("fwdtwo"); pyf_path, pyf_ik = seed_file("pyforward")
        o2 = await fq2.link("offer", **{"as": "fwdtwo/x", "peer": BOT, "label": "knock python forwards"})
        lo2 = o2["link"]["id"]
        out = airc("passport", "new", "--as", "alice/bot", "--delegate", f"home.test:{pin(pyf_ik)}", "--uses", "1")
        rf = py_url(out)
        out = airc("passport", "delegate", rf, "--sign-key", pyf_path, "--to", "//airc.test/fwdtwo/x", "--expires", "30m",
                   "--offer", P.offer_hash_of(o2["link"]))
        uf = py_url(out)
        from airc.client import Client
        pc = await Client.connect(SOCK)
        try: ra = await pc.link("accept", **{"as": "alice/bot", "id": lo2, "passport": uf})
        except Exception as ex: ra = {"ok": False, "reason": str(ex)}
        finally:
            try: await pc.close()
            except Exception: pass
        await asyncio.sleep(1)
        ls2 = (await fq2.link("list", **{"as": "fwdtwo/x"})).get("links", [])
        off2 = [l for l in ls2 if l["id"] == lo2]; fwd = [l for l in ls2 if l["state"] == "active" and l["a"] == "airc://home.test/alice/bot"]
        check(off2 and off2[0]["state"] == "pending" and off2[0].get("answered") and fwd and off2[0]["answered"] == fwd[0]["id"],
              f"python forwards the edge's knock; the edge redeems it and marks its offer answered ({ra.get('reason', '')[:60]})")

        print("R. a receptionist (§12.9, §4.6), across realms")
        # R1: python knocks on an edge receptionist with a credential; it answers with a passport to its support namespace
        rq = await edge_ws("recep1")
        rfleet = E2E.Keystore("airc://airc.test/recep1/fleet", f"{T}/recep1"); rfleet.ensure()
        await rq.passport("key-add", **{"as": "recep1/", "scope": "recep1/support/", "key": rfleet.ik})
        async def support_passport(to, offer_id=None, offer_hash=""):
            """for_offer: the edge computes the offer hash from its own record of the offer (§12.9); the fleet key signs it."""
            token, exp = "".join(secrets.choice(B62) for _ in range(32)), int(time.time()) + 3600
            canon = terms("airc://airc.test/recep1/support/", token, exp, 1, to, 86400, "both", offer_hash)
            args = {"as": "recep1/", "scope": "recep1/support/", "token": token, "expires_at": exp, "uses": 1, "link_ttl": 86400,
                    "to": to, "auth": [{"key": rfleet.ik, "sig": rfleet.sign(canon)}]}
            if offer_id:
                args["for_offer"] = offer_id
            try: return await rq.passport("new", **args)
            except Exception as ex: return {"ok": False, "reason": str(ex)}
        out = airc("link", "offer", "//airc.test/recep1/receptionist", "--as", "alice/bot", "--label", "warranty", "--credential", "WARRANTY-0815")
        mr = re.search(r"link (L[0-9a-f]{8})", out); lr1 = mr.group(1) if mr else ""
        n = await wait_inbox(rq, lambda m: m.get("hdr", {}).get("airc-link") == lr1)
        check(n is not None and n["hdr"].get("airc-offer-credential") == "WARRANTY-0815" and "WARRANTY-0815" not in n["body"],
              "python's credential reaches the edge receptionist in airc-offer-credential, not in the text")
        rrec = next((l for l in (await rq.link("list", **{"as": "recep1/receptionist"})).get("links", []) if l["id"] == lr1), None)
        rhash = P.offer_hash_of(rrec) if rrec else ""
        sp_loose = await support_passport("//home.test/alice/**", lr1, rhash)
        a_loose = await rq.link("accept", **{"as": "recep1/receptionist", "id": lr1, "passport": sp_loose.get("url", "")})
        check(not a_loose.get("ok") and "bound" in a_loose.get("reason", ""), f"python refuses an answer not bound to exactly the caller ({a_loose.get('reason', '')[:70]})")
        sp_mis = await support_passport("//home.test/alice/bot", lr1, "0" * 64)
        check(not sp_mis.get("ok") and "does not verify" in sp_mis.get("reason", ""), f"the edge refuses to issue for_offer over another signed hash ({sp_mis.get('reason', '')[:60]})")
        sp_plain = await support_passport("//home.test/alice/bot")
        a_plain = await rq.link("accept", **{"as": "recep1/receptionist", "id": lr1, "passport": sp_plain.get("url", "")})
        check(not a_plain.get("ok") and "passport does not answer this offer" in a_plain.get("reason", ""),
              f"python refuses an edge answer that signs no offer hash ({a_plain.get('reason', '')[:70]})")
        sp = await support_passport("//home.test/alice/bot", lr1, rhash)
        check(sp.get("passport", {}).get("offer") == rhash, "the edge's support passport records the offer hash python computes too")
        a1 = await rq.link("accept", **{"as": "recep1/receptionist", "id": lr1, "passport": sp.get("url", "")})
        check(a1.get("ok") and a1.get("delivery") == "delivered", f"the edge receptionist answers with its support passport; python follows it ({a1.get('reason', '')[:60]})")
        await asyncio.sleep(1)
        lines_ = airc("links", "--all")
        check("airc://airc.test/recep1/support/" in lines_ and "active" in "".join(l for l in lines_.splitlines() if "recep1/support/" in l),
              "python is linked to the edge's support namespace")
        sd = airc("send", "--plain", "--from", "alice/bot", "//airc.test/recep1/support/desk", "my claim")
        m = await wait_inbox(rq, lambda m: m["body"] == "my claim")
        check(m is not None, f"python reaches recep1/support/desk over it ({sd[:40]})")
        # R2: an edge caller knocks on a python receptionist, which answers with a passport to its namespace
        rc2 = await edge_ws("recep2")
        fl_path, fl_ik = seed_file("pyfleet2")
        airc("passport", "keys", "add", "--as", "alice/bot", "--scope", "alice/", "--key-file", fl_path)
        o2 = await rc2.link("offer", **{"as": "recep2/x", "peer": BOT, "label": "knock", "credential": "REG-42"})
        lo2 = o2["link"]["id"]; await asyncio.sleep(1)
        note = next((m for m in lines(f"{T}/bot.jsonl") if m.get("hdr", {}).get("airc-link") == lo2), None)
        check(note is not None and note["hdr"].get("airc-offer-credential") == "REG-42" and "REG-42" not in note.get("body", ""),
              "the edge's credential reaches the python receptionist in airc-offer-credential")
        async def py_accept(url):
            from airc.client import Client
            pc = await Client.connect(SOCK)
            try: return await pc.link("accept", **{"as": "alice/bot", "id": lo2, "passport": url})
            except Exception as ex: return {"ok": False, "reason": str(ex)}
            finally:
                try: await pc.close()
                except Exception: pass
        out = airc("passport", "new", "--as", "alice/bot", "--scope", "alice/", "--sign-key", fl_path, "--no-identity-key", "--to", "//airc.test/recep2/x")
        ra = await py_accept(py_url(out))                      # §12.9: no --for-offer, so no offer hash signed
        st2 = [l for l in (await rc2.link("list", **{"as": "recep2/x"})).get("links", []) if l["id"] == lo2]
        check(not ra.get("ok") and "passport does not answer this offer" in ra.get("reason", "") and st2 and st2[0]["state"] == "pending",
              f"the edge refuses a python answer that signs no offer hash ({ra.get('reason', '')[:70]})")
        out = airc("passport", "new", "--as", "alice/bot", "--scope", "alice/", "--sign-key", fl_path, "--no-identity-key", "--to", "//airc.test/recep2/**",
                   "--for-offer", lo2)
        ra = await py_accept(py_url(out))
        ls2 = (await rc2.link("list", **{"as": "recep2/x"})).get("links", [])
        st2 = [l for l in ls2 if l["id"] == lo2]
        check(not ra.get("ok") and st2 and st2[0]["state"] == "pending" and not st2[0].get("answered"),
              f"the edge refuses an answer bound by a pattern, not exactly to the caller; the offer stays pending ({ra.get('reason', '')[:70]})")
        out = airc("passport", "new", "--as", "alice/bot", "--scope", "alice/", "--sign-key", fl_path, "--no-identity-key", "--to", "//airc.test/recep2/x",
                   "--for-offer", lo2)
        ra = await py_accept(py_url(out))
        await asyncio.sleep(1)
        ls2 = (await rc2.link("list", **{"as": "recep2/x"})).get("links", [])
        st2 = [l for l in ls2 if l["id"] == lo2]; nl2 = [l for l in ls2 if l["state"] == "active" and l["a"] == "airc://home.test/alice/"]
        check(st2 and nl2 and st2[0]["state"] == "pending" and st2[0].get("answered") == nl2[0]["id"], f"python's receptionist answer opens a link to alice/ at the edge, the offer marked answered ({ra.get('reason', '')[:60]})")
        an = await wait_inbox(rc2, lambda m: m.get("hdr", {}).get("airc-passport-scope") == "airc://home.test/alice/")
        check(an is not None and an["hdr"].get("airc-link-action") == "accept", "the edge caller's accept notice names the scope it reached")
        # R3: an answer from another realm without layers is refused by the offerer
        o3 = await rc2.link("offer", **{"as": "recep2/y", "peer": BOT, "label": "knock 3"})
        foreign = sp_loose.get("url", "")                      # an airc.test passport, but the offeree is home.test
        r3 = await control("airc://home.test/alice/bot", "airc://airc.test/recep2/y", {"action": "accept", "link": o3["link"], "passport": foreign})
        check(r3["status"] == "failed" and "not from the offeree's realm" in r3.get("reason", ""), f"an answer to another realm without layers is refused ({r3.get('reason', '')[:70]})")

        print("S. challenges on link offers (§11.6), across realms")
        import hashlib as _h2, hmac as _hm, base64 as _b2, threading as _th
        from http.server import BaseHTTPRequestHandler as _BH, HTTPServer as _HS
        def lz(h):
            n = 0
            for c in h:
                if c == 0: n += 8; continue
                return n + 8 - c.bit_length()
            return n
        def solve(cid, offerer, bits):
            i = 0
            while True:
                x = f"s{i}"
                if lz(_h2.sha256(f"airc-pow\n{cid}\n{offerer}\n{x}".encode()).digest()) >= bits: return x
                i += 1
        def login_code(secret, cid): return _b2.b32encode(_hm.new(secret.encode(), ("airc-login\n" + cid).encode(), _h2.sha256).digest()).decode()[:10]
        from airc.client import Client
        async def py_offer(peer, **extra):
            pc = await Client.connect(SOCK)
            try: return await pc.link("offer", **{"as": "alice/bot", "peer": peer, "label": "knock", **extra})
            except Exception as ex: return {"ok": False, "reason": str(ex)}
            finally:
                try: await pc.close()
                except Exception: pass
        gate = await edge_ws("gatews")
        # S1: python -> edge powgate, the CLI solves the work
        out = airc("link", "offer", "//airc.test/gatews/powgate", "--as", "alice/bot", "--label", "pow")
        n = await wait_inbox(gate, lambda m: m.get("hdr", {}).get("airc-link-action") == "offer" and "powgate" in m.get("to", ""))
        check(n is not None, f"python meets the edge's pow challenge and the offer arrives ({out[:70]})")
        # S2: python -> edge logingate, the code computed here (the site's login page would show it)
        r = await py_offer("//airc.test/gatews/logingate")
        ch = (r.get("challenges") or [{}])[0]
        check(not r.get("ok") and r.get("code") == "challenge" and ch.get("kind") == "login" and ch.get("url", "").startswith("https://login.airc.test/?c="),
              f"the edge challenges python with a login ({r.get('reason', '')[:50]})")
        r2 = await py_offer("//airc.test/gatews/logingate", proof={"challenge": ch.get("id"), "code": login_code("interop-login-secret", ch.get("id", ""))})
        await asyncio.sleep(1)
        act = [l for l in airc("links", "--all").splitlines() if "gatews/logingate" in l and "active" in l]
        check(r2.get("ok") is not False and act, f"with the login code the edge accepts at once; python holds the link active ({str(r2.get('reason', ''))[:50]})")
        # S3: python -> edge oauthgate through the edge's OAuth routes, against a fake provider here that checks PKCE
        seen = {}
        class Prov(_BH):
            def do_POST(self):
                f = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
                ver = f.get("code_verifier", [""])[0]
                okp = _b2.urlsafe_b64encode(_h2.sha256(ver.encode()).digest()).decode().rstrip("=") == seen.get("challenge")
                email = "carol@example.com" if f.get("code", [""])[0] == "goodcode" else "mallory@evil.example"
                claims = _b2.urlsafe_b64encode(json.dumps({"email": email, "email_verified": True}).encode()).decode().rstrip("=")
                body = json.dumps({"access_token": "t", "id_token": f"e30.{claims}.sig"} if okp else {"error": "invalid_grant"}).encode()
                self.send_response(200 if okp else 400); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
            def log_message(self, *a): pass
        prov = _HS(("127.0.0.1", 28601), Prov); _th.Thread(target=prov.serve_forever, daemon=True).start()
        try:
            r = await py_offer("//airc.test/gatews/oauthgate")
            ch = (r.get("challenges") or [{}])[0]
            check(ch.get("kind") == "oauth" and ch.get("provider") == "fake" and "/airc/v0/login/oauth?c=" in ch.get("url", ""), "the edge challenges with oauth")
            cid = ch.get("id", "")
            class NoRedir(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k): return None
            op = urllib.request.build_opener(NoRedir)
            loc = ""
            try: op.open(EDGE + "/airc/v0/login/oauth?c=" + urllib.parse.quote(cid, safe=""), timeout=10)
            except urllib.error.HTTPError as ex: loc = ex.headers.get("Location", "")
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
            seen["challenge"] = q.get("code_challenge", [""])[0]
            check(loc.startswith("https://provider.example/authorize?") and q.get("state", [""])[0] == cid and q.get("code_challenge_method") == ["S256"]
                  and q.get("client_id") == ["airc-interop"], "the login route redirects to the provider with PKCE (S256) and the challenge id as state")
            bad = urllib.request.urlopen(urllib.request.Request(EDGE + "/airc/v0/login/oauth/callback?code=badcode&state=" + urllib.parse.quote(cid, safe="")), timeout=10) if False else None
            try:
                urllib.request.urlopen(EDGE + "/airc/v0/login/oauth/callback?code=badcode&state=" + urllib.parse.quote(cid, safe=""), timeout=10); refused = False
            except urllib.error.HTTPError as ex: refused = ex.code == 403
            check(refused, "an account outside challenge_oauth_allow gets no code")
            page = urllib.request.urlopen(EDGE + "/airc/v0/login/oauth/callback?code=goodcode&state=" + urllib.parse.quote(cid, safe=""), timeout=10).read().decode()
            mcode = re.search(r"letter-spacing:\.1em'>([A-Z2-7]{10})<", page)
            check(mcode is not None, "the callback exchanges the code (PKCE checked by the provider), reads the email and shows the code")
            r3 = await py_offer("//airc.test/gatews/oauthgate", proof={"challenge": cid, "code": mcode.group(1) if mcode else ""})
            n = await wait_inbox(gate, lambda m: m.get("hdr", {}).get("airc-link-action") == "offer" and "oauthgate" in m.get("to", ""))
            check(n is not None, f"with the OAuth code the offer is admitted ({str(r3.get('reason', ''))[:50]})")
        finally:
            prov.shutdown()
        # S4, S5: edge -> python, pow then login
        ch4 = await edge_ws("chalout")
        o = await ch4.link("offer", **{"as": "chalout/x", "peer": "//home.test/alice/powgate", "label": "pow"})
        c4 = (o.get("challenges") or [{}])[0]
        check(not o.get("ok") and o.get("code") == "challenge" and c4.get("kind") == "pow" and c4.get("bits") == 10, f"python challenges the edge with pow:10 ({o.get('reason', '')[:50]})")
        o2 = await ch4.link("offer", **{"as": "chalout/x", "peer": "//home.test/alice/powgate", "proof": {"challenge": c4.get("id"), "x": solve(c4.get("id", ""), "airc://airc.test/chalout/x", 10)}})
        check(o2.get("ok") and (o2.get("link") or {}).get("state") == "pending" and o2.get("delivery") == "delivered", f"with the proof of work python admits the edge's offer ({o2.get('reason', '')[:50]})")
        o = await ch4.link("offer", **{"as": "chalout/y", "peer": "//home.test/alice/logingate", "label": "login"})
        c5 = (o.get("challenges") or [{}])[0]
        check(c5.get("kind") == "login" and c5.get("url", "").startswith("https://login.home.test/?c="), "python challenges the edge with a login")
        o3 = await ch4.link("offer", **{"as": "chalout/y", "peer": "//home.test/alice/logingate", "proof": {"challenge": c5.get("id"), "code": login_code("py-login-secret", c5.get("id", ""))}})
        await asyncio.sleep(1.5)
        act = [l for l in (await ch4.link("list", **{"as": "chalout/y"})).get("links", []) if l["state"] == "active"]
        check(o3.get("ok") and act, f"with the login code python accepts at once and the edge holds the link active ({o3.get('reason', '')[:50]})")

        print("T. rejection by key (§12.7) and the realm pin (§12.3), across realms")
        RPIN_BAD = "passport: the realm pin does not match the issuer's key"
        # T1: an edge endpoint refuses python's key: its link closes on both sides, new grants are refused, unreject lifts it
        out = airc("passport", "new", "--as", "alice/bot", "--uses", "3", "--label", "reject me")
        pu = py_url(out); ppin = no_rpin(pu).split("#passport=")[1].split(".")[1] if pu else ""
        check(rpin_of(pu) == pin(pk.public_b64), f"python's passport carries .r= the pin of home.test's signing key ({pu[-30:]})")
        rk = await edge_ws("rejk1")
        forged = pu.replace(".r=" + (rpin_of(pu) or "-"), ".r=" + pin(SeedKey().ik))
        rf = await rk.passport("redeem", **{"as": "rejk1/y"}, passport=forged)
        check(not rf.get("ok") and rf.get("reason") == RPIN_BAD, f"the edge refuses python's passport under another realm pin ({rf.get('reason', '')[:60]})")
        r1 = await rk.passport("redeem", **{"as": "rejk1/y"}, passport=pu)
        lk1 = r1.get("link") or {}
        check(r1.get("ok") and lk1.get("origin", {}).get("pins") == [ppin], f"the edge redeems it under the right realm pin; origin.pins recorded ({r1.get('reason', '')[:50]})")
        s1 = await rk.send(BOT, "before the rejection", frm="rejk1/y"); check(s1["status"] == "delivered", f"edge -> python over it ({s1.get('reason', '')[:40]})")
        rj = await rk.link("revoke", **{"as": "rejk1/y", "key": ppin})
        check(rj.get("ok") and (rj.get("link") or {}).get("b") == "*" and (rj.get("link") or {}).get("origin", {}).get("reject_key") == ppin
              and lk1.get("id") in (rj.get("closed") or []), f"the edge endpoint rejects python's key and closes the link ({rj.get('closed')})")
        await asyncio.sleep(1)
        check("revoked" in "".join(l for l in airc("links", "--all").splitlines() if lk1.get("id", "-") in l), "python's copy of the link is revoked (a revoke control)")
        s2 = await rk.send(BOT, "after the rejection", frm="rejk1/y"); check(s2["status"] == "failed", f"edge -> python refused after it ({s2.get('reason', '')[:50]})")
        r2 = await rk.passport("redeem", **{"as": "rejk1/y"}, passport=pu)
        live = [l for l in (await rk.link("list", **{"as": "rejk1/y"})).get("links", []) if l["state"] == "active"]
        check(f"passport refused: key {ppin} is rejected by airc://airc.test/rejk1/y" in r2.get("reason", "") and not live,
              f"a new grant from python carrying the key is refused at the edge, as redeemer (python reports it: {r2.get('reason', '')[-70:]})")
        ur = await rk.link("unreject", **{"as": "rejk1/y", "key": ppin})
        r3 = await rk.passport("redeem", **{"as": "rejk1/y"}, passport=pu)
        check(ur.get("ok") and r3.get("ok"), f"after unreject python's grant is accepted again ({r3.get('reason', '')[:50]})")
        # T2: python refuses an edge key: the edge's copy is revoked, python refuses new grants, and the edge refuses at issue
        rk2 = await edge_ws("rejk2")
        kq = E2E.Keystore("airc://airc.test/rejk2/q", f"{T}/rejk2"); kq.ensure()
        await E2E.ensure_published(kq, rk2.keys_publish)
        ep = await edge_passport(rk2, "rejk2/q", "airc://airc.test/rejk2/q", [kq], uses=3, label="python rejects me")
        eu = ep.get("url", ""); epin = pin(kq.ik)
        check(rpin_of(eu) == pin(EDGE_PUB), f"the edge's passport carries .r= the pin of airc.test's signing key ({eu[-30:]})")
        out = airc("accept", eu.replace(".r=" + (rpin_of(eu) or "-"), ".r=" + pin(SeedKey().ik)), "--as", "alice/bot")
        check("realm pin does not match" in out, f"python refuses the edge's passport under another realm pin ({out[:70]})")
        out = airc("accept", eu, "--as", "alice/bot")
        mt = re.search(r"(L[0-9a-f]{8})", out); lt2 = mt.group(1) if mt else ""
        check(bool(lt2) and "fail" not in out.lower(), f"python redeems it under the right realm pin ({out[:60]})")
        out = airc("link", "revoke", "--key", epin, "--as", "alice/bot")
        check("refuses links authorized by key" in out and lt2 in out, f"python rejects the edge key and closes the link ({out[:90]})")
        await asyncio.sleep(1)
        st = [l for l in (await rk2.link("list", **{"as": "rejk2/q"})).get("links", []) if l["id"] == lt2]
        check(st and st[0]["state"] == "revoked", "the edge's copy is revoked (a revoke control)")
        out = airc("accept", eu, "--as", "alice/bot")
        check(f"passport refused: key {epin} is rejected by airc://home.test/alice/bot" in out, f"python refuses a new grant carrying the key ({out[:90]})")
        out = airc("link", "unreject", "--key", epin, "--as", "alice/bot")
        check("no longer refuses" in out, f"python lifts the rejection ({out[:60]})")
        # T3: at the issuer: the edge scope endpoint rejects one of its passport's keys, so python's redemption is refused there
        kx = SeedKey()
        await rk2.passport("key-add", **{"as": "rejk2/", "scope": "rejk2/q", "key": kx.ik})
        ep3 = await edge_passport(rk2, "rejk2/q", "airc://airc.test/rejk2/q", [kq, kx], uses=1, label="co-signed")
        rj3 = await rk2.link("revoke", **{"as": "rejk2/q", "key": pin(kx.ik)})
        out = airc("accept", ep3.get("url", ""), "--as", "alice/bot")
        check(ep3.get("ok") and rj3.get("ok") and f"passport refused: key {pin(kx.ik)} is rejected by airc://airc.test/rejk2/q" in out,
              f"the edge refuses at issue a passport whose key its scope endpoint rejects ({out[:90]})")
    finally:
        for p in (lst, py, vic):
            if p: p.terminate()
    print("PASS" if not fails else f"FAIL: {fails}")
# Schema check (draft 0.12 step 1): every frame and HTTPS body the in-process clients exchanged with the edge is
# validated against schemas/airc-frames.schema.json, when jsonschema is installed. tests/test_schema.py has the hooks.
try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_schema as SCHEMA
    REC = SCHEMA.Recorder().start() if SCHEMA.jsonschema else None
except Exception as e:  # noqa: BLE001
    print(f"schema check off: {e!r}"); REC = None
asyncio.run(main())
if REC:
    REC.stop()
    rep = SCHEMA.validate_records(REC.records)
    print(f"schema: {rep.total} frame/def checks against schemas/airc-frames.schema.json ({len(REC.records)} items recorded)")
    for line in rep.lines("  "):
        print(line)
    check(rep.total > 0 and not rep.failures and not rep.unknown, f"every frame exchanged with the edge validates ({len(rep.failures)} distinct violations)")
    print("PASS" if not fails else f"FAIL: {fails}")
else:
    print("schema: skipped (jsonschema not installed)")
sys.exit(1 if fails else 0)
