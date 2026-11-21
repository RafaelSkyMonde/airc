# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""The operator's status page, GET /admin (HTML) and /admin.json.

What the realm server knows about who may talk to whom: the active links and
when each last carried a message (and between which endpoints), pending
offers, recent revocations, the open reply windows, and the policy rules in
evaluation order. Metadata only, never message bodies. Served to internal
networks only (httpbind.admin_allowed; config admin.networks)."""
from __future__ import annotations

import html as _h
import time

from . import __version__
from . import address as A
from .profile import FAVICON_HREF

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'"

_CSS = """
:root{--fg:#1b1b1f;--bg:#fff;--mute:#6b6f76;--line:#e3e5e8;--link:#0b57d0;--ok:#1b7f3b;--warn:#b26a00;--bad:#b3261e;--chip:#f1f3f5}
@media(prefers-color-scheme:dark){:root{--fg:#e6e6ea;--bg:#121316;--mute:#9a9ea6;--line:#2a2d33;--link:#7cb0ff;--ok:#6fcf8a;--warn:#f0b35a;--bad:#f28b82;--chip:#1e2126}}
body{margin:0;font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--fg);background:var(--bg)}
main{max-width:1180px;margin:0 auto;padding:20px 24px 48px}
h1{font-size:20px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}
.sub{color:var(--mute);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}
th{color:var(--mute);font-weight:600;white-space:nowrap}
code{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--chip);padding:1px 4px;border-radius:4px}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}.mute{color:var(--mute)}
.nowrap{white-space:nowrap}
.label{min-width:22em}
form{display:inline;margin:0}
button{font:12px system-ui,sans-serif;color:var(--bad);background:transparent;border:1px solid var(--line);border-radius:4px;padding:2px 7px;cursor:pointer}
button:hover{border-color:var(--bad)}
.notice{margin:12px 0;padding:8px 12px;border-radius:6px;background:var(--chip)}
"""


def _dir(u: dict, which: str, realm) -> dict | None:
    """The last message one way over a link: {last, from, to, count}. Usage recorded before directions were
    kept (aircd 0.12.2 and older) has only the overall last message, placed here by the realm it came from."""
    d = u.get(which)
    if isinstance(d, dict):
        return d
    if "sent" in u or "received" in u or not u.get("from"):
        return None
    try:
        from_here = A.parse(u["from"]).realm == realm
    except (A.AddressError, KeyError):
        return None
    return {"last": u.get("last"), "from": u.get("from"), "to": u.get("to")} if from_here == (which == "sent") else None


def _ago(ts, now) -> str:
    if not ts:
        return "never"
    d = max(0, int(now - float(ts)))
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h {d % 3600 // 60}m ago"
    return f"{d // 86400}d {d % 86400 // 3600}h ago"


def _in(ts, now) -> str:
    if not ts:
        return "never"
    d = int(float(ts) - now)
    if d < 0:
        return "expired"
    if d < 3600:
        return f"in {d // 60}m"
    if d < 86400:
        return f"in {d // 3600}h"
    return f"in {d // 86400}d"


def _iso(ts) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(float(ts))) if ts else ""


def view(srv, now: float | None = None) -> dict:
    """Everything the page shows, as JSON-ready data."""
    now = time.time() if now is None else now
    links = srv.links
    pol = srv.policy
    recs = sorted(links.links.values(), key=lambda l: float(l.get("created") or 0), reverse=True)

    def row(l):
        u = links.usage.get(l["id"]) or {}
        return {
            "id": l["id"], "a": l.get("a"), "b": l.get("b"), "direction": l.get("direction"), "state": l.get("state"),
            "label": l.get("label") or "", "created": l.get("created"), "expires": l.get("expires"),
            "offered_by": l.get("offered_by"), "pins": list(((l.get("origin") or {}).get("pins") or [])),
            "last_used": u.get("last"), "last_from": u.get("from"), "last_to": u.get("to"), "uses": int(u.get("count") or 0),
            "sent": _dir(u, "sent", srv.realm), "received": _dir(u, "received", srv.realm),
        }

    active = [row(l) for l in recs if l.get("state") == "active" and links._live(l, now)]
    active.sort(key=lambda r: float(r["last_used"] or 0), reverse=True)
    pending = [row(l) for l in recs if l.get("state") == "pending" and links._live(l, now)]
    week = now - 7 * 86400
    closed = [row(l) for l in recs if l.get("state") in ("revoked", "declined") or (l.get("state") == "active" and not links._live(l, now))]
    closed = [r for r in closed if float(r["created"] or 0) >= week or float(r["last_used"] or 0) >= week][:50]
    conv = [{"from": a, "to": b, "last": t} for (a, b), t in getattr(pol, "_conv", {}).items() if now - t <= 86400]
    conv.sort(key=lambda c: c["last"], reverse=True)
    rules = []
    for i, r in enumerate(pol.rules):
        if r.get("links"):
            rules.append({"index": i, "links": True, "note": r.get("note") or ""})
        else:
            rules.append({"index": i, "from": r.get("from", "*"), "to": r.get("to", "*"), "allow": bool(r.get("allow", True)),
                          "mode": r.get("mode", "any"), "window": r.get("window") if r.get("mode") == "reply" else None,
                          "note": r.get("note") or ""})
    passports = []
    for r in sorted(getattr(getattr(srv, "passports", None), "recs", {}).values(), key=lambda r: float(r.get("created") or 0), reverse=True):
        exp = r.get("expires")
        state = r.get("state") or "active"
        if state == "active" and exp and float(exp) <= now:
            state = "expired"
        used = [{"redeemer": u.get("redeemer"), "at": u.get("at"), "link": u.get("link")} for u in (r.get("used") or [])]
        if state != "active" and not any(float(u["at"] or 0) >= week for u in used) and float(r.get("created") or 0) < week:
            continue                                    # old and closed: not interesting any more
        passports.append({"id": r["id"], "scope": r.get("scope"), "label": r.get("label") or "", "state": state,
                          "direction": r.get("direction"), "bind_to": r.get("bind_to"), "created": r.get("created"),
                          "expires": exp, "uses": int(r.get("uses") or 0), "used": used,
                          "answers_offer": bool(r.get("offer")), "delegation": bool(r.get("delegates")),
                          "issued_by": r.get("issued_by"), "revoked_by": r.get("revoked_by")})
    passports = passports[:200]
    return {
        "t": "admin", "realm": srv.realm, "server": f"aircd/{__version__}", "now": now,
        "links": {"active": active, "pending": pending, "closed_recently": closed, "total": len(recs)},
        "passports": {"outstanding": [p for p in passports if p["state"] == "active"],
                      "settled_recently": [p for p in passports if p["state"] != "active"]},
        "conversations": conv[:200],
        "policy": {"default_allow": bool(pol.default_allow), "has_links_marker": any(r.get("links") for r in pol.rules), "rules": rules},
        "stats": dict(getattr(srv, "stats", {}) or {}),
    }


def html_page(v: dict, token: str = "", notice=("", "")) -> str:
    e = _h.escape
    now = v["now"]
    realm = v["realm"]

    def local(addr) -> bool:
        a = str(addr or "")
        return a.startswith(f"airc://{realm}/") or a == f"airc://{realm}/"

    def button(action, ident, text):
        if not token:
            return ""
        return (f"<form method=post action='/admin/action'><input type=hidden name=token value='{e(token)}'>"
                f"<input type=hidden name=action value='{action}'><input type=hidden name=id value='{e(ident)}'>"
                f"<button type=submit>{text}</button></form>")

    def arrow(d):
        return {"both": "↔", "a-initiates": "→", "b-initiates": "←"}.get(d or "", "↔")

    def short(addr):
        a = str(addr or "")
        return a[len("airc:"):] if a.startswith("airc://") else a

    out = [f"<!doctype html><html lang=en><head><meta charset=utf-8><title>{e(v['realm'])} · AIRC status</title>",
           "<meta name=robots content='noindex,nofollow'><meta name=viewport content='width=device-width,initial-scale=1'>",
           f'<link rel=icon type=image/svg+xml href="{FAVICON_HREF}">',      # double quotes: the SVG data uses single ones
           f"<style>{_CSS}</style></head><body><main>",
           f"<h1>{e(v['realm'])} <span class=mute>· links and policy</span></h1>",
           f"<div class=sub>{e(v['server'])} · {_iso(now)} · internal page, metadata only · <a href='/admin.json'>json</a></div>"]

    ok_msg, err_msg = (notice or ("", ""))
    if ok_msg:
        out.append(f"<div class=notice><span class=ok>done:</span> {e(ok_msg)}</div>")
    if err_msg:
        out.append(f"<div class=notice><span class=bad>not done:</span> {e(err_msg)}</div>")

    L = v["links"]
    out.append(f"<h2>Active links <span class=mute>({len(L['active'])})</span></h2>")
    if L["active"]:
        out.append("<table><tr><th>link</th><th>between</th><th class=label>label</th><th>last sent</th><th>last received</th><th>uses</th><th>created</th><th>expires</th><th></th></tr>")
        for r in L["active"]:
            def when(d):                                    # the time, with the exact from -> to on hover
                if not d:
                    return "<td class=nowrap><span class=mute>never</span></td>"
                tip = f"{_iso(d.get('last'))}: {short(d.get('from'))} → {short(d.get('to'))}"
                return f"<td class=nowrap title='{e(tip)}'><span class=ok>{e(_ago(d.get('last'), now))}</span></td>"
            exp = r["expires"]
            expc = "bad" if exp and float(exp) - now < 86400 else ("warn" if exp and float(exp) - now < 7 * 86400 else "")
            out.append(f"<tr><td class=nowrap><code>{e(r['id'])}</code></td>"
                       f"<td><code>{e(short(r['a']))}</code> {arrow(r['direction'])} <code>{e(short(r['b']))}</code></td>"
                       f"<td class=label>{e(r['label'])}</td>{when(r['sent'])}{when(r['received'])}"
                       f"<td>{r['uses']}</td><td class=nowrap title='{e(_iso(r['created']))}'>{e(_ago(r['created'], now))}</td>"
                       f"<td class='nowrap {expc}' title='{e(_iso(exp))}'>{e(_in(exp, now)) if exp else 'never'}</td>"
                       f"<td>{button('revoke-link', r['id'], 'revoke')}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class=mute>none</p>")

    if L["pending"]:
        out.append(f"<h2>Pending offers <span class=mute>({len(L['pending'])})</span></h2><table><tr><th>link</th><th>between</th><th>offered by</th><th>label</th><th>since</th><th>expires</th><th></th></tr>")
        for r in L["pending"]:
            act = button("withdraw-offer", r["id"], "withdraw") if local(r["offered_by"]) else button("decline-offer", r["id"], "decline")
            out.append(f"<tr><td class=nowrap><code>{e(r['id'])}</code></td><td><code>{e(short(r['a']))}</code> {arrow(r['direction'])} <code>{e(short(r['b']))}</code></td>"
                       f"<td><code>{e(short(r['offered_by']))}</code></td><td>{e(r['label'])}</td><td class=nowrap>{e(_ago(r['created'], now))}</td><td class=nowrap>{e(_in(r['expires'], now)) if r['expires'] else 'never'}</td><td>{act}</td></tr>")
        out.append("</table>")

    if L["closed_recently"]:
        out.append(f"<h2>Closed in the last 7 days <span class=mute>({len(L['closed_recently'])})</span></h2><table><tr><th>link</th><th>between</th><th>state</th><th>label</th><th>last used</th><th>uses</th></tr>")
        for r in L["closed_recently"]:
            st = r["state"] if r["state"] != "active" else "expired"
            out.append(f"<tr><td class=nowrap><code>{e(r['id'])}</code></td><td><code>{e(short(r['a']))}</code> {arrow(r['direction'])} <code>{e(short(r['b']))}</code></td>"
                       f"<td class=mute>{e(st)}</td><td>{e(r['label'])}</td><td class=nowrap>{e(_ago(r['last_used'], now))}</td><td>{r['uses']}</td></tr>")
        out.append("</table>")

    PP = v.get("passports") or {"outstanding": [], "settled_recently": []}

    def pp_rows(rows, settled):
        for r in rows:
            kind = " <span class=mute>(answers a link offer)</span>" if r["answers_offer"] else (" <span class=mute>(delegation)</span>" if r["delegation"] else "")
            if r["used"]:
                red = "<br>".join(f"<code>{e(short(u['redeemer']))}</code> {e(_ago(u['at'], now))}" + (f" → <code>{e(u['link'])}</code>" if u.get("link") else "") for u in r["used"])
            else:
                red = "<span class=mute>not yet</span>"
            left = r["uses"] - len(r["used"])
            to = f"<br><span class=mute>for</span> <code>{e(r['bind_to'])}</code>" if r.get("bind_to") else ""
            st = f"<span class=mute>{e(r['state'])}</span>" if settled else f"{left} of {r['uses']} left"
            tail = f"<td class=nowrap>{e(_ago(r['created'], now))}</td><td class=nowrap>{e(_in(r['expires'], now))}</td>"
            tail += "" if settled else f"<td>{button('revoke-passport', r['id'], 'revoke')}</td>"
            out.append(f"<tr><td class=nowrap><code>{e(r['id'])}</code></td><td><code>{e(short(r['scope']))}</code>{kind}{to}</td>"
                       f"<td>{e(r['label'])}</td><td class=nowrap>{st}</td><td>{red}</td>{tail}</tr>")

    out.append(f"<h2>Outstanding passports <span class=mute>({len(PP['outstanding'])})</span></h2>")
    if PP["outstanding"]:
        out.append("<table><tr><th>passport</th><th>scope</th><th>label</th><th>uses</th><th>redeemed by</th><th>issued</th><th>expires</th><th></th></tr>")
        pp_rows(PP["outstanding"], False)
        out.append("</table>")
    else:
        out.append("<p class=mute>none</p>")
    if PP["settled_recently"]:
        out.append(f"<h2>Passports settled in the last 7 days <span class=mute>({len(PP['settled_recently'])})</span></h2>"
                   "<table><tr><th>passport</th><th>scope</th><th>label</th><th>state</th><th>redeemed by</th><th>issued</th><th>expired</th></tr>")
        pp_rows(PP["settled_recently"], True)
        out.append("</table>")

    C = v["conversations"]
    out.append(f"<h2>Open reply windows <span class=mute>({len(C)}, last 24 h)</span></h2>")
    if C:
        out.append("<table><tr><th>from</th><th>to</th><th>last message</th></tr>")
        for c in C:
            out.append(f"<tr><td><code>{e(short(c['from']))}</code></td><td><code>{e(short(c['to']))}</code></td><td class=nowrap title='{e(_iso(c['last']))}'>{e(_ago(c['last'], now))}</td></tr>")
        out.append("</table><p class=sub>A pair listed here lets the recipient answer the sender for 24 hours under a <code>mode: reply</code> rule or a one-way link.</p>")
    else:
        out.append("<p class=mute>none</p>")

    P = v["policy"]
    dflt = "<span class=bad>allow</span>" if P["default_allow"] else "<span class=ok>deny</span>"
    out.append(f"<h2>Policy rules <span class=mute>(first match wins; no match: {dflt})</span></h2>")
    if P["rules"]:
        out.append("<table><tr><th>#</th><th>from</th><th>to</th><th>decision</th><th>note</th></tr>")
        for r in P["rules"]:
            if r.get("links"):
                out.append(f"<tr><td>{r['index']}</td><td colspan=3><em>links and passports are evaluated here</em></td><td class=mute>{e(r['note'])}</td></tr>")
                continue
            dec = "<span class=ok>allow</span>" if r["allow"] else "<span class=bad>deny</span>"
            if r["mode"] == "reply":
                dec += f" <span class=mute>(reply within {int(r['window'] or 86400)} s)</span>"
            out.append(f"<tr><td>{r['index']}</td><td><code>{e(r['from'])}</code></td><td><code>{e(r['to'])}</code></td><td class=nowrap>{dec}</td><td class=mute>{e(r['note'])}</td></tr>")
        out.append("</table>")
    else:
        out.append("<p class=mute>no rules</p>")
    if not P["has_links_marker"]:
        out.append("<p class=sub>No <code>{\"links\": true}</code> marker: links and passports are evaluated before the first rule.</p>")
    out.append("</main></body></html>")
    return "".join(out)



html = html_page
