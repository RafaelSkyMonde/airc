# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Authorization: may `from` send to `to`?

A policy is an ordered list of rules; the first rule whose from/to patterns
both match decides. No match -> the policy's default (v0: allow).

  {"from": "//example.com/**",  "to": "//example.com/**", "allow": true}
  {"from": "*",  "to": "//product.com/support-agent", "allow": true}    # open channel
  {"from": "//partner.com/**", "to": "//example.com/alice/**", "allow": true, "mode": "reply"}
  {"from": "*",  "to": "*", "allow": false}

Patterns are absolute-address globs (see address.pattern_match).

mode (optional, default "any"):
  any       the rule applies to every message
  reply     the rule only applies when `to` has messaged `from` within
            `window` seconds (default 86400). This is how you let an outside
            party ANSWER your agents without letting it INITIATE contact:
            your agent opens the conversation, the reply window opens, the
            outsider can respond, and when the window closes so does the door.

Directional authorization therefore falls out of one mechanism: an
"initiate" permission is an ordinary allow; a "reply-only" permission is an
allow with mode=reply. The conversation table that backs it is kept by the
deciding server and is per (a,b) pair, refreshed on every allowed message.

Both the sending server (egress) and the receiving server (ingress) evaluate
their own policy; a message must pass both. The sending server's check is a
courtesy that fails fast; the receiving server's check is the one that
protects it.
"""
from __future__ import annotations

import time

from . import address as A


class Policy:
    """Rules plus links. Links (see links.py) are grants endpoints made for
    themselves; they are evaluated where a rule `{"links": true}` sits in the
    list, or before the first rule when there is no such marker. Put your
    deny rules ahead of the marker if they must override links."""

    def __init__(self, rules: list[dict] | None = None, default_allow: bool = True, links=None):
        self.rules = list(rules or [])
        self.default_allow = default_allow
        self.links = links
        # (from, to) -> last time `from` messaged `to` (allowed).
        self._conv: dict[tuple[str, str], float] = {}

    def note_delivery(self, frm: A.Address, to: A.Address) -> None:
        self._conv[(frm.key, to.key)] = time.time()
        if len(self._conv) > 50000:  # crude bound
            cutoff = time.time() - 7 * 86400
            self._conv = {k: v for k, v in self._conv.items() if v > cutoff}

    def _in_reply_window(self, frm: A.Address, to: A.Address, window: float) -> bool:
        t = self._conv.get((to.key, frm.key))
        return t is not None and time.time() - t <= window

    def _links_decision(self, frm, to):
        if self.links is None:
            return None, ""
        return self.links.decision(frm, to, lambda f, t: self._in_reply_window(f, t, 86400))

    def check(self, frm: A.Address, to: A.Address) -> tuple[bool, str]:
        has_marker = any(r.get("links") for r in self.rules)
        if not has_marker:
            d, why = self._links_decision(frm, to)
            if d:
                return d == "allow", why
        for i, r in enumerate(self.rules):
            if r.get("links"):
                d, why = self._links_decision(frm, to)
                if d:
                    return d == "allow", why
                continue
            try:
                if not A.pattern_match(r.get("from", "*"), frm):
                    continue
                if not A.pattern_match(r.get("to", "*"), to):
                    continue
            except A.AddressError:
                continue
            mode = r.get("mode", "any")
            if mode == "reply" and not self._in_reply_window(frm, to, float(r.get("window", 86400))):
                continue
            allowed = bool(r.get("allow", True))
            return allowed, f"rule#{i}" + (f" ({r['note']})" if r.get("note") else "")
        return self.default_allow, "default"
