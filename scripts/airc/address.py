# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Agent addresses, per "AIRC Addressing Scheme — Specification" draft 0.1.

    airc-uri      = "airc:" network-form
    network-form  = "//" authority "/" path [ "#" fragment ]
    local-form    = path [ "#" fragment ]
    authority     = host [ ":" port ]          ; host = DNS name or IP literal
    path          = segment *( "/" segment ) [ "/" ]   ; trailing "/" = namespace
    segment       = 1*63( ALPHA / DIGIT / "-" / "_" )  ; no leading/trailing "-"

Forms and who resolves them:
    airc://realm/alice/net-ops   URI form: the only form allowed on the wire
    //realm/alice/net-ops        network form: what humans type; == URI form
    alice/net-ops                local form: the namespace of local user alice
    net-ops                      local form: the invoking user's own namespace

Rules implemented here:
  - realm (the authority host) is case-insensitive, canonical lower case; a
    default port is dropped; IP literals are kept verbatim.
  - segments are case-insensitive, canonical lower case; '.' is not allowed,
    so the authority is the only dotted component.
  - a trailing '/' marks a NAMESPACE (fan-out target), not an endpoint; the
    two are never equivalent.
  - the fragment is parsed and carried, but excluded from equality, routing
    and matching (`key`).
  - segments starting with '_' are reserved (_resolver, _postmaster, _dir).
  - the whole address is at most 1024 octets.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from . import DEFAULT_PEER_PORT

_SEG = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)\Z")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*\Z")
_SCHEME = "airc:"
MAX_OCTETS = 1024
RESERVED_PREFIX = "_"
WELL_KNOWN = ("_resolver", "_postmaster", "_dir")


class AddressError(ValueError):
    pass


@dataclass(frozen=True)
class Address:
    realm: str                     # lower-case DNS name or IP literal (no brackets)
    path: tuple[str, ...]          # >= 1 lower-case segment
    port: int | None = None        # explicit non-default port, else None
    namespace_ref: bool = False    # True if written with a trailing '/'
    fragment: str | None = field(default=None, compare=False)

    # --- rendering ----------------------------------------------------------
    @property
    def authority(self) -> str:
        host = f"[{self.realm}]" if ":" in self.realm else self.realm
        return host if self.port is None else f"{host}:{self.port}"

    @property
    def local_path(self) -> str:
        return "/".join(self.path) + ("/" if self.namespace_ref else "")

    def network(self, with_fragment: bool = True) -> str:
        s = "//" + self.authority + "/" + self.local_path
        if with_fragment and self.fragment:
            s += "#" + self.fragment
        return s

    def uri(self, with_fragment: bool = True) -> str:
        return _SCHEME + self.network(with_fragment)

    def __str__(self) -> str:       # wire form
        return self.uri()

    @property
    def key(self) -> str:
        """Comparison / routing key: URI form without the fragment."""
        return self.uri(with_fragment=False)

    # --- structure ----------------------------------------------------------
    @property
    def namespace(self) -> str:
        """The segments before the endpoint ('' for a root-level endpoint)."""
        return "/".join(self.path[:-1])

    @property
    def name(self) -> str:
        return self.path[-1]

    @property
    def is_reserved(self) -> bool:
        return any(s.startswith(RESERVED_PREFIX) for s in self.path)

    def in_realm(self, realm: str) -> bool:
        return self.realm == realm.lower().rstrip(".")

    def under(self, prefix: "Address") -> bool:
        """True if self is prefix itself or lies beneath it (delegation)."""
        return (self.realm == prefix.realm and self.port == prefix.port
                and self.path[:len(prefix.path)] == prefix.path)

    def without_fragment(self) -> "Address":
        return Address(self.realm, self.path, self.port, self.namespace_ref, None)

    def relative_to(self, realm: str, namespace: str = "", aliases: dict | None = None) -> str:
        """Shortest form a sender in (realm, namespace) can type to reach self.

        Local forms are only meaningful on the same authority; anything else
        is written in network form, which is what humans type and read.
        """
        if not self.in_realm(realm) or self.port is not None:
            return alias_display(self, aliases) or self.network()
        ns = tuple(s for s in namespace.lower().split("/") if s)
        tail = ("#" + self.fragment) if self.fragment else ""
        if ns and self.path[:len(ns)] == ns and len(self.path) > len(ns):
            return "/".join(self.path[len(ns):]) + ("/" if self.namespace_ref else "") + tail
        return self.local_path + tail


def _segments(text: str) -> tuple[tuple[str, ...], bool]:
    ns_ref = text.endswith("/")
    raw = text[:-1] if ns_ref else text
    if raw == "":
        raise AddressError("empty path")
    segs = raw.split("/")
    for s in segs:
        if s == "":
            raise AddressError("empty path segment")
        if not _SEG.match(s):
            raise AddressError(f"bad path segment {s!r}")
    return tuple(s.lower() for s in segs), ns_ref


def _authority(text: str) -> tuple[str, int | None]:
    port = None
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        if rest and not rest.startswith(":"):
            raise AddressError(f"bad authority {text!r}")
        if rest[1:]:
            port = _port(rest[1:])
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            raise AddressError(f"bad IPv6 literal {host!r}")
        return host.lower(), port
    host, sep, p = text.rpartition(":")
    if sep:
        port = _port(p)
    else:
        host = text
    host = host.lower().rstrip(".")
    try:
        ipaddress.IPv4Address(host)
        return host, port
    except ValueError:
        pass
    if not host or not _HOST.match(host):
        raise AddressError(f"bad realm {host!r}")
    return host, port


def _port(p: str) -> int | None:
    if not (p.isascii() and p.isdigit()) or not 0 < int(p) < 65536:
        raise AddressError(f"bad port {p!r}")
    n = int(p)
    return None if n == DEFAULT_PEER_PORT else n


def parse(text: str, realm: str | None = None, namespace: str = "", aliases: dict | None = None) -> Address:
    """Parse any of the three forms into an absolute Address.

    `realm` and `namespace` are the local resolver's own authority and the
    invoking user's namespace, used for local forms. A local form with no
    realm raises AddressError: the spec forbids sending one on the wire.
    """
    if not isinstance(text, str):
        raise AddressError("address must be a string")
    t = alias_expand(text, aliases).strip()
    if len(t.encode()) > MAX_OCTETS:
        raise AddressError("address exceeds 1024 octets")
    if any(c.isspace() for c in t):
        raise AddressError("whitespace in address")
    t, _, fragment = t.partition("#")
    fragment = fragment or None
    if t.lower().startswith(_SCHEME):
        t = t[len(_SCHEME):]
        if not t.startswith("//"):
            raise AddressError("airc: must be followed by //authority/path")
    if t.startswith("//"):
        auth, sep, path = t[2:].partition("/")
        if not sep:
            raise AddressError("network form needs a path after the authority")
        host, port = _authority(auth)
        segs, ns_ref = _segments(path)
        return Address(host, segs, port, ns_ref, fragment)
    if t.startswith("/"):
        raise AddressError("a single leading '/' is not an address; use //authority/path or a local form")
    if realm is None:
        raise AddressError(f"local form {text!r} needs the local authority to resolve")
    segs, ns_ref = _segments(t)
    ns = tuple(s for s in namespace.lower().split("/") if s)
    if len(segs) == 1 and ns and not ns_ref:
        segs = ns + segs
    host, port = _authority(realm)
    return Address(host, segs, port, ns_ref, fragment)


# ---------------------------------------------------------------- local aliases
# A site-local convenience, not part of the protocol: a fleet names a prefix in another realm (a realm or a namespace,
# "//airc.harness.travelreactor.com/singularity/") with a short alias ("tr-singularity"), so its agents read and are
# typed as "tr-singularity/skymonde". Aliases are applied only where an address enters or leaves the local server
# (what a user types, what a relay shows); every frame on the wire, every signature, link, policy rule and audit
# line keeps the full address.

def alias_prefix(prefix: str) -> "Address":
    """Parse an alias target: a network-form realm or namespace, ending in '/'."""
    p = prefix.strip()
    if not p.endswith("/"):
        raise AddressError("an alias names a realm or namespace: end it with '/'")
    if p.lower().startswith(_SCHEME):
        p = p[len(_SCHEME):]
    if p.startswith("//") and p[2:].count("/") == 1 and p.endswith("/"):      # a whole realm: //realm/
        host, port = _authority(p[2:-1])
        return Address(host, (), port, True, None)
    a = parse(p)
    if a.fragment:
        raise AddressError("an alias target has no fragment")
    return a


def alias_expand(text: str, aliases: dict | None) -> str:
    """'alias/rest' -> '//realm/ns/rest' when the first segment of a local form is an alias; else text unchanged."""
    if not aliases or not isinstance(text, str):
        return text
    t = text.strip()
    if t.startswith("/") or t.lower().startswith(_SCHEME) or "/" not in t:
        return text                                     # network forms, and bare names (always this fleet's)
    first, _, rest = t.partition("/")
    target = aliases.get(first.lower())
    if not target:
        return text
    return target.rstrip("/") + "/" + rest


def alias_display(addr: "Address", aliases: dict | None) -> str | None:
    """The alias form of addr ('tr-singularity/skymonde'), by the longest matching prefix, or None."""
    if not aliases:
        return None
    best, best_len = None, -1
    for name, target in aliases.items():
        try:
            pre = alias_prefix(target)
        except AddressError:
            continue
        if addr.under(pre) and len(addr.path) > len(pre.path) and len(pre.path) > best_len:
            rest = "/".join(addr.path[len(pre.path):]) + ("/" if addr.namespace_ref else "")
            best, best_len = f"{name}/{rest}" + (("#" + addr.fragment) if addr.fragment else ""), len(pre.path)
    return best


def is_qualified(text: str) -> bool:
    """True if `co tell` should hand the target to airc: any '/' means a
    namespace other than the sender's own, or a network/URI form."""
    return "/" in text.strip()


def pattern_covers(pattern: str, ns: Address) -> bool:
    """True when every endpoint beneath the namespace (or realm) `ns` matches `pattern` (§12.6: a passport
    bound to a pattern may be redeemed by a namespace only if the pattern covers all of it):
    `//r/a/**` and `//r/a/` cover `a/` and `a/b/`; `//r/**` and `*` cover everything; a pattern of fixed
    depth covers no namespace."""
    p = pattern.strip()
    if p == "*":
        return True
    if p.lower().startswith(_SCHEME):
        p = p[len(_SCHEME):]
    if not p.startswith("//"):
        raise AddressError(f"pattern must be absolute: {pattern!r}")
    host, _, path = p[2:].partition("/")
    host = host.lower()
    if host != "*" and host != ns.authority:
        return False
    n = ns.path
    segs = [s.lower() for s in path.strip("/").split("/") if s]
    if path.endswith("/") and "**" not in segs and "*" not in segs:
        return bool(segs) and len(segs) <= len(n) and n[:len(segs)] == tuple(segs)
    if "**" not in segs:
        return False
    i = segs.index("**")
    if i > len(n):
        return False
    return all(ps == "*" or ps == n[k] for k, ps in enumerate(segs[:i]))


def pattern_match(pattern: str, addr: Address) -> bool:
    """Glob match for policy rules and binds. NOT address syntax: patterns are
    transport-level and never travel in a message.

      *                      everything
      //realm/a/*            one segment under a
      //realm/a/**           one or more segments under a
      //realm/a/             (namespace form) a and everything beneath it
      //*/a/b                any realm
    """
    p = pattern.strip()
    if p == "*":
        return True
    if p.lower().startswith(_SCHEME):
        p = p[len(_SCHEME):]
    if not p.startswith("//"):
        raise AddressError(f"pattern must be absolute: {pattern!r}")
    host, _, path = p[2:].partition("/")
    host = host.lower()
    if host != "*" and host != addr.authority:
        return False
    ns_ref = path.endswith("/")
    segs = [s.lower() for s in path.strip("/").split("/") if s]
    if not segs:
        return False
    if ns_ref:  # the namespace is what lies beneath the prefix, not the prefix itself
        return len(addr.path) > len(segs) and addr.path[:len(segs)] == tuple(segs)
    for i, ps in enumerate(segs):
        if ps == "**":
            return i < len(addr.path)
        if i >= len(addr.path):
            return False
        if ps != "*" and ps != addr.path[i]:
            return False
    return len(segs) == len(addr.path)
