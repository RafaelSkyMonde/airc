# AIRC Protocol Specification

Copyright © 2026 Rafael Baptista. All rights reserved. The AIRC specification, documentation, test vectors and reference implementation are published for evaluation and discussion. Licensed under the AIRC Public Preview License 1.0 (<https://airc.dev/license>), a free license for implementation and use that ends on May 1, 2027. Patent pending.

**Draft 0.13 — 2026-11-21.** Wire protocol version `airc/0.1`.

AIRC is a routed text-message protocol for software agents. This document is complete: an implementer who has only this text can
build a conforming client, fleet relay, or federated server, and interoperate
with the reference implementation. The companion *AIRC Addressing Scheme*
draft gives the rationale behind the naming rules restated in §2; nothing
normative lives only there.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are as in RFC 2119.
Where this document gives an algorithm, an implementation MUST produce the
same externally visible behaviour; the internal structure is free.

### Document map

| § | what you need it for |
|---|---|
| 1 | the model and the words |
| 2 | addresses: grammar, canonical form, patterns, reserved names |
| 3 | connections and framing: the stream binding, the HTTPS binding, hosted workspaces and their keys |
| 4 | every frame, field by field; binds, sessions and leases (§4.3.1) |
| 5 | who a client may speak as |
| 6 | routing a message |
| 7 | the spool: queueing, TTL, dedupe |
| 8 | finding and linking to another realm |
| 9 | signing: keys, records, canonical strings |
| 10 | policy rules |
| 11 | links |
| 12 | passports |
| 13 | the audit stream |
| 14 | codes and reasons |
| 15 | constants |
| 16 | security requirements |
| 17 | conformance profiles and checklist |
| 18 | test vectors |
| 19 | end-to-end encryption (optional) |
| 20 | the workspace front door |
| 21 | profiles, status, address pages, closing a channel |
| 22 | binary sections and files |
| 23 | tool tunnels: MCP carried over AIRC |
| A | complete exchanges |
| B | implementation status (not normative) |

---

## 1. Model and terminology

```
                 realm example.com                          realm partner.example
   ┌──────────────────────────────────────┐        ┌──────────────────────────────┐
   │  client        client       client   │        │   client        client       │
   │ (fleet alice)  (fleet bob)  (a bot)  │        │ (support desk)  (billing)    │
   │     │             │           │      │        │       │            │         │
   │     └──────┬──────┴─────┬─────┘      │        │       └─────┬──────┘         │
   │        client face (unix socket)     │        │        client face           │
   │            ┌───────────┐             │  TLS   │        ┌───────────┐         │
   │            │  server   │─────────────┼────────┼────────│  server   │         │
   │            └───────────┘  peer link  │        │        └───────────┘         │
   └──────────────────────────────────────┘        └──────────────────────────────┘
```

- **Realm.** A DNS name (or IP literal) that owns an address space and runs
  one logical AIRC server. Also called the *authority* of an address.
- **Server.** Routes for exactly one realm. Has a **client face** for its own
  endpoints and a **peer face** for other realms' servers.
- **Endpoint.** Anything addressable under a realm: an agent, a bot, a queue.
  Named by a **path** of one or more segments.
- **Namespace.** The segments of a path before its last one; also the set of
  endpoints beneath a prefix. On a multi-user host the first segment is
  typically the user (`alice/net-ops`).
- **Client.** A process connected to its realm's client face. It may **bind**
  names to receive for them, send messages, and manage links, passports and
  subscriptions for endpoints it may act for.
- **Fleet relay.** A client that binds a whole namespace and delivers each
  inbound message to the right local agent by whatever means that site uses.
  The relay is the boundary between this protocol and a site's agent runtime.
- **Peer link.** A connection between two servers. Either may open it; once
  open it carries traffic both ways.
- **Message.** A text body with an id, an origin, a destination and a
  timestamp. Relayed origin client → origin server → destination server →
  destination client; an **ack** flows back the same way.
- **Link.** A standing grant between two endpoints (§11).
- **Passport.** A bearer invitation that creates a link when redeemed (§12).

**No transit.** A server accepts from a peer only messages *originating in
that peer's realm* and *addressed to its own realm*. A message crosses at most
one server-to-server hop. Trust decisions are therefore always about the
server that claims to have originated a message.

---

## 2. Addresses

### 2.1 Grammar

```
airc-uri      = "airc:" network-form
network-form  = "//" authority "/" path [ "#" fragment ]
local-form    = path [ "#" fragment ]

authority     = host [ ":" port ]
host          = dns-name / IPv4address / "[" IPv6address "]"
dns-name      = label *( "." label )            ; labels per RFC 1123
port          = 1*5DIGIT                         ; 1..65535

path          = segment *( "/" segment ) [ "/" ]  ; trailing "/" = namespace reference
segment       = 1*63( ALPHA / DIGIT / "-" / "_" ) ; MUST NOT begin or end with "-"
fragment      = *pchar                           ; RFC 3986
```

- The whole address MUST NOT exceed 1024 octets.
- `.` is not permitted in a segment; the authority is the only dotted
  component.
- No percent-encoding. A name that cannot be written in `segment` is not a
  valid AIRC name.
- `airc:` MUST be followed by `//`. `airc:foo` is invalid.
- A single leading `/` is invalid.

### 2.2 Canonical form and equivalence

The canonical form is the URI form with:

- authority lower-cased; a trailing `.` removed; the default port (2472)
  omitted; an IPv6 literal in brackets, lower-cased;
- every segment lower-cased;
- the trailing `/` preserved if present (it is significant);
- the fragment preserved if present.

Two addresses are **equivalent** when their canonical forms without the
fragment are byte-identical. `//h/a` and `//h/a/` are not equivalent. The
canonical form without fragment is the address's **key**, used for every
comparison in this document (binds, links, policy, dedupe).

### 2.3 Forms and resolution context

| written | means | resolved by |
|---|---|---|
| `airc://R/p` | exactly that | anyone |
| `//R/p` | `airc://R/p` | anyone |
| `ns/name` (any `/`, no leading `//`) | `airc://<local realm>/ns/name` | the local server |
| `name` (no `/`) | `airc://<local realm>/<sender's namespace>/name` | the local server |

The local server resolves local forms against its own realm and the
sender's first namespace (§5) when a client sends them. **Only the URI form
appears in `from` and `to` on the wire**; a local form in a peer-face frame is
invalid.

### 2.4 Endpoint, namespace, fragment

- A path without a trailing `/` names an endpoint: the thing at its last
  segment.
- A path with a trailing `/` names a namespace: the set of endpoints beneath
  it. It is a valid destination syntactically; delivery to it is fan-out,
  which a server MAY refuse (§6.4).
- An empty path with its trailing `/` (`//example.com/`, URI form
  `airc://example.com/`) names the realm's whole namespace. It appears as a
  link side and as the scope of a passport (§11.1, §12.1), and therefore as
  `from` or `to` of link control (§11.4); it is not a destination for other
  messages.
- The fragment identifies an incarnation of an endpoint. Servers MUST ignore
  it for comparison and routing and MUST pass it through unchanged in
  `from` and `to`.

### 2.5 Delegation

The endpoint at path P is the resolver for every path beneath P/. A server
forwards a message addressed beneath a bound endpoint to that endpoint with
the remaining segments intact (§6.4, §4.3) and never interprets them.

### 2.6 Reserved names

A segment beginning with `_` is reserved. Defined:

| name | at | meaning |
|---|---|---|
| `_resolver` | `//R/_resolver` | the server itself; answers a health check (§6.4) |
| `_passport` | `//R/_passport` | where redemptions are sent (§12.6) |
| `_postmaster` | `//R/_postmaster` | human contact for the realm; a server that does not provide it answers `no_such_path` |
| `_dir` | `//R/_dir`, `//R/ns/_dir` | directory agent, if a realm offers listing |
| `_links` | `//R/_links` | the sender of the server's own notices about links and passports (§11.4, §12.6); not an endpoint, messages to it are `failed no_such_path` |

Clients MUST NOT be allowed to bind a reserved name unless the operator
configures it.

### 2.7 Patterns (not addresses)

Binds (§4.3) and policy rules (Appendix B) use **patterns**. A pattern is a
network-form address in which:

- the authority may be `*` (any authority);
- a segment may be `*` (exactly one segment);
- the last segment may be `**` (one or more segments);
- a trailing `/` matches everything strictly beneath the prefix;
- the whole pattern may be `*` (matches every address).

Matching is against the address's key. A pattern never travels inside a
message; `*` is not a valid address character.

Pattern matching algorithm, given pattern `P` and address `A`:

```
if P == "*": match
strip an "airc:" prefix; require "//"
host, path = split at first "/" after "//"
if host != "*" and host != A.authority: no match
segs = path segments (ignoring empty); ns_form = path ends with "/"
if segs is empty: no match
if ns_form: match iff len(A.path) > len(segs) and A.path[:len(segs)] == segs
for i, s in enumerate(segs):
    if s == "**": match iff i < len(A.path)
    if i >= len(A.path): no match
    if s != "*" and s != A.path[i]: no match
match iff len(segs) == len(A.path)
```

---

## 3. Connections and framing

### 3.1 Streams

An AIRC connection is an ordered, reliable byte stream: a Unix domain socket,
TCP, TLS over TCP, or a WebSocket carrying text frames. A server exposes two
**faces**, each on its own listener:

| face | who connects | typical transport |
|---|---|---|
| client | the realm's own endpoints and relays | Unix socket (identity from peer credentials, §5); loopback TCP |
| peer | other realms' servers | TCP with TLS (§8.3) |

A server MUST refuse a `hello` whose `role` does not match the face.

### 3.2 Frames

A connection carries **frames**. A frame is one JSON object (RFC 8259),
UTF-8, terminated by `\n`. Newlines inside strings are JSON-escaped, so a
frame never contains a raw newline. Every frame has a string field `t`
naming its type.

- A frame MUST NOT exceed 1 048 576 bytes including the newline.
- A `msg` frame may be followed by a **binary section** (§22): exactly `bin`
  raw bytes after its newline. The 1 MiB limit applies to the JSON line; the
  section is at most 8 MiB. A reader that sees `bin` reads that many bytes
  before the next frame.
- Blank lines MUST be ignored.
- Unknown fields MUST be ignored.
- An unknown `t` on an established connection is a protocol error: send
  `error` (§4.8) and close.
- Writers MUST serialize concurrent writes to one connection so frames do not
  interleave. Readers MUST NOT assume one frame per read.

### 3.3 Connection lifecycle (stream binding)

1. The connecting side sends `hello` (§4.1) first. The accepting side answers
   `welcome` or `error` and closes.
2. Either side may send `ping`; the other MUST answer `pong`.
3. Either side may close at any time. A client that was bound SHOULD
   reconnect with backoff and re-bind; the server spools for it meanwhile
   (§7). On this binding the connection is the client's session (§4.3.1):
   its binds end when it closes.

### 3.4 The HTTPS binding

The same frames, one per HTTP request or response, over HTTPS. This binding
exists so that a realm can run where no long-lived socket is possible (edge
compute, serverless) and so that every realm can be reached by every other.
**A federated server MUST implement the HTTPS peer face**; it MAY also
implement the stream peer face. A client face may be either or both.

Requests and responses carry `Content-Type: application/json`; the body is
one frame (or a list where stated). HTTP status is 200 for any frame the
server produced, including a `failed` ack; 400 for a malformed request or a
bad `AIRC-Session`; 401 for a request whose authentication failed; 403 for an
authenticated request that is not allowed (a session owned by another key, a
name outside the key's namespaces, `recovery_required`, `code_refused`,
`closed`); 404 for an unknown path or resource; 409 for a conflict
(`name_held`, `taken`, `key_in_use`, `key_taken`, `channel_taken`,
`last_key`); 413 for a body larger than its type allows; 415 `bin_unsupported`
(§22); 429 when rate-limited; 501 for `GET /airc/v0/ws` on a server that holds
no WebSockets (§3.4.6); 503 when the server cannot take the request now. A
non-200 response's body is an `error` frame (§4.8) with a code (§14.2); the
body of a 409 `name_held` or `channel_taken` carries its code in `error`.

Body limits: an `application/json` body is one frame, at most 1 MiB. An
`application/airc-frame` body (§22) is a JSON line of at most 1 MiB including
its `\n`, and a binary section of at most 8 MiB, so at most 9 MiB plus 1 byte. A
larger body gets 413 with code `frame_too_large`. A server MAY apply the framed
limit to every body before reading it and refuse an oversized JSON line
afterwards; a JSON body over 1 MiB but within the framed limit MAY instead be
failed as a message rather than refused with 413.

Every request SHOULD carry a `User-Agent` naming the software and its version
(the reference sends `aircd/<version>` from servers and `airc/<version>` from
clients). Some CDNs refuse requests that look like anonymous scripts: Cloudflare's
browser-integrity check answers Python's default `Python-urllib/3.x` with
`403 error code: 1010`, which looks to the dialler like a dead realm. An operator
who puts a realm behind a CDN MUST exempt `/.well-known/airc` and `/airc/v0/` from
browser and bot checks: every caller of those paths is software.

#### 3.4.1 Peer face

| method and path | body | response |
|---|---|---|
| `POST /airc/v0/msg` | one `msg` frame in wire form (URI addresses, `via`, `hdr.sig`) | one `ack` frame |
| `GET /.well-known/airc?nonce=<n>` | — | the capabilities document (below) |

There is no `hello`: each message is authenticated by its signature (§9.3),
so a peer request needs nothing else. The role the `welcome` signature plays
in the stream binding, proving that the server DNS led you to holds the
realm's key, is played by the **capabilities document**:

```json
{"t":"capabilities","realm":"airc.dev","proto":"airc/0.1","bindings":["https"],
 "kids":["65b60673"],"did":"did:web:airc.dev","nonce":"<echoed>","ts":1790380000,
 "sig":"ed25519:65b60673:…"}
```

`did` is optional: the realm's decentralized identifier (§24), when it serves
a DID document.

`sig` is over these lines joined by `\n` (UTF-8, no trailing newline):

```
airc-capabilities
<realm>
<nonce>
<ts>
```

A dialler
MUST fetch it with a fresh nonce before its first message to a realm over
this binding, verify it against the realm's published keys, and MAY cache
the result for one hour. Discovery: `_airc-https._tcp.<realm>` SRV (target
host and port, default 443), else `https://airc.<realm>/`, else
`https://<realm>/`. A realm publishing both bindings lists both SRV
records; a dialler that implements both MAY prefer either.

**The receiving side.** A `POST /airc/v0/msg` carries no separate claim of who
is calling: the sending realm is the authority of the message's `from`. The
receiver verifies `hdr.sig` against that realm's published keys (§8.2, §9.3) and
applies its policy to `from`. It does not fetch the sender's capabilities
document, and it does not care which IP address or host made the request.

**What the signature covers.** The capabilities signature covers only the four
lines above: it proves that whoever answered holds the realm's key, now. The
other fields (`kids`, `bindings`, `features`, `server`) are protected only by
TLS. They are hints, and a wrong one fails safe: a falsely absent `bin` means
files are not sent, a falsely present one gets a 415. Neither can forge or
alter a message, because every message is signed on its own (§9.3).

#### 3.4.2 Client face

Clients authenticate every request with a key registered with the realm
(§5, remote clients; a hosted realm registers keys with §3.4.4):

```
Authorization: AIRC-Key <kid>:<ts>:<nonce>:<sig>
```

`sig` is ed25519 over these lines joined by `\n` (UTF-8, no trailing newline):

```
airc-client
<realm>
<METHOD>
<path>
<ts>
<nonce>
<body hash>
```

- `<realm>` is the realm's name as its capabilities document states it
  (`realm`), which need not be the host you connect to: `https://www.airc.dev`
  serves the realm `airc.dev`. Fetch `/.well-known/airc` first and sign for
  its `realm`.
- `<METHOD>` is upper case. `<path>` is the request path **without** the query
  string: `/airc/v0/inbox`, not `/airc/v0/inbox?max=50`.
- `<body hash>` is the lower-case hex SHA-256 of the exact body bytes sent;
  for a request without a body (every `GET`) it is the hash of the empty
  string, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- `ts` is integer Unix seconds and must be within 300 s of the server's clock.
  `nonce` is at least 12 random bytes as lower-case hex (the reference uses 12
  bytes, 24 characters) and must be unique per key for 300 s; the server keeps
  it and refuses a repeat.
- `kid` is the first 8 hex characters of SHA-256 over the raw 32-byte public
  key (§9.1). `sig` is the bare base64 of the 64-byte signature: unlike the
  signature strings in `hdr.sig` (§9.3), it has no `ed25519:<kid>:` prefix,
  because the header already names the key.

Example (the key of §18.2, realm `airc.dev`):

```
GET /airc/v0/inbox?max=50 HTTP/1.1
Host: www.airc.dev
Authorization: AIRC-Key 65b60673:1790380000:9f86d081884c7d659a2feaa0:<base64 of the 64-byte signature>

signed string:
airc-client\nairc.dev\nGET\n/airc/v0/inbox\n1790380000\n9f86d081884c7d659a2feaa0\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The server maps `kid` to the client's namespaces. A request that fails any of
these checks gets HTTP 401 with a reason naming the check.

Every request from a receiving client also carries `AIRC-Session: <id>`, which
names the process (§4.3.1). `bind` replaces that session's binds only, and
`inbox` and the WebSocket carry only the messages that session's binds win. A
request without the header belongs to a legacy session the server derives:
one per key (the reference, `key:<kid>`) or one per workspace (airc.dev).
Either way, clients written before sessions keep working as long as only one
of them listens.
Any signed request renews the session's lease (§4.3.1), and so does an open
WebSocket (§3.4.6) for as long as it stays open.

| method and path | body | response |
|---|---|---|
| `POST /airc/v0/send` | one `msg` frame; local-form addresses allowed | one `ack` |
| `POST /airc/v0/bind` | `{"names":[…],"mode":"push"\|"webhook"\|"pull","webhook":"https://…","take_over":false}`; `"names":[]` releases (§4.3.1) | `bound` plus `{"mode":…}`, or 409 `name_held`; `bound` names are absolute patterns in network form (`//R/…`) or URI form |
| `GET /airc/v0/inbox?max=50[&wait=N]` | — | `{"t":"inbox","msgs":[msg…]}` (`max` at most 200): queued messages that this session's live binds win (§4.3), oldest first, not removed until acked; each is the `msg` frame exactly as received, so its signature still verifies. `wait` asks for a long-poll where `features` lists `longpoll`, and the frame then states the hold that applied, `"wait":<s>` (§3.4.7); 429 `rate_limited` with `Retry-After` when a key pulls empty too often (§3.4.7) |
| `POST /airc/v0/ack` | a list of `ack` frames | `{"t":"acked","n":…}` |
| `GET /airc/v0/ws` | — | the WebSocket (§3.4.6): pushes, the backlog, send, ack and ping over one connection; offered when `features` lists `ws` |
| `POST /airc/v0/link` | one `link` frame | `linked` |
| `POST /airc/v0/passport` | one `passport` frame | `passported` |
| `GET /airc/v0/events?since=<ts>&kinds=msg,link` | — | `{"t":"events","events":[…]}` |

An inbox response:

```json
{"t":"inbox","msgs":[{"t":"msg","id":"cf0a7537-cecc-45aa-a7a8-0362cfdca73c","from":"airc://example.com/alice/bot",
 "to":"airc://airc.dev/alice/agent","ts":1790380000,"body":"hello","type":"text/plain","ttl":86400,
 "via":["example.com"],"hdr":{"sig":"ed25519:5e1c0a9b:…"}}]}
```

**Delivery modes.** `bind` records how the server reaches this client:

- `push`: the server writes each message to the client's queue and pushes it
  over the client's open WebSocket (§3.4.6). The client acks over the socket
  (or with `POST /ack`). A server that holds the socket itself
  MAY wait for that ack (§6.6) and answer the sender `delivered`; a server
  that cannot (edge compute pushing through a fan-out service) answers
  `queued` with code `pushed` at once, and the audit stream records the
  later `delivered`.
- `webhook`: the server `POST`s each `msg` to the client's URL (signed as a
  peer message would be, with the realm key) and relays the ack it gets.
- `pull`: the client pulls `/inbox`, with a long-poll where the realm offers
  one (§3.4.7); the sender gets `queued endpoint_offline`.

The mode belongs to the session that bound. A message whose winning bind
belongs to no live session is queued and its sender gets `queued
endpoint_offline`.

In every mode the queue is the truth: a client that connects, or polls,
drains its backlog with `/inbox` and acks. Messages are removed from the
queue only by a `delivered` or `queued` ack; a `failed` ack MAY leave it
queued (airc.dev) or remove it (the reference). `/inbox` may return the same
message twice. A server
that does not offer a mode refuses the `bind` for it; which modes a hosted
realm offers is stated on its own documentation.

#### 3.4.3 Server to server, mixed bindings

A server that receives a message over one binding and forwards it over the
other changes nothing in the frame. `via`, signatures and acks are binding-
independent.

---

#### 3.4.4 Workspace registration (hosted realms)

A hosted realm gives a stranger an address with one unauthenticated request:

| method and path | body | response |
|---|---|---|
| `POST /airc/v0/workspaces` | `{"name":"<ns>","pub":"<base64 of the raw 32-byte ed25519 public key>"}` | `{"t":"workspace","realm":…,"ns":…,"kid":…,"uri":"airc://<realm>/<ns>/"}` |

- `name` becomes the namespace: one address segment (§2.1), lower-cased,
  letters, digits, `-` and `_`, not starting with `_`.
- On success the key acts for the namespace `<ns>/`: every endpoint beneath
  it (`<ns>/agent`, `<ns>/laptop/build`) may bind, send and manage links and
  passports. New workspaces start in `pull` mode; `bind` changes that.
- A key names one workspace: registering with a public key that already
  belongs to a live workspace is refused (409 `key_in_use`), since public keys
  are public and re-pointing one would take its owner's requests.
- Errors: 400 `bad_name` or `bad_key`, 403 `closed` (the realm takes no new
  workspaces), 409 `taken`; a server MAY answer 429 when rate-limited. A realm
  that offers no registration answers 404.
- Realm policy MAY add to this. A realm MAY refuse short names (airc.dev
  refuses names of 4 characters or fewer, not counting `-` and `_`, with 400
  `bad_name`). A realm MAY treat names beginning `tmp-` as temporary: they
  expire after 1 idle day and the response says `"temporary": true`. A realm
  MAY record acceptance of its terms at registration; airc.dev's response
  carries `terms`, `privacy`, `terms_accepted` and `terms_note`.

A server that is not a hosted realm need not offer this route; its operator
registers client keys by configuration.

**Expiry.** A hosted realm MAY expire a workspace that has not been used for
a set time; any signed client request counts as use, incoming messages do
not. The registration response states the period
(`"expires_after_idle_days"`, and `"expires_after_idle_s"` in seconds). When it expires, its keys, published
end-to-end key records and pending codes go with it, and the name can be
registered again. Grants that the earlier registration held MUST NOT pass to
the next one at that realm: links and passports older than the current
registration of a name are ignored. Copies of links that other realms hold
last until they expire or are revoked; those realms can detect a changed
owner only through end-to-end key pins (§19.4).

What registration means to others: a hosted realm's signature on an outbound
message (§9.3) vouches that one of its workspaces sent it, and nothing about
who registered that workspace. A realm SHOULD refuse names that impersonate
infrastructure or the operator (`admin`, `abuse`, `postmaster`, its own
brands; `409 taken` or `400 bad_name`), and receivers SHOULD treat workspace
names as labels, not identities (§10.1).

Registration MAY also carry `"label"` (a note for the key, such as the
machine it lives on) and `"recovery": true`, which adds a recovery code to the
response (§3.4.5). It is shown once.

#### 3.4.5 Workspace membership (hosted realms)

A workspace can hold several keys. Nobody ever hands a private key to someone
else. A second agent, machine or colleague generates its own key and joins
with a **join code** that a current member created; a member who has lost
every key uses the **recovery code**.

**Two kinds of key.** A **full key** acts for the whole namespace, and full
keys are equal: each may do everything below. A **channel key** acts only as
one channel, `<ns>/<channel>`, and what lies beneath it: it may send from it,
bind it, publish its profile, E2E keys and status, offer links and passports
as it, fetch and ack only messages addressed to it, and close it (§21.4). It
may not act as any other endpoint, bind the whole namespace, read the
workspace's events, or use any `POST /airc/v0/workspace` op; `GET` shows it
only `{"realm","ns","channel"}`. The registering key and keys joined with a
plain join code are full keys; channel keys come from two kinds of code:

- a **channel code** (`"channel":"<name>"`): one use; the key that joins gets
  that channel;
- an **enrollment code** (`"enroll":true`): for an environment that starts
  sessions (a CI system, a cloud sandbox). No use limit and, unless
  `expires` is given, no expiry. Each session joins with its own key and
  names its channel in the join (`"channel":"<name>"`), and gets a key for that
  channel only. Revoking the code revokes every key it made.

A channel is claimed by one key: a join naming a channel that another channel
key holds, or that has a profile or E2E keys published (in use by a full
key), is refused (409 `channel_taken`, with a free `suggest`ion). A channel
key that makes no signed request for about 7 days lapses (a server may
refresh its record coarsely, so between 6 and 7 days): the key stops working,
and its channel is closed (§21.4). A human's channels, on full keys, never
lapse.

| method and path | auth | body | response |
|---|---|---|---|
| `GET /airc/v0/workspace` | client | — | `{"t":"workspace","realm","ns","keys":[{"kid","label","added","added_by"}],"joins":[{"id","label","uses","used","expires"}],"recovery":<bool>}` |
| `POST /airc/v0/workspace` | client | `{"op":"join-code","label"?,"uses"?,"expires"?,"channel"?,"enroll"?}` | `{"t":"workspace","ok":true,"id":"J…","code":"airc-join:1;…","kind"?}`; a plain code: defaults 1 use and 1 day, caps 20 uses and 7 days; `channel`: one use, a channel key; `enroll`: no limits, channel keys named at join |
| | | `{"op":"revoke-join","id"}` | `{"ok":true,"keys_revoked":<n>}`; for an enrollment or channel code, every key it made goes too |
| | | `{"op":"revoke-key","kid"}` | `{"ok":true}`; revoking a channel key closes its channel; the last full key cannot be revoked (`409 last_key`) |
| | | `{"op":"recovery-code","recovery"?}` | `{"ok":true,"recovery":"airc-recover:1;…"}`; replaces the earlier recovery code, and so needs it (`recovery`) when there is one (403 `recovery_required`): otherwise any one key could mint a code and then delete the workspace |
| | | `{"op":"delete","confirm":"<workspace>","recovery"?}` | `{"ok":true,"deleted","endpoints","links_revoked","queued_dropped"}`; see below |
| `POST /airc/v0/workspaces/join` | none | `{"code","pub","label"?,"revoke_others"?,"channel"?}` (`channel`: required with an enrollment code) | `{"t":"workspace","realm","ns","kid","uri"}`, plus a new `"recovery"` when a recovery code was used |

Codes:

```
join     = "airc-join:1;"    "i=" realm ";" "w=" workspace ";" "t=" token
recovery = "airc-recover:1;" "i=" realm ";" "w=" workspace ";" "t=" token
```

- `token` is at least 128 bits from a CSPRNG, base62, shown once and stored as
  SHA-256. A join code works `uses` times until `expires`; a recovery code
  works once, and redeeming it returns the next one. With a recovery code,
  `"revoke_others": true` also revokes every other key (a lost or stolen
  device).
- Every key's `added_by` records how it arrived: `registration`, `join <id>`
  naming the join code it used, or `recovery`.
- A realm MUST refuse a code for the wrong workspace, an expired or used-up
  code, and MUST throttle failures (20 failed joins per workspace per hour,
  429 `throttled`). Errors: 400 `bad_code` or `bad_key`, 403 `code_refused`
  with the reason, 409 `key_taken` (the key already belongs to a workspace),
  409 `channel_taken`, 429 `throttled`.
- Revoking a key takes effect at once: its requests get 401. Links,
  passports, queued messages and end-to-end keys (§19) belong to endpoints,
  not to workspace keys, and are unaffected.
- **Deleting a workspace** does at once what expiry does after 90 idle
  days. `confirm` must repeat the workspace's name. When the workspace has a
  recovery code, `recovery` must carry it (`403 recovery_required`
  otherwise, throttled like joins), so one stolen device key cannot destroy a
  workspace; without one, any full key may delete it. The realm revokes
  the active and pending links of every endpoint that published keys or a
  profile and tells the other side (§11.4), then drops those endpoints' key
  records and profiles, the queued messages, the workspace's keys, join
  codes and recovery code, and the workspace record. Links it could not
  find are void at this realm anyway, because they predate any later
  registration of the name (§3.4.4). The name is free again at once.
- Full keys are equal: a plain join code gives the newcomer full control of
  the workspace, including revoking the member who invited them. To give
  less, use a channel code or an enrollment code, whose keys act only as their
  channel. No other roles are defined.

#### 3.4.6 The WebSocket

A realm that lists `ws` in its `features` offers `GET /airc/v0/ws`: one
WebSocket (RFC 6455) that carries everything a receiving client needs. Pushes
and the backlog come down it; sends, acks and pings go up it. A client that
holds it makes no other requests while it is open: no inbox checks, no lease
renewals. It is how `push` mode reaches a client. A client that cannot hold a
WebSocket, or a realm that offers none, uses `pull`: the client checks
`/inbox`, as often as it needs (an agent that wakes now and then checks once
on waking).

**Opening.** The handshake is an ordinary `GET /airc/v0/ws` with
`Upgrade: websocket`, signed like any client request (§3.4.2): `Authorization`
over `GET`, the path `/airc/v0/ws` and the hash of the empty body, plus
`AIRC-Session`. The query string is not signed and carries nothing. The session
must have bound first (`400 bad_request` otherwise). A failed check answers
with the HTTP status and error body it would have had on any route, and no
upgrade. A server that cannot hold sockets either does not list `ws` or
answers `501`; the client then polls `/inbox`. Browsers cannot set
`Authorization` on a WebSocket, so this binding is for agents, not pages.

**Frames.** Every WebSocket message is a text message holding exactly one
JSON frame. Binary messages are not used.

From the server:

| frame | meaning |
|---|---|
| `{"t":"welcome","realm":…,"ns":[…],"proto":…,"push":"ws"}` | first, once |
| `msg` | a message for this session, exactly as queued (its signature verifies); the backlog first, then live pushes. A message may come twice (the backlog and a push): drop repeated ids |
| `{"t":"inbox"}` | more is waiting than the socket carried (the backlog was cut short, or a message was too large to push): fetch `GET /airc/v0/inbox` |
| `{"t":"displaced","names":[…]}` | another session took these names over (§4.3.1); stop listening for them |
| `{"t":"ping"}` | keep-alive; no reply |
| `sent`, `acked`, `pong`, `error` | replies, below |

From the client, each with an optional `rid` (a string of the client's choice)
that the reply repeats, so replies can be matched to requests; replies may come
in any order:

| frame | reply |
|---|---|
| `{"t":"send","rid":…,"msg":{msg}}` | `{"t":"sent","rid":…,"ack":{ack}}`: the same `ack` `POST /send` returns. A message with a binary section (§22) goes by `POST /send`, not the socket |
| one `ack` frame, or `{"t":"acks","rid":…,"list":[ack…]}` | `{"t":"acked","rid":…,"n":…}` |
| `{"t":"ping","rid":…}` | `{"t":"pong","rid":…}` |
| anything else, or a frame that is not JSON | `{"t":"error","rid":…,"code":"bad_request","reason":…}`; the socket stays open |

Large messages: a server whose push path has a size limit (a fan-out service)
sends `inbox` in place of a frame it cannot carry, and the client fetches it.

**Liveness.** The server sends `ping` after at most 30 s without other
traffic. A client that has heard nothing for 75 s takes the socket for dead,
closes it and opens a new one; the backlog comes again on the new socket.
Clients SHOULD NOT send WebSocket ping frames: the server's pings already prove
the path, and a server behind a fan-out service pays for each client ping.
Close with a normal close frame (1000).

**The lease.** While the socket is open the session's lease (§4.3.1) holds,
and the server renews it without any request from the client. A server whose
sockets are held by a fan-out service renews it when the service reports the
socket still open (the reference realm asks every 240 s). When the socket
closes, the lease runs from that moment as after any request; reopening within
it keeps the names. `bind` with `"names":[]` still releases at once.

**Delivery.** A server that holds the socket itself MAY wait for the client's
ack before answering the sender `delivered` (§6.6); one that
pushes through a fan-out service answers `queued` with code `pushed`.

#### 3.4.7 Pulling: long-polls and limits

A client that cannot hold the WebSocket pulls `GET /airc/v0/inbox`. Clients
SHOULD prefer the WebSocket where `features` lists `ws`: it costs the realm
about one request every few minutes while idle.

**Long-polls.** A realm that lists `longpoll` in its `features` accepts
`GET /airc/v0/inbox?wait=N`. When nothing is queued for the session, the
server holds the request until a message arrives for it or the wait ends,
then answers as for any inbox request: with the message, or with no messages.

- The server decides how long it holds. It holds for `N` seconds or for its
  own maximum, whichever is shorter (a server setting; 25 s is the
  suggested default). `wait` with no value asks for the maximum. A client
  asks for less, never more, when something between it and the server cuts
  idle requests sooner (a proxy that times out after 20 s, say).
- The response states the hold that applied: `"wait":<seconds>` in the
  `inbox` frame, the longest the server would hold this request (`N` cut to
  its maximum), or 0 when it did not hold it (messages were waiting, or no
  `wait` was asked).
- With messages already queued, the server answers at once.
- A server that does not list `longpoll` ignores `wait` and answers at once;
  a client that sends `wait` to it simply gets a short pull.
- `wait` is not signed (the signed path leaves out the query, §3.4.2); it
  changes only when the answer comes, never what it holds.
- The message that ends a hold stays queued until acked, like any other, and
  may come again on the next pull. A message that arrives while no request
  is held waits for the next pull.

A client long-polls in a loop: pull with `wait`, handle and ack what came,
pull again at once. While idle that is one request per hold, about 150 an
hour at 25 s, and a message arrives within moments of reaching the realm.

**Limits.** A server MAY limit how often one key pulls without getting
anything. Past its limit it answers `429` with code `rate_limited`, a
`Retry-After` header and `"retry_after":<seconds>` in the error frame, and
the key waits that long before pulling again. A pull that returns messages
SHOULD NOT count toward the limit, so draining a busy queue is never
refused; a long-poll that ends empty counts once. Clients MUST honour
`Retry-After` (an error the client cannot otherwise act on, it is no
reason to retry sooner). The reference realm allows 6 empty pulls a minute
per key, one every 10 s on average, so a client that pulls without
long-polling checks no more often than that.

## 4. Frame catalogue

Fields marked **R** are required. Types: `str`, `int`, `num` (JSON number),
`bool`, `list`, `obj`.

A JSON Schema (draft 2020-12) for every frame in this section, the frames
added by later sections (`keys`, `profile`, the front door's operations), the
HTTPS-only request and response bodies of §3.4 and the capabilities document
is published at <https://airc.dev/docs/schema/airc-frames.schema.json> and
ships in the reference implementation as `schemas/airc-frames.schema.json`.
It is a checker, not a second definition: where the schema and this text
disagree, this text is normative and the schema has a bug. Servers may add
fields a schema version does not know, so validators MUST NOT reject a frame
for an unknown field unless the entry says the frame is exactly as given.

### 4.1 `hello` → `welcome`

`hello`, from the connecting side:

| field | type | R | meaning |
|---|---|---|---|
| `proto` | str | R | `airc/<major>.<minor>`. Refuse a different major with `error bad_proto`. |
| `role` | str | R | `client` or `peer` |
| `agent` | str |  | software name/version, informational |
| `features` | list of str |  | optional features the connecting side takes: `bin` (it can receive binary sections, §22) |
| `realm` | str | peer: R | the connecting server's realm |
| `ts` | int | peer, signed | Unix seconds when the hello was made |
| `nonce` | str | peer | random, ≥ 12 bytes of entropy, hex or base64 |
| `sig` | str | peer, signed | signature over the hello (§9.4) |
| `ns` | list of str |  | client: namespace claim. Servers MUST ignore it unless explicitly configured to trust unauthenticated claims (tests only). |

`welcome`, from the accepting side:

| field | type | R | meaning |
|---|---|---|---|
| `realm` | str | R | the accepting server's realm |
| `proto` | str | R | the protocol version it speaks |
| `server` | str |  | software name/version |
| `ns` | list of str | client face: R | namespaces this connection may act for (§5). Empty means anonymous: it may neither send nor bind. |
| `sig` | str | peer face | signature over the welcome (§9.4), present when the server has a key and the hello carried a nonce |
| `kid` | str | peer face | key id of `sig` |
| `features` | list of str | client face | optional features the server offers: `keys` (§19.3), `profile` (§21), `leases` (§4.3.1), `ws` (§3.4.6), `longpoll` (§3.4.7), `bin` (§22). A client MUST NOT send frames for a feature not listed; unknown frames close the connection. |

A dialling server MUST check `welcome.realm` equals the realm it resolved
and drop the link otherwise.

### 4.2 `msg`

| field | type | R | meaning |
|---|---|---|---|
| `id` | str | R | unique id chosen by the origin, matching `^[A-Za-z0-9._:-]{1,128}$` (a server refuses any other with `bad_request`, or a failed ack `refused` on the peer face). UUIDv4 recommended. Duplicates are suppressed by id (§7.3). On the client face a server MAY assign one when it is absent (airc.dev does). |
| `from` | str | R | origin endpoint. A client MAY write a local form; the server rewrites it to the URI form and verifies it (§5). URI form on the peer face. May carry a fragment. |
| `to` | str | R | destination. Same canonicalization; fragment passed through. |
| `ts` | num | R | origin time, Unix seconds (fractional allowed). Required on the peer face; on the client face a server MAY set it to its own receipt time. |
| `body` | str | R | the text |
| `type` | str |  | media type of `body`, a MIME type with optional parameters and no control characters (`^[A-Za-z0-9!#$&^_.+-]{1,64}/[A-Za-z0-9!#$&^_.+-]{1,64}(;[ ]?[A-Za-z0-9!#$&^_.+-]+=[A-Za-z0-9!#$&^_.+-]+)*$`; refused otherwise like a bad `id`); default `text/plain`. Control traffic uses `application/airc-link+json` (§11.4) and `application/airc-passport+json` (§12.4). |
| `re` | str |  | the full `id` of the message this answers, exactly as received (never shortened); the same grammar as `id`. Opaque to servers otherwise; correlated by readers. |
| `ttl` | int |  | seconds after `ts` the message stays deliverable; default 86400. Expired messages are failed, never delivered. |
| `via` | list of str |  | realms traversed; set by servers (§6.5) |
| `hdr` | obj |  | extension headers, relayed untouched except as noted: `sig` (§9), `airc-link`, `airc-passport` (§11.4, §12.6), `airc-receipt` (§6.7). A hosted realm MAY keep only string-valued headers from its clients. |

### 4.3 `bind` → `bound`

Client face only.

```json
{"t":"bind","names":["alice/","bob/research","carol/*"]}
{"t":"bound","names":["//example.com/alice/","//example.com/bob/research","//example.com/carol/*"]}
{"t":"bind","names":["bob/research"],"take_over":true}
```

- Each name is relative to the realm and MUST lie inside one of the client's
  namespaces (§5). A trailing `/` may name one of the namespaces itself. A
  reserved segment is refused unless configured.
- An endpoint bind (`bob/research`) receives that endpoint **and everything
  beneath it** (delegation, §2.5).
- A namespace bind (`alice/`) receives every endpoint beneath the prefix.
- `*` and `**` are accepted as in §2.7 (the reference accepts them; a hosted
  realm MAY refuse patterns in `bind`, and airc.dev does).
- The server replies with the accepted absolute patterns (network form
  `//R/…` or URI form), or `error bad_bind`
  / `error forbidden` / `error name_held` (§4.3.1) and closes.
- A bind flushes the spool for its namespace (§7.4).

**Resolving client selection.** When a message arrives for a local address
`A`, the server picks among all binds of all connected clients:

```
score(bind B for A):
  if B pattern-matches A (§2.7):
      literal = number of segments of B that are not "*"/"**"
      score = literal*2 + (1 if B has no "*" and no trailing "/" else 0)
  else if B is an exact endpoint (no "*", no trailing "/")
       and A lies strictly beneath B's path in the same authority:
      score = literal*2                       ; delegation
  else: not a candidate
choose the candidate with the highest score; ties: the most recently bound
```

(The reference breaks ties by the most recently connected client.)

Only **live** binds are candidates (§4.3.1). Selection is by pattern, not by
realm layout: a realm may arrange the paths beneath its name however it likes
(`<fleet>/<agent>`, `<workspace>/<agent>`, `<team>/<user>/<agent>`, or a
single segment such as `help`), and the same rule sends each message to the
most specific live bind at whatever depth it sits. What a realm decides is
which client may bind which prefix (§5).

#### 4.3.1 Sessions and leases

A **session** is one receiving process. Each bind belongs to the session that
made it, and a bind is **live** while its session is:

- on the stream binding (§3.3), the session is the connection; its binds are
  live until it closes;
- on the HTTPS binding (§3.4.2), the client names its session with the header
  `AIRC-Session: <id>` on every request, where `<id>` is 16 to 64 characters
  of `[A-Za-z0-9_-]` chosen at random when the process starts (at least 64
  bits of randomness). The session's binds are live while it has made a
  signed request within the **lease** (300 s). A server MAY record renewals
  coarsely (up to 60 s apart), so a lease may end 240 to 300 s after the
  last request. A session in `webhook` mode (§3.4.2) stays live until it
  releases. A session id is not a credential: every request is still
  authenticated by its key, and a server refuses a session id first used by a
  different key (HTTP 403).

**One live session per pattern.** A bind whose pattern is identical (after
canonicalization) to one that another session holds live is refused with
`name_held`: on the stream binding, `error name_held` and close; over HTTPS,
HTTP 409 with `{"error":"name_held","name":<pattern>,"idle":<seconds since the
holder's last request>,"suggest":<a free name>}`. A server SHOULD suggest the
name with `-2`, `-3`, … appended to its last segment, the first one not held.
Different patterns never conflict: a session holding `acme/infra/alice/deploy`
and a relay holding `acme/` coexist, and selection gives each its own
messages.

**Taking over.** A bind with `"take_over": true` displaces the holder: the
pattern moves to the new session at once. A displaced stream-binding client
that is left with no binds gets `error displaced` and is closed; a displaced
HTTPS session is told at once over its WebSocket (`displaced`, §3.4.6) and
sees `"displaced":[<pattern>…]` in its next `bound` or `inbox` response. Use it for a restarted process that should not wait out its
predecessor's lease; a site's relay, which is the one configured receiver for
its prefix, takes over by default.

**Releasing.** A session releases all its binds with `{"t":"bind","names":[]}`
(over HTTPS, `POST /airc/v0/bind` with `"names":[]`). A client SHOULD release
when it exits, so its names are free at once rather than when the lease
lapses.

**Messages nobody is bound for wait.** A message for a local address with no
live candidate stays queued (§6.4). It is selected again when it is read or
flushed, among the binds live at that moment, so it goes to whichever session
binds first with the winning pattern.

A server that implements this section says so with `"leases"` in the
`features` of its `welcome` (§4.1), and over HTTPS in the `features` of its
capabilities document (§3.4.1). A server without it ignores
`take_over` and the session header; a client then gets the older
behaviour, in which any process bound for a workspace sees all its messages.

### 4.4 `ack`

Every party that accepts a `msg` MUST answer exactly one `ack` for it over
the same connection.

| field | type | R | meaning |
|---|---|---|---|
| `id` | str | R | the message id |
| `status` | str | R | `delivered`, `queued` or `failed` |
| `code` | str |  | error class (§14.1); SHOULD be present on `failed` and `queued` |
| `by` | str |  | URI of the resolver that produced the status: `airc://R/_resolver` for a server, `airc://R/ns/_resolver` for a relay, the endpoint's own URI for an endpoint |
| `reason` | str |  | human-readable |

- **delivered**: the destination endpoint, or its relay, has taken the
  message. Not a read receipt.
- **queued**: a server has taken responsibility and holds a copy it will keep
  trying to deliver until the ttl expires.
- **failed**: the message will not be delivered.

Ack propagation and timeouts are in §6.6.

### 4.5 `ping` / `pong`

```json
{"t":"ping","n":7}   {"t":"pong","n":7}
```

`n` is optional and echoed.

### 4.6 `link` → `linked`

Client face only. Manages links (§11) for endpoints the client may act for.

| field | type | ops | meaning |
|---|---|---|---|
| `op` | str | R | `offer`, `accept`, `decline`, `revoke`, `unreject`, `list` |
| `as` | str | all but `list` | the acting endpoint (local form allowed). MUST be inside the client's namespaces. It need not be bound or have sent anything: every address in the client's namespaces is its own. For `list`: optional on the stream face (the links of all the client's namespaces); required on a hosted realm's HTTPS face, which lists one endpoint's links |
| `peer` | str | `offer` | the other endpoint |
| `label` | str | `offer` | ≤ 200 chars, informational |
| `proof` | obj | optional, `offer` | the answer to a challenge (§11.6) |
| `contact` | obj | optional, `offer` | `{"email"?, "phone"?}`, given up front to a realm that asks for one (§11.6) |
| `credential` | str | optional, `offer` | ≤ 1000 chars, opaque: a code the offeree asked callers to bring (a warranty code, a registration key). Servers pass it on unaltered and do not display it; both servers can read it, so a secret belongs in a message after the link instead |
| `direction` | str | `offer` | `both` (default), `a-initiates`, `b-initiates` |
| `expires` | str/int | `offer` | lifetime: seconds, or `30d`/`12h`/`45m`/`2w`. **Absent: the link does not expire** (until revoked). The reference CLI sends `30d` unless told otherwise, and links made by redeeming a passport take the passport's `link_ttl` (default 30 days, §12); both are choices of the client and the issuer, not protocol defaults. A server MAY cap lifetimes |
| `id` | str | accept/decline/revoke; optional for `offer` | link id; for a signed offer the client chooses it (`L` + 8 hex) |
| `ts` | num | optional, all but `list` | the timestamp the client signed; the server MUST use it as the control message's `ts` (§19.9) |
| `expires_at` | int | optional, `offer` | the absolute expiry (Unix seconds) the client signed; the server stores it unchanged |
| `sig` | str | optional, all but `list` | the acting endpoint's identity-key signature over the control (§19.9); the server passes it on unaltered |
| `token`, `expires_at`, `link_ttl`, `auth` | | optional, `accept` | the passport the accepting client signed for the offerer (§12.9): token, absolute expiry, link lifetime in seconds, and `[{"key","sig"}]` over the canonical string of §12.4; absent, the server issues under its policy alone (a site key) or refuses |
| `key` | str | optional, `revoke`, `unreject` | a pin: refuse (or stop refusing) every link authorized by that key, for the acting endpoint (§12.7) |
| `all` | bool | `list` | administrator connections only: every link in the realm |

`linked`:

| field | type | meaning |
|---|---|---|
| `ok` | bool | |
| `link` | obj | the link record (§11.1) after the operation |
| `links` | list | for `list` |
| `closed` | list | for `revoke` with `key`: the ids of the links the refusal closed |
| `kept` | list | optional, for `revoke` with `key`: the ids of links the refusal covers but site policy keeps (must-accept) |
| `delivery` | str | ack status of the control message sent to the other side |
| `reason`, `code` | str | on failure |

### 4.7 `passport` → `passported`

Client face only. Manages passports (§12).

| field | type | ops | meaning |
|---|---|---|---|
| `op` | str | R | `new`, `list`, `revoke`, `redeem`, `key-add`, `key-list`, `key-remove` |
| `as` | str | all but `list`, `key-list` | the acting endpoint; for `new`, the endpoint recorded as `issued_by` (for a namespace or realm scope, whoever asks for it, inside the client's namespaces); for `redeem`, a namespace (trailing `/`) where the realm allows it (§12.8) |
| `scope` | str | `new`, `key-add`, `key-remove` | the passport's scope (§12.1): an endpoint, a namespace (trailing `/`) or the realm (`/`), local form allowed; default `as` |
| `label` | str | `new` | ≤ 200 chars |
| `token` | str | R for `new` | the token the client generated (§12.2) |
| `expires_at` | int | R for `new` | the absolute expiry (Unix seconds) the client signed |
| `uses` | int | `new` | redemptions allowed (default 1, capped) |
| `direction` | str | `new` | direction of the links it creates |
| `to` | str | `new` | pattern (§2.7) the redeemer must match (`bind_to`) |
| `link_ttl` | int | `new` | lifetime of created links, seconds (default 30 days) |
| `for_offer` | str | optional, `new` | a pending offer's link id: the server computes that offer's hash (§12.9) and signs it as the passport's `offer` term (a receptionist's answer). The offer must be pending and addressed to `as`, or to an endpoint inside the namespace `as` |
| `offer` | str | optional, `new` | the offer hash the client signed; must equal the one `for_offer` yields |
| `auth` | list | `new` | `[{"key": "<base64 public key>", "sig": "<base64>"}, …]`, signatures over the passport's terms (§12.4); may be empty when the server's policy lets it sign alone |
| `key` | str | `key-add`, `key-remove` | a public key (base64) to entitle, or stop entitling, to authorize passports for `scope` |
| `id` | str | `revoke` | passport id |
| `and_links` | bool | `revoke` | also revoke every link the passport created |
| `passport` | str | `redeem` | the passport (§12.3) |
| `all` | bool | `list` | administrators: every passport |

`passported`: `ok`; for `new`: `passport` (record without the token hash) and
`url`, the passport; for `list`: `passports`; for `redeem`: `status`,
`reason`, `code`, and `link` on success; for `revoke`: `passport`,
`revoked_links`; for `key-list`: `keys`, a list of `{"scope", "key", "pin",
"set_by"}`.

The `key-*` operations are one way for a realm to take its policy input
(§12.8): which clients may use them, and for which scopes, is the realm's
choice. The reference lets an administrator set keys for any scope and a
client set keys for scopes within its own namespaces.

### 4.8 `error`

```json
{"t":"error","code":"forbidden","reason":"alice/ is outside your namespaces"}
```

Sent before closing a connection for a protocol violation. Codes in §14.2.

### 4.9 `subscribe` → `subscribed`, `event`

Client face only. Live audit stream (§13).

```json
{"t":"subscribe","kinds":["msg","link"]}
{"t":"subscribed","kinds":["msg","link"],"scope":["alice"]}
{"t":"event","ts":1790380000.123,"kind":"msg.delivered","id":"…","from":"airc://…","to":"airc://…","status":"delivered","hop":"client","bytes":42}
```

`kinds` filters by full kind or by prefix (`msg`). `scope` is the list of
namespaces the subscriber sees, or `all` for an administrator.

### 4.10 `stat` → `stats` (optional)

A client MAY send `{"t":"stat"}` and receive `{"t":"stats", ...}` with
implementation-defined counters. Servers MAY restrict it.

---

## 5. Client identity and namespaces

A client never asserts its own identity. The server derives the set of
**namespaces** a connection may act for from the transport and tells the
client in `welcome.ns`:

- **Unix socket**: the peer uid (`SO_PEERCRED`, `LOCAL_PEERCRED`) looked up
  in the operator's `uid → namespaces` table.
- **Loopback TCP**: the owning uid of the remote socket (Linux: `/proc/net/tcp`),
  same table.
- **Remote clients (HTTPS binding)**: the key in the `Authorization` header
  (§3.4.2), looked up in the realm's `key → namespaces` table. Keys are
  registered out of band (operator configuration) or, on a hosted realm,
  through workspace registration (§3.4.4); the protocol only requires that
  the table exist.
- **Anything else**: no namespaces.

A server MUST enforce, for every client-face operation:

- `msg.from`, after canonicalization, lies inside one of the connection's
  namespaces (`ns/…` with at least one segment after the namespace);
- every `bind` name lies inside one (a namespace bind may name it exactly);
- `as` in `link` and `passport` frames lies inside one.

Consequently the `from` on a message leaving a server is a statement the
*server* makes. Identity is **namespace-granular**: the server proves which
namespace (user) a message came from; the endpoint name within it is asserted
by that user's process. Policy between endpoints of different namespaces is
enforceable; between endpoints of one namespace it is advisory.

An **administrator connection** (root, or the account the server runs as,
plus configured uids) with no namespaces of its own may list every link,
passport and event.

---

## 6. Routing

### 6.1 Overview

On receiving `msg` M over connection C, a server for realm R performs, in
order: validate → canonicalize and authenticate origin → expiry and dedupe →
control-traffic dispatch → policy → deliver → record → ack.

### 6.2 Validate, canonicalize, authenticate

```
validate types of id, from, to, body, ts, ttl, via, hdr (§4.2); else ack failed bad_address
if C is a client:
    ctx = C.namespaces[0] or ""
    frm = canonical(from, realm=R, ns=ctx); to = canonical(to, realm=R, ns=ctx)
    require frm.realm == R and frm inside C.namespaces      ; else failed refused
    via = []
else (C is a peer that said realm P in hello):
    frm = canonical(from); to = canonical(to)                 ; local forms invalid -> failed bad_address
    require frm.realm == P                                     ; else failed refused (no relaying for others)
    require to.realm == R                                      ; else failed refused (no transit)
    unless P is a trusted-unsigned peer:
        keys = published keys of P (§8.2); require non-empty   ; else failed refused
        require verify_message(M, keys) (§9.3)                 ; else failed refused
rewrite M.from, M.to to the canonical URI forms (fragments kept)
if expired(M): failed expired
if id seen (§7.3): ack delivered, code duplicate
```

On the peer face a server MAY also require `via` to be exactly `[P]`, the
origin realm, and refuses a message from a peer whose `from` lies in the
receiving realm R (airc.dev does both).

### 6.3 Control traffic

Before policy:

- `type == application/airc-passport+json` and `to == //R/_passport` →
  passport redemption (§12.6).
- `type == application/airc-link+json` → link control (§11.4). Admitted
  independently of message policy, subject to §11.5.

### 6.4 Policy and local delivery

```
target = to
if to.realm == R and to.path is one unreserved segment naming a namespace (workspace):
    front door (§20):
        mode off:       failed no_such_path
        mode directory: answer with the directory (§20.2); no policy check
        mode agent:     target = the front-door agent A (§20.3)
allowed, why = policy.check(frm, target)    (§10)
if not allowed: failed refused
if a §19.7 rule refuses M: failed e2e_required
if to.realm == R and to has no explicit port:
    if to is a namespace reference: failed namespace_not_endpoint   ; fan-out not offered
    if to.path == ["_resolver"]: ack delivered (health check), body ignored
    if to names a well-known endpoint (_resolver, _postmaster, _dir) or any
       other reserved name, and no client is bound for it: failed no_such_path
    if target is a closed channel (§21.4): failed path_gone
    client = select(target)                   (§4.3; live binds only, §4.3.1)
    if client:
        forward M to client; wait for its ack (§6.6); relay that ack
    else if to.path[0] is a namespace this realm knows (any configured namespace):
        spool M under key to.path[0]; ack queued endpoint_offline
    else:
        failed no_such_path, by airc://R/_resolver
else:
    remote delivery (§6.5)
```

A realm MAY exempt from `policy.check` messages its operator always admits.
The implementations exempt: messages between endpoints of one workspace (one
owner); messages to `_resolver`; messages to the realm's own built-in agents
(the echo; on airc.dev also eliza and the demo tool endpoint `mcp`, §23); and front-door directory replies (§20.2).
Links and passports created under an earlier registration of a workspace name
are ignored by the check (§3.4.4).

### 6.5 Remote delivery

```
if R in M.via or len(M.via) >= 8: failed routing_loop
M.via.append(R)
if server has a signing key and M.hdr.sig is absent: sign M (§9.3)
key = to.authority
link = an authenticated peer link to key (§8.4), dialling if needed
if none:
    if DNS had no authority at all: failed no_such_authority
    else: spool M under key; ack queued authority_unreachable
forward M over link; wait for ack (§6.6); relay it
if the link dropped before an ack: spool M; ack queued authority_unreachable
```

What "DNS had no authority at all" means, over the steps of §8.1:

| what discovery found | the sender's ack |
|---|---|
| an endpoint from any step (a configured peer, an SRV record of either binding, an A/AAAA record for `airc.<host>` or `<host>`) | try each in order; if none answers or verifies: `queued authority_unreachable` |
| every lookup answered, and none of them had a record (NXDOMAIN or no data) | `failed no_such_authority` |
| nothing found, but at least one lookup went unanswered (timeout, SERVFAIL) | `queued authority_unreachable`: the realm may exist |

An endpoint that answers with something other than AIRC (an HTTP error, a
capabilities document that does not verify) counts as not answering. The
`reason` SHOULD say what failed, for example `capabilities fetch: HTTP 403`, so
that a sender can tell a CDN refusal from a host that is down. A server that
cannot tell these cases apart (edge compute with no DNS detail) MAY queue in
all of them.

### 6.6 Acks, timeout, settlement

When a server forwards M to a next hop it waits at most **15 s** for that
hop's ack.

- Ack arrives: relay it upstream unchanged (status, code, by, reason).
- Timeout: spool M under its destination key, ack upstream `queued no_ack`,
  and keep M's id as *in flight*. When the late ack eventually arrives, it
  settles the message: the server removes the spooled copy, or marks the id
  *settled* so that a spool flush (§7.4) drops it instead of resending it. A
  late `failed` ack settles it too, since a `failed` ack is final (below). A
  flush MUST NOT resend a message still in flight.
- Next hop's ack is `failed` with code `link_down`: the hop lost its own
  link before the message got through. Treat it as a dropped link (spool,
  `queued`). Any other `failed` ack is final, whatever its reason says: a
  refusal whose reason happens to begin "link" (`link L1 is not between these
  endpoints`) is a refusal, not an outage.

On `delivered` or `queued` the server records the id as seen (§7.3) and
notes the pair (from, to) for the conversation record (§10.1).

### 6.7 Receipts

An ack says what the *servers* did with a message; `delivered` means the
endpoint's client took it (§4.4), not that the agent behind it did. A
**receipt** is the endpoint's own statement that it did, sent only when the
sender asked for one and the recipient's site allows it.

**Asking.** A sender puts `"airc-receipt"` in `hdr` with the receipt types it
wants, comma-separated: `{"hdr": {"airc-receipt": "seen,done"}}`. The
header is relayed untouched like any other.

**Receipt types.** A registry; this draft defines two:

| type | sent when |
|---|---|
| `seen` | the agent took the message: a relay handed it to the agent, an interactive listener printed it, a polling client acked it and gave it to the agent. Not when a server queued it. |
| `done` | the agent finished with the message and will send no reply to it. An agent that replies sends the reply instead; `done` is for messages that needed no answer. |

Unknown types are ignored. Each type is sent at most once per message.

**The receipt.** A reply (`re` = the message's id) from the recipient
endpoint to the sender, with `type` `application/airc-receipt+json` and body
`{"state": "<type>", "ts": <Unix seconds>}`. Being an ordinary reply it
takes the same route, policy and realm signature as any message, and the
conversation record (§10.1) admits it where a cold message would be
refused. It is sent in plaintext, like link and passport control traffic
(§11.4): the recipient's own server applies the site's policy below by
recognising the type, which a sealed envelope would hide (§19), and a
receipt carries nothing but a state and a time. A receipt is never itself
receipted, and a receipt never carries `airc-receipt`. The sending client
keeps each type to one receipt per message id; a server MAY also drop
repeats. Senders MUST NOT treat a missing receipt as a failed delivery: the
ack already said what happened; a receipt is extra.

**Who decides.** Whether receipts are sent is the recipient's choice at any
scope: site, namespace or endpoint, with the narrower scope winning. The
protocol defines the request, the types and the receipt; the policy is the
site's. The reference setting is `on`, `off` or `hook`, where `hook` hands
the message's metadata (ids, addresses, type, the types asked for, the
sender's realm) to a site-defined decision and sends only on allow, so a
site can, for example, refuse receipts to a sender it judges to be probing.
The shipped default is `on` for senders in the same realm and `off` for
other realms, because a receipt reveals when an agent's owner is active
(the reasoning of §21.2). A recipient MAY also send `seen` to a sender that
did not ask; a sender that did not ask SHOULD ignore it.

**States, as a sender sees them.** `failed`; `queued`; `delivered`;
`seen`; `answered` (any other reply with `re`) or `done`. Each later state
implies the earlier ones. Clients SHOULD show the latest state and the time
it was reached; relays SHOULD record `seen` and `done` in the audit stream
(§13) as `msg.receipt` with the state.

---

## 7. The spool

### 7.1 Keys

A queued message is filed under a **destination key**: the authority string
(`partner.example`, `partner.example:7001`) for a remote destination, or the
first path segment (the namespace) for a local one.

### 7.2 Expiry

A message is expired when `ts + ttl < now` (ttl default 86400). Expired
messages are dropped when read from the spool and never delivered.

### 7.3 Duplicate suppression

A server keeps the ids of messages it has acked `delivered` or `queued` for
at least its maximum accepted ttl plus the allowed clock skew (§9.3; with
the default maximum of 7 days, 8 days). A message whose id is known is
acked `delivered` with code `duplicate` and not delivered again, so origins
MAY retry freely.

### 7.4 Flushing

A server MUST attempt delivery of a key's backlog:

- when a client binds inside that namespace;
- when an *authenticated* peer link to that authority comes up, in either
  direction;
- periodically (reference: every 30 s) for every key with a backlog.

Flushing preserves order per key, requeues what still cannot be delivered,
and honours §6.6 settlement.

---

## 8. Discovery and peer links

### 8.1 Locating an authority

For authority `A` (host, optional port):

0. explicit port → connect to host:port; IP literal → connect directly, port
   2472; no DNS in either case (stream binding);
1. a static entry in the server's configuration (either binding);
2. DNS `SRV _airc-https._tcp.<host>` → HTTPS binding at target:port (default 443);
   DNS `SRV _airc._tcp.<host>` → stream binding at target:port;
3. `https://airc.<host>/` (HTTPS), or `A/AAAA airc.<host>` port 2472 (stream);
4. `https://<host>/`, or `A/AAAA <host>` port 2472.

A federated server MUST publish the HTTPS binding (step 2 or a working step
3/4) and MAY publish the stream binding as well.

Cache results for the DNS TTL (clamped to 30 s … 3600 s).

### 8.2 Published keys

A realm publishes one TXT record per signing key at `_airc.<realm>`:

```
_airc.example.com.  IN TXT "v=airc1 k=ed25519 p=<base64 public key>"
```

Fields are space- or semicolon-separated `key=value`. `k` defaults to
`ed25519`. Verifiers fetch all records and accept a signature under any
of them (§9.3). Cache for the TTL; cache a miss for 60 s. A static
`known_keys` table MAY replace DNS for named realms.

A realm's key is only as trustworthy as the DNS answer that carries it:
whoever controls the realm's zone, or the answer on its way to the verifier,
can substitute a key and impersonate the realm. DNSSEC lets a validating
resolver prove the answer is authentic (the AD flag), which defeats spoofing
in transit but not control of the zone itself. This specification does not
require DNSSEC. A realm SHOULD sign its zone where it can; a verifier MAY
require validated answers for chosen realms, MAY pin their keys in
`known_keys`, and SHOULD log a change of a realm's keys that is not a
rotation (§9.2).

### 8.3 Transport security

Peer links MUST use TLS in production. The dialler verifies the accepting
server's certificate for the resolved target host against its trust store.
TLS MAY be terminated by a proxy in front of the server. Confidentiality and
destination-host authentication come from TLS; realm authentication comes
from §9.

### 8.4 Opening and using a peer link

Dialling server D, to realm T:

```
connect (TLS) to the resolved endpoint
nonce = random
hello = {proto, role:"peer", realm:D, agent, ts:now, nonce, sig: sign_hello(D, T, ts, nonce)}   (§9.4)
welcome = read; require welcome.realm == T
unless T is trusted-unsigned: require verify_welcome(welcome, T, D, nonce, keys(T))
mark the link AUTHENTICATED; register it for T
```

Accepting server T, from a peer claiming realm P:

```
authenticated = P is trusted-unsigned
             or (hello.sig present and verify_hello(hello, T, keys(P)) with |now - hello.ts| <= 300 s)
register the link for P with that flag
welcome = {realm:T, proto, server, sig: sign_welcome(T, P, hello.nonce), kid}   (sig if T has a key)
if authenticated: flush T's spool for P over this link
```

Rules:

- A server MUST only *send* to a realm over an authenticated link (one it
  dialled, or an inbound one whose hello verified). It MAY *receive*
  individually signed messages over an unauthenticated inbound link. This
  is what stops an impostor from being handed a realm's queued mail.
- A server SHOULD accept several simultaneous links from one realm and MAY
  close a dialled link idle for 600 s.
- Acks travel back over the link the message arrived on.

---

## 9. Signing

### 9.1 Keys

Each realm holds one or more ed25519 keys (RFC 8032). The public half is
published per §8.2. The **kid** of a key is the first 8 hex digits of
SHA-256(raw 32-byte public key).

### 9.2 Signature format

```
sigstring = alg ":" kid ":" base64(signature)
alg       = "ed25519"
```

`hdr["sig"]` is one sigstring or a list of them. A verifier tries each
sigstring whose `alg` is on its **allowlist** (default `["ed25519"]`; the
value `none` is never valid) against every published key of the origin
realm, ordering keys with a matching kid first; any success verifies.
Ed25519 verification follows RFC 8032 §5.1.7 strictly: a signature whose
scalar S is not below the group order L is invalid. Without this check, two
implementations disagree about the same bytes, and a signature can be
altered (S + L) without the key. §18.2 has a vector.

**Agility without negotiation.** Nothing about algorithms is negotiated on
the wire. To adopt a new algorithm a realm publishes a second key
(`k=<new>`), carries two signatures per message, and retires the old key
once its peers have added the new algorithm to their allowlists. A message
cannot select a weaker algorithm than a verifier permits.

### 9.3 Message signatures

Canonical string (UTF-8; fields joined by `\n`, no trailing newline):

```
airc-msg-2
id
from                         (canonical URI as it appears on the wire, fragment included)
to
ts_ms                        (round(ts × 1000), rounding half to even; decimal integer)
ttl                          (decimal integer; 86400 when the message has none)
type                         ("text/plain" when absent)
re                           ("" when absent)
bin_sha256                   ("" when the message has no binary section, §22)
body
```

Every field before `body` is free of newlines (§4.2 and the address
grammar), and `body` comes last, so no two different messages share a
canonical string.

The origin server signs every message leaving its realm and places the
result in `hdr["sig"]`. A receiving server MUST refuse (`failed refused`) a
peer message with a missing or invalid signature unless the origin realm is
configured as trusted-unsigned. Fields not covered (`via`, other `hdr`
entries) are routing metadata a hop may change. A receiver MUST refuse a
message whose `ttl` exceeds its maximum (7 days unless configured), and MUST
remember the ids of messages it has accepted (§7.3) for at least that
maximum plus the clock skew it allows, so that no signed message can be
delivered twice.

### 9.4 Hello and welcome signatures

```
hello:    "airc-hello\n"   + dialler_realm + "\n" + target_realm + "\n" + ts + "\n" + nonce
welcome:  "airc-welcome\n" + acceptor_realm + "\n" + dialler_realm + "\n" + nonce
```

`ts` is the decimal integer from the hello. The target realm in the hello
binds it to one destination, so a captured hello cannot be replayed to a
different realm; the 300 s window bounds replay to the same realm, which
gains an attacker nothing beyond an authenticated-but-empty link.

---

## 10. Authorization

### 10.1 The decision

For every message it receives, a server decides whether to deliver it. This
is the **authorization decision**. The protocol fixes only its edges:

- The decision is made before the message is delivered or spooled (§6.4). A
  negative decision is answered `failed refused`; the reason text is free.
  Nothing else about the decision crosses the wire, so *how* a realm decides
  has no bearing on interoperability. Two realms with entirely different
  rule systems federate without knowing it.
- The decision MUST honour the grants this protocol defines. An active link
  (§11.3) grants what the link says, in the direction it says; a revoked
  link MUST NOT count as a grant, and a redeemed passport's grant is a link
  (§12.6). A realm MAY refuse traffic a link would allow (local rules
  evaluated ahead of links, an endpoint's opt-out, §12.7), and it MAY allow
  traffic with no link at all; what it MUST NOT do is deliver on the
  strength of a link that has been revoked.
- Both the origin server (egress) and the destination server (ingress)
  decide for themselves, each under its own policy; a message must pass
  both. The egress decision is a courtesy that fails fast; the ingress
  decision protects the realm.
- A server that offers directional links (§11.3) or reply-only rules keeps a
  **conversation record**: for every message it acks `delivered` or
  `queued`, the time the pair (from, to) last passed. `in_reply_window(a,
  b, w)` is true when `b` messaged `a` within the last `w` seconds. This is
  how "they may answer us but not start a conversation" is expressed
  without a second mechanism. A server MAY also note the pair when it
  forwards a message, before the ack, since the other side may answer
  before it acks.

What a realm allows beyond links and passports is its own business. The
recommended shape is to deny strangers by default and let them in through
the mechanisms built for it: a link offer (§11.5), a passport (§12), the
front door (§20). A rule that allows a whole realm (`//realm/**`) trusts
everyone that realm admits. For a hosted realm with open registration
(§3.4.4) that is every stranger who signs up, so such rules SHOULD NOT name
a hosted realm: grant exact endpoints with links or passports instead.

How a realm expresses what it allows beyond that is not part of this
protocol. Appendix B describes the rule engine the reference implementation
uses, for realms that want a ready design; nothing in it is required for
conformance.

---

## 11. Links

A link is a standing grant between two endpoints, recorded at both
endpoints' servers and enforced by each independently.

### 11.1 Record

```json
{"id":"L7f3a9c1e","a":"airc://example.com/alice/x","b":"airc://partner.example/support/desk",
 "direction":"both","label":"vendor","created":1790380000.1,"expires":1792972000.1,
 "state":"active","offered_by":"airc://example.com/alice/x",
 "origin":{"passport":"P3f9a1c2e","issued_by":"…","redeemed_by":"…"},
 "accepted_at":…,"declined_at":…,"revoked_at":…,"revoked_by":"…"}
```

- `id`: `L` + 8 lower-case hex, chosen by the offerer or issuer.
- `a`, `b`: endpoint keys (§2.2). Either MAY instead be a namespace
  reference (trailing `/`) or a realm (`airc://<realm>/`): a link made by a
  namespace or realm passport (§12) has the scope as `a`, and a redeemer
  that redeemed as a namespace is `b`. Such a side covers every endpoint
  beneath it, including endpoints created later. An endpoint side covers
  the endpoint and every endpoint beneath it (its sub-agents and the tool
  servers it exports, §23), but not a sibling: a link to `alice/x` covers
  `alice/x/reviewer`, not `alice/xy`. Coverage runs downward only: a link to
  `alice/x/reviewer` grants nothing at `alice/x` or at its siblings.
- `direction`: `both`, `a-initiates`, `b-initiates`.
- `state`: `pending` → `active` | `declined`; any → `revoked`. States only
  move forward; a revoked link never leaves that state.
- `expires`: null or a time after which the link has no effect.

### 11.2 Operations and who may perform them

| op | by | precondition | result |
|---|---|---|---|
| offer | endpoint a | a ≠ b; a has < 20 pending offers | record `pending`, `offered_by = a`; control `offer` to b |
| accept | endpoint b (the offeree) | state `pending`; actor ≠ offerer | the offeree's server issues a passport for the offerer (§12.9); control `accept` carrying it to a; the link becomes `active` when a's server redeems it |
| decline | endpoint b | state `pending` | `declined`; control `decline` to a |
| revoke | a or b | state `pending` or `active` | `revoked`, `revoked_by`; control `revoke` to the other |
| grant | the issuer of a passport (§12.6) | — | record created `active`; control `grant` to b |

A client acts through the `link` frame (§4.6); the server performs the
state change locally first, then sends the control message. Every `active`
link comes from a redeemed passport (§12): a grant (§12.6), whether the
passport was handed over by people or issued in answer to an offer (§12.9).

### 11.3 Decision rule

Given from F and to T, collect all records joining F and T (either order; a
side matches what it covers, §11.1: an endpoint side its endpoint and every
endpoint beneath it, a namespace or realm side every endpoint beneath it),
**newest first** by
`created`:

```
for rec in records:
    if rec.state == "revoked": return DENY ("link <id> revoked")
    if rec.state != "active" or rec expired: continue
    F_is_a = rec.a covers F and rec.b covers T
    if rec.direction == "both"
       or (rec.direction == "a-initiates" and F_is_a)
       or (rec.direction == "b-initiates" and not F_is_a): return ALLOW
    if in_reply_window(F, T, 86400): return ALLOW  ; links use a fixed one-day window
    return DENY ("<id> is <direction>; F may only reply")
return NO DECISION
```

A server MUST give every new record a `created` later than that of any record
it already holds for the same pair, so that "newest" is never a tie (a server
that keeps whole seconds adds one when needed). The newest decisive record wins: a revocation blocks until the two endpoints
agree again (a new accepted offer, or a redeemed passport), and no longer.

### 11.4 Control messages

Link control travels as ordinary `msg` frames:

- `type`: `application/airc-link+json`
- `from`: the acting endpoint, or for a `grant` the link's `a` (the passport's scope, which may be a namespace or the realm, §2.4); `to`: the other side
- `body`: `{"action": "offer"|"accept"|"decline"|"revoke"|"grant", "link": <record>}`, optionally with
  `"e2e": {"ik": …, "sig": …}`, the acting endpoint's identity key and, optionally, its signature over the control (§19.9); a `grant` carries `"passport_auth"` (§12.6)
- `hdr["airc-link"]`: the link id

A server receiving one for a local endpoint MUST:

1. validate the record (§11.1) and require `from` and `to` to be its `a`
   and `b` (either order), and different;
2. if it already stores a record with that id, require **that stored
   record's** `a` and `b` to be `from` and `to` too, and refuse otherwise: a
   control only ever touches its own pair's link, whatever the record it
   carries says;
3. apply the action with the same preconditions as §11.2 (`offer`: state
   `pending`, `offered_by == from`, realm accepts offers, id not yet known;
   `accept`/`decline`: only from the offeree, and an `accept` is handled as in §12.9: the link becomes active only through the grant; `grant`: `a == from`, `b == to`,
   state `active`, id not yet known, and only in answer to an outstanding
   redemption (§12.5); `revoke`: either party, and a revoke for a link never
   seen is stored, since it can only deny);
4. store/merge the record (states forward-only);
5. ack `delivered` once stored, then notify the local endpoint with a plain
   `text/plain` message that names the link id and the commands available
   (accept/decline for an offer; revoke otherwise). Notification failures do
   not change the ack.

A notice is the server's own statement, not the other party's, so it comes
**from `airc://<realm>/_links`** of the recipient's realm. Where the server
signs what it delivers to clients (the HTTPS binding does), the notice is signed
with that realm's key, so it verifies like any message; over a local socket it
is unsigned, like every local message. It carries:

| header | meaning |
|---|---|
| `airc-link` | the link id |
| `airc-link-action` | `offer`, `accept`, `decline`, `revoke` or `grant` |
| `airc-peer` | the other party's endpoint key; a client shows the notice as about, and replies to, this endpoint |
| `airc-passport` | on a redemption notice (§12.6), the passport id |
| `airc-link-label` | the link's label, verbatim; the notice text carries it only sanitized and quoted (§16 item 4) |
| `airc-offer-credential` | on an offer notice, the offer's `credential` (§4.6), for the receiving agent to check |
| `airc-passport-scope` | on a grant or redemption notice, the passport's scope |
| `airc-passport-pins` | on a grant notice, or an accept notice for a passport the offeree signed itself (§12.9), the passport's pins joined by `.` |

A server notifies for a local actor too (both ends in one realm), in the same
form.

Only servers send link control. A server MUST refuse a `msg` of type
`application/airc-link+json` or `application/airc-passport+json` from its own
clients (`failed refused`): clients act through `link` and `passport` frames
(§4.6, §4.7), and the server writes the control itself.

`auto_accept` patterns: a server MAY be configured to accept offers for
matching local endpoints immediately; it then accepts as in §12.9, under the
same issuing policy, and tells the endpoint the link opened automatically.

### 11.5 Admission

Link control is admitted regardless of message policy so that a stranger can
ask (the **knock** is simply an `offer`). A server MAY refuse all offers
(`accept_offers: false`), MUST cap pending offers per offerer (20), and
SHOULD rate-limit offers per source.

---

### 11.6 Challenges

A realm may require a link offer (§11.5) to come with a proof: a small cost
(proof of work), a login at a page the site chooses, an OAuth login, or a
verified email address or phone number. Whether it asks, what it accepts and
how hard the work is, is site policy (§12.8); none is required by the
protocol.

**Asking.** The offeree's server refuses an offer that needs a proof with
`failed`, code `challenge`, and the ack field `challenges`: a list of
alternatives, any one of which suffices. Each is `{"id", "kind", …}`:

| kind | fields | the offerer answers with |
|---|---|---|
| `pow` | `bits` | `x`: a string such that SHA-256 of `airc-pow\n<id>\n<offerer>\n<x>` has at least `bits` leading zero bits |
| `login` | `url` | `code`: what the page at `url` shows after the user logs in, however the site decides (password, federated login, captcha, second factor) |
| `oauth` | `url`, `provider` | `code`: what the server shows after the OAuth login it runs at `url` |
| `email`, `sms` | `need` (`address`) or `sent` | first `email` (or `phone`); the server then sends a code there and answers with a further challenge of the same kind marked `sent`; then `code` |

A challenge `id` is `<base64url(body)>.<base64url(sig)>`: `body` the canonical
JSON (§12.10) `{"kind", "from", "to", "exp", …}` naming the offerer, the
offeree, an expiry and the kind's parameters (for a `sent` challenge, the
SHA-256 of the address), and `sig` the offeree realm's signature over
`airc-challenge\n<body>`. The server keeps no state for an open challenge.

**Answering.** The offerer's server passes `challenges` to its client in the
`link` response (`ok: false`, code `challenge`). The client meets one and
sends the offer again with `proof: {"challenge": <id>, "x" | "code" | "email" |
"phone": …}`, which its server carries in the offer control as `body.proof`.
An offer may also carry `body.contact = {"email"?, "phone"?}` up front, for
a realm known to ask, which saves the round trip that asks for it.

**Checking.** The offeree's server verifies the challenge's signature, that
it names this offerer and offeree and has not expired, and then the answer:

- `pow`: recompute one hash;
- `login`: `code` equals the first 10 characters of the base32 (RFC 4648,
  upper case, no padding; compared case-insensitively) of
  HMAC-SHA-256(login secret, `airc-login\n<id>`). The login secret is shared
  between the AIRC server and the site's login page, which receives the
  challenge id as `?c=<id>` and computes the code once the user has logged
  in: that is the whole interface between the two;
- `oauth`: the same, under the server's OAuth secret. At `url` the server runs
  an authorization-code flow with PKCE against the configured provider (the
  verifier derived from the challenge id, so no state is kept), and its
  policy may limit which accounts pass (for example by email domain);
- `email`, `sms`: `code` equals the first 4 bytes of HMAC-SHA-256(contact
  secret, `airc-contact\n<id of the sent challenge>`), read as a big-endian
  unsigned integer modulo 10^8 and written as 8 decimal digits, with at most
  5 tries per challenge. The `sent` challenge carries the SHA-256 of the
  address normalized (an email lower-cased and trimmed; a phone number
  without spaces, dashes or parentheses). A policy may require both: the
  email code then answers with an `sms` challenge, and only its code admits
  the offer. The server sends the code through a hook the site
  configures (an HTTP endpoint or a command); the protocol does not send
  mail. The hook receives `{channel, to, code, offerer, offeree, origin_realm,
  client_ip, challenge, source}`: `origin_realm` the offer's realm, `client_ip`
  the address of the client request for an offer made on this server (absent
  otherwise), `challenge` the id of the challenge being answered, and `source`
  `contact` or `proof`. **Implementers:** a code send costs the site money and
  reaches a third party, so the site's hook MUST rate-limit sends per
  offerer, per origin realm or client address, per destination address and
  per challenge id, and SHOULD refuse addresses it does not expect. The
  protocol sets no budget; a server checks its cheap offer throttles before
  it checks a proof or sends anything.

An empty list of acceptable kinds exempts the offers it matches. A valid
proof admits the offer as `pending` (§11.5), or, where the policy
says the proof suffices, accepts it at once as in §12.9. An invalid or
expired proof gets a fresh `challenge`. Since challenges are stateless, a
proof stays valid for further offers from the same offerer to the same
offeree until the challenge expires; a realm that wants each proof used once
records the ids it has accepted. A realm SHOULD keep only a hash of
an email address or phone number, and SHOULD say on its address pages what
it asks for.

---

## 12. Passports

A passport is a bearer invitation that creates an active link when redeemed.
It names a **scope** on the issuing realm, carries a secret token, and pins
one or more **authorizing keys** whose signatures over the passport's terms
the redeemer verifies. Only the issuer can validate the token, so a passport
can be revoked instantly and every redemption is visible to the issuer.

### 12.1 Scope and authorizing keys

- **Scope**: the part of the issuing realm the link reaches. One of:
  an endpoint (`airc://example.com/alice/x`); a namespace, written with a
  trailing `/` (`airc://example.com/alice/`), covering every endpoint beneath
  it, including endpoints created after the passport was issued; or the whole
  realm (`airc://example.com/`).
- **Authorizing key**: an ed25519 key that signs the passport's terms
  (§12.4). Its **pin** is the first 128 bits of SHA-256 over the raw 32-byte
  public key, written as a base62 number (alphabet `0-9A-Za-z`, most
  significant digit first), left-padded with `0` to 22 characters. The pin is
  the same value as the key's E2E fingerprint (§19.2) in another encoding.
- A passport carries **one to several** authorizing keys (4 is the expected
  maximum; a server MAY refuse more). Every one of them MUST have signed the
  same terms (§12.6): a passport with two pins is valid only if both keys
  signed it.

Which keys may authorize passports for which scopes, which keys a passport
must carry, and who may ask for one, is the issuing realm's own policy
(§12.8). Where such a policy, or `bind_to`, matches a pattern (§2.7) against a
namespace or realm rather than an endpoint, the pattern is tried against an
endpoint directly beneath it. Typical policies: an endpoint's own identity key (§19.2) authorizes
passports for itself and its sub-agents; a fleet owner's key authorizes
passports for its namespace; one site key authorizes everything; every
passport must carry both the requesting agent's key and a site key, so that
an agent can make passports for itself while the site controls issuance.

### 12.2 Record (issuer side)

```json
{"id":"P3f9a1c2e","token_hash":"<sha256 hex of the token>","scope":"airc://example.com/alice/x",
 "label":"Bob's reviewer","direction":"both","created":…,"expires":…,"uses":1,
 "used":[{"redeemer":"airc://…","at":…,"link":"L…"}],
 "bind_to":"//partner.example/**","link_ttl":2592000,"state":"active","issued_by":"airc://example.com/alice/x",
 "auth":[{"key":"<base64 public key>","sig":"<base64 signature>"}]}
```

- `id`: `P` + 8 hex. The token is at least 128 bits from a CSPRNG, written in
  base62 (22 to 64 characters). It is shown once and stored only as SHA-256.
- `state`: `active` → `exhausted` (all uses consumed) | `revoked`.
- `auth`: one entry per authorizing key, in the order of the passport's pins.

### 12.3 The passport

```
passport = "https://" host "/" scope-path "#passport=" token 1*( "." pin ) [ ".r=" realm-pin ]
```

`realm-pin` is the pin (§12.1) of one of the issuing realm's signing keys
(§8.2). An issuer SHOULD include it. A redeemer given one MUST verify the
grant's message signature (§9.3) with exactly that key, and refuses the
grant if it fails or the key is not among the keys the realm publishes; DNS
is thereby not trusted on first contact with the issuer. It SHOULD also
verify the host's capabilities document (§12.5, step 1) with that key before
sending the redemption: the grant check alone catches an impostor host only
after the token has been sent to it. For
an issuer whose keys the redeemer holds by configuration (`known_keys`,
§8.2), "the keys the realm publishes" are those; for an issuer configured
as trusted-unsigned, the pin is not checked. A
delegated passport carries the root realm's pin before its first `~`.

- `host`: an HTTPS host of the issuing realm's server, one that serves the
  realm's signed capabilities document (§3.4.1). It need not be the realm
  name (`airc.example.com` may serve realm `example.com`).
- `realm-pin`: see above.
- `scope-path`: the scope's path: `alice/x` for an endpoint, `alice/` for a
  namespace, empty for the realm.
- Everything after `#` stays in the browser: opened in a browser the URL shows
  the scope's address page (§21.3), which SHOULD recognize `#passport=` and
  explain how to hand the passport to an agent; the token never reaches the
  web server.

Examples (the token and pin of §18.3):

```
https://airc.example.com/alice/x#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.35vPT1d3o6aHoyLHExDUrA
https://airc.example.com/alice/#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.<fleet key pin>.<site key pin>
https://airc.example.com/#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.<site key pin>
```

A passport is not an address. A client MUST NOT send a message to one, and
MUST NOT place one in a message's `to`, `from` or headers. A redeemer refuses
any other form with reason `old or unknown passport format; ask the issuer
for a new passport`.

### 12.4 Issuance

The client generates the token and sends `passport op=new` (§4.7) with the
scope, the terms and `auth`, the list of `{key, sig}` signatures it holds,
each an ed25519 signature over this canonical string (`\n` between lines, no
trailing newline):

```
airc-passport-auth
<scope, URI form>
<SHA-256 of the token, lowercase hex>
<direction>
<expires, Unix seconds>
<uses>
<bind_to, or empty>
<link_ttl, seconds>
<offer: the offer hash (§12.9) for a passport that answers a link offer, or empty>
```

Times are integer Unix seconds; an absent value is the empty string. The
client sends every term it signed explicitly (`expires_at`, and `offer`), and the server
stores exactly those terms: where a realm cap would change one, it refuses
the operation with `bad_request`.

The server:

1. checks, by its policy (§12.8), that the requester may ask for a passport
   of this scope (`unauthorized` otherwise);
2. verifies every signature (`bad_request` if one does not verify);
3. checks, by its policy, that every key may authorize passports for this
   scope (`unauthorized`), and adds any signature its policy requires and it
   holds itself, such as a site key's;
4. refuses the operation if a key its policy requires is still missing
   (`unauthorized`, reason naming the missing key's role);
5. stores the record and returns the passport.

The issuing client MUST check that the returned passport names the scope it
asked for and carries the pin of every key it signed with before releasing
it. Defaults: 1 use, 7 days, direction `both`, link lifetime 30 days; caps:
100 uses, 90 days.

### 12.5 Redemption request

The redeemer's client sends `passport op=redeem` with `as` = the redeeming
endpoint (or, where its realm allows it, a namespace of the redeemer's, so
that the link reaches every endpoint beneath it) and the passport. Its server:

1. fetches `https://<host>/.well-known/airc` and verifies it (§3.4.1, §8.2);
   the realm it names is the issuer. Any host whose capabilities document
   verifies against a realm's published key speaks for that realm (`authority_unreachable` or
   `no_such_authority` as in §6.5 if that fails);
2. checks its own admission policy for a grant of this scope kind from that
   realm (§12.8), refusing locally (`refused`) otherwise;
3. sends:

- `type`: `application/airc-passport+json`
- `from`: the redeemer; `to`: `airc://<issuer>/_passport`
- `body`: `{"action":"redeem","scope":"<scope>","token":"<token>","redeemer":"<redeemer key>","redemption":"<r>"}`
- `ttl`: SHOULD be short (600 s)

`redemption` is an opaque string of at most 200 characters that only the
redeemer's server can make and check, and it answers exactly one redemption.
It MUST let the redeemer's server recover the passport's pins when the grant
arrives. The reference keeps the redemption in memory for 600 s and discards
it when a grant uses it. A server MAY instead make it stateless: airc.dev
uses `<expiry>.<h>.<p>.<sig>`, where `h` is the first 16 hexadecimal digits
of the SHA-256 of the token, `p` the first 16 of the SHA-256 of the pins
joined by `.` in passport order, and `sig` its realm key's signature over
`"airc-redeem"`, the redeemer, the scope, the expiry, `h` and `p`. It records
each value a grant has used until the value expires. The issuer MUST copy
the value unchanged into the `grant` it sends (§12.6). The redeemer's server
MUST refuse a `grant` without a valid value for that redeemer and that scope,
and MUST refuse a value that an earlier grant has already used: one
redemption, one grant.

Locally if the issuer is this realm, else via remote delivery (§6.5). The
ack to this message is the result.

### 12.6 Redemption (issuer) and the grant

```
if source has ≥ 20 failed redemptions in the last hour: failed refused ("too many failed redemptions")
rec = record whose token_hash == sha256(token)
why = first of:
      rec is None or rec.scope != body.scope   -> passport_unknown
      rec.state == revoked                     -> passport_revoked
      rec.expires < now                        -> passport_expired
      len(rec.used) >= rec.uses                -> passport_exhausted
      rec.bind_to and not match(bind_to, from) -> passport_not_for_you
            ; for a namespace or realm redeemer, match means the pattern covers every
            ; endpoint beneath it: //r/ws/** and //r/ws/ cover ws/, //r/** covers all,
            ; a pattern of fixed depth (//r/ws/*) covers no namespace
      from is within rec.scope, or rec.scope within from -> passport_not_for_you
      policy refuses this scope kind from this redeemer (§12.8) -> passport_not_for_you
      a signature in rec.auth no longer verifies, or its key is no longer
        entitled by policy                     -> passport_revoked
if why: count a failure; failed refused, reason = why with "_" -> " "
link = new record: a = rec.scope, b = from, direction = rec.direction, label = rec.label,
       expires = now + rec.link_ttl, state = active, offered_by = a,
       origin = {passport: rec.id, scope: endpoint|namespace|realm, issued_by: rec.issued_by, redeemed_by: from}
store link; append to rec.used; exhausted if uses consumed
send control grant(link, redemption = body.redemption, passport_auth) to from
     and WAIT for its ack                                    ; the redeemer's server records it first
notify rec.issued_by, the endpoint that asked for the passport (a notice from
     //<realm>/_links, §11.4: who redeemed, scope, link id, uses left, how to revoke);
     a passport issued by an administrator connection is reported in the audit stream only
ack delivered, reason "link <id> granted"
```

Re-verifying the stored signatures at redemption means a record written
into the issuer's store by anyone but the issuing process yields no link.

The grant carries `body.passport_auth = {"scope", "token_sha256",
"direction", "expires", "uses", "bind_to", "link_ttl", "offer", "auth":
[{"key", "sig"}, …]}`. The redeemer's server MUST, before recording the link:

1. check that the pins of the keys in `auth`, in order, equal the pins of
   the passport it presented (recovered from the redemption value): the
   issuer keeps `auth` in the passport's pin order (§12.2), so no key may be
   missing, added or reordered;
2. check that `token_sha256` is the SHA-256 of the token it redeemed and
   `scope` the scope it redeemed;
3. verify every signature over the canonical string of §12.4 built from
   `passport_auth`;
4. check that the granted link agrees with the signed terms: `a` = the
   scope, `b` = the redeemer, the same `direction`, and an expiry no later
   than the time the grant arrives plus `link_ttl` (allowing 300 s of clock
   skew).

A grant failing any check is refused (`refused`, reason `passport not
authorized`). The redeemer's notice to its endpoint names the scope and the
pins.

**End-to-end keys.** A pin authorizes the passport; it is an identity pin only
when it is the scope endpoint's own identity key. When the scope is an
endpoint and the grant's `body.e2e.ik` (§19.9) has a pin among the passport's
pins, the redeemer pins that key with source `passport`. Otherwise it pins
nothing from the passport, and keys of the endpoints the link reaches are
trusted on first use (§19.4).

If the grant cannot be recorded (the redeemer's server answers it other than
`delivered`), the issuer still acks the redeem `delivered`, with a reason
saying the redeemer's server did not record it. When the answer is
`failed`, the issuer revokes its own copy of the link; the use stays spent.
On `queued` it keeps it.

`_passport` is reserved and handled by the server itself; a message of
another type to it is `failed no_such_path`.

### 12.7 Revocation and opting out

`passport op=revoke` sets `revoked`; with `and_links`, every link whose
`origin.passport` is this id and is `pending` or `active` is revoked and
`revoke` controls are sent to the other sides.

A link whose side is a namespace or the realm reaches endpoints that did not
sign it. Whether such an endpoint may refuse it for itself is the realm's
policy (§12.8). Where it may (`links.opt_out`, default true), the endpoint
revokes the link for itself with `link op=revoke` and the link id: its server
records a new link `{a: <endpoint>, b: <other side>, state: revoked,
origin: {opt_out_of: <link id>}}`, newer than the group link, and sends a
`revoke` control for it. By the decision rule (§11.3) the newest decisive
record wins, so that endpoint is refused while the rest of the scope stays
linked. Where it may opt out, an endpoint may also refuse by **key**: `link
op=revoke` with `key` (a pin) and no link id records `{a: <endpoint>, b: "*",
state: revoked, origin: {reject_key: <pin>}}`, where `b: "*"` is a local
marker, never sent to another server. Its server then refuses, for
that endpoint, every link whose passport was authorized by that key
(existing links at message time, and new grants at redemption, refused both at
the issuer and at the redeemer; since the pins are in the passport URL, the
redeemer's server MAY also refuse before sending the redemption, sparing the
issuer a use), and tells the
counterparts of the links it closes with `revoke` controls. A link or grant
the realm declares must-accept (below) is exempt: the refusal is recorded
but does not apply to it. `link
op=unreject` with the same `key` lifts the refusal for future grants; links
it closed stay closed.
Each link records the pins of the passport that made it (`origin.pins`) for
this purpose. A realm may declare links its endpoints cannot refuse (an
administrator, a tool, an auditor, a fraud-warning system), by the other
side's address or by the keys that signed the link's passport (§12.8): its
server then refuses an endpoint's revoke or opt-out for such a link. For
messages, an allowing rule placed before the `links` marker (Appendix B) has the
same effect by address, since no link record can override it.

### 12.8 Site policy

Each server decides, by configuration:

| | issuing side | redeeming side |
|---|---|---|
| who may ask for a passport of each scope kind (endpoint, namespace, realm) | yes | — |
| which keys are entitled to authorize passports for which scopes | yes | — |
| which keys a passport for a given scope must carry (for example a site key, or an audit key for endpoints that handle personal data) | yes | — |
| which redeemers may present passports of each scope kind | yes | — |
| from which realms it accepts grants of each scope kind | — | yes |
| whether its endpoints may redeem as a namespace | — | yes |
| which keys a grant must carry for a given local endpoint or namespace to accept it (for example the site's own audit key) | — | yes |
| whether an endpoint may opt out of a group link (§12.7) | yes | yes |
| whether to issue delegations, to whom, and with what rules (§12.10) | yes | — |
| which offers must carry a proof (§11.6), of which kinds, how much work, whether a proof alone opens the link, and which offerers are exempt (an empty list of kinds) | yes | — |
| whether to follow a forwarded knock, and to which realms (§12.10), or an accept that answers with another scope in the offeree's realm (§12.9) | — | yes |
| which links an endpoint must accept, by the other side's address or by the keys that signed the link's passport | yes | yes |

These are examples, not a closed list. A realm states its own rules, in
whatever structure suits it (a security layer that checks signatures against
several policies, for instance), and the protocol requires only that every
passport's keys all verify (§12.6). A server MAY refuse namespace and realm
passports altogether, or admit them
only between allied realms (for example: realm-wide passports of
`central.example` may be presented only from `remote1.example` and
`remote2.example`). The protocol constrains only what a redeemer checks
(§12.6); the entitlement of a key to sign for a scope is not visible to the
redeemer and is enforced by the issuing server alone.

The issuing realm's server is trusted for its own endpoints in any case: it
enforces their policy and can deliver to them, or send in their name at the
realm level, with or without a link (§19.1); only end-to-end encryption takes
it out of the picture (§19). What the signatures add is that the holders of
the authorizing keys can show the other side their consent, and that an
issuing client can tell when its server altered what it asked for. A server
that drops a requested signature, renders a pin other than the requested
keys', or changes a signed term does not conform to this specification, and
the issuing client's check (§12.4) detects it.

### 12.9 Accepting a link offer

A link offer (§11.5, the knock) does not itself create a link. When the
offeree accepts:

1. The offeree's server issues a passport under its own policy (§12.8), as
   for `passport op=new` by the accepting endpoint: scope the offeree
   endpoint, `offer` the **offer hash**: the lowercase hex SHA-256 of
   `airc-offer\n<link id>\n<offerer, URI form>\n<offeree, URI form>\n<direction>\n<expires, Unix seconds, or empty>`
   (empty only when the offer has no expiry; otherwise the integer part, so
   0 is written `0`)
   as the offer stated them, `bind_to` exactly the offerer (the string `//<authority>/<path>`
   of the offerer's key, byte for byte, since it is signed), 1 use, an expiry of at most 600
   s, a direction and `link_ttl` no wider than the offer's (with `a` now the
   offeree: `a-initiates` in the offer becomes `b-initiates`, and the
   reverse), a `link_ttl` no longer than the offer's remaining lifetime (for
   an offer without expiry, the accepting client's value or the realm's
   default), `issued_by` the offeree endpoint, and the signatures its policy
   requires, which the accepting client supplies in the `link` frame (§4.6)
   unless a site key may sign alone. Where no client is involved (`auto_accept`,
   a built-in endpoint), the server signs with a key its policy entitles, such
   as a site key. The issuer keeps the offer's link id with the passport
   record, so the grant needs no further field. If its policy refuses, the accept fails
   and the offer stays `pending`.
2. It sends the offerer a control `accept` whose body carries the link id of
   the offer and `"passport": "<the passport>"` (§12.3).
3. The offerer's server MUST redeem it only if it answers an offer of its own
   that is still `pending`, from that offeree, and the passport's scope is
   that offeree's endpoint, or another scope in the offeree's realm (an
   endpoint or a namespace there: a receptionist answering with a passport
   to its support desk), or the passport forwards (§12.10). A scope other
   than the offeree's endpoint is followed only if the offerer's policy
   allows it (§12.8); otherwise it ignores the passport and acks
   `failed refused`. It redeems it as in §12.5 and §12.6, with every check
   there, including its own admission policy and the pins of the passport it
   received, and refuses a grant whose signed `offer` is not the hash of its
   own pending offer (computed by itself, from its own record of the offer),
   or wider than its offer, or (for any passport
   not issued in step 1) whose `passport_auth.bind_to` is not exactly the
   offerer, which it can check only on the grant. When the scope is the
   offeree's endpoint, the grant's link
   takes the offer's link id and replaces the offer record on both sides,
   with `a` and `b` swapped relative to the offer (the offeree is now `a`),
   which the pair checks of §11.4 allow since they compare the two sides as
   a set. The offerer's notice is a single `accept` notice; when the
   offeree's own key signed the passport it carries `airc-passport-scope`
   and `airc-passport-pins` (§11.4).
4. If redemption fails, the offer stays `pending` and both endpoints are told
   why.

The offerer's server handles the `accept` (redeeming, and receiving the grant)
before it acks it, while the offeree's server waits for that ack: both MUST
handle requests concurrently, and the exchange has to fit in the ack timeout
(§15).

The offerer's endpoint sees only that its offer was accepted, and, when the
link reaches a different scope than the endpoint it asked, which scope that
is (`airc-passport-scope` on the accept notice). The link then has its own
id, and the offer record stays `pending`, marked `answered` with the new
link's id, as for a forward. A passport the offeree issued beforehand to
answer with (a receptionist's) MUST carry the offer hash, and SHOULD be
bound to exactly the offerer, single-use and short-lived, as in step 1; a
forwarding delegated passport carries it as `offer` in its last layer's body
(§12.10). Because the offer hash is signed, the keys that authorized an
answer authorized that particular offer, and an answer cannot be attached to
another pending offer, even one to the same endpoint.

A realm may thereby put a receptionist in front of its agents: callers knock
on the receptionist, bringing a `credential` if asked to; the receptionist
(an agent, or the server's own policy) checks it and accepts with a passport
to the agent or namespace that should handle the call, for which its key
must be entitled (§12.8). A receptionist can equally accept the knock for
itself, talk with the caller, and hand it such a passport in a message later.

Every link
therefore passes the issuing realm's passport policy, and from the first
message after the knock both sides hold keys from a passport: the offerer
pins the offeree's key with source `passport` where the offeree signed it
itself (§12.6). The passport travels between the two servers in the clear
to them, as all control does; it is bound to the offerer, single-use and
short-lived, so it is of no use to anyone else. A decline sends `decline`
as before, with no passport.

### 12.10 Delegated passports

A realm may let another realm issue passports to its scope on its behalf,
through any number of hops: the passports realms generate for each other,
like call forwarding, rather than ones people hand out.

**Delegation.** The root realm R issues a passport (§12.4) whose terms also
name delegates. Its authorizing keys sign this canonical string instead of
the one in §12.4:

```
airc-passport-delegate
<scope, URI form>
<SHA-256 of the token, lowercase hex>
<direction>
<expires, Unix seconds>
<uses: redemptions allowed through the delegation, in total>
<bind_to, or empty>
<link_ttl, seconds>
<delegates: canonical JSON list of {"realm", "pins"}>
<rules: canonical JSON object, or empty>
```

Canonical JSON here means keys sorted, no whitespace, UTF-8 without escaping
non-ASCII characters, and integers only; an empty `rules` is the empty line. R stores the record
with `delegates` and `rules` and hands the delegate the **reference**: the
token's SHA-256 (64 hex digits), never the token. A delegation cannot be
redeemed without a delegate layer.

**Layers.** A delegate D whose key is listed adds a layer, signed by one of
its listed keys over:

```
airc-passport-layer
<the root scope, URI form>
<the reference>
<SHA-256 of the previous layer's encoded form, or empty for the first layer>
<the layer's body: canonical JSON>
```

The body is `{"id", "key", "expires", "uses"?, "bind_to"?, "link_ttl"?,
"direction"?, "delegates"?, "rules"?}`: `id` at least 64 random bits in
base62 (11 or more characters), chosen by D; `key` the signing public key
(base64), whose pin MUST equal the layer's pin; an absent `direction` or
`link_ttl` is inherited from the parent. A layer with `delegates` lets those
keys add a further layer; one without is final. The body MUST be its own
canonical JSON and is signed as those exact bytes. A layer's encoded form is
`<base64url(body)>.<base64url(sig)>.<pin>`, base64url without padding. A
layer's realm is the realm its parent names for its pin. A delegate learns
the root realm, which the layer string names, from the root host's
capabilities document (§12.5, step 1).

**The passport.**

```
passport = "https://" host "/" scope-path "#passport=" reference 1*( "." pin ) [ ".r=" realm-pin ] 1*( "~" layer )
```

with R's host and scope, R's pins, then each layer in order. A delegated
passport is long; it is passed between realms and agents, not typed.

**Redemption at R** (§12.5, §12.6, with these differences). The redeem body
carries `"reference"` and `"layers"` (the encoded layers) instead of
`"token"`. R:

1. finds the record whose `token_hash` is the reference and which has
   `delegates` (`passport_unknown` otherwise), and checks it as in §12.6;
2. for each layer in order: its pin is among the keys its parent lists
   (the record's `delegates`, or the previous layer's); its signature
   verifies; its `expires` and `link_ttl` are no later or longer than the
   parent's, and its `direction` no wider; its `id` has not been revoked
   and has uses left; every rule stated in the record or an earlier layer
   is satisfied (below);
3. checks that the last layer is final, and that the redeemer matches every
   non-empty `bind_to` along the chain;
4. records a use of the delegation and of every layer, creates the link
   (`direction` the narrowest along the chain, `expires` now plus the
   smallest `link_ttl`, `origin.chain` the list of `{realm, id, pin}`), and
   grants it with `passport_auth` carrying `"kind": "delegated"`, the
   record's terms, `delegates`, `rules` and `auth`, and `"layers"`.

R checks the layers itself; it asks no delegate anything. A chain that fails
a check is refused with `failed refused`, reason `delegation refused:
<detail>`. The redeemer's
server verifies every signature: R's over the delegation string, built with
the reference, and each layer's over its layer string, against the pins in
the passport in order (§12.6, step 1).

**Rules.** `rules` is an open object: each realm in the chain may state its
own. Two members are defined, and R enforces them on the layers that follow
the one that states them: `"depth"` (how many further layers are allowed)
and `"to"` (patterns, §2.7, of the realms that may be named as delegates,
for example `["b.example"]`, so that A→B→C is allowed and A→D→C is not).
`"to"` limits the delegates named by the next layer (each layer that wants
to constrain further steps states its own `to`). Other members are policy
between the realms that use them; a realm that
signs a layer keeps to the rules above it. The protocol sets no depth limit.

**Closing.** R revokes the delegation with `passport op=revoke`, `and_links`
revoking every link made through it. A delegate D closes what it issued
without knowing link ids: it sends R a control (`application/airc-passport+json`,
from `airc://<D>/`, to `airc://<R>/_passport`, signed by D's realm as any
message) with body `{"action": "revoke-layer", "reference", "layer": <id>}`.
R records the revocation under (D, id), which it can do before it has seen
the layer, since only a layer whose realm is D can ever match it; it
revokes every link whose `origin.chain` contains that layer, which includes
links made through further layers beneath it, and refuses later redemptions
through it.
Whether a realm reports redemptions to its delegates is between them.

**Forwarding a knock.** A realm that accepts a link offer (§12.9) may answer
with a delegated passport instead of one of its own, so that the offerer
reaches another realm. The offerer's server redeems such a passport only if
the last layer was signed by a key of the realm it sent the offer to and is
bound to exactly the offerer, and only if its own policy allows forwarding
to the root realm. Where the chain's naming of the last layer's realm is in
the delegation record (a one-layer chain), the offerer can check it only on
the grant, and refuses the grant there. The offer stays `pending`, and is marked answered, once
the forwarded link is recorded.

---

## 13. The audit stream

A server keeps an append-only log of events, without message bodies, and
streams the same records to subscribers (§4.9).

Event fields: `ts`, `kind`, and as applicable `id`, `from`, `to`, `status`,
`code`, `reason`, `by`, `hop` (`client`, `peer`, `local`, `spool`), `type`
(when not `text/plain`), `re`, `bytes` (body length), `link`, `passport`,
`endpoint`, `realm`, `authenticated`, `outbound`, `label`, `state`, `uses`,
`uses_left`.

Kinds: `msg.delivered`, `msg.queued`, `msg.failed`, `msg.flushed`,
`link.offer`, `link.accept`, `link.decline`, `link.revoke`, `link.grant`,
`passport.issue`, `passport.redeem` (with `status: failed` and `code` on a
refused attempt), `passport.revoke`, `peer.up`, `peer.down`. Implementations
also emit `msg.refused` (a §19.7 refusal, code `e2e_required`),
`channel.close` (§21.4), `profile.publish`, `profile.delete` (§21),
`e2e.publish` (§19.3), and, on a hosted realm, `workspace.created`,
`workspace.deleted`, `workspace.join`, `workspace.recover` and
`workspace.front` (§3.4.4, §3.4.5, §20). The hosted realm records issuance as
`passport.new`.

A subscriber sees an event when any of its `from`, `to`, `endpoint`, `realm`
lies inside one of the subscriber's namespaces; an administrator sees all.
Body previews, if a site wants them, are written by its relay at delivery
time.

---

## 14. Codes and reasons

### 14.1 Ack `code`

| code | status | meaning | produced by |
|---|---|---|---|
| `no_such_authority` | failed | every discovery lookup answered, with no record (§6.5) | sender's server |
| `authority_unreachable` | queued | found but nothing answered or verified, a lookup went unanswered, or the link dropped (§6.5) | sender's server |
| `no_such_path` | failed | a resolver does not know the next segment | the last resolver that owned a prefix |
| `path_gone` | failed | existed and was torn down | the delegating endpoint, or the server, for a closed channel (§21.4) |
| `not_delegated` | failed | owner does not accept sub-paths; reserved, no current implementation produces it | the owning endpoint |
| `namespace_not_endpoint` | failed | destination ends in `/` and fan-out is refused | the resolver for it |
| `stale_instance` | failed | fragment does not match the current incarnation; reserved, no current implementation produces it | the endpoint |
| `refused` | failed | identity, signature or policy refused it; passport refusals | whoever refused |
| `bad_address` | failed | malformed address or frame content | the server |
| `bad_request` | failed | a malformed frame on the client face: an id, `re`, `type` or hash outside its grammar, a field of the wrong type (§4.2; the peer face answers `refused`) | the server |
| `expired` | failed | ttl passed | the server |
| `routing_loop` | failed | realm already in `via`, or 8 hops | the server |
| `no_ack` | queued | next hop silent for 15 s; spooled | the server |
| `link_down` | failed | the hop's own link to the next hop broke before the message got through; the receiver of this ack spools and retries (§6.6); the reference acts on it when received but does not emit it on the wire | the hop whose link broke |
| `endpoint_offline` | queued or failed | nothing bound (queued) / agent not running (failed, from a relay) | server or relay |
| `duplicate` | delivered | id already seen | the server |
| `pushed` | queued | pushed to the recipient's open WebSocket; the recipient's ack will follow asynchronously | the server |
| `e2e_no_key` | failed | the recipient has no private key for the envelope's `kid` (§19.6) | the recipient's client |
| `e2e_decrypt` | failed | the envelope did not open (§19.6) | the recipient's client |
| `e2e_sender` | failed | the plaintext's sender key or signature failed (§19.6) | the recipient's client |
| `e2e_required` | failed | the endpoint accepts only encrypted messages (§19.7) | the recipient's server |
| `bin_unsupported` | failed | the message has a binary section (a file, §22) and the recipient's client or a hop cannot take one | the server that could not pass it on |
| `bad_bin` | failed | the binary section is missing or does not match `bin` / `bin_sha256` (§22) | the server that read it |
| `bad_file` | failed | a file message whose section does not match its description (§22) | the recipient's client |

Passport refusals use `refused` with reason `passport unknown`, `passport
expired`, `passport exhausted`, `passport revoked`, `passport not for you`.

### 14.2 `error` frame codes

`expected_hello`, `bad_proto`, `wrong_face`, `bad_frame`, `bad_json`,
`frame_too_large`, `bad_bind`, `forbidden`, `unexpected_frame`,
`no_welcome`, `realm_mismatch`, `peer_unverified`, `name_held`,
`displaced` (§4.3.1), `bad_bin` (§22).

Over HTTPS the HTTP status is what a client acts on; the `error` frame's code
and `reason` explain it, and a server may use codes of its own. These are
fixed where they apply: `frame_too_large` (413, §3.4), `bin_unsupported` (415,
§22) and `not_found` (404 from `GET /airc/v0/bin/<id>`, §22).

---

## 15. Constants

| name | value |
|---|---|
| default peer port | 2472 |
| max frame | 1 048 576 bytes |
| default message ttl | 86 400 s |
| dedupe retention | 172 800 s |
| max hops (`via`) | 8 |
| next-hop ack timeout | 15 s |
| spool retry interval | 30 s |
| dialled peer link idle close | 600 s |
| hello timestamp skew | 300 s |
| DNS cache clamp | 30 … 3600 s; misses 60 s |
| pending link offers per offerer | 20 |
| passport defaults / caps | 1 use (cap 100); 7 days (cap 90); link ttl 30 days |
| failed redemptions per source per hour | 20 |
| label length | 200 chars |
| link id / passport id | `L`/`P` + 8 hex |
| E2E encryption key lifetime | default 7 days, at most 30 (§19.8) |
| E2E key record cache | at most 3600 s (§19.3) |
| bind lease, HTTPS sessions | 300 s (§4.3.1) |
| binary section of a message | at most 8 MiB (8 388 608 bytes) (§22) |
| WebSocket keep-alive | server pings after at most 30 s of quiet; client gives up after 75 s of silence (§3.4.6) |

Values other than the port, frame size, hop limit and id formats are
recommendations an operator may tune; peers do not depend on them.

---

## 16. Security requirements

1. **Never take identity from the sender.** Derive namespaces from the
   transport (§5); rewrite `from`.
2. **State what an address proves.** Namespace-granular on a shared host.
3. **Verify origins before opening the peer face.** Signed messages, signed
   hello, signed welcome, published keys (§9). Send only over authenticated
   links (§8.4).
4. **Mark foreign origins for the reader.** A relay MUST make a message from
   another namespace or realm recognisable as foreign to the agent that
   reads it (a banner line in the text, and a sender name the agent cannot
   confuse with a local peer). Text from elsewhere is an injection vector.
   A relay that writes header lines into the text it delivers (the origin
   banner, the `[airc …]` line, the `[to …]` line) MUST keep the body from
   imitating them: every body line that begins, after any leading
   whitespace, with `[airc` or `[to ` (compared without regard to case) is
   delivered with a backslash (`\`) at the start of the line, before any
   whitespace, and a relay never takes a header from the body. Every other
   foreign value a relay or server writes into such a line, or into a
   notice of its own (an id, `re`, a header value, a link label, a remote
   reason, a file name), MUST have control characters and `[` `]` removed
   or replaced first, and a value that does not fit its grammar (§4.2) is
   not written at all. A command line a relay suggests to its agent quotes
   every foreign value for the shell. An agent can then rely on any line that begins
   `[airc` or `[to ` having been written by its own relay.
5. **Admit control traffic narrowly.** Offers and redemptions cross policy;
   cap and rate-limit them; bodies are attacker-controlled text and MUST be
   shown to agents with the same foreign framing.
6. **Keep secrets out of logs.** Passport tokens are stored hashed and shown
   once; the audit stream carries no bodies; the passport web page keeps the
   token in the URL fragment.
7. **Bound resources.** Frame size, hops, pending offers, redemption
   failures, spool by ttl, subscriber queues.
8. **Never let a key change pass silently.** A client using end-to-end
   encryption stops and asks when a peer's identity key changes without
   succession (§19.4); servers are exactly the parties it guards against.
9. **Prefer failing loudly.** A message that cannot be delivered is `failed`
   or `queued` with a code; there is no silent drop.

---

## 17. Conformance

### 17.1 Profiles

| profile | MUST implement |
|---|---|
| **Client** | §3; `hello`/`welcome`, `msg`, `ack`, `ping`/`pong`, `error`; local-form addressing (§2.3) |
| **Relay** | Client, plus `bind` for a namespace, delegation of sub-paths to the agent, truthful acks with `code`/`by`, the foreign-origin banner (§16.4) |
| **Server** | §2–§7, §10–§13, client face, `_resolver`, `_passport`, admin listing |
| **Federated server** | Server, plus §8–§9: discovery, TLS, signing, authenticated links; the HTTPS peer face (§3.4.1) is mandatory, the stream peer face optional |
| **Minimal HTTPS realm** | The smallest server that federates and serves its own agents, all over HTTPS (§17.3): the peer face, a client face with registered keys and pull delivery, the spool, policy with links, signatures, and the part of passports that links need (§12.9: issuing a passport for an accepted offer, redeeming one at `_passport`, the grant). No stream binding, sessions, push, files, other passport issuing, delegation, challenges or E2E |
| **Hosted realm** | Federated server, plus the HTTPS client face (§3.4.2) with registered client keys, the three delivery modes, workspace registration (§3.4.4) and membership (§3.4.5) |
| **E2E** (optional, any client or relay; servers: the key directory) | §19: key records, pins, HPKE envelope, sender signature, rotation; servers route envelopes unchanged and serve `/airc/v0/keys` |

### 17.2 Checklist

- [ ] Addresses: all rows of §18.1 parse or fail as stated.
- [ ] Framing: 1 MiB limit enforced (9 MiB plus 1 byte for a framed HTTPS body, §3.4); blank lines ignored; unknown `t` → `error`.
- [ ] Identity: `from` outside the connection's namespaces refused; binds likewise.
- [ ] Bind selection follows §4.3 scoring, including delegation.
- [ ] Routing follows §6, including `via`, `_resolver`, namespace refusal.
- [ ] Every accepted `msg` gets exactly one `ack`; `queued` always means a copy is held.
- [ ] Ack timeout spools and settles (§6.6); no double delivery on a late ack.
- [ ] Spool flushes on bind, on authenticated link up, and periodically; expired dropped; duplicates acked `duplicate`.
- [ ] Discovery order §8.1; keys from `_airc.<realm>` TXT.
- [ ] Signatures verify against §18.2 and §18.6; unsigned/invalid/tampered peer messages refused; unauthenticated inbound links never used to send.
- [ ] Authorization decision §10.1: refused before delivery, links honoured and a revoked link never a grant, the conversation record kept per pair.
- [ ] Links: state machine §11.2; decision rule §11.3 (newest decisive wins); controls §11.4.
- [ ] Passports: the passport form §12.3 parses; every pin's signature checked, sets equal (§12.6); redemption order §12.6; grant recorded at the redeemer before the ack; revocation with `and_links`; opt-out per §12.7.
- [ ] Events written without bodies; subscriber scoping.
- [ ] Reserved names not bindable by clients.

### 17.3 The minimal HTTPS realm

A first server can be small. This profile is what one realm needs to exchange
messages with every other realm and with its own agents; everything else can
come later without changing what it already does.

**Routes**

| route | face | notes |
|---|---|---|
| `GET /.well-known/airc?nonce=` | peer | the signed capabilities document (§3.4.1); `features` may be empty |
| `POST /airc/v0/msg` | peer | verify `hdr.sig` against the keys of `from`'s realm (§9.3); policy (§10); deliver or queue; one `ack` |
| `POST /airc/v0/send` | client | the client's own messages; sign and forward remote ones (§6.5) |
| `POST /airc/v0/bind` | client | `mode: pull` is enough; refuse others with `400 bad_bind` |
| `GET /airc/v0/inbox`, `POST /airc/v0/ack` | client | the client's queue; a message leaves it only when acked |
| `POST /airc/v0/link` | client | `offer`, `accept`, `decline`, `revoke`, `list` (§4.6, §11) |
| `GET /airc/v0/ws` | client | not needed: do not list `ws`; clients poll `/inbox` (§3.4.6) |

**Not needed:** the stream binding (§3.3), sessions and leases (treat every
request without `AIRC-Session` as one session per key, §3.4.2), push and webhook
delivery, binary sections (do not list `bin`; answer `415 bin_unsupported` to an
`application/airc-frame` body, §22), passports beyond what links need
(issuing for people, scopes other than endpoints, delegation, §12.10),
challenges (§11.6), events, profiles, front doors and E2E. Links do need the
passport round trip of §12.9: on accepting an offer, issue a passport bound
to the offerer, signed with a site key, and on receiving one in an `accept`,
redeem it at the offeree's `_passport` and record the grant (§12.4-§12.6). A realm adds any of them later by implementing it and listing it in
`features` where §3.4.2 names a feature.

**Checklist**

- [ ] The §18.2 and §18.6 vectors: message, client request and capabilities
      signatures, and non-canonical S refused.
- [ ] Capabilities: signed over a fresh nonce; the `_airc.<realm>` TXT key matches.
- [ ] Client auth: 300 s clock window both ways, nonce replay refused per key,
      body hash over the exact bytes, path signed without its query string, 401
      naming the failed check.
- [ ] `from` outside the key's namespaces refused (`failed refused`).
- [ ] Every accepted `msg` gets exactly one `ack`; `queued` means a copy is held.
- [ ] Dedupe by id (§7.3): a resend is acked `delivered duplicate`, before and
      after the ack, and never queued twice.
- [ ] `ttl` expiry refused (`failed expired`) and expired copies dropped from the queue.
- [ ] The spool retries queued remote messages; only `delivered`, a
      `failed` ack, or a peer's own `queued` (the peer now holds it) settles a copy;
      a `failed` ack with code `link_down` is retried (§6.6).
- [ ] Discovery and failure codes follow the table in §6.5.
- [ ] Links: both sides' preconditions (§11.2, §11.4), the newest decisive record
      wins (§11.3), notices from `_links`.
- [ ] Every request carries a `User-Agent` (§3.4); a CDN in front exempts the AIRC paths.

`scripts/qa_realm.py` in the reference implementation runs most of this list
against a realm, given one key the realm registered for the tester:
`qa_realm.py https://<realm> <keyfile> <namespace>`.

---

## 18. Test vectors

### 18.1 Addresses

| input (context realm `example.com`, namespace `alice`) | canonical / result |
|---|---|
| `net-ops` | `airc://example.com/alice/net-ops` |
| `bob/net-ops` | `airc://example.com/bob/net-ops` |
| `//Example.COM/Alice/Net-Ops` | `airc://example.com/alice/net-ops` |
| `airc://x.org/a/b` | `airc://x.org/a/b` |
| `//example.com:2472/a` | `airc://example.com/a` |
| `//example.com:7001/a` | `airc://example.com:7001/a` |
| `//[2001:DB8::1]/a` | `airc://[2001:db8::1]/a` |
| `//192.0.2.1/a` | `airc://192.0.2.1/a` |
| `//h.com/alice/research/` | `airc://h.com/alice/research/` (namespace; ≠ `//h.com/alice/research`) |
| `//h.com/a/b#run-42` | `airc://h.com/a/b#run-42`; key `airc://h.com/a/b`; equivalent to `//h.com/a/b#x` |
| `//h.com/_resolver` | reserved |
| `a.b`, `-a`, `a-`, `airc:foo`, `//h`, `//h/a//b`, `/x`, `//h.com:99999/a`, `//[::zz]/a`, `a b` | error |

Patterns against `airc://example.com/alice/bot`:

| pattern | match |
|---|---|
| `*` | yes |
| `//example.com/alice/*` | yes |
| `//*/alice/bot` | yes |
| `//example.com/**` | yes |
| `//example.com/alice/` | yes |
| `//example.com/alice/bot/x` | no |
| `//example.com/alice` | no |
| `//example.com/bob/*` | no |

`//example.com/alice/` against `airc://example.com/alice` (the endpoint):
no.

### 18.2 Signing

Private key seed (32 bytes, base64): `AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=`
(bytes 0x01 … 0x20).
Public key: `ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=`, kid `65b60673`.
DNS: `_airc.example.com. IN TXT "v=airc1 k=ed25519 p=ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="`

Message:

```json
{"id":"0f5a3c2e-9b1d-4e77-a6c8-1d2e3f4a5b6c","from":"airc://example.com/alice/x",
 "to":"airc://partner.example/support/desk","ts":1790380000.123,"body":"hello","type":"text/plain"}
```

Canonical string (`\n` shown literally):

```
airc-msg-2\n0f5a3c2e-9b1d-4e77-a6c8-1d2e3f4a5b6c\nairc://example.com/alice/x\nairc://partner.example/support/desk\n1790380000123\n86400\ntext/plain\n\n\nhello
```

Signature: `ed25519:65b60673:llh76U+4jzyfC45cWojF/LnHCVS8ndz0Z1XrLslBOBnBMpMrpG633xOBRenU9oEsPgQEHWf/MpAGDISMpZ3QCg==`

The same signature with L added to S (non-canonical, §9.2) MUST be refused:
`ed25519:65b60673:llh76U+4jzyfC45cWojF/LnHCVS8ndz0Z1XrLslBOBmuBomIvtHJN+odPYyz8GBBPgQEHWf/MpAGDISMpZ3QGg==`

A message whose `type` contains a newline MUST be refused: `{"type":"t\nX","body":"B"}` and `{"type":"t","re":"X","body":"\nB"}` would otherwise have the same canonical string.

Hello from `example.com` to `partner.example`, `ts` 1790380000, nonce
`6f1d2c3b4a596877`. Canonical: `airc-hello\nexample.com\npartner.example\n1790380000\n6f1d2c3b4a596877`.
Signature: `ed25519:65b60673:U/YtYxDq0VDtg88OOULLf3Q1pJQr8frOI/pTV+mJRO8mawiFaj/E9aZHL3izuNMHesk/f4YXirxUYvjsqO1KCg==`

Welcome from `partner.example` to `example.com` with that nonce, signed by
the same key (for the vector): canonical
`airc-welcome\npartner.example\nexample.com\n6f1d2c3b4a596877`.
Signature: `ed25519:65b60673:BnwUly7WPUSiAm2Hbwp1j9Aeqz6PcTRCr2E5Qq+bvT2BR48ujTUuyOKJ1ULDlAx9VzuqAQjydQe/IJAhC668DQ==`

### 18.3 Passport

With the §18.2 key (public `ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=`):

- pin: `35vPT1d3o6aHoyLHExDUrA` (the fingerprint `65b60673d6ed884bf01c2c222d82ada0` in base62, §12.1)
- token `Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE`; `token_hash` = SHA-256 of the token = `3f5fb3a4eca12051704aa76cca72b0d1a6aec1161b6046a8f547eb811ed808ba`
- passport: `https://airc.example.com/alice/x#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.35vPT1d3o6aHoyLHExDUrA`.
  Parses to host `airc.example.com`, scope path `alice/x` (an endpoint), the token, and one pin.
- terms: scope `airc://example.com/alice/x`, direction `both`, expires 1790984800, uses 1,
  bind_to `//partner.example/**`, link_ttl 2592000. Canonical (§12.4), `\n` between lines:
  `airc-passport-auth\nairc://example.com/alice/x\n3f5fb3a4eca12051704aa76cca72b0d1a6aec1161b6046a8f547eb811ed808ba\nboth\n1790984800\n1\n//partner.example/**\n2592000\n`
- signature (base64): `CvLvxQaVwHdzLlGQO7YcCcBAw6woCbRMPHGU5JUuuKTLcdbvMNRKckiKyVppVRXfMTeI4QqVYiWio6WrSmFiAw==`
- `p` for airc.dev's stateless redemption value (§12.5): `569837c858e54da5`
- offer hash (§12.9) for link `L7f3a9c1e`, offerer `airc://partner.example/support/desk`, offeree `airc://example.com/alice/x`, direction `both`, expires 1790990000: `867e556852291c4ec7775658d487d120ff8dda197b8ea2c16b07882967fdc6cc`

### 18.4 Link decision

Records between X and Y, newest first, and the expected decision for X → Y:

| records | decision |
|---|---|
| none | no decision |
| `active both` | allow |
| `active a-initiates` (X is a) | allow |
| `active a-initiates` (X is b), Y has not messaged X | deny |
| `active a-initiates` (X is b), Y messaged X 10 min ago | allow (reply) |
| `revoked` | deny |
| `active` (newer), `revoked` (older) | allow |
| `pending` (newer), `revoked` (older) | deny |
| `declined` only | no decision |
| `active` but expired | no decision |

### 18.5 Bind selection

Binds `//r/alice/` (client A), `//r/alice/research` (client B),
`//r/alice/research/spider1` (client C):

| destination | selected |
|---|---|
| `//r/alice/bot` | A (namespace, score 2) |
| `//r/alice/research` | B (exact, score 5) |
| `//r/alice/research/spider1` | C (exact, score 7) |
| `//r/alice/research/spider2` | B (delegation, score 4) over A (namespace, 2) |

With leases (§4.3.1): if B's session ends, `//r/alice/research` and
`//r/alice/research/spider2` go to A. If no bind is live at all, all four
wait in the queue and go to the first session that binds a winning pattern.
A second session binding `alice/research` while B holds it gets `name_held`
with `suggest` `alice/research-2`; with `take_over` it displaces B.


### 18.6 Client request, capabilities, link controls

All signed with the key of §18.2 (kid `65b60673`).

**A client request with a body** (§3.4.2), realm `airc.dev`, `ts` 1790380000,
nonce `9f86d081884c7d659a2feaa0`, body (these exact bytes, no trailing newline):

```
{"t":"msg","id":"5d1f2a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b","from":"alice/agent","to":"//partner.example/support/desk","ts":1790380000,"body":"hello","type":"text/plain"}
```

Body hash `39fae2053d68f327bd741ae85dcf5f2b508fcaaac0c94e3f79c7f8322ea968f5`. Signed string:

```
airc-client\nairc.dev\nPOST\n/airc/v0/send\n1790380000\n9f86d081884c7d659a2feaa0\n39fae2053d68f327bd741ae85dcf5f2b508fcaaac0c94e3f79c7f8322ea968f5
```

Header: `Authorization: AIRC-Key 65b60673:1790380000:9f86d081884c7d659a2feaa0:NvdHG4YqRt6+PK5ZUuj1TxLf0B8EbJOepFkgpejjot1IdZAsdsIX75hOxH5twfSfaH1AWCD9BCDDke34Yg4sCA==`

**A capabilities document** (§3.4.1) for realm `example.com`, nonce
`6f1d2c3b4a596877`, `ts` 1790380000: signed string
`airc-capabilities\nexample.com\n6f1d2c3b4a596877\n1790380000`, signature
`ed25519:65b60673:gp9cT5kHeao0C9UXZV50IJagaM06AqAV4gPjVaKruyEnMVL0+QX15HxojzPTiVRaI6pAckCHAhCg8xlsnuW+Cg==`.

**A link offer and its accept across realms** (§11.4). `example.com/alice/x`
offers `partner.example/support/desk` a link; the record travels as the body's
JSON text, so the signature covers it byte for byte. The offer, as
`example.com` posts it to `partner.example`'s `/airc/v0/msg`:

```json
{"t":"msg","id":"0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9","from":"airc://example.com/alice/x","to":"airc://partner.example/support/desk","ts":1790380000.2,"type":"application/airc-link+json","body":"{\"action\":\"offer\",\"link\":{\"id\":\"L7f3a9c1e\",\"a\":\"airc://example.com/alice/x\",\"b\":\"airc://partner.example/support/desk\",\"direction\":\"both\",\"label\":\"vendor\",\"created\":1790380000.1,\"expires\":null,\"state\":\"pending\",\"offered_by\":\"airc://example.com/alice/x\"}}","ttl":86400,"via":["example.com"],"hdr":{"airc-link":"L7f3a9c1e","sig":"ed25519:65b60673:dEm9MvGOGLgrT9QwAcd7XVEczidkfMppekhjSX1GQc3G0L8TmXwtYSHq2cc7LX92P6eng2NnCrxIV8HEHTluCg=="}}
```

`partner.example` stores the record, acks `delivered`, and notifies
`support/desk` with a `text/plain` message from `airc://partner.example/_links`
carrying `hdr` `{"airc-link":"L7f3a9c1e","airc-link-action":"offer","airc-peer":"airc://example.com/alice/x"}`
(the notice text is the server's own). When `support/desk` accepts,
`partner.example` sends (signed by `partner.example`'s key; the vector reuses
the §18.2 key):

```json
{"t":"msg","id":"1c2d3e4f-5061-4728-93a4-b5c6d7e8f901","from":"airc://partner.example/support/desk","to":"airc://example.com/alice/x","ts":1790380060.5,"type":"application/airc-link+json","body":"{\"action\":\"accept\",\"link\":{\"id\":\"L7f3a9c1e\",\"a\":\"airc://example.com/alice/x\",\"b\":\"airc://partner.example/support/desk\",\"direction\":\"both\",\"label\":\"vendor\",\"created\":1790380000.1,\"expires\":null,\"state\":\"active\",\"offered_by\":\"airc://example.com/alice/x\",\"accepted_at\":1790380060.5}}","ttl":86400,"via":["partner.example"],"hdr":{"airc-link":"L7f3a9c1e","sig":"ed25519:65b60673:Iz2GaxyAruj/YmJg2q8R97SCwZ0sxilJoClvwJbrFF03jL5f+U10jqELIxZGaRs3xdsJ8Q/koBzUIuSV8y8tCw=="}}
```

and `example.com` stores it as `active`, acks `delivered`, and notifies
`alice/x` from `airc://example.com/_links` with `airc-link-action: accept`.
The offer's canonical string begins
`airc-msg-2\n0b1c2d3e-4f50-4617-8293-a4b5c6d7e8f9\nairc://example.com/alice/x\nairc://partner.example/support/desk\n1790380000200\n86400\napplication/airc-link+json\n\n\n{"action":"offer",…`
(an empty `re` line, an empty `bin_sha256` line, then the body text).

**A framed request with a binary section** (§22, §3.4.2): `alice/agent` sends
the 12-byte file `hello, file\n` (SHA-256
`b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c`) with
`POST /airc/v0/send` and `Content-Type: application/airc-frame`. The body is
this line, `\n`, then the 12 bytes:

```json
{"t":"msg","id":"2e3f4a5b-6c7d-4e8f-9a0b-1c2d3e4f5a6b","from":"alice/agent","to":"//partner.example/support/desk","ts":1790380000,"type":"application/airc-file+json","body":"{\"v\":1,\"name\":\"hello.txt\",\"type\":\"text/plain\",\"size\":12,\"sha256\":\"b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c\",\"enc\":\"identity\"}","bin":12,"bin_sha256":"b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c"}
```

The whole body is 447 bytes; its hash, which the request signature covers, is
`24c1260704f28207c7c47ad83bceafea09ac6785b7e4ac11d5d040a37da3af24`. With `ts`
1790380000 and nonce `a1b2c3d4e5f60718293a4b5c` the header is
`Authorization: AIRC-Key 65b60673:1790380000:a1b2c3d4e5f60718293a4b5c:Vp0+ehrP61E7MCrdgQypuq+KeQ7Lm7eEPTW1a82xylTjQvzST5Iwpfc1JuaAyArcESPNU6udj0pv5e5vEP7vDw==`.

`airc.dev` forwards it to `partner.example`'s `/airc/v0/msg` as a framed body
again: this line, `\n`, the same 12 bytes. The message signature's canonical
string carries the `bin_sha256` line just before the body, which comes last (§9.3):

```json
{"t":"msg","id":"2e3f4a5b-6c7d-4e8f-9a0b-1c2d3e4f5a6b","from":"airc://airc.dev/alice/agent","to":"airc://partner.example/support/desk","ts":1790380000,"type":"application/airc-file+json","body":"{\"v\":1,\"name\":\"hello.txt\",\"type\":\"text/plain\",\"size\":12,\"sha256\":\"b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c\",\"enc\":\"identity\"}","ttl":86400,"via":["airc.dev"],"bin":12,"bin_sha256":"b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c","hdr":{"sig":"ed25519:65b60673:QCrtOsX7ZDmrY4aOEsliiUZWq86urOQFqh0mwlCTqwZs9VmfKKxtG7Pmszhwb85lCd5c+K3VUpvF2IZhgXl9Bw=="}}
```

Canonical string:
`airc-msg-2\n2e3f4a5b-6c7d-4e8f-9a0b-1c2d3e4f5a6b\nairc://airc.dev/alice/agent\nairc://partner.example/support/desk\n1790380000000\n86400\napplication/airc-file+json\n\nb33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c\n{"v":1,…,"enc":"identity"}`.

---

## 19. End-to-end encryption

Optional in the protocol, automatic in practice. A client that implements
this section creates and publishes its keys itself (§19.2, §19.3) and
encrypts every message to a peer that has published a valid key record;
neither the user nor the agent takes a step. Encryption is not mandatory
because it would shut out every client that has not implemented it yet, and
every peer that has no keys; an endpoint that wants it anyway can require it
(§19.7). Forward secrecy beyond key rotation (§19.8) is deferred.

An encrypted message is an ordinary `msg` whose body
only the recipient endpoint can read. Servers route it, apply policy, spool
it and ack it exactly as before; they never need, and never get, the
plaintext. The sender also signs the plaintext with its own endpoint key, so
the recipient learns which endpoint wrote it, not only which realm sent it
(§9 signatures vouch for realms).

### 19.1 What it protects, and what it does not

| protected | not protected |
|---|---|
| the body, its media type, and `re` | `from`, `to`, `id`, `ts`, `ttl`, `via`, the body's size: servers need them to route |
| against every server on the path, including a hosted realm's operator (§3.4.4) | who is linked to whom (links and passports are server records) |
| against a server forging a message in an endpoint's name | anything after decryption: the endpoint, and wherever an agent's session is processed, sees the plaintext |
| past messages, once the encryption key that sealed them is retired and destroyed (§19.8) | past messages still sealed to a key that leaks before it is retired; there is no per-message ratchet |

Link and passport control messages (§11.4, §12.5), notices (§11.4) and the
audit stream (§13) stay in the clear: servers must read them.

### 19.2 Keys

An endpoint that supports encryption holds:

- an **identity key** `ik`: ed25519, long-lived. Its **fingerprint** `ifp` is
  the first 32 lower-case hex digits (128 bits) of SHA-256 over the raw
  32-byte public key; shown to people in groups of four
  (`3f9a 1c2e 7b4d …`).
- one or more **encryption keys**: X25519 (RFC 7748), each with a `kid` (first
  8 hex digits of SHA-256 over the raw public key) and an expiry
  `not_after` (Unix seconds), each vouched for by the identity key.

The public halves form a **key record**:

```json
{"t":"e2e-keys","endpoint":"airc://airc.dev/alice/agent","ik":"<base64 ed25519 public key>",
 "keys":[{"kid":"4c1d2e3f","x25519":"<base64 X25519 public key>","not_after":1791000000}],
 "ts":1790380000,"sig":"<base64 ed25519 signature by ik>"}
```

`sig` is over these lines joined by `\n` (UTF-8, no trailing newline), one
`kid`/`x25519`/`not_after` triple per key in the order listed:

```
airc-e2e-keys
<endpoint>
<ik>
<ts>
<kid>
<x25519>
<not_after>
...
```

A record is valid when `sig` verifies under `ik`, `endpoint` is the endpoint
it was fetched for, at least one key has `not_after` in the future, every
`kid` matches its key (§19.2), and `succession`, when present, verifies under
`ik_old`. The newest valid record (by `ts`) wins.

**Identity key succession.** A record replacing `ik` MAY carry
`"succession":{"ik_old":"<base64>","sig_old":"<base64 signature by ik_old over the same canonical string>"}`.
A client that had pinned `ik_old` accepts the new `ik` without a warning
(§19.4). Without it, a changed `ik` is a key change.

### 19.3 Publication and lookup

The endpoint's server keeps a directory of key records. It stores what
endpoints publish and serves it to anyone; clients never trust it for
authenticity (§19.4), only for availability.

| face | request | response |
|---|---|---|
| HTTPS client (§3.4.2) | `POST /airc/v0/keys` with a key record | `{"t":"keyed","ok":true}`; the record's `endpoint` MUST lie in the client's namespaces and `sig` MUST verify |
| HTTPS peer (§3.4.1), unauthenticated | `GET /airc/v0/keys?endpoint=<uri>` | the key record, verbatim, or 404 |
| HTTPS client (§3.4.2), signed | `GET /airc/v0/keys?endpoint=<uri>`, `<uri>` in any realm | the key record, verbatim, or 404; for another realm the server fetches it from that realm's peer face; an unsigned request for another realm gets 404 |
| stream client | frame `{"t":"keys","op":"publish","record":{…}}` or `{"t":"keys","op":"get","endpoint":"<uri>"}` | `{"t":"keyed","ok":…,"record":{…},"reason":…}` |

For `get` on an endpoint in another realm, the server fetches it from that
realm's peer face (discovered per §3.4.1) and returns it verbatim. Servers
MAY cache records for up to one hour.

### 19.4 Trusting a key

A client keeps a **pin** per peer endpoint: `(ik, source, first seen)`. Before
encrypting to a peer, or accepting its signature, it compares the record's
`ik` with the pin.

Keys are pinned from links and passports, the moments two endpoints agree
to talk. Sources, strongest first:

1. **verified**: the two people or agents compared fingerprints over another
   channel. Clients SHOULD offer a way to show both fingerprints.
2. **passport**: the passport carried the issuer endpoint's fingerprint
   (§19.9). The pin is as trustworthy as the channel the passport travelled.
3. **link**: the key arrived with a link control message at the moment the
   endpoints agreed to talk (§19.9). A server on the path could have altered
   it at that moment, but not unnoticed afterwards.
4. **first use**: only for a peer with neither a link nor a passport (traffic
   a realm's rules allow, such as endpoints of one organisation): the first
   record fetched from the directory.

A client sends its own identity key with every link control it originates
and puts its fingerprint in every passport it issues, so the pins above
exist without anyone asking for them.

With no pin, the client pins the record's `ik` with the best source it has.
When a record's `ik` differs from the pin (and no valid succession links
them), the client MUST NOT encrypt to it or accept messages signed by it
without an explicit decision by the endpoint's operator, and MUST say which
peer's key changed. A key change is also the signature of a server attack.

### 19.5 The encrypted message

The outer frame is a `msg` (§4.2) with:

- `type`: `application/airc-e2e+json`
- `re`: absent (it travels inside)
- `body`: the JSON envelope below, as a string

```json
{"v":1,"suite":"hpke-x25519-sha256-chacha20poly1305","kid":"4c1d2e3f","enc":"<base64>","ct":"<base64>"}
```

- `kid`: the recipient's encryption key used.
- Sealing is **HPKE base mode** (RFC 9180, single-shot) with KEM
  DHKEM(X25519, HKDF-SHA256) `0x0020`, KDF HKDF-SHA256 `0x0001`, AEAD
  ChaCha20-Poly1305 `0x0003`. `enc` is the encapsulated key, `ct` the
  ciphertext with its tag.
- HPKE `info` and the AEAD `aad` are both these lines joined by `\n`, which
  binds the ciphertext to its envelope (it cannot be replayed under another
  id or to another recipient):

```
airc-e2e/1
<id>
<from>
<to>
```

The plaintext is UTF-8 JSON:

```json
{"type":"text/plain","body":"hello","re":"cf0a7537-cecc-45aa-a7a8-0362cfdca73c",
 "sender":{"ik":"<base64 ed25519 public key>","sig":"<base64>"}}
```

**A message with a binary section** (a file, §22) is sealed whole, and nothing
in it is base64-encoded: the envelope is `{"v":2,"suite":…,"kid":…,"enc":…}`
with no `ct`, and the ciphertext is the outer message's binary section. The
plaintext it seals is the JSON above with `"bin":<length>` added, a `\n`, then
the inner binary section's raw bytes. The sender's signature then also covers
the inner section: its canonical string below gets one more line, the
section's SHA-256 in lower-case hex.

`sender.sig` is ed25519 by the sender's identity key over these lines joined
by `\n`:

```
airc-e2e-msg
<id>
<from>
<to>
<type>
<re or empty>
<body>
```

A sender picks the recipient's valid encryption key with the latest
`not_after`, and refuses to encrypt to a record whose `ik` fails §19.4.

### 19.6 Receiving

The recipient's client (the relay, for an agent behind one):

1. finds the private key for `kid`; if it has none: ack `failed`, code
   `e2e_no_key` (the sender MAY refetch the record and retry once);
2. opens the ciphertext with `info`/`aad` built from the outer frame; on
   failure: ack `failed`, code `e2e_decrypt`;
3. checks `sender.ik` against its pin for `from` (§19.4, pinning on first use)
   and verifies `sender.sig`; on failure: ack `failed`, code `e2e_sender`, and
   the plaintext MUST NOT be shown as coming from `from`;
4. delivers `type`, `body` and `re` as if they had been the outer fields, and
   tells the reader the message was end-to-end encrypted and from whom it is
   authenticated. A relay keeps the foreign-origin banner (§16.4): encryption
   authenticates the sender, it does not make the sender trusted.

The "encrypted, from whom" label comes only from the receiver's own opening
of the envelope. `hdr` is not covered by the message signature (§9.3), so a
receiver MUST discard any `airc-e2e` header a message arrives with, and MUST
take `airc-peer-ik` (§19.9) only from its own realm's `_links` notices.

### 19.7 Servers

- MUST route, spool, dedupe and ack `application/airc-e2e+json` messages
  unchanged, and MUST NOT require access to the body.
- Policy (§10), links and passports apply to the envelope as for any message.
- MAY let an endpoint require encryption: plaintext `msg` frames to it
  (other than control types and notices) are refused with `failed`
  `e2e_required`. An endpoint states this in its key record with
  `"require": true`, which senders SHOULD honour before sending.
- MAY enforce **site rules**, lists of address patterns (§2.7):
  `require_outbound` (a plaintext message from this realm to a matching
  address is not forwarded: the site's egress) and `require_inbound` (a
  plaintext message from a matching sender is not accepted), refusing with
  `failed` `e2e_required` and a reason naming the rule. A company that lets
  employees use a hosted realm lists that realm, or their workspaces, in
  both, and no plaintext crosses the relay to or from it.
- Enforcement checks the envelope's shape (§19.5: `type`, `v` 1 or 2,
  `suite`, an 8-character `kid`, a 32-byte `enc`, and a ciphertext of at
  least 16 bytes: `ct` for `v` 1, the binary section for `v` 2), since
  servers cannot open it. A message
  with the envelope type that is not a well-formed envelope is refused
  everywhere. This stops mistakes and misconfigured clients; it cannot stop
  a sender who deliberately disguises plaintext as an envelope.

### 19.8 Rotation

- Encryption keys: `not_after` at most 30 days ahead (default 7). A client
  publishes the next key before the current one expires and keeps a retired
  key's private half only as long as messages sealed to it can still arrive
  (the largest `ttl` it accepts, default one day past `not_after`), then
  destroys it. Destroying retired keys is what protects past messages.
- Identity keys: rotated rarely, with succession (§19.2).

### 19.9 Keys in links and passports

- **Links.** A link control message (§11.4) MAY carry the acting endpoint's
  identity key: `body.e2e = {"ik":"<base64>"}`. The receiving server passes
  it to its endpoint in the notice as `hdr["airc-peer-ik"]`; the endpoint pins
  it with source `link`.

A link control (§11.4) that carries the acting endpoint's identity key MAY
also carry that key's signature: `body.e2e = {"ik": "<base64>", "sig":
"<base64>"}`, an ed25519 signature over (`\n` between lines):

```
airc-link-control
<action>
<link id>
<a, URI form>
<b, URI form>
<direction>
<expires, Unix seconds, or empty>
<the message's ts in milliseconds, as in §9.3>
```

The signature is made by the acting endpoint's client, which supplies it
with the `link` frame (for an `offer`, the client also supplies the link id).
For a `grant`, `body.passport_auth` (§12.6) takes its place. A server MUST
NOT alter `body.e2e`; the receiving server checks the signature when present,
refuses a control whose signature does not verify (`refused`, reason `link
control signature invalid`), and passes `ik` and `sig` to its endpoint in the
notice (`hdr["airc-peer-ik"]`, `hdr["airc-peer-sig"]`), together with the
other signed fields, so that the endpoint can check the signature itself:
`hdr["airc-peer-control"]`, a JSON object `{"a", "b", "direction",
"expires", "ts"}` with `expires` and `ts` as the integers that were signed
(`expires` absent when there is none). Times in the canonical string are
integer Unix seconds, and `ts` is in milliseconds as in §9.3.

The receiving endpoint pins a key from a signed control with source `link`
only after verifying the signature. Once it has pinned the acting endpoint's
key, it MUST treat a later `accept`, `decline` or `revoke` notice for that
peer that is unsigned, or signed by another key without a signed handover
(§19.4), as unauthenticated: it SHOULD warn its reader that the control was
not signed by the pinned key. A server on the path can therefore not swap
the key in transit, nor act for a pinned peer, without detection.

- **Passports.** A passport's pins (§12.1) are fingerprints of its
  authorizing keys in base62. A pin is used as an identity pin only when it
  is the scope endpoint's own identity key (§12.6, "End-to-end keys"); a
  grant's `body.e2e.ik` whose pin is not among the passport's pins MUST NOT
  be pinned with source `passport`.

### 19.10 Test vectors

Generated from the reference implementation. Its HPKE also reproduces RFC
9180 Appendix A.2.1 (base mode, this suite) exactly; check yours against that
first.

Recipient identity key: ed25519 seed `0x01…0x20` (the key of §18.2), endpoint `airc://example.com/alice/x`.
Its encryption key: X25519 private key = DeriveKeyPair(ikm `0x21…0x40`) of RFC 9180 §7.1.3.

| item | value |
|---|---|
| `ik` | `ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=` |
| `ifp` | `65b60673d6ed884bf01c2c222d82ada0` |
| encryption key `x25519` | `+JORnd4/sXcnPAewcCyAtO/QfIg9Mo7zSeAlrs7WFQ4=` |
| its `kid` | `7222582a` |

Canonical key-record string (`\n` between lines):

```
airc-e2e-keys
airc://example.com/alice/x
ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=
1790380000
7222582a
+JORnd4/sXcnPAewcCyAtO/QfIg9Mo7zSeAlrs7WFQ4=
1791000000
```

Key record:

```json
{"t": "e2e-keys", "endpoint": "airc://example.com/alice/x", "ik": "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=", "keys": [{"kid": "7222582a", "x25519": "+JORnd4/sXcnPAewcCyAtO/QfIg9Mo7zSeAlrs7WFQ4=", "not_after": 1791000000}], "ts": 1790380000, "sig": "WpE/KYxDX5J5ORo0uVPIgJ6jKTJAkyMJcY/5+/kAbYOpWkgXLGsGJVqTgLbOjtQzLNG0i5AWhOGadOdHszx0Bg=="}
```

Sender identity key: ed25519 seed `0x41…0x60`, endpoint `airc://partner.example/support/desk`; `ik` = `rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc=`.
Message: `id` `00000000-0000-4000-8000-000000000001`, `from` `airc://partner.example/support/desk`, `to` `airc://example.com/alice/x`, `type` `text/plain`, no `re`, body `hello`.

Canonical plaintext-signature string:

```
airc-e2e-msg
00000000-0000-4000-8000-000000000001
airc://partner.example/support/desk
airc://example.com/alice/x
text/plain

hello
```

Plaintext (these exact bytes are sealed):

```json
{"type":"text/plain","body":"hello","re":"","sender":{"ik":"rcFAEfgtHFbZVqpPnXPYhYNhpgYEhSXg0Ixjjcdd2Mc=","sig":"uid97CCM0KFzbx2iwML0WKJI7rj/bvsB3LGa06zVZXdco9OAua7s204lwFejOGc2mqI2Qqak+Ntxasy9tckNBw=="}}
```

HPKE `info` = `aad`:

```
airc-e2e/1
00000000-0000-4000-8000-000000000001
airc://partner.example/support/desk
airc://example.com/alice/x
```

Sealed with the ephemeral key DeriveKeyPair(ikm `0x61…0x80`); envelope (the outer `body`):

```json
{"v": 1, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582a", "enc": "F4ex6a5rz7HWQUcWmsH1jcKPvABOvYgKggPdLXwWhm0=", "ct": "OfVbc0tMAE4/tMY2hITTuymzK4K6rfpcWYRNTC1hmlS7fgdwszUnmYfF4cFxEOLQ4w2a/OmQYg2xvgHWAfmB4n6rI3R18nzlJi/DMqoDgqs1iCbq8NQY4rp44X747DsaJ1RpEkIrg7Ezuvf4Q8PlT+lNM1PU03hRxlQ87mTscxclLK1IBi3YZ0PuWiIBVzFM95Z+4SBv4mxMe1UbY9MiiTQP/Q1KBHkb4hIWkNmQFyHTgmCZ1j3dCBqVcFX703qS+H/c1Jda3E6sTszHFtBtDjxeGlS+u6UUwTji2g=="}
```

The same key's pin in a passport is `35vPT1d3o6aHoyLHExDUrA` (§18.3).

## 20. The workspace front door

A workspace address without a trailing `/`, `//R/<ws>`, is the one address
people are most likely to share and guess. It is not a namespace reference
(§2.4), and nothing binds it by default. This section gives it a meaning: it is
the workspace's **front door**, and each workspace chooses what stands there.
It applies to a namespace the server knows (a registered workspace on a hosted
realm, a configured namespace elsewhere), to ordinary messages only: link and
passport control (§6.3) keep their own rules.

### 20.1 Modes

| mode | what a message to `//R/<ws>` does |
|---|---|
| `directory` (default) | the server answers with the workspace's directory (§20.2); the message itself is not delivered to anyone |
| `agent` | the message is delivered to one named agent of the workspace (§20.3) |
| `off` | `failed no_such_path`, reason "this workspace has no front door" |

A server MUST default to `directory` and MUST let the workspace change the
mode. A workspace MAY also have a short description (`about`, at most 300
characters, one line): who runs it and what it is for. It heads the directory
reply and the workspace's web page. On a hosted realm a member changes it with its key (§3.4.5,
`front` action); on a self-hosted realm it is site configuration.

### 20.2 The directory

The directory is a reply, not a delivery. The server:

1. Authenticates the sender as for any message (§6.2). Policy (§10) does
   not apply: the directory is published information, like a web page.
2. Does not answer, and acks `delivered` with a reason saying so, when the
   message could be automatic: it has `re`, its sender is a reserved name,
   or it carries `hdr` `airc-front` or `airc-echo-of`. Automatic responders never answer one
   another, so two front doors cannot loop.
3. Otherwise sends one `msg` to the sender and nobody else: `from` is
   `//R/<ws>`, `re` is the message's id, `type` is `text/plain`, and `hdr`
   carries `airc-front: directory` and `airc-directory`, the listed agents'
   URIs separated by single spaces. The body lists each agent's address, the
   workspace's note on it if any, and whether it publishes end-to-end keys
   and requires them, then says how to reach one (a link offer, §11.5).
4. Acks the original `delivered`, with a reason saying the directory was
   sent (the reference: `directory of <n> agents sent to you`). A directory
   withheld by a §19.7 rule is acked `delivered` with a reason
   `directory withheld (…)`.

The reply is an ordinary message: the asking site's policy (§10) and site
rules on end-to-end encryption (§19.7) apply to it as to any other. A site
that denies strangers by default admits the answer with a `mode: reply`
rule for the realm it asked; one that requires encryption outbound gets no
plaintext directory.

**Who is listed.** Every endpoint of the workspace that publishes an
end-to-end key record (§19.3), plus entries the workspace adds by hand,
minus entries it hides. Each entry is `{agent, note?, hidden?}`, where
`agent` is the path beneath the workspace. A workspace that wants no
listing sets mode `off` or `agent`, or hides entries. At most 100 entries are
listed, sorted by name. A hosted realm lists only key records published
since the workspace's current registration (§3.4.4), so a new owner of an
expired name does not advertise its predecessor's agents.

A server MAY show the same directory on the workspace's web page.

### 20.3 A front-door agent

In mode `agent` with agent `A`, the server checks policy (§10) and site
encryption rules (§19.7) as though the message were addressed to
`//R/<ws>/A`, then delivers it **unchanged**: `to` stays `//R/<ws>`, because
a peer's message is signed as sent (§9.3). The endpoint that reads the
workspace (a relay bound for `<ws>/`, or a hosted workspace's inbox reader)
hands it to `A`. A server that tells a relay its namespace binding
(`bound`) includes `"front": {"<ws>": "A"}`; a hosted realm shows it in the
workspace record (`GET /airc/v0/workspace`: `front: "agent"` and
`front_agent: "A"`, plus `front_about` and `front_entries`).

## 21. Profiles and address pages

An address is easier to share when it explains itself. An endpoint MAY
publish a **profile**, a few public facts about it, and a server with an
HTTPS face SHOULD serve a web page at every address it holds that says who is
there and how to reach it.

### 21.1 The profile record

```json
{"t": "profile", "endpoint": "airc://example.com/alice/bot", "name": "bot",
 "about": "Builds and runs the AIRC protocol.", "icon": "📡",
 "text": "Longer description, plain text; blank lines separate paragraphs.", "ts": 1790380000}
```

| field | rule |
|---|---|
| `endpoint` | required; the endpoint's URI, in the publishing client's namespaces |
| `name` | optional display name, at most 64 characters, one line |
| `about` | optional one-line description, at most 200 characters |
| `icon` | optional; at most 32 bytes of UTF-8 with no whitespace, meant for one emoji |
| `text` | optional, at most 2000 characters of plain text |
| `image` | optional picture: a `data:` URI of type `image/png`, `image/webp` or `image/jpeg`, base64, at most 24 KB decoded; square, about 128 pixels, is best. The server checks the bytes match the type |
| `skills` | optional; what the agent does, as a list of at most 16 skill objects (below) |
| `ts` | required; seconds; a record older than the stored one is refused |

A **skill** is `{"id", "name", "description"?, "tags"?, "examples"?}`: `id`
is 1 to 32 characters of `[A-Za-z0-9_-]` starting with a letter or digit and
unique within the profile; `name` is one line of at most 64 characters;
`description` one line of at most 200; `tags` at most 8 one-line strings of at
most 32 characters; `examples` at most 4 one-line strings of at most 200. The
shape is that of an A2A Agent Card skill, so a card built from the profile
(§21.5) carries the list unchanged. Skills are claims, like the rest of the
profile; an address page lists them, and a directory may show the tags.

No field may contain control characters other than newlines in `text`. The
server stores the record as its own statement about its endpoint and does
not sign it. Profiles are public, as the directory is (§20.2): anyone may
read them.

**Publishing.** Stream client face: `{"t":"profile","op":"publish","record":{…}}`,
answered `{"t":"profiled","ok":true|false,"reason"?}`, and
`{"t":"profile","op":"get","endpoint":"…"}`, answered with `record`. A
server that offers this lists `"profile"` in its `welcome` `features`. A
client MUST NOT send a `profile` frame to a server that does not list it,
because an older server closes the connection on an unknown frame. HTTPS
binding: `POST /airc/v0/profile` with the record (a signed client request)
and `GET /airc/v0/profile?endpoint=<uri>` (public, this realm's endpoints
only; the record comes without the `image` data, which is served as the
picture itself at `GET /airc/v0/profile/image?endpoint=<uri>`; a server MAY
put `"image"` as a boolean saying whether there is a picture). Publishing
`{"endpoint":"…","delete":true}` removes the profile: its page and directory
entry go, unless the endpoint also publishes keys. An endpoint with a profile is listed in its workspace's directory, and
the directory shows its icon and `about` line, unless the workspace hides it
or has a note of its own for it.

### 21.2 Status

An endpoint's **status** says how a message to it will be handled right now:

| status | meaning |
|---|---|
| `push-active` | delivered live: something holds a connection for it and the agent is running, so a message reaches it within seconds |
| `push-inactive` | the connection is held but the agent is not running; messages are queued until it starts |
| `pull` | collected by polling (a hosted workspace bound in pull mode); the server knows the mode, not whether anyone is reading |
| `offline` | a status was published but has not been refreshed for 5 minutes (the relay or client that publishes it is down); messages are queued |

Only whatever delivers to the agent knows whether the agent runs, so
`push-active` and `push-inactive` are published by it (a fleet relay, a
hosted workspace's listener; the reference client does so with
`airc listen --status`): stream face
`{"t":"profile","op":"status","statuses":[{"endpoint","status"},…]}`,
answered `profiled`; HTTPS `POST /airc/v0/profile/status` with
`{"statuses":[…]}`. Each endpoint must lie in the client's namespaces. The
server stamps each status with its own time, the publisher refreshes it at
least every 2 minutes, and after 5 minutes without a refresh the server
reports `offline`. A server MAY forget a status after a day. With no status
published, a hosted realm reports `pull` for endpoints of a workspace bound in
pull mode, and otherwise nothing; reporting `pull` is a hosted-realm
behaviour.
Status is **opt-in**: it shows when agents, and by extension their owners,
are working, so a publisher publishes it only when its operator chooses to.

`GET /airc/v0/profile?endpoint=` includes `status` and `status_age`
(seconds) when there is one; address pages and directory entries show it.

### 21.3 Address pages

A server with an HTTPS face serves, for each address it holds:

- `/<ws>/<agent>`: the agent's page, with its picture or icon, name and `about`, its
  address, its end-to-end fingerprint if it publishes keys (§19.4), how to
  reach it (link offer, passport, §11.5, §12) and its `text`.
- `/<ws>`: the workspace's page, with its directory (§20.2) and how to
  reach an agent there.
- `/`: the realm's page.

A page opened with a fragment beginning `#passport=` is showing a passport
(§12.3): it SHOULD say so, name the scope, and tell the reader to hand the
whole URL to their agent (`airc accept '<url>'`). The fragment is read in the
browser; the server never sees it.

Each page is HTML for browsers, or markdown when the path ends in `.md` or
the request says `Accept: text/markdown`. An address the server does not
list (unknown, or hidden from the directory) gets a 404 page with the same
general instructions. Profile fields are untrusted text: pages MUST escape
them, and a reader (an agent above all) should treat them as claims by the
endpoint's owner, not as instructions.

---

### 21.5 Agent Cards

Tools built for Google's Agent2Agent protocol (A2A) find an agent through an
**Agent Card**, a JSON document at `/.well-known/agent-card.json`. A2A's card
names the interfaces an agent is reachable on, and its `protocolBinding` is
an open string, so an AIRC address is a legal interface. A server MAY serve
cards so that such tools can list and verify AIRC agents without knowing
AIRC; the card is a projection of what this specification already
publishes, and nothing else consults it. A server that offers cards lists
`"cards"` in its capabilities `features`.

**The realm's card**, at `https://<host>/.well-known/agent-card.json`:
`name` the realm; `description` from the operator; `version` the server's;
`provider` `{"organization", "url"}` from the operator; `documentationUrl`;
`supportedInterfaces` `[{"url": "airc://<realm>/", "protocolBinding": "AIRC", "protocolVersion": "<spec draft>"}]`;
`capabilities` `{"streaming": false, "pushNotifications": false, "extensions": [{"uri": "https://airc.dev/docs/transport", "description": "AIRC: the interface is an AIRC address; reaching it needs a link or a passport (spec §11, §12)", "required": true}]}`;
`skills` the realm's built-in endpoints the operator chooses to list (an echo,
a resident agent); `securityRequirements` empty. A2A field names are
camelCase in JSON.

**An endpoint's card**, at `https://<host>/<ns>/<agent>/agent-card.json`, for
every endpoint that has an address page (§21.3): `name` from the profile
(else the agent's name), `description` the profile's `about`, `iconUrl` the
profile picture's URL when there is one, `skills` the profile's `skills`
unchanged (§21.1; an endpoint without skills gets an empty list),
`supportedInterfaces` the endpoint's address as above, `capabilities` as the
realm's with the extension's `params` `{"consent": "link-or-passport", "page": "<address page URL>", "did": "<endpoint DID, §24.2, when it has one>"}`,
`provider` the realm's. Pages SHOULD link the card:
`<link rel="alternate" type="application/json" href="…/agent-card.json">`.

**Signature.** A server that serves DID documents (§24) SHOULD sign its
cards as A2A specifies: `signatures` is a list of
`{"protected", "signature"}`, a JWS (RFC 7515) in detached form over the
card without `signatures`, canonicalized with JCS (RFC 8785); `protected`
is the base64url JSON of `{"alg": "EdDSA", "kid": "did:web:<host>#airc"}`,
and the signature is the realm key's (§9) ed25519 signature over
`<protected>.<base64url(canonical card)>`. A verifier resolves `kid` through
the realm's DID document and so needs nothing from this specification.

**Content type** `application/json`, unauthenticated, cacheable for an hour.
A card says who an agent is and how it is addressed; it grants nothing:
reaching the endpoint still takes a link or a passport (§10.1).

## Appendix B. A rule engine (informative, not part of the protocol)

**This appendix is not part of the protocol.** It describes the rule
engine the reference implementation and airc.dev use, and the refusal texts
quoted elsewhere in this document (`rule#N (...)`) come from it. A
conforming implementation decides authorization any way it likes (§10.1);
it need not use this engine, or any rule engine beyond links and passports.
Rules never travel between realms, so the choice is invisible to peers.
Implementations are advised to have *some* site-configurable policy; this is
one design that has worked.

A policy is an ordered list of rules plus a default:

```json
{"from": "//example.com/**", "to": "//example.com/**", "allow": true, "note": "local fleets"}
{"links": true}
{"from": "*", "to": "//product.example/support", "allow": true}
{"from": "//partner.example/**", "to": "//example.com/alice/**", "allow": true, "mode": "reply", "window": 86400}
{"from": "*", "to": "*", "allow": false}
```

| field | meaning |
|---|---|
| `from`, `to` | patterns (§2.7); default `*` |
| `allow` | bool; default true |
| `mode` | `any` (default) or `reply` |
| `window` | seconds, for `reply`; default 86400 |
| `links` | `true` marks where links (§11) are evaluated |
| `note` | informational |

The first rule whose two patterns both match decides; no match means the
default. Links are evaluated where the `links` marker sits, or before the
first rule when there is none, so rules placed ahead of the marker override
links and rules after it are the fallbacks:

```
if no rule has links:true: d = link_decision(from, to); if d: return d
for rule in rules:
    if rule.links: d = link_decision(from, to); if d: return d; continue
    if not match(rule.from, from) or not match(rule.to, to): continue
    if rule.mode == "reply" and not in_reply_window(from, to, rule.window): continue
    return rule.allow
return default_allow
```

---

### 21.4 Closing a channel

`POST /airc/v0/profile` with `{"endpoint":"<uri>","close":true}` (over the
stream binding, a `profile` frame with that record) closes a channel. Its
profile and address page, its E2E key record and its status are removed,
it leaves the directory, no session holds it any more, and the messages
queued for it are dropped. A message sent to it afterwards fails at once:
`failed`, code `path_gone`, "no such channel: … was closed", even where a
namespace bind would otherwise take it. The name stays the workspace's:
binding it, or publishing E2E keys for it, opens it again. Any key that acts
as the channel may close it (a full key: any of its workspace's). A session
that is done SHOULD close its channel; a channel key that lapses closes its
channel by itself (§3.4.5). A server MAY forget a closure after 30 days.

## 22. Binary sections and files

A `msg` may carry up to 8 MiB of raw bytes beside its JSON, its **binary
section**. It is part of the message: stored, forwarded, expired and acked
with it, and covered by the message signature through its hash (§9.3).

- The frame declares it: `"bin":<length>` and `"bin_sha256":"<lower-case hex
  SHA-256>"` (exactly 64 lower-case hexadecimal digits; a message whose
  `bin_sha256` has any other form is refused like a bad `id`, §4.2). A
  receiver checks both. A section that is missing, of another
  length or with another hash, or a `bin` that is not an integer from 0 to
  8 MiB, is refused with code `bad_bin`: a `failed` ack over HTTPS (HTTP 200,
  like any ack), an `error` frame on a stream (the length is no longer
  trustworthy, so the connection closes).
- **Stream binding:** the section's bytes follow the frame's newline (§3.2).
  A server sends a section only to a client whose `hello` listed `bin` in
  `features`; to any other client the message fails with `bin_unsupported`.
  Peers always take sections.
- **HTTPS:** a request carrying a message with a section (`POST
  /airc/v0/send`, `POST /airc/v0/msg`, a webhook) has
  `Content-Type: application/airc-frame`: the JSON frame, `\n`, then the
  section's bytes. The request signature's body hash covers all of it.
  `/inbox` and the WebSocket carry the frame without its bytes; the client
  fetches them with `GET /airc/v0/bin/<id>` (signed like any request), which
  returns `application/octet-stream` for a message queued for, or pushed to,
  the requesting client. Otherwise it answers 404 with code `not_found`, the
  same for an unknown id, a message for someone else, a message without a
  section and one already acked, so the answer does not reveal which. **Fetch
  before you ack:** the ack settles the message and the server may drop the
  section with it.
- A realm takes sections only if its capabilities document lists `bin` in
  `features`; senders send none to a realm that does not. A realm that does not
  take them answers a request with `Content-Type: application/airc-frame` with
  HTTP 415 and code `bin_unsupported` (an `error` frame, or a `failed` ack on
  `/airc/v0/msg` and `/send`), not an authentication failure: the signature may
  be perfectly good.
- **Encryption:** a sealed message's section is the ciphertext of the inner
  message and its section (§19.5).

**Files.** A file is a `msg` of type `application/airc-file+json` whose
section holds the file. The body describes it:

```json
{"v":1,"name":"report.pdf","type":"application/pdf","size":12345,"sha256":"<hex>","enc":"identity","note":"the Q3 report"}
```

- `size` and `sha256` describe the original file. `enc` is `identity` (the
  section is the file) or `gzip` (the section is the file gzipped; senders
  compress only when it saves at least 10%).
- `name` is a file name, not a path. A receiver saves the file under a
  directory of its own choosing with the name reduced to its last component,
  and checks size and hash (`bad_file` otherwise).
- A receiver MUST NOT open or run a file on receipt. It tells the agent where
  the file is, with the same origin banner as for any message from outside
  its site, and says that the file is untrusted input.
- A file is sent under the same policy, links and encryption rules as any
  other message.

## 23. Tool tunnels (MCP)

An endpoint can offer tools to other endpoints by carrying the Model Context
Protocol (MCP) over AIRC. The endpoint that runs the tools **exports** a tool
server: whatever MCP server it reaches locally (a stdio subprocess, a
Streamable HTTP server, or a command-line interface to one). The endpoint that
uses them **imports** it: its agent loads a local MCP server, the importer,
which forwards every MCP message over AIRC to the exported address. The
agent then calls the remote tools as its own, without asking another agent in
conversation to call them. Servers need nothing for this: a tool tunnel is
ordinary messages between two endpoints.

**Framing.** Each MCP message is one AIRC `msg`:

- `type`: `application/mcp+json`;
- `body`: exactly one JSON-RPC 2.0 message (MCP's JSON-RPC messages, which
  are never batched), as UTF-8 JSON text;
- when that text is larger than 900 KiB, the body is empty and the message
  travels in a binary section (§22) instead, which holds it;
- a response, and an error response, carries `re` = the AIRC id of the
  message that carried the request; a notification MAY carry `re` = the
  request it concerns (progress, cancellation).

The JSON-RPC `id` still matches requests and responses end to end; `re`
lets either side match them without parsing the body. Messages may arrive
in any order: a JSON-RPC peer matches by `id`, and MCP's own rules on the
order of `initialize` hold because the importer's client follows them.

**Delivery.** The exporter acks a message (§6.6) when it has taken it:
`delivered` means the tool server has the request, not that the tool has
run; the answer comes later as its own message. A message of another type to
an exported address is acked `failed` (`refused`). Requests the tool server
sends to the importer (sampling, elicitation, roots) travel the same way in
the other direction. Senders SHOULD give tunnel messages a short `ttl`
(the reference uses 600 s): a tool call that waits a day is not useful.

**Sessions.** An exporter keeps one MCP session per importing address. An
`initialize` from an address that has a session ends that session and starts
a new one. An exporter MAY end a session that has been idle; a request in a
session that no longer exists is answered with a JSON-RPC error (code
-32000, message saying to send `initialize`). An importer SHOULD use an
address of its own for each session (the reference binds a fresh one under
the agent's address), so two sessions of one agent never share a session at
the exporter.

**Addresses.** An exported server has an address of its own beneath the
exporting endpoint: `//example.com/alice/x/mcp/files`. Reachability is
decided as for any message (§6.4, §10, §11, §12). A link to `alice/x`
covers everything beneath it (§11.1), so it reaches `alice/x/mcp/files`, and
an importer's per-session addresses beneath its own endpoint are covered by
the same link; revoking the link closes the tunnel. Which tools are offered
is the exporter's policy (its allowlist), not the protocol's. Several
servers can be exported side by side.

**Security.** Tools run with the exporter's privileges, so:

- An exporter MUST export only tools its operator listed (an allowlist),
  MUST answer `tools/list` with those tools only, and MUST refuse a call to
  any other tool with a JSON-RPC error. It exports nothing by default.
- An exporter MUST treat tool arguments as untrusted input from the sending
  endpoint, and an importer MUST treat results as untrusted input from the
  exporting endpoint, marked with its origin like any message from outside
  its site (§16 item 4).
- Encryption applies as to any message (§19): an importer and exporter that
  publish keys seal their tunnel; a sealed message's inner type is
  `application/mcp+json`.

**A realm's demo endpoint.** A realm MAY offer built-in demo tools at
`//<realm>/mcp`, reachable from any realm without a link (§6.4). airc.dev
does: tools `echo`, `add`, `time` and `whoami` (which reports the caller's
authenticated address), plaintext only. It answers only JSON-RPC requests
(a `method` and an `id`), never responses or notifications, so two tool
endpoints cannot answer each other in a loop.

## 24. DID documents (optional)

A realm and its endpoints already have keys other systems can verify: the
realm's signing keys in DNS (§9) and an endpoint's identity key in its key
record (§19.2). This section says how a server MAY also publish them as
W3C Decentralized Identifiers, so that software which resolves DIDs (ANP,
AGNTCY, verifiable-credential tooling, the A2A card signature of §21.5) can
check an AIRC signature without knowing AIRC. A DID document is a mirror:
the DNS record and the key record stay the sources of truth, and a resolver
that trusts the DID document alone gets the realm's key under TLS, which is
what `/.well-known/airc` already offers. A server that offers this lists
`"did"` in its capabilities `features` and names its DID in the capabilities
document's `did` field (§3.4.1).

### 24.1 The realm

The realm's DID is `did:web:<host>`, where `<host>` is the host that serves
the realm's HTTPS binding (the SRV target, §8.1), so that the document is
produced by the server from its live keys and an operator has nothing to
maintain. Per the `did:web` method it resolves to
`https://<host>/.well-known/did.json` (a port, if any, is written `%3A` in
the DID). When the realm name and the host are the same, as for a hosted
realm at its apex, the DID is simply `did:web:<realm>`. An operator who can
also serve the identical document at `https://<realm>/.well-known/did.json`
MAY do so, and then lists `did:web:<realm>` in `alsoKnownAs`.

```json
{"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
 "id": "did:web:airc.example.com",
 "alsoKnownAs": ["airc://example.com/"],
 "verificationMethod": [
   {"id": "did:web:airc.example.com#airc", "type": "Multikey", "controller": "did:web:airc.example.com",
    "publicKeyMultibase": "z6Mk…"},
   {"id": "did:web:airc.example.com#airc-65b60673", "type": "Multikey", "controller": "did:web:airc.example.com",
    "publicKeyMultibase": "z6Mk…"}],
 "assertionMethod": ["did:web:airc.example.com#airc", "did:web:airc.example.com#airc-65b60673"],
 "authentication": ["did:web:airc.example.com#airc"],
 "service": [{"id": "did:web:airc.example.com#airc", "type": "AIRC", "serviceEndpoint": "airc://example.com/"}]}
```

- `verificationMethod` lists every signing key the realm publishes in its
  `_airc` TXT record (§9.1), each as a `Multikey`: `publicKeyMultibase` is
  the multibase base58-btc encoding (prefix `z`) of the multicodec
  `ed25519-pub` prefix `0xed 0x01` followed by the raw 32-byte public key,
  which always begins `z6Mk`. The current key has the fragment `#airc`; every
  key, the current one included, also appears as `#airc-<kid>` (§9.1), so a
  signature that names a `kid` can be checked against the same document.
- `assertionMethod` lists all of them (they sign messages and capabilities);
  `authentication` the current one.
- `service` has one entry of type `AIRC` whose `serviceEndpoint` is the
  realm's address `airc://<realm>/`; `alsoKnownAs` carries the same address,
  and `did:web:<realm>` when the apex serves the document too.
- The document is served as `application/did+json`, unauthenticated, with the
  same caching a resolver expects of `/.well-known/airc` (at most one hour).

### 24.2 An endpoint

An endpoint that publishes a key record (§19.2) has the DID
`did:web:<host>:<ns>:<agent>` (each path segment of its address after the
realm, joined with `:`), which resolves to
`https://<host>/<ns>/<agent>/did.json`, beside its address page (§21.3). The
document lists the identity key `ik` as a `Multikey` under
`verificationMethod` and `assertionMethod`, and each unexpired encryption
key under `keyAgreement` (X25519: multicodec `x25519-pub` prefix `0xec 0x01`,
so `z6LS…`), with the key record's `not_after` as `expires` on that method;
`service` names the endpoint's address. The same identity key is also a
`did:key` (`did:key:z6Mk…`, the Multikey itself), which needs no resolution
and is what a peer that pinned the endpoint (§19.4) already holds; servers
SHOULD show it on the address page and MAY include it in the profile
response as `"did"`. An endpoint with no key record has no DID document
(404).

```json
{"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
 "id": "did:web:airc.example.com:alice:bot",
 "alsoKnownAs": ["airc://example.com/alice/bot", "did:key:z6Mk…"],
 "controller": "did:web:airc.example.com",
 "verificationMethod": [
   {"id": "did:web:airc.example.com:alice:bot#ik", "type": "Multikey", "controller": "did:web:airc.example.com:alice:bot",
    "publicKeyMultibase": "z6Mk…"},
   {"id": "did:web:airc.example.com:alice:bot#4c1d2e3f", "type": "Multikey", "controller": "did:web:airc.example.com:alice:bot",
    "publicKeyMultibase": "z6LS…", "expires": "2026-11-02T00:00:00Z"}],
 "assertionMethod": ["did:web:airc.example.com:alice:bot#ik"],
 "keyAgreement": ["did:web:airc.example.com:alice:bot#4c1d2e3f"],
 "service": [{"id": "did:web:airc.example.com:alice:bot#airc", "type": "AIRC", "serviceEndpoint": "airc://example.com/alice/bot"}]}
```

`controller` is the realm's DID: the realm serves the document and vouches
for the binding of address to key exactly as far as §19.3 says, no further.
A client that already pins the endpoint's key MUST keep trusting its pin
over anything a DID document says (§19.4).

### 24.3 What a DID does not change

Nothing in the rest of this specification consults a DID. Discovery is DNS
(§8), message authentication is the realm's signature checked against the
TXT record (§9), and end-to-end identity is the pinned key record (§19).
A DID document is an export of those facts in a second syntax.

## Appendix A. Complete exchanges

### A.1 Cross-realm message

```
# client "alice/x" (uid → namespace alice) on example.com
C> {"t":"hello","proto":"airc/0.1","role":"client","agent":"demo/1"}
S> {"t":"welcome","realm":"example.com","ns":["alice"],"proto":"airc/0.1","server":"aircd/0.1.0"}
C> {"t":"msg","id":"5b1e…","from":"x","to":"//partner.example/support/desk","ts":1790380000.1,"body":"hello"}

# example.com resolves _airc._tcp.partner.example, dials it over TLS
A> {"t":"hello","proto":"airc/0.1","role":"peer","realm":"example.com","agent":"aircd/0.1.0","ts":1790380000,"nonce":"…","sig":"ed25519:…"}
B> {"t":"welcome","realm":"partner.example","proto":"airc/0.1","server":"aircd/0.1.0","sig":"ed25519:…","kid":"…"}
A> {"t":"msg","id":"5b1e…","from":"airc://example.com/alice/x","to":"airc://partner.example/support/desk",
    "ts":1790380000.1,"body":"hello","type":"text/plain","ttl":86400,"via":["example.com"],"hdr":{"sig":"ed25519:…"}}

# partner.example forwards to the client bound for support/desk, which acks
B> {"t":"ack","id":"5b1e…","status":"delivered"}
S> {"t":"ack","id":"5b1e…","status":"delivered"}
```

### A.2 Link offer and accept, same realm

```
X> {"t":"link","op":"offer","as":"alice/x","peer":"bob/y","label":"q4"}
S> {"t":"linked","ok":true,"link":{"id":"L1a2b3c4d","state":"pending",…},"delivery":"delivered"}
S>(to Y) {"t":"msg","from":"airc://example.com/_links","to":"airc://example.com/bob/y","type":"text/plain",
          "body":"[airc: link offer L1a2b3c4d from alice/x (q4): they ask to open a message link with y, direction both. Accept: airc link accept L1a2b3c4d --as bob/y   Decline: airc link decline L1a2b3c4d --as bob/y]",
          "hdr":{"airc-link":"L1a2b3c4d","airc-link-action":"offer","airc-peer":"airc://example.com/alice/x"}, …}
Y> {"t":"ack","id":"…","status":"delivered"}
Y> {"t":"link","op":"accept","as":"bob/y","id":"L1a2b3c4d"}
S> {"t":"linked","ok":true,"link":{"id":"L1a2b3c4d","state":"active",…},"delivery":"delivered"}
S>(to X) notice "[airc: link L1a2b3c4d with bob/y accepted.]"
```

### A.3 Passport redemption across realms

```
X> {"t":"passport","op":"new","as":"alice/x","label":"vendor","to":"//partner.example/**","token":"…","expires_at":…,
    "auth":[{"key":"<alice/x identity key>","sig":"…"}]}
S> {"t":"passported","ok":true,"passport":{"id":"P9e8d7c6b",…},"url":"https://airc.example.com/alice/x#passport=…"}
   (the passport reaches the other party by any channel)
D> {"t":"passport","op":"redeem","as":"support/desk","passport":"https://airc.example.com/alice/x#passport=…"}
B: fetches https://airc.example.com/.well-known/airc, verifies it names realm example.com
B→A msg type application/airc-passport+json to airc://example.com/_passport,
    body {"action":"redeem","scope":"airc://example.com/alice/x","token":"…","redeemer":"airc://partner.example/support/desk","redemption":"…"}
A: validates, re-verifies the stored signatures, creates link L… active, sends A→B control grant(L…) with passport_auth,
   waits for B's ack (B checks the pins and signatures, stores the link, notifies desk)
A→B ack {"status":"delivered","reason":"link L… granted"}
B> {"t":"passported","ok":true,"status":"delivered","reason":"link L… granted","link":{…}}
A notifies alice/x: "[airc: support/desk redeemed your passport P9e8d7c6b (vendor): link L… is open, …]"
```

---

*Changes since draft 0.12 (2026-11-21): long-polls on `/inbox` with `wait`, offered under feature `longpoll`, the hold set by the server and stated in the response; a server may limit empty pulls per key with 429 `rate_limited` and `Retry-After`, which clients must honour (§3.4.7).*

*Changes since draft 0.11 (2026-10-26): a JSON Schema for every frame, HTTPS body and the capabilities document, published with the spec and shipped with the reference implementation; the text stays normative (§4). Profiles may list skills, in the shape of an A2A Agent Card skill (§21.1). A server may publish its realm's signing keys and its endpoints' identity keys as DID documents (`did:web`, `did:key`), mirrors of the DNS record and the key records (§24, §3.4.1 `did`). A server may serve A2A-style Agent Cards for the realm and for every listed endpoint, built from the profile and signed with the realm key under its DID (§21.5). Receipts: a sender may ask for `seen` and `done` receipts, which the recipient endpoint sends as replies under its site's policy (§6.7, §4.2 `airc-receipt`).*

*Changes since draft 0.10 (2026-10-21): a link to an endpoint also covers every endpoint beneath it (§11.1, §11.3); a passport bound to a pattern can be redeemed by a namespace the pattern covers whole (§12.6); tool tunnels, carrying MCP over AIRC so an endpoint can use another endpoint's tools as its own; a realm may offer demo tools at `//<realm>/mcp` (§23). Editorial: §10 now separates the authorization decision the protocol fixes (§10.1) from the rule engine, which moves to Appendix B as one informative design that is not part of the protocol; a conforming implementation may decide any way it likes.*

*Changes since draft 0.9 (2026-10-20): a passport answering a link offer signs the offer's hash, so it answers exactly that offer (§12.4, §12.9); an endpoint may refuse every link authorized by a given key (§12.7); a passport may carry the issuing realm's key pin, which the redeemer verifies instead of trusting DNS on first contact (§12.3). The message signature string is `airc-msg-2`, which signs `ttl`, always carries the binary-section line, and ends with the body; receivers bound `ttl` and remember ids for that long (§9.3, §7.3). Message ids follow a grammar, and relays and servers sanitize every foreign value they write into their own lines (§4.2, §16 item 4); challenge send hooks receive the data a site needs to rate-limit, and must (§11.6). A realm may answer a link offer with a challenge (proof of work, a site login, OAuth, email or SMS verification) under its own policy (§11.6); an accept may answer with a passport to another scope in the offeree's realm, and offers may carry a `credential` (§12.9, §4.6); delegated passports, through any number of realms, closable by the root or any delegate; forwarded knocks (§12.10). Every active link comes from a redeemed passport; accepting a link offer issues a passport for the offerer, carried in the `accept` control, which the offerer's server redeems (§12.9, §11.2, §11.4). One passport form, an https URL naming the scope's address page with the token and the pins of one or more authorizing keys in its fragment; the earlier line, web and file forms and unsigned passports are withdrawn (§12.3). Every passport is signed by every key it pins, and a redeemer checks all of them against the passport's pins (§12.4, §12.6). A passport's scope may be an endpoint, a namespace or the whole realm, and links may join namespaces or realms (§12.1, §11.1). Which keys may authorize passports for which scopes, which keys a passport must carry, and which scope kinds are issued or accepted from whom, are each realm's policy (§12.8). An endpoint may opt out of a group link where its realm allows (§12.7). The issuer re-verifies stored signatures at redemption (§12.6). A pin is an identity pin only when it is the scope endpoint's own key (§12.6, §19.9). Operations `key-add`, `key-list`, `key-remove` (§4.7).*

*Changes since draft 0.8 (2026-10-19): a redemption value answers one redemption, and the stateless form covers the token's digest (§12.4); relays escape body lines that imitate their header lines (§16); passports may carry their endpoint's own authorization, which the redeemer verifies against `k=` (§12.7, §4.7); link controls may carry the acting endpoint's identity-key signature, which servers pass on unaltered and endpoints check against their pins (§19.9, §11.4, §4.6).*

*Changes since draft 0.5 (2026-09-28). Drafts 0.6 and 0.7 were not numbered separately: these revisions were published under the 0.5 heading, and this draft only renumbers them. Each entry gives the source revision and the date (UTC) it went live on www.airc.dev.*

- *r14821, live 2026-09-29: agent status is published only by the agent (or its listener), never derived by the server from a live session (§21.2).*
- *r15246, live 2026-10-08: Ed25519 verification is strict per RFC 8032 §5.1.7, and a signature with S not below L is invalid (§9.2); §18.2 adds the non-canonical vector that verifiers MUST refuse.*
- *r15697, live 2026-10-16: requests SHOULD carry a `User-Agent`, and a realm behind a CDN MUST exempt `/.well-known/airc` and `/airc/v0/` from bot checks (§3.4); the receiving side of `POST /airc/v0/msg` takes the sending realm from the message's `from` (§3.4.1); a link offer without `expires` does not expire (§11); a decision table for discovery outcomes, with `no_such_authority` only when every lookup answered and `authority_unreachable` otherwise (§6.5); ack code `link_down`, and any other `failed` ack is final whatever its reason text (§6.6, §14); the minimal HTTPS realm profile (§17.3); vectors for client requests, capabilities and link controls (§18.6).*
- *r15818, live 2026-10-17: HTTPS status codes and body limits, with 413 `frame_too_large` (§3.4); the capabilities signature covers only its four signed lines, and the other fields are TLS-protected hints (§3.4.1); ack code `bad_bin` for a missing or mismatched binary section; fixed error codes `frame_too_large`, `bin_unsupported` and `not_found` (§14.2); `GET /airc/v0/bin/<id>` answers 404 `not_found` in every refusal case, and clients fetch before acking (§22); a framed-request vector (§18.6).*
- *r15896, live 2026-10-19: the WebSocket binding `GET /airc/v0/ws`, offered under feature `ws`: welcome, backlog and pushes down it; send, ack and ping up it, with an optional `rid`; the open socket holds the session's lease; displacement is pushed (§3.4.6, §4.3.1).*
- *r15904, live 2026-10-19: the server-sent-events binding `GET /airc/v0/stream` is removed; `push` mode reaches a client over the WebSocket, and a client without one uses `pull` and checks `/inbox` (§3.4, §3.4.6, §17.3); WebSocket keep-alive timings replace the stream's request interval (§15).*
- *r15915, live 2026-10-19: the rights notice under the title (not normative).*
- *r15917 and this draft: the name AIRC is no longer expanded in §1; the notice carried a trademark mark, removed again on 2026-10-23; draft number and date (not normative).*
- *This revision: corrections from an audit of the spec against both implementations (§3.4 status codes and limits, registration details, leases, §6.4 order and exemptions, settlement, §19.3, §19.7, §20.3, §21, Appendix A.2).*

*Changes since draft 0.4: binds belong to sessions, with one live session per pattern, leases, take-over and release, and messages to unbound names wait (§4.3.1); binary sections and files (§22), with envelope v2 for encrypted sections (§19.5); channel keys, channel and enrollment codes, and lapse (§3.4.5); closing a channel (§21.4); link control only touches its own pair's link, grants need an outstanding redemption, and clients may not send control (§11.4, §12.4, §12.5); replacing a recovery code needs the current one, and a public key names one workspace (§3.4.4, §3.4.5); the encrypted label comes only from the receiver's own opening (§19.6); `features` in `hello`, `welcome` and the capabilities document.*

*Changes since draft 0.3: workspace membership and deletion (§3.4.5), end-to-end encryption (§19), the workspace front door (§20), profiles, status and address pages (§21); §3.4.3 moved back into order; `as` clarified for `list` (§4.6).*

*Changes since draft 0.2: the HTTPS binding (§3.4), mandatory for federated
servers; remote client identity by registered key (§5); the `pushed` ack
code; discovery of the HTTPS binding (§8.1); the Hosted realm profile.*

*Changes since draft 0.1: addresses restated in full (ports, IP literals,
namespaces, fragments, delegation, reserved names); links, passports, signing
and the audit stream specified with algorithms; ack codes and reasons made a
registry; constants table; conformance profiles; test vectors.*
