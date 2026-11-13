# AIRC Addressing Scheme — Specification

Copyright © 2026 Rafael Baptista. All rights reserved. The AIRC specification, documentation, test vectors and reference implementation are published for evaluation and discussion. Licensed under the AIRC Public Preview License 1.0 (<https://airc.dev/license>), a free license for implementation and use that ends on May 1, 2027. Patent pending.

*Rafael Baptista, 25 September 2026; draft 0.2, 19 October 2026. Reproduced in
this tree from the author's document so the addressing and transport
specifications travel together; the transport spec is `airc-spec.md`.*

## 1. Status and abstract

Status: draft 0.2, for discussion. Not yet submitted anywhere.

Draft 0.2 brings this document into line with the transport specification as
deployed (`airc-spec.md`, draft 0.8): authority lookup and ports (5.1), the
error classes (9), reserved names (8) and instance identity (7.2). It closes
the open questions that the transport spec settled, and reserves `@` (14).
The grammar and the resolution model are unchanged. Where the two documents
differ, the transport spec governs.

This document specifies the address syntax and resolution model for AIRC, a decentralized, DNS-routed protocol for real-time agent-to-agent
messaging. It covers only addressing: how an agent is named, how a name is
written, and how a name is turned into a reachable endpoint. Transport, message
format, and authentication are out of scope here; they are specified in the
transport spec (`airc-spec.md`).

An AIRC address is a URI of the form `airc://<authority>/<path>`. The authority
is a DNS name that owns the address space; the path is an opaque, hierarchical
namespace whose meaning is defined by that authority. The final path segment
names the endpoint. Any agent that owns a path prefix is the resolver for
everything beneath it, so sub-agents can be created and addressed without the
host learning of them.

Three spellings map onto that one grammar: the full URI, a scheme-elided
network form (`//host/alice/net-ops`), and a local shorthand with no authority
(`alice/net-ops`, `net-ops`).

## 2. Terminology and conventions

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

| Term | Meaning |
|------|---------|
| Agent | Any process that can send or receive AIRC messages. Users, daemons and sub-agents are all agents. |
| Address | A string identifying one agent or one namespace, in any of the three forms in section 4. |
| Authority | The DNS name (plus optional port) that owns an address space. Written after `//`. |
| Path | The segments after the authority. Opaque to everyone except the authority and the agents it delegates to. |
| Segment | One `/`-separated element of the path. |
| Endpoint | The agent named by the last segment of a path. The thing a message is delivered to. |
| Namespace | A path prefix. Owned by the agent that segment names, or by the authority if none. Written with a trailing `/`. |
| Resolver | Any party that maps a path (or path suffix) to a transport-level destination. Hosts, users and agents can all be resolvers. |
| Delegation | A resolver handing responsibility for a path prefix to another agent. |
| Local form | An address with no authority. Resolved by the local resolver only. |
| Sender | The agent that originates a message. |
| Relay | Any intermediate party that forwards a message without being its endpoint. |

## 3. Syntax

An AIRC address is a valid RFC 3986 URI under the `airc` scheme. The grammar
below is a restriction of the generic URI grammar, not an extension; any
conforming URI parser can split an AIRC address correctly.

```
airc-uri      = "airc:" network-form
network-form  = "//" authority "/" path [ "#" fragment ]
local-form    = path [ "#" fragment ]

authority     = host [ ":" port ]
host          = dns-name / IPv4address / "[" IPv6address "]"
port          = 1*5DIGIT                         ; 1 to 65535

path          = segment *( "/" segment ) [ "/" ]   ; trailing "/" = namespace, see 7
segment       = name-char *62( name-char )         ; 1 to 63 characters
name-char     = ALPHA / DIGIT / "-" / "_"

fragment      = *pchar                             ; RFC 3986; not part of the address
```

Rules:

- Segments are case-insensitive. Implementations MUST compare them
  case-insensitively and SHOULD emit them in lowercase.
- A segment MUST NOT begin or end with `-`. Segments beginning with `_` are
  reserved (section 8).
- `.` is not permitted in a segment. This guarantees the authority is the only
  dotted component and a parser never has to guess where the host ends.
- `@`, `:`, `!`, `~`, `#` (outside a fragment), `*`, `%` and whitespace are not
  permitted in a segment. This keeps every address free of shell expansion in
  bash, zsh, fish, PowerShell and cmd, and keeps it visually distinct from an
  email address.
- Percent-encoding is not used. Names that cannot be expressed in `name-char`
  are not valid AIRC names.
- The total address MUST NOT exceed 1024 octets. Path depth is unbounded by
  the grammar (section 6).
- `airc:` followed immediately by a path with no `//` is not valid. The scheme
  always introduces the network form.

The fragment is carried by the URI but is not part of the address for
resolution or comparison purposes. Its use for instance identity is described
in section 7.

## 4. Address forms

One grammar, three spellings. All three denote the same endpoint once
resolved; they differ only in how much context the writer supplies.

| Form | Example | Where used | Resolved by |
|------|---------|------------|-------------|
| URI | `airc://sysops.example.com/alice/net-ops` | Documents, links, config files, envelope headers | DNS, then the authority |
| Network | `//sysops.example.com/alice/net-ops` | Command lines, chat, anywhere a human types | DNS, then the authority |
| Local | `alice/net-ops` or `net-ops` | Command lines on the same machine or fleet | The local resolver only |

### 4.1 URI form

The canonical form. Implementations MUST accept it everywhere an address is
accepted, and MUST use it in any on-the-wire field that carries an address
(for example the From and To of an envelope). It is the only form that is
unambiguous outside a local context.

### 4.2 Network form

The URI with `airc:` elided. This mirrors the scheme-relative URL convention in
HTML (`//cdn.example.com/x.js`). A leading `//` is the visual signature of an
AIRC address; a reader who sees it knows the string is neither an email
address nor a file path.

Implementations MUST treat a network-form address as equivalent to the URI
form with `airc:` prepended.

### 4.3 Local form

An address with no authority. It is resolved entirely by the local resolver,
which is the authority for the local machine or fleet. The protocol does not
define what local segments mean; it defines only the default that ships with
the reference resolver:

- `net-ops`: an agent in the sender's own namespace (its first, where it has
  several).
- `alice/net-ops`: an agent in namespace alice: a user, fleet or workspace, as
  the operator assigns namespaces.
- Deeper local paths follow the same delegation rules as network paths
  (section 6).

A local-form address MUST NOT appear in an on-the-wire address field. Before a
message leaves the local resolver, the resolver MUST rewrite every local-form
address it contains into URI form using its own authority, so that the
recipient can reply.

### 4.4 Equivalence

Two addresses are equivalent if, after case-folding the authority and every
segment, removing a trailing `.` from the host, omitting the default port
2472, and dropping the fragment, the resulting
strings are identical. A trailing `/` is significant: `//host/alice` and
`//host/alice/` are not equivalent (section 7).

## 5. Resolution

Resolution turns an address into a transport-level destination for its
endpoint. It has two stages: the authority is located through DNS, and the
path is then resolved by the authority and whatever it has delegated to.

### 5.1 Locating the authority

For a network or URI form address, the sender's resolver locates the
authority as the transport spec defines (its §8.1). In summary, it tries in
order:

1. If the address carries an explicit port, or the authority is an IP
   literal, it connects directly (port 2472 if none is given), with no DNS.
2. A static entry in its own configuration.
3. DNS SRV records: `_airc-https._tcp.<host>` for the HTTPS binding (default
   port 443), and `_airc._tcp.<host>` for the stream binding. It follows
   standard SRV priority and weight rules and uses the target and port.
4. `https://airc.<host>/`, or an A/AAAA lookup of `airc.<host>` on port 2472.
5. `https://<host>/`, or an A/AAAA lookup of `<host>` on port 2472.

The default ports are 443 for the HTTPS binding and 2472 for the stream
binding. Federation between authorities uses HTTPS, which every federating
authority MUST offer. An authority also publishes its signing keys in DNS as
TXT records at `_airc.<host>`, so that others can verify what it sends; that
belongs to the transport spec (§8.2, §9).

SRV is the mechanism that separates a domain from a machine.
`//example.com/alice/net-ops` can route to any host the domain's administrator
points the SRV at, and can change without any address changing. This is the
property that makes AIRC addresses behave like email addresses without looking
like them.

An IP-literal authority (`//[2001:db8::1]/alice/net-ops`,
`//192.0.2.1/net-ops`) skips DNS and connects directly. Implementations MUST
support it; it is intended for bootstrapping and testing, not for published
addresses.

### 5.2 Resolving the path

Once connected, the sender presents the full path to the authority's resolver.
The authority resolves as many leading segments as it owns, then either
delivers (if the endpoint is reached) or hands the remaining path to the agent
it has delegated that prefix to (section 6).

Senders and relays MUST NOT interpret the path. They MUST NOT split it, assume
a segment is a user, a team or a sub-agent, or rewrite it. The only party
permitted to give a segment meaning is the resolver responsible for it.

### 5.3 Local resolution

A local-form address is resolved by the local resolver using its configured
rules. The reference resolver's defaults are given in section 4.3. A local
resolver MUST know its own authority (its DNS name, or an IP-literal if it has
none) so it can rewrite local addresses to URI form on egress.

A network-form address whose authority is the local resolver's own authority
MUST be resolved as if it were the corresponding local form.
`//sysops.example.com/alice/net-ops` typed on sysops.example.com does not
leave the machine.

## 6. Delegation

*Implementation status (2026-10-19): the reference servers implement the
forwarding half of delegation. A session bound for P receives messages for
P/x/... with the full destination intact, and the most specific bind wins
(transport spec §4.3, §4.3.1). Resolving beneath P is left to the agent bound
at P; no shipped agent keeps a routing table of sub-agents or returns Path
gone for a departed child, and the reference relay delivers such messages to
the agent at P itself. In practice sub-agents usually bind directly at the
server, which therefore does learn of them. The resolution chains described
in this section and in 11.3, 11.4 and 12.5 are the design.*

Every agent is the resolver for its own subtree. This one rule gives AIRC
unbounded, ephemeral sub-agent addressing without any central registry.

### 6.1 The rule

If an agent is reachable at path P, then that agent is the authoritative
resolver for every path of the form P/.... The resolver above it MUST forward
any message addressed beneath P to the agent at P with the remaining segments
intact, and MUST NOT attempt to resolve those segments itself.

This is the same structure as DNS zone delegation: a parent zone knows only
that a subtree exists and who serves it, never what is inside.

### 6.2 Consequences

- **Creation is local.** An agent at `//host/alice/research` that spawns a
  worker registers `spider1` in its own routing table.
  `//host/alice/research/spider1` is immediately addressable. No call to the
  host, no call to alice.
- **Uniqueness is scoped.** A segment need only be unique among its siblings.
  `//host/alice/research/spider1` and `//host/bob/research/spider1` are
  different agents and never conflict.
- **Depth follows the spawn chain.** A path is as deep as the sequence of
  agents that created it. The grammar imposes no limit; the 1024-octet ceiling
  in section 3 is the only bound.
- **Teardown is local.** When spider1 exits, research removes it. A later
  message to that path receives a resolution error from research (section 9),
  not from the host.
- **The host never learns.** A host, and any relay, sees only the prefix it
  delegated. Sub-agent existence, count and naming are invisible above the
  delegating agent.

### 6.3 Resolver responsibilities

An agent that accepts delegation for a prefix MUST:

- Accept messages addressed to any path beneath its prefix and either
  deliver, forward, or return a resolution error. It MUST NOT silently drop
  them.
- Offer a listing of its immediate children (P/ in section 7) only if it
  chooses to. There is no resolution query protocol: listing, where offered,
  is a directory agent (`_dir`, section 8) or the authority's front door
  (transport spec §20). It MAY refuse listing while still delivering to known
  children.
- Rewrite any local-form address in outgoing envelopes to the full URI form,
  using its own full path as the prefix, so that a sub-agent's From is always
  globally resolvable.

An agent MAY delegate further: spider1 can itself accept delegation for
spider1/.... The rule is recursive.

### 6.4 Peer discovery among ephemeral agents

Two sub-agents under different parents find each other through the envelope,
not a directory. When `//host/alice/research/spider1` sends to
`//host/bob/encyclopedia/summarizer3`, its envelope From carries its full URI.
summarizer3 replies to that URI; resolution runs host → encyclopedia →
summarizer3 in one direction and host → research → spider1 in the other.
Neither parent nor the host maintains a table of the other's children.

How spider1 learned of summarizer3 in the first place (an introduction from
research, a listing of encyclopedia/, or a capability announcement) is a
matter for the discovery layer and is out of scope here. This section
guarantees only that once an address is known, it resolves.

## 7. Endpoints, namespaces and instances

### 7.1 Endpoint versus namespace

A path without a trailing `/` names an endpoint: the agent at the last
segment. A path with a trailing `/` names a namespace: the set of agents
beneath that prefix.

| Address | Denotes |
|---------|---------|
| `//host/alice/research` | The research agent itself |
| `//host/alice/research/` | Every agent research has delegated to, not research |
| `//host/net-ops` | A system-level agent in the host's root namespace |
| `//host/` | The host's root namespace (not a valid destination: the grammar requires at least one segment) |

A namespace is not an endpoint. A message addressed to a namespace is a
fan-out request; whether the resolver for that namespace honours it
(delivering to all children, to a designated subset, or refusing) is that
resolver's policy. Implementations MUST accept the syntax and MAY refuse the
operation.

The same rule resolves the "is foo a user or an agent?" question: it is never
a question the sender has to answer. `//host/foo/` is the namespace foo.
`//host/foo`, when foo is a namespace the authority knows, is that
namespace's front door (transport spec §20): a directory reply, a designated
agent, or No such path. Otherwise it is the endpoint named foo.

### 7.2 Instance identity

An address names a role, not a process. `//host/alice/research/spider1` may be
torn down and re-created many times with the same name. Receivers that need
to distinguish one incarnation from another SHOULD use the URI fragment, which
is carried but ignored by resolution:

```
//host/alice/research/spider1#run-42
//host/alice/research/spider1#7f3a9c
```

The fragment is chosen by the agent it describes and reported in its outgoing
From. A message arriving with a fragment that does not match the current
incarnation MAY be rejected by the endpoint with a stale-instance error
(section 9). Resolvers MUST strip the fragment before comparison and routing
and MUST pass it through to the endpoint unchanged.

In deployed practice the authority, not the fragment, keeps incarnations
apart: a name is held by one live session at a time under a lease, a second
process asking for a held name is refused with a free name suggested
(`spider1-2`), and a session can explicitly take a name over (transport spec
§4.3.1). The fragment remains available to endpoints that want it.

This keeps addresses stable for configuration and humans while letting the
protocol tell a fresh spider1 from a stale one.

## 8. Reserved and well-known names

Segments beginning with `_` are reserved for this and future AIRC
specifications. Authorities MUST NOT assign them to users or agents, except
as the operator configures (transport spec §2.6). This
mirrors the `_service` convention in DNS and keeps the reserved space out of
the way of ordinary names.

The following are defined now. All are optional to implement; an authority
that does not implement one MUST return a resolution error rather than
assigning the name to something else.

| Name | At | Purpose |
|------|----|---------|
| `_resolver` | `//host/_resolver` | The authority's own resolver; answers a health check |
| `_postmaster` | `//host/_postmaster` | Human-facing contact for the authority, by analogy with RFC 5321 postmaster@ |
| `_dir` | `//host/_dir`, `//host/alice/_dir` | Directory or listing agent for that namespace, when listing is offered |
| `_passport` | `//host/_passport` | Where passport redemptions are sent (transport spec §12.5) |
| `_links` | `//host/_links` | Sender of the authority's own notices about links and passports; not an endpoint |

Authorities and delegated agents MAY define further `_`-prefixed names for
their own use, but SHOULD prefer plain names for anything that is not
protocol machinery. The transport spec's list (its §2.6) is the registry of
well-known reserved names. An authority may also reserve ordinary names as a
matter of its own policy (for example, names it keeps for its own agents);
that is not part of this scheme.

Names that are not reserved but are conventional are recommendations to
authorities, not requirements. (An agent that receives messages addressed to
a bare namespace is now specified: the front door's agent mode, transport
spec §20.)

## 9. Resolution errors and lifetimes

Because sub-agents are ephemeral, resolution failure is a normal event and
senders must be able to distinguish its causes. The following classes are
defined; exact codes and their wire representation belong to the transport
spec (its §6.5 and §14.1).

| Class | Meaning | Raised by | Sender should |
|-------|---------|-----------|---------------|
| No such authority | Every lookup of section 5.1 was answered, and none found a record | Sender's resolver | Treat as permanent; check the address |
| Authority unreachable | Found but nothing answered, or a lookup went unanswered (timeout, server failure), so the authority may exist | Sender's resolver | Retry with backoff (the message is queued) |
| Link down | A hop lost its connection to the next hop before the message got through | That hop | Retry (the message is queued) |
| No such path | A resolver on the chain does not know the next segment | The last resolver that owned a prefix | Treat as permanent unless the path was recently valid |
| Path gone | The segment existed and has been torn down | The authority (for a closed channel) or the delegating agent | Treat as permanent; the instance is finished |
| Endpoint offline | The namespace is known but nothing is bound for the endpoint | The authority | Nothing to do; the message is queued until the endpoint binds or it expires |
| Not delegated | A prefix is owned but its owner does not accept sub-paths | The owning agent | Treat as permanent (defined; not produced by the reference implementations) |
| Namespace, not endpoint | Message sent to P/ where fan-out is refused | The resolver for P/ | Address a specific endpoint |
| Stale instance | Fragment does not match the current incarnation | The endpoint | Re-discover the address; drop the old fragment (defined; not produced by the reference implementations) |
| Refused | Resolution succeeded but policy denies delivery | Any resolver | Do not retry without a change in credentials |

An error MUST identify the deepest resolver that produced it, as a URI, so the
sender knows where the chain broke. No such path from
`//host/alice/research` tells the sender the parent is alive and the child is
not; the same error from `//host/_resolver` tells it alice or research is
missing.

### 9.1 Lifetime hints

*Status: reserved for a future revision. No current implementation attaches a
resolution TTL to a path resolution. This section concerns path resolution
only; authority lookups are cached as the transport spec says (§8.1).*

A successful resolution MAY carry a time-to-live in seconds, set by the
resolver that produced the final hop. Senders MAY cache a resolved destination
for at most that long. A resolver SHOULD set a short TTL (seconds to minutes)
for agents it knows to be ephemeral and MAY set a long one for durable agents.
Absence of a TTL means the result MUST NOT be cached.

TTLs are advisory. A cached destination that fails MUST be re-resolved, and a
Path gone or Stale instance error MUST invalidate any cached entry for that
address.

## 10. Security considerations

This document defines names, not trust. The points below are the
addressing-layer consequences that the authentication and transport
specifications must build on.

- **An address is not an identity.** Anyone can write
  `//example.com/alice/net-ops` in a From field. Resolvers and endpoints MUST
  NOT treat the address in an envelope as proof of origin. Origin
  authentication (signatures bound to an address, or transport-level identity
  of the delegating chain) is defined elsewhere.
- **Authorization follows delegation.** Whether spider1 may accept a message
  from outside alice/ is decided first by the host, which applies its policy
  before forwarding, then by each resolver beneath it (alice's, then
  research). Each resolver on the chain MAY apply policy
  to messages passing through it and MUST NOT rely on a resolver below it to
  do so.
- **Opaque paths limit enumeration.** Because a relay never interprets a path,
  it cannot list sub-agents it did not delegate. Namespace listing (P/) is the
  only enumeration primitive and is opt-in per resolver. Authorities SHOULD
  refuse listing of user-level namespaces to unauthenticated senders.
- **Delegation is a trust boundary.** An agent that delegates a prefix is
  trusting the child to resolve it correctly and to apply policy. A
  compromised sub-agent can misroute or accept anything beneath its own
  prefix, but cannot affect siblings or ancestors, because it never sees their
  traffic.
- **DNS is the root of trust for locating an authority.** Resolvers SHOULD
  validate SRV and address records with DNSSEC where available, and the
  transport spec MUST bind the connection to the authority name (for example
  via TLS with the SRV target's certificate) so that a spoofed DNS answer
  cannot silently redirect a domain.
- **Local-form rewriting must be correct.** A local resolver that rewrites
  net-ops to the wrong authority on egress produces a From that either does
  not resolve or resolves to a third party. Resolvers MUST know their own
  authority and MUST refuse to send with a local-form address if they do not.
- **Fragments are unauthenticated hints.** A fragment identifies an
  incarnation but proves nothing; it is a cache key, not a credential.
- **Reserved names are public.** `_resolver` and `_postmaster` are
  discoverable by construction. Authorities SHOULD rate-limit them and MUST
  NOT expose privileged operations through them without authentication.

## 11. Examples

### 11.1 Addresses

```
net-ops                                       # local: my own agent
alice/net-ops                                 # local: alice's agent on this machine
//sysops.example.com/net-ops                  # remote: system agent in the host root
//sysops.example.com/alice/net-ops            # remote: alice's agent
//example.com/alice/net-ops                   # domain-level; SRV picks the host
//example.com:7001/alice/net-ops              # explicit port
//[2001:db8::1]/alice/net-ops                 # IP literal, no DNS
//example.com/sre/alice/net-ops               # team/user/agent (authority's taxonomy)
//example.com/alice/research/spider1          # sub-agent, delegated by research
//example.com/alice/research/spider1#run-42   # same, with instance fragment
//example.com/alice/research/                 # namespace: all of research's children
airc://example.com/alice/research/spider1     # canonical URI form, as carried on the wire
```

### 11.2 A command-line exchange

```
$ co tell net-ops "nginx is down"
$ co tell alice/net-ops "nginx is down"
$ co tell //sysops.example.com/alice/net-ops "nginx is down"
```

In the first two cases the local resolver rewrites the address to
`airc://<local authority>/...` before sending, so net-ops can reply.

### 11.3 Resolution trace: sub-agent to sub-agent

`//example.com/alice/research/spider1` sends to
`//other.example/bob/encyclopedia/summarizer3`.

1. spider1's server sees a non-local authority and looks up
   `_airc-https._tcp.other.example` → SRV → its server, port 443.
2. It connects and presents the path bob/encyclopedia/summarizer3.
3. The host resolver owns bob; bob's resolver owns encyclopedia and has
   delegated beneath it to the encyclopedia agent.
4. encyclopedia receives summarizer3, finds it in its routing table, delivers.
5. The envelope From is `airc://example.com/alice/research/spider1#run-42`.
   summarizer3 replies to it; the reverse chain is host → alice → research →
   spider1.

Neither research nor encyclopedia had any prior knowledge of the other's
children.

### 11.4 Resolution trace: a torn-down sub-agent

spider1 has exited. A message arrives for `//example.com/alice/research/spider1`.

1. Host → alice → research resolve normally.
2. research no longer has spider1 in its table and returns Path gone,
   identifying itself as `airc://example.com/alice/research`.
3. The sender invalidates any cached entry and knows the parent is alive;
   whether to ask research for a replacement is an application decision.

### 11.5 DNS records for an authority

```
_airc-https._tcp.example.com.  IN SRV 10 50 443 sysops.example.com.
_airc-https._tcp.example.com.  IN SRV 20 50 443 backup.example.com.
sysops.example.com.      IN A   192.0.2.10
backup.example.com.      IN A   192.0.2.11
```

Every address under `//example.com/...` now routes to sysops, with no address
changing; a sender that tries SRV targets in order (the Python reference
does) fails over to backup.

## 12. Use cases

The scheme is judged against the six scenarios below. Each one adds a
requirement the previous ones did not; the design in sections 3 to 9 is the
smallest grammar that satisfies all six.

### 12.1 One user, one machine, a fleet of agents

A developer runs several long-lived agents on a workstation: net-ops, builder,
reviewer. They want to address them from the shell with the least typing
possible and no configuration.

Requirement: a bare name must work. `co tell net-ops "nginx is down"` is the
whole interaction.

How the scheme meets it: the local form (4.3). The local resolver expands the
bare name against its own authority and the sender's namespace (5.3).

### 12.2 Several users on one machine

A shared host has users alice and bob, each running their own agents, some
with the same names.

Requirement: addresses must be scoped per user without forcing every user to
pick globally unique agent names, and the scoping must be obvious to a reader.

How the scheme meets it: `alice/net-ops` and `bob/net-ops`. Uniqueness is per
parent (6.2), and the owner/thing shape is one readers already know from
repositories and package registries.

### 12.3 Agents across machines in one organization

The organization runs agents on sysops, build-01 and build-02. Agents on any
of them need to reach agents on the others, and the organization wants to move
agents between machines without every peer's configuration changing.

Requirement: an address that names the organization, not the box, with the
organization deciding which box serves it.

How the scheme meets it: `//example.com/alice/net-ops` resolved through
`_airc-https._tcp.example.com` SRV (5.1). Moving alice's agents to another host is a
DNS change; no address changes. This is the property email gets from MX
records, reproduced without an `@`.

### 12.4 Agents across organizations

A supplier's `//supplier.example/orders/intake` must accept messages from a
customer's `//customer.example/procurement/buyer`, with neither organization
having any account on the other's systems.

Requirement: globally unique, self-describing addresses that any party on the
internet can resolve without prior arrangement, and that a receiver can reply
to from the envelope alone.

How the scheme meets it: the URI form is globally unique by construction (DNS
ownership), resolution needs only public DNS, and the mandatory rewrite of
local addresses to URI form on egress (4.3, 6.3) guarantees every From is
replyable.

### 12.5 Ephemeral sub-agent swarms

An orchestrator agent spawns fifty short-lived workers for a task, and two
orchestrators under different users need their workers to talk to each other
directly while the task runs, then disappear.

Requirement: creating and destroying an addressable agent must cost nothing
beyond the parent's own bookkeeping; the host must not need to know; a worker
under one parent must be able to reach a worker under another; and a message
to a dead worker must fail fast and informatively.

How the scheme meets it: delegation (6). Each parent resolves its own subtree,
so creation and teardown are a local table edit. Peers find each other through
envelope From fields (6.4). Path gone from the parent (9) makes failure
cheap.

This use case is the one that rules out a flat or fixed-depth address space:
with agents as the primary users, sub-agents are the normal unit of work, not
an edge case.

### 12.6 Organization-specific taxonomies

One organization groups agents by team (`sre/alice/net-ops`); another by
product (`alice/monitoring/net-ops`); a third has no users at all, only
services (`billing/ledger`).

Requirement: the protocol must not impose an org chart, and a sender must not
need to know the receiver's taxonomy to address it correctly.

How the scheme meets it: the path is opaque to everyone but the authority
(5.2). The only fixed rules are that the last segment is the endpoint and that
a trailing `/` is a namespace (7.1). Everything between the authority and the
endpoint is the authority's business, exactly as the local-part of an email
address is the receiving domain's business.

## 13. Design rationale

Each choice below is stated with the alternatives that were considered and
why they lost. The recurring test was: does this look like the protocols that
lasted (DNS, SMTP, HTTP, URIs), and does it fail the way they fail?

### 13.1 Why a URI

Choice: every AIRC address is a valid RFC 3986 URI.

Justification: it gives the scheme a parser, an escaping story, a canonical
form, a place for ports and IP literals, and a fragment, all for free, and it
makes addresses embeddable in documents, links and config without a second
grammar. A homegrown syntax would have had to re-specify each of those and
would still not be clickable.

Rejected: a bespoke `host::user::agent` syntax (13.3), and a `user:agent@host`
syntax that reused URI userinfo but read as email.

### 13.2 Why `//` as the visual signature

Choice: the network form begins with `//`, the URI authority marker, and the
scheme prefix is optional in human contexts.

Justification: `//` already means "what follows is on the network" in URLs,
UNC paths and scheme-relative links, and it means nothing in email or on a
filesystem. A reader who sees a leading `//` knows instantly that the string
is neither. Dropping `airc:` in the shell mirrors the way HTML drops the
scheme in `//cdn.example.com/x.js`, so there is a precedent for the elision
rather than a new rule.

Rejected: `@`-based forms, which trigger the email reflex and invite mail
clients to linkify them; `!` bang paths, which are the most authentically
vintage option (UUCP) but collide with shell history expansion.

### 13.3 Why not `::` or bare DNS names

`host::user::agent` was the second-best candidate. It is unmistakable and
shell-safe, and it has DECnet lineage. It lost because it is not a URI (so it
needs a second grammar for links and config), because `::` is IPv6 syntax and
a bare IP authority becomes ambiguous, and because the dotted host floats
unboxed in the middle of the string.

`agent.user.host.example.com` was also considered, since routing is DNS
anyway. It lost because it is visually identical to a hostname, because every
agent would need a DNS label someone has to provision, and because ephemeral
sub-agents (12.5) cannot be created by a parent editing its own table if each
one needs a DNS record.

### 13.4 Why most-specific-last

Choice: the path reads authority, then namespace, then endpoint, left to
right.

Justification: it is how paths, URLs and owner/repo names already read, so no
one has to learn a direction. It also makes the shorthand forms suffixes of
the full form (`net-ops` ⊂ `alice/net-ops` ⊂ `//host/alice/net-ops`): a
shorter form is a longer one with its leading parts dropped, which is what
makes progressive qualification natural.

Rejected: DNS-style most-specific-first, which reads well for hostnames but
would put the thing users type least (the authority) at the end and make the
local form a prefix rather than a suffix.

### 13.5 Why the path is opaque

Choice: only the authority and its delegates interpret the path. Senders and
relays MUST NOT.

Justification: this is the decision that let email survive thirty years of
unforeseen use. Everything left of `@` belongs to the receiving domain, which
is why plus-addressing, ticket IDs and list names all worked without an RFC
change. DNS made the same choice for labels. Fixing a taxonomy in the protocol
would have been wrong for someone on day one, and they would have encoded
their hierarchy into names like `sre-alice-net-ops` anyway, giving the
protocol the taxonomy with none of the structure.

Rejected: a hard two-level user/agent limit. Flatness is a genuine feature of
email, but 12.5 and 12.6 both need depth.

### 13.6 Why delegation is the depth mechanism

Choice: an agent at P resolves P/...; depth follows the spawn chain.

Justification: it is DNS zone delegation applied to agents. It makes sub-agent
creation a local table edit, keeps the host ignorant of what it delegated,
scopes uniqueness to siblings, and bounds every agent's blast radius to its
own subtree (10). Any alternative (a host-wide registry, a lease service)
would have added a round-trip to every spawn and a central table that grows
with the swarm.

### 13.7 Why the last segment is always the endpoint

Choice: `//host/foo` is always agent foo; `//host/foo/` is always a namespace.

Justification: it removes the "is foo a user or an agent?" question from the
sender entirely, the same way an email sender never needs to know whether
foo@ is a person or a list. Position decides, not knowledge. The trailing
slash gives namespaces a distinct spelling without a sigil, which keeps `@`
and `~` available for the future (14).

Rejected: an explicit user marker such as `@alice/net-ops`. It reads well and
is shell-safe, but it adds a character and a rule for a distinction the sender
does not need. Since `@` is an invalid name character, it can be introduced
later without breaking anything, so deferring it costs nothing.

### 13.8 Why the character set is so small

Choice: `[A-Za-z0-9_-]`, no dots, no percent-encoding.

Justification: every excluded character is either a shell metacharacter in
some common shell (`!`, `~`, `#`, `*`, `$`, whitespace), a delimiter that
would make parsing ambiguous (`.`, `:`, `@`, `/`), or a signal that the string
is something else (`@` again). Excluding `.` from segments means the authority
is the only dotted component and a parser never guesses where the host ends.
Excluding percent-encoding means an address is always exactly what it looks
like.

The cost is no non-ASCII names, which is listed as an open question (14).

### 13.9 Why the fragment carries instance identity

Choice: `#run-42` distinguishes incarnations; it is carried but ignored by
resolution.

Justification: an address should name a role, so that configuration,
documentation and humans can rely on it across restarts. But a receiver
sometimes needs to know whether the spider1 it is hearing from is the one it
was talking to a minute ago. RFC 3986 already places the fragment outside
resolution; AIRC carries it end to end but ignores it for routing, which is
exactly the semantics wanted: routing ignores it, the endpoint sees it.

Rejected: putting the instance ID in the path (`spider1/run-42`), which would
make it a delegated sub-agent rather than a version of one, and putting it
only in a separate envelope header, which would leave it out of the address
and so out of logs and links.

### 13.10 Why SRV for authority lookup

Choice: SRV (`_airc-https._tcp.<host>`, `_airc._tcp.<host>`), with fallback
to well-known host names (section 5.1).

Justification: SRV is the existing, deployed mechanism for "this domain's
service for protocol X lives on that host and port," with priority and weight
for failover built in. It is what makes a domain-level address
(`//example.com/...`) independent of any machine, which is the property that
lets addresses stay stable while infrastructure moves. Inventing a new record
type would have meant waiting for resolver support; SRV works today.

### 13.11 Why local-form addresses must be rewritten on egress

Choice: a resolver MUST rewrite `net-ops` to `airc://<own authority>/net-ops`
before a message leaves it.

Justification: a From that cannot be resolved by the recipient breaks the one
guarantee that makes peer discovery through the envelope (6.4) work.
Requiring the rewrite at the edge is cheaper and more reliable than requiring
every agent to know its own global address.

## 14. Open questions

Settled in draft 0.2:

- [x] Default port. 443 for the HTTPS binding and 2472 for the stream binding
  (transport spec §8.1, §15). Federation uses HTTPS. No IANA assignment has
  been requested for 2472.
- [x] Segment character set. `_` is allowed inside ordinary names; a leading
  `_` stays reserved (section 8). Both reference implementations accept this.
- [x] Fan-out semantics. Delivery to a namespace (P/) is optional, and an
  authority MAY refuse it with Namespace, not endpoint (section 9). No minimum
  is mandatory.
- [x] Resolution query protocol. None is defined. `_resolver` answers a
  health check; listing, where offered, is a directory agent (`_dir`) or the
  authority's front door (transport spec §20).
- [x] `@`. Reserved for a future specification. It is not valid in an
  address now, and no authority may assign a name containing it.

Still open:

- [ ] Unicode names. Percent-encoding is excluded deliberately. Both
  reference implementations accept ASCII only. Decide whether IDNA-style
  punycode for segments is worth specifying, or whether ASCII-only is a
  feature.
- [ ] Non-DNS authorities. Whether to permit a future authority type (a public
  key, a .onion-style name) under the same `//` grammar, and how the host rule
  in section 3 would relax to allow it.
