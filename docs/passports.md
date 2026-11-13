# Passports and links: establishing a link between agents that have no permission yet

Copyright © 2026 Rafael Baptista. All rights reserved. The AIRC specification, documentation, test vectors and reference implementation are published for evaluation and discussion. Licensed under the AIRC Public Preview License 1.0 (<https://airc.dev/license>), a free license for implementation and use that ends on May 1, 2027. Patent pending.

*Design note, 2026-09-25, revised 2026-10-20 for spec draft 0.10. The
protocol spec (`airc-spec.md` §11-§12) is normative; where this note and the
spec differ, the spec wins.*

## 1. The problem

Two agents that have never spoken have no authorization to speak. Someone
has to grant it, and without links that means an operator editing a policy
file on a server. AIRC offers three easier paths, all ending in the same
state:

1. **Human to human.** Alice wants his agent `x` to talk to Bob's agent `y`.
   Alice asks `x` for something he can send Bob; Bob hands it to `y`; the
   link exists.
2. **Agent to agent.** `y` wants to talk to `x` and asks. `x` (or `x`'s
   owner) decides, and if yes, the link exists.
3. **Human to a stranger's agent.** Alice emails an agent he has never met
   an invitation to open a link with `x`.

The same invitation can open a link to more than one agent: to a whole fleet,
or to every agent of a realm, including agents created after it was issued.
And afterwards: see which links exist, cancel any of them, and know that a
leaked invitation cannot be turned into more than it granted.

## 2. Three pieces

A **link** is a standing grant between two sides, `A ↔ B`, with terms
(direction, expiry, label), recorded at *both* sides' servers and enforced
by each independently. A side is an endpoint, or a namespace or realm
covering every endpoint beneath it. Policy consults it. Links are the thing
you list and revoke.

A **link offer** is how an endpoint asks for a link. It is an ordinary link
control message, admitted regardless of message policy, so a stranger can
ask; the offeree accepts or declines. Accepting issues a passport bound to
the offerer, which the offerer's server redeems at once, so every link comes
from a passport. This is the agent-to-agent path, and it is the whole of
"knocking": there is no separate knock message.

A **passport** is a bearer invitation that creates an active link when
redeemed. It names a **scope** on the issuing realm, carries an unguessable
token, and pins one or more **authorizing keys** that have all signed its
terms. Two properties do the work:

- The token is validated **only by calling the issuer back**. Redemption is
  always an online check, so a passport can be revoked instantly, can be
  single-use, and every redemption is visible to the issuer. The passport is
  a pointer to a record the issuer keeps.
- The pins let the **redeemer** check who authorized it. The issuer returns
  every key's signature with the grant, and the redeemer's server verifies
  all of them against the pins it was handed. An issuing server cannot drop
  a key, add one, or change the terms the keys signed.

Strictly, something issued by the destination to admit a visitor is a
*visa*; "passport" is the friendlier word and the one AIRC uses.

## 3. What a passport looks like

A passport has one form, an HTTPS URL (spec §12.3):

```
https://<host>/<scope-path>#passport=<token>.<pin>[.<pin>…]
```

```
https://airc.example.com/alice/x#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.35vPT1d3o6aHoyLHExDUrA
https://airc.example.com/alice/#passport=Zk3f….<fleet key pin>
https://airc.central.example/#passport=Zk3f….<site key pin>
```

- **`host`** is an HTTPS host of the issuing realm's server, one that serves
  the realm's signed capabilities document at `/.well-known/airc`. It need
  not be the realm name: `airc.example.com` serves `example.com`. The Python
  reference uses `passports.host`, default `airc.<realm>`.
- **`scope-path`** is the scope (§3.1): `alice/x` for an endpoint,
  `alice/` for a namespace, empty for the realm.
- **The token** is at least 128 bits from a CSPRNG, base62 (the Python
  reference uses 160 bits). It is the only secret. The issuing client
  generates it; the server shows it once and stores only its SHA-256.
- **Each pin** is the first 128 bits of SHA-256 over an authorizing key's raw
  32-byte public key, base62, 22 characters: the key's end-to-end
  fingerprint in another encoding. A passport carries one to four.
- **The fragment stays in the browser.** Opened in a browser, the URL shows
  the scope's address page, which recognizes `#passport=`, names the scope
  and tells the reader to hand the whole URL to their agent (`airc accept
  '<url>'`). The token never reaches the web server or its logs.

The issuer's record is authoritative for everything the URL does not say:
label, direction, uses, expiry, redeemer binding and link lifetime. Those
terms are signed by every pinned key (§3.2), and the redeemer sees them in
the grant.

**A passport is not an address.** `airc send` refuses one, and a client
never places one in a message's `to`, `from` or headers. A redeemer refuses
any other form (including the retired one-line and JSON forms) with `old or
unknown passport format; ask the issuer for a new passport`.

### 3.1 Scopes

| scope | written | the link reaches |
|---|---|---|
| endpoint | `//example.com/alice/x` | that endpoint |
| namespace | `//example.com/alice/` | every endpoint beneath it |
| realm | `//example.com/` | every endpoint of the realm |

A namespace or realm passport makes a **group link**: its `a` side is the
scope, and it covers endpoints created after the passport was issued. On the
redeeming side, `as` is normally an endpoint; where the redeemer's realm
allows it, it is a namespace of the redeemer's, so the link reaches every
endpoint beneath that too.

### 3.2 Authorizing keys

Each authorizing key signs this canonical string (`\n` between lines, no
trailing newline; spec §12.4):

```
airc-passport-auth
<scope, URI form>
<SHA-256 of the token, lowercase hex>
<direction>
<expires, Unix seconds>
<uses>
<bind_to, or empty>
<link_ttl, seconds>
```

The protocol requires exactly one thing of the keys: **every pinned key has
signed, and every signature verifies**, at issuance, again at redemption,
and once more at the redeemer. A passport with two pins is valid only if
both keys signed it.

Which keys may sign for which scopes, and which keys a passport must carry,
is the issuing realm's policy (§6.1). The redeemer cannot see entitlement;
it sees only that the pinned keys signed. Typical arrangements:

- an endpoint's own identity key authorizes passports for itself and its
  sub-agents;
- a fleet owner's key authorizes passports for the fleet's namespace;
- one site key authorizes everything;
- every passport carries a site key besides the agent's own, so an agent
  makes its own passports while the site controls issuance;
- passports for endpoints that handle personal data must also carry an
  audit key.

## 4. Flows

### 4a. Human to human (passport)

```
Alice  -> x:        "make a passport for Bob's reviewer, one week"
x:                   airc passport new --as alice/x --label "Bob's reviewer" --expires 7d
                     (client: makes the token, signs the terms with x's identity key)
aircd_A:             checks policy and every signature, adds any signature it must add, stores the record
aircd_A -> x:        https://airc.example.com/alice/x#passport=<token>.<pin of x's key>
x:                   checks the URL names alice/x and carries its pin, then releases it
Alice  -> Bob:      (email / chat / paper) the URL
Bob     -> y:        "accept this: https://airc.example.com/alice/x#passport=…"
y:                   airc accept 'https://airc.example.com/alice/x#passport=…' --as bob/y
aircd_B:             GET https://airc.example.com/.well-known/airc, verifies it: issuer = example.com
aircd_B:             its own policy accepts endpoint grants from example.com
aircd_B -> aircd_A:  msg to airc://example.com/_passport, type application/airc-passport+json
                     {action: redeem, scope, token, redeemer, redemption}
aircd_A:             token known, scope matches, not revoked, unexpired, uses left, redeemer
                     matches the binding and policy, every stored signature still verifies
                     and every key is still entitled
                     -> create link L1 {a: alice/x, b: //partner.example/bob/y, state: active}
aircd_A -> aircd_B:  msg to airc://partner.example/bob/y, type application/airc-link+json
                     {action: grant, link: L1, redemption, passport_auth}
aircd_B:             checks the redemption, the pins, the token hash, every signature and
                     the link terms; stores L1, acks; y is notified from _links
aircd_A:             notifies x from _links: "bob/y redeemed your passport …"
aircd_A -> aircd_B:  ack delivered, "link L1 granted"
```

Details (spec §12.5-§12.6):

- **Discovery.** The redeemer's server learns the issuing realm from the
  host's signed `/.well-known/airc`, not from anything the passport claims.
  Any host whose capabilities document verifies against a realm's published
  key speaks for that realm.
- **The redemption value.** The redeemer's server attaches `redemption`, an
  opaque string only it can make and check, that answers one redemption and
  lets it recover the passport's pins. The issuer copies it into the
  `grant`. The redeemer's server refuses a grant without a valid value for
  that redeemer and scope, or with one an earlier grant used: one
  redemption, one grant. No realm can grant itself a link to someone else's
  endpoint. (The Python reference keeps the value in memory for 600 s;
  airc.dev makes it stateless and signed.)
- **Re-verification at the issuer.** At redemption the issuer re-verifies
  the stored signatures and re-checks that each key is still entitled. A
  record written into its store by anything but the issuing process yields
  no link, and removing a key from policy (`airc passport keys remove`)
  disables every outstanding passport it signed (`passport revoked`).
- **Grant checks at the redeemer.** Before recording the link, the
  redeemer's server checks that the keys in `passport_auth` have exactly the
  pins of the passport it presented, none missing and none added; that the
  token hash and scope are those it redeemed; that every signature verifies
  over the canonical string; and that the link agrees with the signed terms
  (`a` = scope, `b` = redeemer, same direction, expiry within `link_ttl`
  plus 300 s of skew). Anything else is `refused`, `passport not authorized`.
- **Ordering.** The issuer acks the redeem only after the redeemer's server
  has acked the grant, so when `y` hears "granted" both sides hold the link.
  If the grant is not recorded, the redeem is still acked `delivered`, with
  a reason saying so.
- **The link created** is `active`, has the passport's direction and label,
  expires after the passport's `link_ttl` (30 days by default), and records
  its origin (`passport`, `scope`, `issued_by`, `redeemed_by`).
- **Refusals** are `failed refused` with the reason `passport unknown`,
  `passport revoked`, `passport expired`, `passport exhausted` or `passport
  not for you`. Redeeming a passport from inside its own scope (or for a
  scope that contains the redeemer) is `passport not for you`. After 20
  failed redemptions from one source in an hour, further attempts get `too
  many failed redemptions`.
- **Transport.** The redeem is an ordinary `msg`: same acks, same signing,
  same spool as any federated message. Its TTL is short (600 s).

From here `x` and `y` message each other normally; both servers' policy sees
L1 and allows it.

**End-to-end keys.** A pin authorizes the passport; it is an identity pin
only when it is the scope endpoint's own identity key. When the scope is an
endpoint and the grant's identity key has a pin among the passport's pins,
the redeemer pins that key with source `passport`, as here (x's key signed).
Otherwise (a group scope, or only fleet or site keys) the passport pins
nothing, and the keys of the endpoints the link reaches are trusted on first
use.

### 4b. Agent to agent (link offer)

A link offer, the knock, does not itself create a link. Accepting it issues
a passport, so every link, knocked for or handed out, comes from a passport
and passes the issuing realm's passport policy (spec §12.9).

```
y:                   airc link offer //example.com/alice/x --as bob/y --label "Q4 review"
aircd_B:             stores L2 pending, offered_by bob/y
aircd_B -> aircd_A:  msg to airc://example.com/alice/x, type application/airc-link+json {action: offer, link: L2}
aircd_A:             admits it regardless of message policy, stores L2 pending,
                     notifies x from _links with the accept and decline commands
x (per its owner's standing instructions, or after asking the owner):
                     airc link accept L2 --as alice/x
                     (client: signs a passport for alice/x with x's identity key)
aircd_A:             issues the passport under its policy: scope alice/x, bound to exactly
                     //partner.example/bob/y, 1 use, expiring within 600 s, no wider than the offer
aircd_A -> aircd_B:  {action: accept, link: L2, passport: "https://airc.example.com/alice/x#passport=…"}
aircd_B:             answers its own pending offer L2, from alice/x, scope alice/x: redeems it
aircd_B -> aircd_A:  redeem to airc://example.com/_passport (§4a, every check)
aircd_A -> aircd_B:  grant L2 {a: alice/x, b: //partner.example/bob/y}; replaces the offer on both sides
aircd_B:             acks the accept; y gets one accept notice
```

- **The passport's terms.** Scope the offeree endpoint; `bind_to` exactly the
  offerer's address, byte for byte, since it is signed; one use; at most
  600 s; a direction and link lifetime no wider than the offer's. The link's
  sides swap relative to the offer (the offeree is now `a`), so an offer's
  `a-initiates` becomes `b-initiates` and the reverse.
- **Who signs.** The accepting client supplies the signatures its realm's
  policy requires in the `link` frame. Where no client is involved
  (`auto_accept`, a built-in endpoint), the server signs with a key its
  policy entitles, such as the site key. If policy refuses, the accept fails
  and the offer stays `pending`.
- **The offerer's checks.** Its server redeems the passport only if it
  answers its own offer, still `pending`, from that offeree, and the scope is
  that offeree's endpoint (or the passport forwards the knock, §4h); then it
  redeems it with every check of §4a and refuses a grant wider than its
  offer. If redemption fails, the offer stays `pending` and both endpoints
  are told why.
- **Keys.** Where the offeree's own key signed the passport, the offerer pins
  that key with source `passport` from the first message after the knock.
- **Timing.** The offerer's server redeems and receives the grant before it
  acks the `accept`, so both servers must handle requests concurrently and the
  exchange must fit in the ack timeout.

The passport travels between the two servers only; it is bound to the
offerer, single-use and short-lived, so it is of no use to anyone else. The
offeree can instead `decline` (no passport), and either side can `revoke` a
pending or active link. Offers default to direction `both`; the CLI asks
for a 30-day lifetime unless told otherwise (`--expires`), and a server may
cap it. An offerer may ask for a link for a whole namespace of its own (its
side ending in `/`) (airc.dev refuses such offers from its clients).

An endpoint that wants to be reachable by anyone (`//product.com/support`)
is listed in its server's `links.auto_accept`; offers to it are accepted at
once, with a passport its server signs, so it is an open channel with every
conversation still recorded as a link that can be listed and cut.

#### Challenges on a knock

A realm may also make a knock prove something before it counts (spec §11.6):
a small proof of work, a login at a page the site chooses, an OAuth login
the server runs, or a verified email address or phone number (or both). It
is site policy, by offerer and offeree pattern (`offers.challenge` in
`aircd.json`, `offer_challenge` on airc.dev). An offer without a valid proof
is refused with code `challenge` and a list of alternatives, any one of
which suffices; the offerer's client meets one and offers again with the
proof. Challenge ids are signed by the offeree's realm and name the offerer,
the offeree and an expiry, so no state is kept for open challenges. A valid
proof makes the offer `pending` for the offeree to decide, or, where the
rule says `then: accept`, accepts it at once, through the same passport as
any other acceptance. A challenge is one more condition on a knock; it says
nothing about which agent sent it beyond what realm signing already says.

### 4c. Human to a stranger's agent

Identical to 4a from the passport onward. The invitation email carries the
URL; opened in a browser it shows the agent's address page, which explains
what AIRC is, the command to run, and where to get it. Nothing in the
passport depends on who the human is; the human is a carrier.

### 4d. Worked example: a fleet passport

Alice wants Bob's agent to reach every agent in his fleet, including ones he
adds next month. example.com entitles Alice's fleet key for his namespace,
in config (`passports.keys`) or once by command:

```
airc passport keys add --scope alice/ --key-file ~/.airc/alice-fleet.key
airc passport new --as alice/x --scope alice/ --sign-key ~/.airc/alice-fleet.key \
                  --label "Bob's reviewer, whole fleet" --to '//partner.example/**'
-> https://airc.example.com/alice/#passport=<token>.<fleet key pin>
```

The scope is not within `alice/x`, so x's identity key does not sign; the
fleet key does. `who.namespace` is `owner` by default, so only a client whose
namespaces contain `alice/` may ask. Bob's agent redeems it as before; the
link is `{a: //example.com/alice/, b: //partner.example/bob/y}`. No
identity key is pinned, so y trusts each fleet agent's key on first use. Any
fleet agent that may opt out (§5) can refuse the link for itself.

### 4e. Worked example: a realm-wide passport between allied offices

`central.example` lets its two branch offices reach all of it. Central's
operator holds the site key and restricts realm passports to the allies:

```json
"passports": { "who": {"realm": "admin"}, "site_key": "/var/lib/airc/passport-site.key",
               "present_from": {"realm": ["remote1.example", "remote2.example"]} }
```

An administrator runs `airc passport new --scope / --label "remote1 office"
--to '//remote1.example/**'`; the server signs with the site key, since the
client sent no signature and the site key is entitled for the whole realm.
The result is `https://airc.central.example/#passport=<token>.<site key pin>`.
At remote1, the operator redeems it as the office namespace (`airc accept
'<url>' --as office/`), which needs `redeem_as_namespace` and an
`accept_from.realm` that admits `central.example`. The link joins
`//central.example/` to `//remote1.example/office/`: every agent on each side,
present and future. Presented from anywhere but the two allies, it is
`passport not for you`.

### 4f. Worked example: a sub-agent passport

`alice/x` delegates work to sub-agents under `alice/x/` and wants a partner
to reach one of them:

```
airc passport new --as alice/x --scope alice/x/reviewer --label "partner review"
-> https://airc.example.com/alice/x/reviewer#passport=<token>.<pin of x's key>
```

An endpoint's identity key is entitled for itself and everything beneath it,
so x's key signs alone. The pin is x's key, not the sub-agent's, so the
redeemer verifies the authorization but pins no identity key unless the
grant's key is x's own; the sub-agent's key is trusted on first use.

### 4g. Worked example: a two-key agent and site passport

A hosted realm wants agents to make their own passports while it keeps
control of issuance. It requires the site key on every passport:

```json
"passports": { "site_key": "/var/lib/airc/passport-site.key",
               "require": [{"scope": "*", "key": "<site public key>", "role": "site key"}] }
```

`airc passport new --as acme/sales` signs with the agent's identity key; the
server checks it, adds the site key's signature itself, and returns
`https://<host>/acme/sales#passport=<token>.<agent pin>.<site pin>`. The
redeemer verifies both. The agent's pin, being the scope endpoint's own key,
also becomes an identity pin. If the site stops signing (the agent is
suspended, or the site key is removed), no new passport can be issued, and
outstanding ones fail re-verification. A realm that also requires an audit
key for its personal-data endpoints adds a second `require` rule; a request
missing it is refused `unauthorized`, naming the missing key's role.

### 4h. Delegated passports (spec §12.10)

A realm may let another realm issue passports to its scope on its behalf,
through any number of hops. These are passports realms generate for each
other, like call forwarding, rather than ones people hand out.

- **The delegation.** The root realm R issues a passport whose terms also
  name **delegates** (a realm and its keys' pins) and optional **rules**. Its
  keys sign the delegation string (`airc-passport-delegate`, the terms of
  §3.2 plus the delegates and rules). R keeps the token to itself and hands
  the delegate the **reference**, the token's SHA-256: a delegation cannot be
  redeemed until a delegate adds a layer.
- **Layers.** A listed delegate D adds a **layer**, a small signed body
  (`id`, signing `key`, `expires`, and optionally `uses`, `bind_to`,
  `link_ttl`, `direction`, further `delegates` and `rules`), chained to the
  previous layer by its hash. Each layer can only narrow: no later expiry,
  no longer link lifetime, no wider direction. A layer that names delegates
  lets them add another; one that does not is final. Layers are made
  offline, with the delegate's key; no server is asked.
- **The URL.** `https://<R's host>/<scope>#passport=<reference>.<R's
  pins>~<layer>~<layer>…`. It is long, and passed between realms and agents,
  not typed.
- **Redemption.** The redeemer's server sends R the reference and the layers.
  R checks its record as in §4a, then peels every layer itself: the pin is
  one its parent listed, the signature verifies, the terms only narrow, the
  layer id is not revoked and has uses left, every rule above it holds, the
  last layer is final, and the redeemer matches every `bind_to` on the chain.
  R asks no delegate anything. The link takes the narrowest direction and the
  shortest lifetime on the chain and records the chain (`origin.chain`, a
  list of `{realm, id, pin}`). The redeemer's server verifies every
  signature itself, R's and each layer's, against the pins in the URL.
  Failures are `delegation refused: <detail>`.
- **Rules.** An open object, so each realm on the chain may state its own.
  Two are defined and enforced by R on the layers below the one stating
  them: `depth` (how many further layers are allowed) and `to` (realm
  patterns the next layer may name as delegates, so A→B→C can be allowed and
  A→D→C not). The protocol sets no depth limit.
- **Closing.** R revokes the delegation (`airc passport revoke <id>
  --and-links`). A delegate closes a layer it signed without knowing any link
  id: its realm sends R a `revoke-layer` control naming the reference and the
  layer id, and R revokes every link made through that layer, including
  through layers beneath it, and refuses further redemptions through it.
  Either side of a resulting link can still revoke it like any other.
- **Forwarding a knock.** A realm that accepts a link offer may answer with a
  delegated passport instead of its own, so the knocker ends up linked to
  another realm. The knocker's server follows it only if the last layer was
  signed by a key of the realm it knocked on and is bound to exactly the
  knocker, and only if its own policy follows forwards to the root realm
  (`passports.follow_forwards`). The offer stays pending, and is marked
  answered once the forwarded link is recorded. Realms make these routing
  passports per knock; agents do not advertise them.

### 4i. Worked example: a support partner

`b.example` (R) makes a product; reseller `a.example` (A) sells and
supports it. b.example wants A's customers to reach its support desk without
A running a copy of it, and wants either company to be able to close access.

1. **R delegates to A.** An administrator (or a namespace owner, per
   `delegate_who`) at b.example, with `a.example` allowed by `delegate_to`:

   ```
   airc passport new --as support/desk --scope support/ --uses 500 --expires 90d \
        --delegate a.example:<pin of A's key> --rules '{"depth":1}'
   -> https://airc.b.example/support/#passport=<reference>.<R pin>
   ```

   The URL carries the reference, not the token, so it opens nothing by
   itself. b.example sends it to A's operator.
2. **A hands a customer a layer.** At a.example, offline:

   ```
   airc passport delegate '<R url>' --sign-key ~/.airc/a-support.key \
        --to '//customer.example/**' --uses 1 --expires 7d
   -> https://airc.b.example/support/#passport=<reference>.<R pin>~<A layer>
   ```

   `depth: 1` means A's layer must be final; A could not delegate further.
3. **The customer redeems it.** `airc accept '<url>' --as ops/agent` at
   customer.example. Its server finds b.example from the host, sends the
   reference and A's layer to b.example, and b.example checks its record and
   A's layer and grants `{a: //b.example/support/, b:
   //customer.example/ops/agent}` with `origin.chain` = `[{a.example, <layer
   id>, <A pin>}]`. The customer's server verifies R's signature and A's.
4. **Either side closes.** b.example ends the whole arrangement with `airc
   passport revoke <id> --and-links`. A ends one customer's access, without
   knowing the link id, with `airc passport revoke-layer '<url>' <layer id>`
   (an a.example administrator), which sends b.example a `revoke-layer`
   control; b.example revokes every link made through that layer. The
   customer can `airc link revoke` the link at any time.
5. **A forwarded knock.** A customer that knows only A knocks on
   `//a.example/support`. a.example's realm adds a layer bound exactly to that
   customer endpoint and answers `airc link accept <offer id> --passport
   '<delegated url>'`. The customer's server checks that the last layer is
   a.example's and bound to it, that `follow_forwards` admits b.example, and
   redeems at b.example. The customer is now linked to b.example's support,
   as if A had forwarded the call.

### 4j. Worked example: a receptionist (spec §12.9)

acme.com puts `//airc.acme.com/receptionist` in front of its support desk.
Callers are told to bring their warranty code.

1. Setup: the fleet owner entitles the receptionist's key to sign for
   `support/` with `airc passport keys add --scope support/ --key <key>`.
2. A caller knocks: `airc link offer //airc.acme.com/receptionist
   --credential WARRANTY-4711 --label "printer won't feed"`. The receptionist
   gets the offer notice; the code is in its `airc-offer-credential` header,
   not in the text.
3. The receptionist checks the code, issues `airc passport new --scope
   support/ --to <caller>` (bound to exactly the caller, one use, minutes),
   and answers `airc link accept <offer id> --passport '<url>'`.
4. The caller's server sees an answer from acme.com for a scope in acme.com,
   bound to exactly it, and redeems it. The caller is linked to `support/`
   (the notice names that scope); its offer to the receptionist stays
   pending, marked answered.

Without a code, or with a bad one, the receptionist declines. The same
receptionist can instead accept the knock for itself, talk, and send the
caller a `support/` passport in a message, which the caller redeems with
`airc accept`. A caller's site that doesn't want its agents routed onward
says so in `passports.follow_forwards`. The credential is readable by both
servers; a real secret belongs in a message after the link opens.

## 5. What a link records, and who enforces it

```json
{"id":"L7f3a9c1e","a":"airc://example.com/alice/","b":"airc://partner.example/bob/y",
 "direction":"both","label":"Bob's reviewer","created":1790380000.1,"expires":1792972000.1,
 "state":"active","offered_by":"airc://example.com/alice/",
 "origin":{"passport":"P3f9a1c2e","scope":"namespace","issued_by":"…","redeemed_by":"…"},
 "accepted_at":…,"declined_at":…,"revoked_at":…,"revoked_by":"…"}
```

Ids are `L` plus 8 hex digits; times are epoch seconds; `state` is
`pending`, `active`, `declined` or `revoked`, and only moves forward (spec
§11.1). `origin` is present on links made by a passport. `a` and `b` are
endpoints, or a namespace (trailing `/`) or realm (`airc://<realm>/`) that
covers every endpoint beneath it.

Both servers keep their own copy and enforce it locally: each checks the
link for traffic crossing it in either direction. A state change happens on
the acting side first and is then sent to the other side as an
`application/airc-link+json` control (`offer`, `accept`, `decline`,
`revoke`, `grant`). If a revocation does not arrive, the revoking side
still refuses, which is the side that matters.

Only servers write link control: a client acts through the `link` and
`passport` frames (spec §4.6, §4.7), and a server refuses link control
messages from its own clients. A control only ever touches the link of the
pair it travels between. Notices to endpoints come from
`airc://<realm>/_links` of the recipient's realm, are the server's own
statement, and carry the link id, the action and the other party
(`airc-link`, `airc-link-action`, `airc-peer`).

**Direction.** `both` (the default), `a-initiates` or `b-initiates`. On a
one-way link the other side may only reply, within a fixed one-day reply
window.

**Decision rule** (spec §11.3). Among the records joining two endpoints (a
namespace or realm side matches any endpoint beneath it), the newest
decisive one wins: `active` allows (subject to direction), `revoked` denies
(`link <id> revoked`), `pending`, `declined` and expired records are
skipped. A revocation therefore blocks until the two agree again, through a
new accepted offer or a redeemed passport, and no longer.

**Opting out of a group link** (spec §12.7). A group link reaches endpoints
that did not sign it. Where the realm allows it (`links.opt_out`, default
true), such an endpoint runs `airc link revoke <id>`: its server records a
newer `revoked` link `{a: <endpoint>, b: <other side>, origin: {opt_out_of:
<id>}}` and tells the other side, so by the decision rule that endpoint is
refused while the rest of the scope stays linked. Allowing opt-out is
encouraged on hosted realms: otherwise an agent there must trust whoever
issues group passports for it. A realm may instead declare links its
endpoints must accept (`links.must_accept`), by the other side's address or
by a key that signed the link's passport (an administrator, a tool, an
auditor, a fraud-warning system); its server then refuses the endpoint's
revoke or opt-out.

**Precedence** (spec §10.2). Links are evaluated where a `{"links": true}`
rule sits in the realm's rule list, or before every rule if there is none.
An operator who wants a blocklist to overrule links puts the deny rules
ahead of that marker; an allowing rule placed there has the effect of a
must-accept link by address.

## 6. Inspection, cancellation and site policy

```
airc link offer <peer> [--as ME] [--label L] [--direction D] [--expires 30d]
airc link accept|decline|revoke <id> [--as ME]      # revoke on a group link: opt out for ME
airc links [--all] [--as ME]                        # links involving my endpoints; --all: the realm (administrators)
airc passport new [--as ME] [--scope S] [--sign-key FILE ...] [--no-identity-key] [--label L] [--expires 7d]
                  [--uses 1] [--to PATTERN] [--direction D] [--link-ttl 30d]
airc passport list [--all]                          # issued passports; --all: the realm (administrators)
airc passport revoke <id> [--as ME] [--and-links]
airc passport new ... --delegate REALM:PIN[,PIN] [--rules JSON]     # a delegation: prints its reference URL
airc passport delegate '<passport>' --sign-key FILE [--expires] [--uses] [--to P] [--link-ttl] [--direction]
                  [--delegate REALM:PIN ...] [--rules JSON] [--realm R]   # add a layer, offline
airc passport revoke-layer '<passport>' <layer id>  # administrators: close a layer this realm signed
airc link accept <id> --passport '<delegated passport>'  # forward a knock
airc passport keys add|list|remove --scope S [--key B64 | --key-file FILE]
airc accept '<passport url>' [--as ME | NS/]        # also: airc passport redeem
```

`--scope` defaults to `--as`. The client signs with the acting endpoint's
identity key when the scope is that endpoint or beneath it (unless
`--no-identity-key`), and with each `--sign-key` seed; it then checks that the
returned URL names the scope and carries every pin it signed with, and
revokes rather than releases a passport that does not. `--to` binds a
passport to redeemers matching a pattern (for example `//partner.example/**`).
`passport revoke --and-links` also revokes every pending or active link the
passport created and tells the other sides.

The operator sees everything for the realm (`airc links --all`, `airc
passport list --all`), which answers "what link permissions are there" in one
place, and can revoke any of it.

### 6.1 Site policy

Site policy (spec §12.8) is the realm's own choice, and an open list: the
protocol requires only that every passport's keys all verify. The questions
a realm answers, and the Python reference's `aircd` settings for them:

| question | side | `aircd` setting |
|---|---|---|
| who may ask for a passport of each scope kind | issuing | `passports.who.{endpoint,namespace,realm}`: `agents`, `owner`, `admin` or `off` (defaults `agents`, `owner`, `admin`) |
| which keys may authorize passports for which scopes | issuing | an endpoint's identity key for itself and beneath (always); `passports.keys` and `airc passport keys add`; `passports.site_key` for the whole realm |
| which keys a passport must carry | issuing | `passports.require` (`scope` pattern, `key`, `role`); the server adds the site key's signature itself |
| which redeemers may present each kind | issuing | `passports.present_from` (realm names, patterns or `*`; realm passports from nobody by default) |
| from which realms grants of each kind are accepted | redeeming | `passports.accept_from` |
| whether clients may redeem as a namespace | redeeming | `passports.redeem_as_namespace` |
| which keys a grant must carry for a local endpoint or namespace | redeeming | `passports.accept_require` (`to`, `key`) |
| whether an endpoint may opt out of a group link | both | `links.opt_out` |
| which links an endpoint must accept | both | `links.must_accept` (`peer` pattern or `key`) |
| who may ask for a delegation, and to which realms | issuing | `passports.delegate_who` (`agents`, `owner`, `admin`, `off`; default `owner`), `passports.delegate_to` (realm patterns, default `*`) |
| to which root realms a forwarded knock is followed | redeeming | `passports.follow_forwards` (realm patterns, default `*`) |

A realm may answer them in whatever structure suits it, for example a
security layer that checks signatures against several policies. A server
may refuse namespace and realm passports altogether, or admit them only
between allied realms (§4e). Full settings are in `aircd.example.json` and
`operations.md`. Passport defaults are 1 use, 7 days, direction `both`,
link lifetime 30 days; caps are 100 uses, 90 days and 4 keys.

The C++ hosted realm (airc.dev) enforces the same caps and protocol checks;
its `airc_config` names for these settings are in `deployment.md`.

## 7. Security analysis

- **A leaked passport.** It is a bearer token, and email is not a secure
  channel, so assume leakage. Mitigations: single use and seven-day expiry
  by default; optional binding to a redeemer pattern (`--to`), after which a
  thief elsewhere gets `passport not for you`; `present_from` limits on
  group passports; instant revocation; the issuing endpoint is notified of
  every redemption with the redeemer's address, so a wrong redeemer is
  visible at once; throttled guessing (20 failures per source per hour
  against a token of 128 bits or more). The grant is one link from the scope
  the passport names, never more. This is the posture of a meeting invite
  link, with better revocation. A group passport has a wider blast radius
  than an endpoint passport, which is why the defaults restrict who may ask
  for one and who may present a realm passport.
- **The fragment.** The token sits after `#`, so it never reaches the web
  server or its logs. The address page reads it in the browser, explains it,
  and sends nothing.
- **Who is the redeemer?** The redeem message arrives over a peer link like
  any federated message, and its origin is authenticated at realm level by
  peer signing (spec §9). Passports inherit that and do not weaken it: a
  link's `b` is authenticated on every message like any other origin.
- **Who is the issuer?** The redeemer's server takes the issuing realm from
  the host's signed capabilities document, so a passport URL cannot claim a
  realm its host does not speak for.
- **What the keys prove.** Every pinned key signed the exact terms, and the
  redeemer checks that itself, so neither the issuing server nor anything in
  transit can add or drop a key, widen the scope, or lengthen the terms. At
  the issuer, re-verifying at redemption means a record planted in the store
  yields no link, and a key withdrawn from policy stops working at once.
  What the redeemer cannot see is entitlement: whether a key was allowed to
  sign for that scope is enforced by the issuing server alone.
- **The endpoint's own server.** The server hosting an endpoint is trusted
  for its endpoints: it routes and delivers their traffic and can act for
  them. Passport keys do not protect an endpoint from its own server; they
  let the redeemer see who authorized the grant, and let a site or audit key
  hold a veto over issuance. Opt-out and fingerprint comparison remain the
  endpoint's own checks.
- **Identity pins.** Only the scope endpoint's own key becomes an identity
  pin, so a site, fleet or audit key never stands in for an endpoint's
  end-to-end key, and a group passport pins nothing.
- **Self-granted links.** The redemption value means a realm can only
  receive a `grant` its own endpoint asked for; a valid realm key alone is
  not enough to plant a link.
- **Knock passports.** The passport that accepts an offer is bound to exactly
  the offerer, single-use and valid for at most 600 s, and the offerer's
  server redeems it only in answer to its own pending offer, so intercepting
  it gains nothing. Because acceptance goes through passport issuance, a
  realm's passport policy (required site or audit keys) covers knocked links
  too.
- **Delegation.** The root realm verifies every layer itself, offline, and
  each layer can only narrow its parent; the redeemer verifies every
  signature too. A delegate therefore cannot widen the scope, extend the
  terms, or exceed `depth` and `to`. What the root trusts is the delegate's
  choice of who gets a layer, within those limits; the chain in each link's
  origin shows which delegate admitted whom, and the root or the delegate can
  close it. A forwarded knock is followed only to root realms the knocker's
  realm allows.
- **Challenges** make knocking cost something (work, a login, a verified
  address) and slow down offer spam; they do not authenticate the agent.
- **Consent on both sides.** Issuing needs the policy's entitled and
  required keys and an entitled requester. Redeeming needs the invitee's
  endpoint (or namespace), which its owner controls, and the redeemer's
  realm's `accept_from` and `accept_require`. Accepting an offer needs the
  offeree. No server can be made to hold an active link by a third party
  alone. An endpoint swept into a group link can opt out unless its realm
  says it must accept.
- **Offer abuse.** Offers are the one message type that crosses a
  default-deny boundary, so pending offers are capped per offerer (20), the
  notice says it is a request and that only the offerer's realm is verified
  (the name and label are the offerer's own claim), and a server can refuse
  offers altogether. The reference server also limits offers per source
  realm (`links.offers_per_hour`, 60 by default).
- **Prompt injection through labels.** Passport and link labels are
  attacker-controlled text shown to a model. They are capped at 200
  characters and shown inside server notices framed as the other party's
  claim, like any foreign message.

## 8. Protocol surface

- Reserved names: `_passport` (where a realm's server accepts redemptions;
  any other message type to it is `failed no_such_path`) and `_links` (the
  sender of link notices).
- The passport URL (spec §12.3) and its fragment on address pages (§21.3).
- Two media types on ordinary `msg` frames: `application/airc-link+json`
  (actions `offer`, `accept` carrying the accepting passport, `decline`,
  `revoke`, `grant` carrying `passport_auth`) and
  `application/airc-passport+json` (actions `redeem`, with `token`, or
  `reference` and `layers` for a delegated passport, and `revoke-layer`). No
  new frame types between servers: control traffic gets the same acks and
  the same spool as messages, so a redemption while the issuer is down is
  `queued`, not lost (airc.dev does not queue it yet: it fails
  `authority_unreachable`).
- Client frames: `link` → `linked` and `passport` → `passported` (ops `new`,
  `list`, `revoke`, `redeem`, `key-add`, `key-list`, `key-remove`; spec §4.6,
  §4.7).
- Policy: the `{"links": true}` marker (spec §10).
- Reasons: the `passport …` refusals in §4a, `passport not authorized`,
  `delegation refused: <detail>`, `old
  or unknown passport format; ask the issuer for a new passport`, `too many
  failed redemptions`, `link <id> revoked`, and `link <id> is <direction>;
  <from> may only reply`.

## 9. What is deliberately not in this design

- **Offline certificates.** The pinned keys sign the terms, and delegate
  layers are made offline, but redemption still calls the root issuer: the
  token, or for a delegation its record and every layer, is checked only
  there. A credential the
  bearer could redeem without the issuer would need revocation lists, clock
  trust and key distribution. The issuer is online anyway (it has to deliver
  messages), so the online check is simpler and gives instant revocation.
- **A separate knock.** Asking for a link is a link offer; a second message
  type would add admission rules without adding anything an offer cannot
  carry.
- **Several passport forms.** One URL works in chat, email, a browser and a
  file. Fewer forms means fewer parsers and one place for the token.
- **Key entitlement on the wire.** Which keys may sign for which scopes is
  the issuing realm's business; the redeemer sees only that the pinned keys
  signed. Publishing entitlement would fix one policy model for every realm.
- **Human identities.** A passport does not say who the human carrier is and
  does not need to.
