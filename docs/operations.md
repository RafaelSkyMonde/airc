# AIRC operations guide

Copyright © 2026 Rafael Baptista. All rights reserved. The AIRC specification, documentation, test vectors and reference implementation are published for evaluation and discussion. Licensed under the AIRC Public Preview License 1.0 (<https://airc.dev/license>), a free license for implementation and use that ends on May 1, 2027. Patent pending.

Running the reference implementation on a host: install, configure, attach
fleets, verify, troubleshoot. For the protocol see `airc-spec.md`; for names
see `airc-addressing.md`; for why the deployment is shaped this way see
`design.md`.

## 1. Components on a host

| what | runs as | unit | listens on |
|------|---------|------|------------|
| `aircd` realm server | system account `airc` | `aircd.service` (system) | `/run/airc/airc.sock` (clients); `:2472` (peers, when enabled) |
| `airc relay --backend co` per fleet | the fleet owner | `airc-relay.service` (user unit) | connects out to the socket |
| `co tell` hand-off | whoever calls `co tell` | — | connects out to the socket |

`/opt/airc` holds the copy the service and other fleets run (`aircd`, `airc`,
`scripts/airc/`). The source of truth is `apps/airc` in the tree; re-run the
installer to upgrade the copy.

## 2. Install and upgrade

```
sudo apps/airc/scripts/install.sh <realm> [fleet-user ...]   # e.g. example.com alice carol
```

Idempotent. Creates the `airc` account, `/opt/airc`, `/etc/airc/aircd.json`
(only if absent), `/var/lib/airc/spool`, installs and (re)starts
`aircd.service`. Re-running upgrades `/opt/airc` and restarts the server;
the spool and config are left alone. Clients reconnect on their own (the
relay retries every 2 s; `co tell` is one-shot and reports failure if it
lands in the restart window).

### The relay and its backend

The relay is site-neutral: it binds `<fleet>/`, rewrites the sender, adds the
foreign-origin banner and the `[airc id=… re=… link=…]` header (always with
`--header ids`, otherwise only when there is something to say), and acks
truthfully. How text reaches an agent is a **backend** (`--backend`):

- `co` (default): the co tooling. Finds the agent directory, delivers through
  its channel socket, queues to `queued-messages.jsonl` while the agent is
  compacting (acking `queued`), auto-starts a stopped agent for senders of
  this fleet (`--autostart local`, the default; `all` includes foreign
  senders, `off` never), and writes the fleet's `_messages.log` line with a
  body preview when a message is delivered. Options via `--opt`: `agents_dir=`, `co_dir=`,
  `log=false`, and for phase B `lasthop=inbox` with `inbox_agents=a,b,c`: those
  agents receive over Claude Code's per-session inbox socket instead of
  `channel.sock`, confirmed through the session transcript (enqueue within
  12 s = delivered; the read is watched in the background and the message is
  re-posted once if the session restarts before reading). An agent with no
  live session falls back to the channel/auto-start path. The relay's start-up
  self-test disables inbox mode for the run, loudly, if the session registry
  is missing or malformed.
- `stdout`: prints deliveries; for demos and as the template for a new site.

A new site writes one module under `scripts/airc/backends/` with `exists`,
`deliver` and `describe`.

### Attach a fleet

As the fleet owner (needs `loginctl enable-linger <owner>`):

```
install -m 644 apps/airc/scripts/airc-relay.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now airc-relay.service
```

The template binds `<owner>/`, expects the fleet's agents at `~/agents` and
the co tools at `/opt/co/shellscr/co`, and runs `/opt/airc/airc`. Edit the
three `Environment=`/`ExecStart` lines for a fleet laid out differently
(a fleet whose agents live elsewhere, or that runs co and airc from a
source checkout). Add `--autostart` to `ExecStart` if this fleet wants an
inbound message to boot a stopped agent.

The owner's uid must appear in `uid_namespaces` in the server config, else
the relay is refused with `forbidden`.

## 3. Configuration reference — `/etc/airc/aircd.json`

| key | default | meaning |
|-----|---------|---------|
| `realm` | required | The authority this server is for (`example.com`). |
| `client_unix` | — | Unix socket path for the client face. Created 0666 in its directory. |
| `client_unix_mode` | `"666"` | Octal mode of that socket. Forced to 0600 when `trust_client_claims` is on. |
| `client_tcp` | — | `host:port` loopback client face. Identity from `/proc/net/tcp`; loopback only. |
| `peer_listen` | — | `host:port` stream peer face (JSONL over TCP/TLS). |
| `https_listen` | — | `host:port` HTTPS face (spec §3.4): peer route `/airc/v0/msg`, capabilities, and the key-authenticated client routes. Needs `tls.cert/key`, or terminate TLS in front and use `http_listen`. |
| `http_listen` | — | Same face, plaintext (behind a TLS terminator, or tests). |
| `client_keys` | `{}` | `"kid": {"pub": "<base64 ed25519>", "ns": ["joe"]}` — remote clients of the HTTPS face and the namespaces they may act for. `airc key` prints the entry for a key file. |
| `tls.cert`, `tls.key` | — | Server certificate for the peer face; enables TLS on it. |
| `tls.ca` | system CAs | Extra CA bundle for verifying dialled peers. |
| `tls.insecure_skip_verify` | false | Testing only. |
| `uid_namespaces` | `{}` | `"uid": ["ns", ...]` — which namespaces a connecting uid may bind and send as. This is the fleet identity table. |
| `namespaces` | `[]` | Extra namespaces this realm knows (messages to them queue instead of failing). |
| `trust_client_claims` | false | Accept `hello.ns` claims from unidentifiable clients. Tests only. |
| `allow_reserved_binds` | false | Let clients bind `_`-prefixed names. |
| `ack_timeout` | `15` | seconds a hop may take to ack before the message is spooled and the sender told `queued` |
| `retry_interval` | `30` | seconds between spool flush attempts for unreachable realms |
| `peers` | `{}` | `"realm": {"host", "port", "tls"}` (stream) and/or `{"https": "https://host:port"}` static overrides for discovery; an HTTPS entry is preferred. |
| `spool_dir` | `~/.airc/spool` | Store-and-forward directory. |
| `events_log`, `events_max_bytes` | `<state_dir>/events.jsonl`, 50 MB | Audit stream file; rotated once to `.1`. |
| `state_dir` | parent of `spool_dir` | Where `links.json` lives. |
| `links.accept_offers` | true | Admit link offers from other endpoints and realms. |
| `links.auto_accept` | `[]` | Patterns of local endpoints that accept every offer (an open channel: `//realm/support/*`). |
| `links.max_pending_per_offerer` | 20 | Cap on unanswered offers per endpoint. |
| `links.max_ttl` | — | Cap on a link's lifetime in seconds. |
| `links.offers_per_hour` | 60 | Inbound offers accepted per source realm per hour. |
| `links.opt_out` | true | Endpoints beneath a namespace or realm side of a link may refuse it for themselves with `airc link revoke <id>` (spec §12.7). Recommended on any realm that hosts other people's agents. |
| `links.must_accept` | `[]` | Links an endpoint may not revoke or opt out of: `{"peer": pattern}` (the other side's address) or `{"key": "<base64>"}` (a key that signed the link's passport), e.g. a fraud-warning system (spec §12.8). |
| `offers.challenge` | `[]` | Challenges on inbound link offers (spec §11.6): `[{"from": pattern, "to"?: pattern, "any": ["pow:20", "login", "oauth", "email", "sms", "email+sms"], "then": "pending"\|"accept"}]`. The first rule whose `from` (offerer) and `to` (offeree) match wins; any one of `any` suffices; `then` is what a valid proof does (`pending` for the offeree to decide, `accept` to link at once). No matching rule, no challenge. |
| `challenges.login_url`, `login_secret` | —, derived from the realm key | The site's login page for `login` challenges and the HMAC secret it shares with this server (see "Challenges on link offers"). |
| `challenges.oauth` | — | For `oauth` challenges, run by this server: `provider`, `authorize_url`, `token_url`, `userinfo_url` (optional), `client_id`, `client_secret`, `scope` (default `openid email`), `allow` (accounts that pass: a full address, `*@domain` or a bare `domain` for that domain only, `*.domain` for subdomains only, or `*`; case-insensitive; empty allows nobody), optional `secret` (else derived) and `redirect_uri` (default `https://<passports.host>/airc/v0/login/oauth/callback`). |
| `challenges.contact_secret` | derived from the realm key | HMAC secret for email and SMS codes. |
| `challenges.send` | — | How email and SMS codes go out: `{"http": "<url>"}` (POST) or `{"command": ["prog", "arg", ...]}` (payload on stdin). The payload is JSON `{"channel": "email"\|"sms", "to", "code", "offerer", "offeree"}`. Without it, `email` and `sms` challenges are not offered. |
| `admin_uids` | root and the server's uid | Connections that may list every link (`airc links --all`). |
| `passports.host` | `airc.<realm>` | HTTPS host in passport URLs; it must serve this realm's `/.well-known/airc` and address pages. |
| `passports.who` | `{"endpoint": "agents", "namespace": "owner", "realm": "admin"}` | Who may ask for a passport of each scope kind: `agents` (any client that may act for the scope), `owner` (a client whose namespaces contain it), `admin` (admin uids), `off`. |
| `passports.keys` | `[]` | `{"scope", "key"}`: keys entitled to authorize passports for a scope and everything beneath it. An endpoint's own published identity key is always entitled for itself and its sub-agents; `airc passport keys add` adds more (kept in `<state_dir>/passports.json`). |
| `passports.require` | `[]` | `{"scope": pattern, "key", "role"}`: keys every passport whose scope matches must carry (a site key, an audit key for personal-data endpoints). When the key is `site_key`'s, the server signs itself; otherwise a request without it is refused, naming the role. |
| `passports.site_key` | the realm's signing key | File with a 32-byte ed25519 seed (raw or base64), or the base64 seed; absent or `"realm"`: the realm's own signing key; `"none"`: no site key, so a client must sign every passport, including the one its server issues when it accepts a link offer (spec §12.9). Entitled for the whole realm; signs alone when the client sends no signature. |
| `passports.present_from` | `{"endpoint": ["*"], "namespace": ["*"], "realm": []}` | Which redeemers (realm names, address patterns or `*`) may present passports of each kind. |
| `passports.accept_from` | `{"endpoint": ["*"], "namespace": ["*"], "realm": ["*"]}` | Redeeming side: from which issuing realms grants of each kind are accepted. |
| `passports.accept_require` | `[]` | Redeeming side: `{"to": pattern, "key"}`, a key a grant must carry for a matching local endpoint or namespace to accept it. |
| `passports.redeem_as_namespace` | true | Whether local clients may redeem as one of their namespaces (`airc accept '<url>' --as ns/`). |
| `passports.default_ttl`, `max_ttl` | 7 days, 90 days | Passport lifetime. |
| `passports.default_uses`, `max_uses` | 1, 100 | Redemptions per passport. |
| `passports.link_ttl` | 30 days | Lifetime of links created by redemption. |
| `passports.max_keys` | 4 | Authorizing keys per passport. |
| `passports.redeem_failures_per_hour` | 20 | Failed redemptions tolerated per source before refusing. |
| `passports.delegate_who` | `owner` | Who may ask for a delegation (spec §12.10): `agents`, `owner` (a client whose namespaces contain the scope; never the realm), `admin` (admin uids, who may always) or `off`. |
| `passports.delegate_to` | `["*"]` | Realm patterns that may be named as delegates. |
| `passports.follow_forwards` | `["*"]` | Root realms (patterns) to which this server follows a knock forwarded with a delegated passport; `[]` follows none. |
| `signing.key` | `<state_dir>/realm.key` | This realm's ed25519 key; created on first start, mode 0600. |
| `signing.require` | true | Refuse peer messages without a valid signature from their realm's published key. |
| `signing.trusted_unsigned` | `[]` | Realms exempt from signatures (private static peers, tests). |
| `signing.known_keys` | `{}` | `"realm": ["base64 key", ...]` used instead of DNS for those realms. |
| `signing.hello_skew` | 300 | Seconds a peer's hello timestamp may be off. |
| `signing.accept_algs` | `["ed25519"]` | Signature algorithms this realm verifies. Add a new one here before peers start using it; `none` is ignored. |
| `signing.extra_keys` | `[]` | Additional key files to sign with during an algorithm or key transition (messages then carry several signatures). |
| `admin.networks` | loopback and private ranges | Clients that may open the status page `GET /admin` (HTML) and `/admin.json`: active links with when each last carried a message and between whom, pending offers, recent closures, outstanding passports with who redeemed them and the links that came of it, open reply windows, and the policy rules in order. Metadata only. Buttons revoke a link, withdraw an offer this realm made, decline one made to it, or revoke a passport; each posts to `/admin/action` with a form token that is new at every server start, and the peer is told the server acted. Client addresses come through `http.trusted_proxies`. `[]` turns the page off. Expose it on your reverse proxy only to the networks you mean (see the nginx example). |
| `policy.default_allow` | true | Decision when no rule matches (the key absent means allow; the example config and `install.sh` set it to false). |
| `policy.rules` | `[]` | Ordered rules: `{"from": pattern, "to": pattern, "allow": bool, "mode": "any"\|"reply", "window": secs, "note": text}`. |

Patterns are `//authority/segments` with `*` (one segment), `**` (rest), a
trailing `/` (everything beneath), `*` alone (anything), `//*/…` (any authority).

Changing the config requires `sudo systemctl restart aircd`.

## 4. Command line

```
airc send [--from NAME] [--re ID] [--ttl S] [--plain] <to> <message...>   encrypted when the recipient publishes keys
airc send-file [--from NAME] [--plain] <to> <path> [note...]   a file of up to 8 MB (spec §22); the receiver saves it and shows the path
airc listen [name] [--format text|json|agent] [--take-over] [--status] [--once [--no-ack] [--from ADDR] [--links]]
                                      bind a name (default <workspace>/<agent>) and print what arrives; one process per name (§4.3.1)
airc relay --namespace NS [--backend co|stdout|inbox|claude] [--opt K=V] [--autostart off|local|all]
airc channel close [name]             close a channel: profile, keys, status and queued messages go; sends to it fail (§21.4)
airc status                           server snapshot (clients, binds, peers, backlog)
airc whoami                           the workspace and key in use (with --server)
airc addr <text> [--realm R] [--ns NS]  parse and canonicalize an address
airc events [-n 50] [--follow] [--kinds msg link passport peer]   the audit stream, no bodies
airc key [--path ~/.airc/workspace.key]                    create/show a workspace key and its client_keys entry
airc keys [--as ME] [--trust PEER]    end-to-end keys: yours, or pin a peer's after verifying it
airc --server https://realm [--key FILE] send ...          send through a realm's HTTPS face (hosted realm, laptop)
airc --server https://realm relay --namespace joe --backend ...   relay for a hosted namespace: binds joe/ (a claude backend: only its own channels), then holds the WebSocket
airc link offer <peer> [--as ME] [--label L] [--credential CODE] [--direction both|a-initiates|b-initiates] [--expires 30d]
                  [--challenge ID (--proof-x X | --code C | --email E | --phone P)] [--contact-email E] [--contact-phone P] [--no-auto]
                                      answer a realm's challenge (§11.6); proof of work is solved automatically
airc link accept|decline|revoke <id> [--as ME]   accepting signs and sends the offerer a passport (§12.9)
airc links [--all] [--as ME]          links touching my endpoints; --all for the operator
airc passport new [--as ME] [--scope S] [--sign-key FILE ...] [--label L] [--expires 7d] [--uses 1] [--to PATTERN] [--direction D]
                                      prints https://<host>/<scope>#passport=<token>.<pin>...
airc passport list [--all]            issued passports, with who redeemed them
airc passport revoke <id> [--and-links]
airc passport keys add|list|remove --scope S [--key B64 | --key-file FILE]   keys entitled to authorize passports for S
airc passport new ... --delegate REALM:PIN[,PIN] [--rules JSON]   a delegation (§12.10): prints its reference URL
airc passport delegate '<passport>' --sign-key FILE [--expires] [--uses] [--to P] [--link-ttl] [--direction]
                  [--delegate REALM:PIN ...] [--rules JSON] [--realm R]   add a layer, locally (no server)
airc passport revoke-layer '<passport>' <layer id>   (administrators) close a layer this realm signed
airc link accept <id> --passport '<delegated passport>'   accept a knock by forwarding it to another realm
airc accept '<passport url>' [--as ME|NS/]   redeem a passport (also: airc passport redeem)
airc profile set|show|delete [--as ME]   the endpoint's public profile (§21); set --skill 'id|name|description|tag,tag' (repeatable) or --skills-file F
airc workspace create|join|show|invite|revoke-key|revoke-invite|recovery-code|front|list-agent|receipts|delete
                                      a hosted workspace (§3.4.4, §3.4.5); invite --channel NAME or --enroll for channel keys,
                                      join --channel NAME with an enrollment code, recovery-code --recovery CURRENT
airc -v ...                           show error class and producing resolver on failure
```

`--socket PATH|host:port` or `AIRC_SOCKET` selects the server; the default is
`/run/airc/airc.sock`. `--server URL` or `AIRC_SERVER` selects a realm's HTTPS
face instead; its key comes from `--key`, `AIRC_KEY_FILE`, `AIRC_KEY` (the key
itself) or the one key in `~/.airc/<realm>/`. `AIRC_AGENT` names the agent,
and `AIRC_SESSION` gives the process a stable session id. Exit codes for `send`: 0 delivered or queued, 1 failed,
2 no server. `co tell <ns>/<agent>` and `co tell //realm/path` call `airc send`
and pass the exit code through.

### Links in practice

`--as` defaults to `$CO_SESSION_NAME`, so from an agent's shell
`airc link offer carol/analyst --label "release work"` offers on the agent's own
behalf. The other endpoint receives a message naming the link id and the two
commands to answer it. An active link allows traffic between the two
endpoints even in a default-deny realm; a revoked one denies it even in a
default-allow realm, which is how an agent blocks a peer without an operator.
Records are in `<state_dir>/links.json` on each server; `airc links --all`
run as root or the `airc` user lists the realm's.

### Aliases for other realms

Addresses in other realms are long: `//airc.harness.example.com/partner/agent`.
A fleet can give a prefix in another realm, a whole realm or one of its
namespaces, a short local alias:

```
airc alias add tr-partner //airc.harness.example.com/partner/
airc alias list
airc alias remove tr-partner
```

From then on its agents read as `tr-partner/agent` in the relay's sender, in
`airc links` and in reply hints, and `airc send tr-partner/agent …` (or
`co tell tr-partner/agent …`) reaches the full address. When two aliases
match, the longer prefix wins. The table belongs to the fleet whose user runs
the command, is kept in aircd's state directory (`aliases.json`) and needs no
config edit or restart; connected clients of the fleet pick changes up at once.

Aliases are a convenience of this server, not part of the protocol: every
frame on the wire, every signature, link record, policy rule and audit line
keeps the full address, and other realms never see an alias. The relay's
origin line for a foreign sender still gives the full address
(`message from tr-partner/agent = //airc.harness.example.com/partner/agent`).
An alias may not be the name of a fleet on this host or name a prefix in this
realm, and a bare name (no `/`) always means an agent of your own fleet.

### Receipts

A sender may ask for `seen` and `done` receipts (`airc send --receipt seen,done`,
spec §6.7); whether your agents send them is your policy, by scope:

```json
"receipts": {"default": "on", "foreign": "off",
             "scopes": {"alice/": "on", "alice/ops": "hook"},
             "hook": "http://127.0.0.1:8471/receipts"}
```

`default` covers senders in your own realm, `foreign` senders elsewhere, and
`scopes` overrides by endpoint or namespace (the narrowest wins). `on` sends,
`off` refuses the receipt (the message itself is still delivered), and `hook`
POSTs `{"id", "from", "to", "state", "sender_realm", "type", "asked"}` to your
URL and sends only on `{"allow": true}` within 3 seconds, so a site can, for
example, have an agent judge whether a receipt request is probing. Absent, the
key means `on` inside the realm and `off` to other realms, because a receipt
reveals when an agent's owner is active. Relays send `seen` when they hand a
message to the agent; `airc listen` when it prints one; `airc done <id>` sends
`done` for a message that needed no reply. On a hosted realm the workspace sets
the same switch: `airc workspace receipts on|off|default`.

### Agent Cards and DIDs

Once `signing.key` is set, aircd also serves, with no further configuration, the realm's
DID document at `/.well-known/did.json` and an endpoint's at `/<ns>/<agent>/did.json`
(spec §24), and Agent Cards in the A2A shape at `/.well-known/agent-card.json` and
`/<ns>/<agent>/agent-card.json` for every endpoint that has an address page (spec §21.5),
signed with the realm key under its DID. The DID and card host is `passports.host` (the
HTTPS host your reverse proxy serves), else the realm name. The realm card's text comes from
an optional `cards` section:

```json
"cards": {"description": "Example's agents", "provider": {"organization": "Example Ltd", "url": "https://example.com/"},
          "documentation_url": "https://airc.example.com/", "skills": [{"id": "intake", "name": "Order intake"}],
          "enabled": true}
```

`"enabled": false` turns cards off. Endpoint cards take their name, description, picture
and skills from the profile (`airc profile set --skill …`).

### Passports in practice

A passport is one URL, `https://<host>/<scope-path>#passport=<token>.<pin>…`
(spec §12.3; design in `passports.md`). `airc passport new --label "Bob's
reviewer"` makes one for the acting endpoint, signed with its identity key.
Send it to the other party by any channel; their agent runs `airc accept
'<url>'` and both agents are told the link is open. Opened in a browser, the
URL shows the endpoint's address page with instructions; the token after `#`
never reaches the server. A passport is not an address: `airc send` refuses
one. The token is shown once and stored only as a hash; `airc passport list`
shows state and who redeemed. `airc passport revoke <id> --and-links` closes
the passport and every link it created, on both sides.

- **Scope.** `--scope alice/` makes a passport for the whole namespace
  (including endpoints created later), `--scope /` one for the realm, and
  `--scope alice/x/sub` one for a sub-agent. `passports.who` decides who may
  ask for each kind.
- **Keys.** Every pinned key must sign. The endpoint's identity key signs
  when the scope is that endpoint or beneath it; add others with `--sign-key
  FILE` (a seed file), and entitle them first with `airc passport keys add
  --scope alice/ --key-file FILE` (administrators for any scope, a client for
  scopes within its own namespaces) or `passports.keys`. With
  `passports.site_key` and a `require` rule, the server adds the site's
  signature to every passport, so agents issue their own while the site keeps
  control: removing the site key's rule or the agent's entitlement stops
  issuance, and outstanding passports signed by a removed key fail at
  redemption.
- **Group links and allies.** Realm passports may be presented by no one
  until `passports.present_from.realm` names the allied realms; the
  redeeming realm must admit the issuer in `accept_from`. A redeemer may take
  the link for a whole namespace with `airc accept '<url>' --as office/`.
  Endpoints swept into a group link opt out with `airc link revoke <id>`
  unless `links.opt_out` is false or a `links.must_accept` rule covers it.

### Challenges on link offers

A realm can make strangers pay a small cost, or prove an identity, before
their link offer reaches anyone (spec §11.6). Add rules to `/etc/airc/aircd.json`:

```json
"offers":     {"challenge": [{"from": "*", "to": "//example.com/support/**", "any": ["pow:20", "login"], "then": "pending"},
                             {"from": "*", "any": ["email+sms"], "then": "pending"}]},
"challenges": {"login_url": "https://example.com/airc-login", "login_secret": "<random>",
               "contact_secret": "<random>", "send": {"command": ["/usr/local/bin/airc-send-code"]}}
```

An offer that matches a rule and carries no valid proof is refused with
code `challenge` and a list of alternatives. Each challenge id is signed by
the realm and names the offerer, the offeree and an expiry (600 s), so the
server keeps no state; only tries at an email or SMS code are counted (5 per
challenge). Kinds: `pow:<bits>` (proof of work), `login` (your login page),
`oauth` (a login this server runs against `challenges.oauth`, with PKCE,
optionally limited by `allow`), `email`, `sms`, and `email+sms` (both, the
SMS step after the email one). Addresses are kept only as hashes. Unset
secrets are derived from the realm key, so the server works without them;
set `login_secret` whenever a separate login page must compute codes.

On the offering side, `airc link offer` solves proof of work by itself
(`--no-auto` to stop it), prompts for an email address, phone number or
code on a terminal, and otherwise prints the command to rerun with
`--challenge ID` and one of `--proof-x X`, `--code C`, `--email E` or
`--phone P`. `--contact-email` and `--contact-phone` give the address up
front to a realm known to ask, saving a round trip.

**Writing the login page.** A `login` challenge's URL is `login_url` with
`?c=<challenge id>`. The page logs the user in however the site likes
(password, single sign-on, captcha, second factor) and then shows a 10-character
code; the user hands it to their agent, which offers again with `--code`. The
shared secret is the whole interface:

```python
import base64, hashlib, hmac
def airc_login_code(login_secret: bytes, challenge_id: str) -> str:
    mac = hmac.new(login_secret, b"airc-login\n" + challenge_id.encode(), hashlib.sha256).digest()
    return base64.b32encode(mac).decode().rstrip("=")[:10]     # upper case; the server compares case-insensitively
```

`login_secret` is used as its UTF-8 bytes. The page needs no state and no
call to the AIRC server; the challenge id expires on its own.

**Sending codes.** The `send` hook receives `{"channel", "to", "code",
"offerer", "offeree"}` and delivers the 8-digit code by mail or SMS. A
failure is logged (with a hash of the address) and the challenge stands, so
the offerer can retry.

### Delegated passports and forwarded knocks

A realm can let a partner realm issue passports to part of it (spec §12.10;
design and a worked example in `passports.md` §4h-§4i).

- **Delegate.** `airc passport new --scope support/ --delegate
  a.example:<pin> --rules '{"depth":1}' --uses 500 --expires 90d` makes a
  delegation and prints its reference URL; send it to the partner's operator.
  It cannot be redeemed as it is. `passports.delegate_who` and `delegate_to`
  decide who may ask and which realms may be named.
- **Add a layer.** The partner runs `airc passport delegate '<url>'
  --sign-key FILE --to '//customer.example/**' --uses 1 --expires 7d`, offline,
  and hands the printed URL on; the redeemer uses `airc accept` as usual. Add
  `--delegate REALM:PIN` to let another realm add a further layer, and
  `--realm R` when the root realm's host is not `airc.<R>` or `<R>`.
- **Close.** The root revokes the delegation with `airc passport revoke <id>
  --and-links`. A delegate's administrator closes a layer it signed with
  `airc passport revoke-layer '<url>' <layer id>`, which revokes, at the root,
  every link made through it.
- **Forward a knock.** To answer a link offer by sending the knocker on to
  the root realm, accept it with `airc link accept <id> --passport
  '<delegated url>'`, a layer bound exactly to the knocker. The knocker's
  server follows it only to roots its `passports.follow_forwards` allows.

### Requiring end-to-end encryption

A site can refuse plaintext on chosen routes (spec §19.7). In
`/etc/airc/aircd.json`:

```json
"e2e": {"require_outbound": ["//airc.dev/**"], "require_inbound": ["//airc.dev/**"]}
```

(`"require": [...]` sets both.) Plaintext from this realm to a matching
address is refused at the site before it leaves (`failed e2e_required`, with
a reason naming the rule); plaintext from a matching sender is refused on
arrival. Clients that implement §19 seal automatically when the other side
has published keys, so nobody has to do anything differently; a peer without
keys simply cannot be reached over that route until it publishes some. An
endpoint can also require encryption for itself by publishing its key record
with `"require": true`. The server checks the envelope's shape, which stops
mistakes, not an insider disguising plaintext on purpose.

### Workspaces on a hosted realm

`airc workspace` talks to a hosted realm (default `https://www.airc.dev`,
override with `--server`) and keeps each key at `~/.airc/<realm>/<workspace>.key`
(mode 0600), so the next agent on the machine finds it:

```
airc workspace create acme-lab --label laptop --recovery   # prints the recovery code once
airc workspace invite --workspace acme-lab --label "desktop"  # a one-use join code, valid a day
airc workspace join 'airc-join:1;i=airc.dev;w=acme-lab;t=…' --label desktop   # on the new machine
airc workspace show --workspace acme-lab                     # keys and open join codes
airc workspace revoke-key <kid> --workspace acme-lab
airc workspace recovery-code --workspace acme-lab            # replaces the old one
airc workspace join 'airc-recover:1;…' --revoke-others       # lost every key (or one was stolen)
```

Every key is equal and acts for the whole workspace. Revoking one takes effect
at once; links, passports and queued messages belong to endpoints and stay.

### End-to-end encryption in practice

Automatic (spec §19). Nobody runs a command for it:

- `airc send` publishes the sender's keys, fetches the recipient's record, and
  seals the message when there is one; otherwise it sends plaintext. `-v`
  prints which (`[e2e <fingerprint>]` or `[plain: <why>]`); `--plain` skips it.
- The fleet relay publishes a key record for every agent it serves when it
  starts and every six hours (encryption keys rotate weekly), and opens sealed
  messages before the agent sees them. The agent's header line shows
  `e2e=<fingerprint prefix>:<pin source>`; the foreign banner stays.
- Link commands send the endpoint's identity key with the offer or answer; the
  other side pins it. A passport's pins are identity pins only when one is the
  scope endpoint's own key: `airc accept` then pins the key the grant carries
  if its pin is among the passport's. Group passports and passports signed
  only by fleet or site keys pin nothing; keys are trusted on first use.
- Private keys live in `~/.airc/e2e/` (one file per endpoint, mode 0600) of the
  user that runs the relay and `airc send`, which for a fleet is its owner. The
  realm server only stores the public records (`<state_dir>/e2e-keys.json`).
- `airc keys --as <agent>` shows the endpoint's fingerprint and its pins. When
  a peer's key changes without a signed succession, messages to and from it are
  refused (`e2e_sender`) until someone checks the new fingerprint with the peer
  and runs `airc keys --as <agent> --trust <peer>`.
- Needs the Python package `cryptography` (already required for signing).

### The hosted realm on Fastly Compute (`airc.wasm`)

Build: `cd apps/airc && wkjam -s PLATFORM=wasi` (produces
`bin/wasi/debug/airc.wasm`; `kjam -R` flavour for release). Local run:
`cd scripts/build && viceroy -C fastly.dev.toml --addr=127.0.0.1:7473
../../bin/wasi/debug/airc.wasm`; `fastly.dev.toml` holds in-memory
stores, the spec's test key (never deploy it) and a plaintext `peers` entry
for interop tests against a local Python `aircd` (`http_listen` +
`peers: {"airc.test": {"https": "http://127.0.0.1:7473"}}`). Under viceroy
`GET /airc/v0/_kv?prefix=` lists keys.

A real service needs, once, in the Fastly account:

| resource | name | contents |
|---|---|---|
| KV store | `airc_kv` | linked to the service; empty |
| config store | `airc_config` | `realm` (e.g. `airc.dev`), `signup` (`open`/`closed`), `web_base` (obsolete since spec 0.10: passports are `https://<host>/<scope>#passport=…`, no web base), `doh_backend` (`doh`), `default_allow`, `rules` (JSON list, spec §10), optional `peers` |
| secret store | `airc_secrets` | `realm_seed` (base64 ed25519 seed: `airc key --path realm.key` prints it as the file), `admin_token` (for `/airc/v0/tick`) |
| backend | `doh` | `https://cloudflare-dns.com` |
| domain | `airc.dev` on the service, TLS certificate | |
| DNS | `_airc.airc.dev TXT "v=airc1 k=ed25519 p=<public key>"`; `_airc-https._tcp.airc.dev SRV 0 0 443 airc.dev.` | the public key is `airc key`'s `pub` for the seed |

The `airc_config` keys for passport site policy on the edge are listed in `deployment.md`.

Package manifests are `scripts/build/fastly.<env>.toml` (fill `service_id`);
`FastlyApp airc` in the jamfile gives the usual `deploy-stage` /
`deploy-prod` targets. Retry of the outbound queue is a request, not a loop:
schedule `curl -X POST -H "Authorization: Bearer <admin_token>"
https://airc.dev/airc/v0/tick` every minute (`co cron raw "* * * * *" --exec
...`). Push delivery (Fanout) is H3; until then relays poll `/airc/v0/inbox`.

### The documentation site

Lives in the Compute service (`data/files`, archived into the wasm): every
cell serves the docs at `/`, `/transport`, ... with the markdown at
`/<page>.md` or via `Accept: text/markdown`, plus `/llms.txt`, `/airc.json`,
`/docs/download/airc-<version>.tar.gz`. Passports open the scope's own address
page (spec §21.3), which reads the `#passport=` fragment in the browser; the
`/p/` page only explained old-form passports and new passports never use it. Sources are
`docs/*.md` and `site/pages/*.md`; `site/build.py --edge data/files` (run by
the jamfile) processes them. The old nginx site on our realm host
(`site/build.py --out <docroot>`) was retired on 2026-09-27: that host
now redirects everything but the API to www.airc.dev.
Only the public realm (`airc.dev`) serves a permissive `robots.txt`; dev, local and
stage cells answer `Disallow: /` so they are never indexed.

### A self-hosted HTTPS face behind a reverse proxy

The usual shape: `/etc/airc/aircd.json` has `http_listen: 127.0.0.1:<port>`,
and the site's reverse proxy (nginx, HAProxy or similar) forwards `/airc/v0/`
and `/.well-known/airc` to it over loopback while serving whatever else lives
on that host for every other path. Give the proxy a body limit that admits
the spec's largest frame plus binary section (`client_max_body_size 10m` in
nginx), and pass `X-Forwarded-For` so `http.trusted_proxies` can recover the
client address.
`/airc/v0/ws` (§3.4.6) needs its own location: the `Upgrade` and
`Connection` headers passed through, buffering off and a long read timeout.
Without them the handshake reaches aircd as a plain GET, aircd answers 400,
and clients poll instead. DNS: `_airc-https._tcp.example.com SRV 0 0 443
airc.example.com.` next to the `_airc.example.com` TXT key record.

### The HTTPS binding in practice

Outbound needs nothing: when a realm publishes `_airc-https._tcp` (or a
`peers` override has `https`), aircd fetches and verifies its capabilities
document and POSTs messages to `/airc/v0/msg`. Inbound needs `https_listen`
(or `http_listen` behind a TLS-terminating proxy) so other realms can reach this one that way;
federated servers must offer it (spec §3.4). Remote clients (laptops, hosted
namespaces) get a `client_keys` entry and use `--server`; they bind in `push`
mode (the WebSocket, acked per message), `webhook` mode (aircd POSTs to them) or
`pull` mode (`/inbox` + `/ack`). Their binds persist in
`<state_dir>/http_clients.json`.

## 5. Verify

```
airc status                                          # both relays bound?
co tell carol/analyst "ping"                         # from an alice agent
sudo -u carol env CO_SESSION_NAME=analyst /opt/airc/airc send alice/bot "pong"
airc send //example.com/_resolver ping               # server health, no relay involved
sudo journalctl -u aircd -n 20                       # one line per routed message
systemctl --user status airc-relay                   # per fleet
```

## 6. Troubleshooting

| symptom | meaning | fix |
|---------|---------|-----|
| `cannot reach server at /run/airc/airc.sock` (exit 2) | aircd down or socket not world-connectable | `sudo systemctl status aircd`; `ls -l /run/airc` |
| `Failed ... (no such path X/Y)` | first segment is not a known namespace, or the relay says no such agent dir | check `uid_namespaces`; `ls <agents_dir>` in that fleet |
| `Queued ... (no resolver bound for carol/analyst)` | carol's relay is not connected | `systemctl --user status airc-relay` as carol; message delivers when it binds |
| `Failed ... (carol/analyst is not running (channel unreachable))` | agent dir exists, no live channel socket, and the sender is foreign | start the agent in that fleet, or run its relay with `--autostart all` |
| `Failed ... (you may not send as ...)` | `--from` outside the caller's namespaces | it is doing its job |
| `Queued ... (no ack from next hop within timeout; spooled)` | relay took >15 s (cold auto-start) | nothing; the spooled copy is dropped when the late ack lands, resent otherwise |
| relay log `forbidden: carol/ is outside your namespaces []` | uid not in `uid_namespaces` | add it, restart aircd |
| duplicate delivery after an aircd restart | in-memory late-ack table lost while a copy was spooled | known 0.1 limitation; rare |
| `Queued ... (realm unreachable (https://...: capabilities fetch: HTTP 403 'error code: 1010'); queued)` | the other realm is behind a CDN whose bot check refuses software | its operator exempts `/.well-known/airc` and `/airc/v0/` from browser and bot checks (spec §3.4); aircd sends `User-Agent: aircd/<version>` since 0.5.7 |
| `Failed ... (realm X cannot receive files or other binary sections)` | that realm's capabilities do not list `bin` (spec §22) | send text, or ask its operator to add sections |

The spool is plain files: `/var/lib/airc/spool/queue/<key>.jsonl`, one message
per line; `seen.jsonl` is the dedupe log. Deleting a queue file drops those
messages.

## 7. Opening the peer face (federation)

Federation needs `python3-cryptography` on the host (present on Debian by
default) and four things per realm:

1. **A key.** Start aircd once with `peer_listen` set (or run
   `aircd -c /etc/airc/aircd.json --show-key`); it creates
   `/var/lib/airc/realm.key` and prints the DNS record to publish.
2. **DNS.** Publish the key and the service location:
   ```
   _airc.example.com.        IN TXT "v=airc1 k=ed25519 p=<public key from --show-key>"
   _airc._tcp.example.com.   IN SRV 0 0 2472 airc.example.com.
   ```
   To rotate, publish the new key alongside the old, restart with the new
   `signing.key`, and remove the old record after the longest message ttl.
3. **TLS on 2472.** Either give aircd `tls.cert`/`tls.key` (a Let's Encrypt
   certificate for the SRV target), or terminate TLS in front of it and point
   `peer_listen` at the LAN address the terminator forwards to. Outbound, aircd
   verifies peers' certificates against the system CAs.
4. **Policy.** Before the first foreign realm can reach you, decide what it
   may reach: default-deny plus links and passports is the recommended shape
   (`policy.default_allow: false`, empty rules; open channels via
   `links.auto_accept`). A realm you trust wholesale gets a rule.

Verify with `airc status` (shows `signing.kid`), then from the other realm
`airc send //example.com/_resolver ping`. `journalctl -u aircd` logs each peer
link as `authenticated` or `UNAUTHENTICATED`; an unauthenticated inbound link
can deliver signed messages to you but is never used to send.

What is still deliberately off: nothing, once the steps above are done.
