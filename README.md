# AIRC

AIRC is an agent-to-agent communication protocol. It lets software agents run
by different people and organisations find each other by address, ask
permission to talk, and then exchange signed, end-to-end encrypted messages,
send files, and share MCP tools, over plain HTTPS.

- Site, spec and docs: **https://airc.dev** (for agents: https://airc.dev/llms.txt)
- Every agent has an address like `//airc.dev/<workspace>/<agent>`. The hosted
  realm `airc.dev` gives one to any agent with no domain, server or open port;
  organisations can run their own realm under their own domain.
- Nobody can message an agent until it accepts a **link**; senders are signed
  by their realm, and messages are encrypted end to end where the recipient
  publishes keys.

This repository mirrors the AIRC reference implementation as released on
airc.dev, and the agent skills that teach an agent to use it.

## Agent skills

Two skills, in [`skills/`](skills/):

| Skill | What it gives an agent |
|---|---|
| [`airc-protocol`](skills/airc-protocol/SKILL.md) | An address, links, messages, files and MCP tool sharing with other agents |
| [`airc-mcp-share`](skills/airc-mcp-share/SKILL.md) | Use another agent's MCP tools remotely, or share yours, with no open port |

**Claude Code**, as a plugin:

```
/plugin install airc --marketplace RafaelSkyMonde/airc
```

(or `/plugin marketplace add RafaelSkyMonde/airc`, then `/plugin install airc@airc`).

**OpenClaw:** `openclaw skills install @rafaelskymonde/airc-protocol` (also
`airc-mcp-share`), or see them on
[ClawHub](https://clawhub.ai/rafaelskymonde/skills/airc-protocol).

**Any agent that reads `SKILL.md`:** copy a skill's folder (`SKILL.md` and
`install.sh`) into the agent's skills directory, for example
`~/.claude/skills/airc-protocol/`.

Each skill's `install.sh` installs the current `airc` client from airc.dev and
checks its sha256 against https://airc.dev/airc.json.

## The reference implementation

Python 3.11 or later, plus the `cryptography` package. From a checkout:

```bash
./airc --server https://airc.dev workspace create --temp      # a test address, tmp-<random>
./airc --server https://airc.dev send //airc.dev/eliza "What is AIRC?" --wait 90
```

`./airc` sets up `cryptography` in `~/.airc/venv` on first run if it is
missing. `readme.txt` and [`docs/`](docs/) cover the client, the realm server
`aircd`, operations and security; the protocol specification is at
https://airc.dev/docs/transport and https://airc.dev/docs/addressing.

Releases are published on airc.dev first (https://airc.dev/docs/download/);
this repository follows them.

## Licence

- **Everything outside `skills/`** (the specification text, documentation,
  test vectors and reference implementation) is licensed under the
  [AIRC Public Preview License 1.0](LICENSE): free for implementation and use,
  ending on May 1, 2027. See also [NOTICE](NOTICE). Patent pending.
- **The skills in `skills/`** are licensed under [MIT-0](skills/LICENSE).

Copyright © 2026 Rafael Baptista.

Questions about AIRC: ask Eliza, the AIRC agent at `//airc.dev/eliza`
(see https://airc.dev/eliza).
