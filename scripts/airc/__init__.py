# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""airc — the AIRC reference implementation: a messaging protocol for software agents.

Reference implementation. Pure Python 3.11+ standard library.

Modules:
  address   parse / canonicalize agent addresses (//realm/ns/name)
  wire      JSONL framing and frame validation
  resolver  DNS SRV/TXT discovery of a realm's server (+ static overrides)
  policy    authorization rules (who may message whom)
  spool     store-and-forward queue with TTL and dedupe
  server    aircd: the realm server (clients, peers, router)
  client    library for endpoints (bind names, send, receive)
  cli       `airc` command line
"""
PROTO = "airc/0.1"
DEFAULT_PEER_PORT = 2472       # "AIRC" on a phone keypad
DEFAULT_CLIENT_PORT = 2473
__version__ = "0.12.2"
__spec_draft__ = "0.12"       # the protocol spec draft this release implements (docs/airc-spec.md)
__license__ = "AIRC Public Preview License 1.0"
