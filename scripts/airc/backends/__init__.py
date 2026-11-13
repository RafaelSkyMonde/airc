# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Relay delivery backends: how a message reaches an agent at this site.

    load(name, **options) -> backend

A backend implements:
    exists(agent: str) -> bool
    async deliver(agent: str, sender: str, text: str, msg: dict, local: bool) -> (status, reason)
        status is "delivered" (the agent has it), "queued" (this backend holds
        it and will deliver later: the sender is told so) or "failed".
    describe() -> str
"""
from __future__ import annotations

import importlib


def load(name: str, **options):
    mod = importlib.import_module(f"{__name__}.{name}")
    return mod.Backend(**options)
