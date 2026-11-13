# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""A site-neutral backend that prints deliveries. For demos, tests and as the
template for a real one."""
from __future__ import annotations

import sys


class Backend:
    def __init__(self, agents: list[str] | None = None, **_):
        self.agents = set(agents or [])     # empty = accept any name
        self.log: list[tuple] = []

    def exists(self, agent: str) -> bool:
        return not self.agents or agent in self.agents

    def list_agents(self) -> list[str]:
        return list(self.agents or [])

    async def deliver(self, agent: str, sender: str, text: str, msg: dict, local: bool = False):
        self.log.append((agent, sender, text))
        print(f"[{agent}] from {sender}: {text}", file=sys.stdout, flush=True)
        return "delivered", ""

    def describe(self) -> str:
        return "stdout"
