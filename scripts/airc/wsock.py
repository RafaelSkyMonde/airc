# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""WebSocket framing (RFC 6455) for the WebSocket binding (spec §3.4.6), stdlib only.

Both ends use it: the reference server (httpbind, asyncio streams) and the client (httpclient, a blocking
socket on a reader thread). Only what AIRC needs: text frames carrying one JSON frame each, ping/pong,
close, and continuation frames on receipt.
"""
from __future__ import annotations

import base64
import hashlib
import os
import struct

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
TEXT, BINARY, CLOSE, PING, PONG = 1, 2, 8, 9, 10
MAX_MESSAGE = 2 * 1024 * 1024          # a text frame is one AIRC frame (1 MiB), with room for escaping


class WsError(Exception):
    pass


def accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def new_key() -> str:
    return base64.b64encode(os.urandom(16)).decode()


def encode(op: int, data: bytes | str, mask: bool) -> bytes:
    """One final frame. Clients mask (mask=True); servers do not."""
    if isinstance(data, str):
        data = data.encode()
    n = len(data)
    mbit = 0x80 if mask else 0
    head = bytes([0x80 | op])
    if n < 126:
        head += bytes([mbit | n])
    elif n < 65536:
        head += bytes([mbit | 126]) + struct.pack(">H", n)
    else:
        head += bytes([mbit | 127]) + struct.pack(">Q", n)
    if not mask:
        return head + data
    m = os.urandom(4)
    return head + m + bytes(b ^ m[i % 4] for i, b in enumerate(data))


class Decoder:
    """Frames from a byte source: read(n) returns exactly n bytes (or raises). Reassembles continuations;
    yields (op, payload) per message, control frames as they come."""

    def __init__(self, require_mask: bool):
        self.require_mask = require_mask
        self._op = None
        self._parts: list[bytes] = []

    def header(self, b0: int, b1: int):
        if b0 & 0x70:
            raise WsError("reserved bits set")
        masked = bool(b1 & 0x80)
        if self.require_mask and not masked:
            raise WsError("client frames must be masked")
        if b0 & 0x08 and ((b1 & 0x7F) > 125 or not b0 & 0x80):    # RFC 6455 §5.5: control frames are short, unfragmented
            raise WsError("control frame too long or fragmented")
        return b0 & 0x80, b0 & 0x0F, masked, b1 & 0x7F

    def payload(self, fin: int, op: int, data: bytes):
        """The message this frame completes, as (op, payload), or None while a fragmented one continues."""
        if op >= 8:
            return op, data
        if op == 0:
            if self._op is None:
                raise WsError("continuation without a start")
        else:
            if self._op is not None:
                raise WsError("new message inside a fragmented one")
            self._op = op
        self._parts.append(data)
        if sum(len(p) for p in self._parts) > MAX_MESSAGE:
            raise WsError("message too large")
        if not fin:
            return None
        out = (self._op, b"".join(self._parts))
        self._op, self._parts = None, []
        return out


def unmask(data: bytes, m: bytes) -> bytes:
    return bytes(b ^ m[i % 4] for i, b in enumerate(data))


def read_sync(read, dec: Decoder):
    """The next message from a blocking source (read(n) -> exactly n bytes)."""
    while True:
        b0, b1 = read(2)
        fin, op, masked, n = dec.header(b0, b1)
        if n == 126:
            n = struct.unpack(">H", read(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", read(8))[0]
        if n > MAX_MESSAGE:
            raise WsError("frame too large")
        m = read(4) if masked else b""
        data = read(n)
        if masked:
            data = unmask(data, m)
        out = dec.payload(fin, op, data)
        if out is not None:
            return out


async def read_async(reader, dec: Decoder):
    """The next message from an asyncio StreamReader."""
    while True:
        b0, b1 = await reader.readexactly(2)
        fin, op, masked, n = dec.header(b0, b1)
        if n == 126:
            n = struct.unpack(">H", await reader.readexactly(2))[0]
        elif n == 127:
            n = struct.unpack(">Q", await reader.readexactly(8))[0]
        if n > MAX_MESSAGE:
            raise WsError("frame too large")
        m = await reader.readexactly(4) if masked else b""
        data = await reader.readexactly(n)
        if masked:
            data = unmask(data, m)
        out = dec.payload(fin, op, data)
        if out is not None:
            return out
