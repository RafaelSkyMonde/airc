# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Wire framing.

Every AIRC connection — client<->server and server<->server — carries a
sequence of frames. A frame is one JSON object encoded in UTF-8 on one line,
terminated by '\n'. Frames never contain raw newlines (JSON escapes them).
Maximum frame size is 1 MiB.

Frame types (field "t"):

  hello     first frame from the connecting side
              proto   "airc/0.1"
              role    "client" | "peer"
              realm   (peer) the connecting server's realm
              agent   (optional) software name/version
  welcome   server's reply to hello
              realm   the server's realm
              ns      (client) namespaces this connection may speak for
  bind      client asks to receive messages for names
              names   list of paths relative to the realm ("alice/*")
  bound     server confirms
              names   the accepted patterns
  msg       a message
              id      unique id (uuid4 string), chosen by the origin
              from    absolute address of the origin endpoint
              to      absolute address of the destination endpoint
              ts      origin time, unix seconds (float)
              body    text
              type    media type of body, default "text/plain"
              re      (optional) id of the message this replies to
              ttl     (optional) seconds the message stays deliverable, default 86400
              via     list of realms traversed (loop detection)
              hdr     (optional) object of extension headers
  ack       delivery status for a msg id
              id      the msg id
              status  "delivered" | "queued" | "failed"
              reason  (optional) human-readable
              code    (optional) error class, see CODES below
              by      (optional) URI of the resolver that produced the status
              bin     (optional) length of the binary section that follows the line (spec §22)
              bin_sha256  its SHA-256, lower-case hex
  ping/pong keepalive; pong echoes any "n" field
  error     protocol error from either side; connection is then closed
              code, reason
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import time
import uuid

MAX_FRAME = 1 << 20
MAX_BIN = 8 << 20             # a message's binary section (spec §22)
DEFAULT_TTL = 86400
MAX_HOPS = 8
# asyncio's StreamReader limit (default 64 KiB) caps readline(); a frame's line may be 1 MiB (§3.2).
# The binary section after it is read with readexactly, which the limit does not bound.
STREAM_LIMIT = MAX_FRAME + 4096

# Recording hook for the schema tests (tests/test_schema.py): when a list is assigned here, every frame that
# encode()/frame_bytes() writes and decode()/loads() reads is appended to it as (where, obj). None costs nothing.
RECORD: list | None = None


def _record(where: str, obj) -> None:
    if RECORD is not None and isinstance(obj, (dict, list)):
        RECORD.append((where, obj))


class WireError(Exception):
    def __init__(self, code: str, reason: str = ""):
        super().__init__(f"{code}: {reason}" if reason else code)
        self.code = code
        self.reason = reason


def encode(frame: dict) -> bytes:
    """The frame's line, then its binary section when it has one (§22). In memory a message keeps its
    section's bytes under "_bin"; the line carries only "bin" (the length) and "bin_sha256"."""
    data = json.dumps(strip(frame), separators=(",", ":"), ensure_ascii=False).encode()
    if len(data) + 1 > MAX_FRAME:
        raise WireError("frame_too_large", f"{len(data)} bytes")
    if RECORD is not None:
        _record("encode", strip(frame))
    return data + b"\n" + (frame.get("_bin") or b"")


def strip(frame: dict) -> dict:
    """The frame as its JSON line carries it: without the binary section's bytes."""
    return {k: v for k, v in frame.items() if k != "_bin"} if "_bin" in frame else frame


def attach_bin(m: dict, data: bytes) -> dict:
    """Give message m a binary section."""
    if len(data) > MAX_BIN:
        raise WireError("bin_too_large", f"a binary section is at most {MAX_BIN >> 20} MiB")
    m["_bin"] = data
    m["bin"] = len(data)
    m["bin_sha256"] = hashlib.sha256(data).hexdigest()
    return m


def check_bin(m: dict, data: bytes) -> None:
    if len(data) != m.get("bin") or hashlib.sha256(data).hexdigest() != m.get("bin_sha256"):
        raise WireError("bad_bin", "the binary section does not match bin / bin_sha256")


def frame_bytes(m: dict) -> bytes:
    """A frame as an HTTPS body: application/airc-frame when it has a binary section, else plain JSON."""
    if RECORD is not None:
        _record("frame_bytes", strip(m))
    return json.dumps(strip(m), separators=(",", ":"), ensure_ascii=False).encode() + (b"\n" + m["_bin"] if "_bin" in m else b"")


def parse_frame_bytes(body: bytes) -> dict:
    """The inverse of frame_bytes: a JSON line, then the binary section it declares."""
    head, nl, rest = body.partition(b"\n")
    frame = decode(head)
    if "bin" in frame:
        if not isinstance(frame["bin"], int) or not 0 <= frame["bin"] <= MAX_BIN:
            raise WireError("bad_bin", "bin must be a length of at most 8 MiB")
        check_bin(frame, rest)
        frame["_bin"] = rest
    elif rest.strip():
        raise WireError("bad_frame", "bytes after the frame, but no bin field")
    return frame


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def loads(data):
    """json.loads for foreign input: NaN/Infinity refused, deep nesting a ValueError, not a RecursionError."""
    obj = _loads(data)
    if RECORD is not None:
        _record("loads", obj)
    return obj


def _loads(data):
    try:
        return json.loads(data, parse_constant=_no_constant)
    except RecursionError:
        raise ValueError("JSON nested too deeply")


def decode(line: bytes) -> dict:
    try:
        obj = _loads(line)
    except ValueError as e:
        raise WireError("bad_json", str(e))
    if not isinstance(obj, dict) or not isinstance(obj.get("t"), str):
        raise WireError("bad_frame", "frame must be an object with string 't'")
    for k in [k for k in obj if isinstance(k, str) and k.startswith("_")]:
        del obj[k]                                       # internal keys (_bin, ...) never come from the wire
    if RECORD is not None:
        _record("decode", obj)
    return obj


# §4.2: message ids (and re) have a grammar; §16 item 4: foreign values written into header lines and notices
ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}\Z")
_UNSAFE = re.compile(r"[\[\]\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ufeff]")


_TOK = r"[A-Za-z0-9!#$&^_.+-]"
TYPE_RE = re.compile(rf"{_TOK}{{1,64}}/{_TOK}{{1,64}}(;[ ]?{_TOK}+={_TOK}+)*")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


def valid_id(v) -> bool:
    return isinstance(v, str) and bool(ID_RE.fullmatch(v))


def clean(v, limit: int = 300) -> str:
    """A foreign value made safe to write into a relay/server line (§16 item 4): control and format characters
    (newlines, bidi overrides, zero-width) and [ ] removed, length bounded."""
    s = _UNSAFE.sub("", "" if v is None else str(v))
    return s if len(s) <= limit else s[:limit] + "…"


def new_msg(frm: str, to: str, body: str, *, mtype: str = "text/plain",
            re_id: str | None = None, ttl: int | None = None,
            hdr: dict | None = None, msg_id: str | None = None) -> dict:
    m = {
        "t": "msg",
        "id": msg_id or str(uuid.uuid4()),
        "from": frm,
        "to": to,
        "ts": round(time.time(), 3),
        "body": body,
        "type": mtype,
        "ttl": int(ttl if ttl is not None else DEFAULT_TTL),
        "via": [],
    }
    if re_id:
        m["re"] = re_id
    if hdr:
        m["hdr"] = hdr
    return m


def validate_msg(m: dict) -> None:
    for k, typ in (("id", str), ("from", str), ("to", str), ("body", str)):
        if not isinstance(m.get(k), typ):
            raise WireError("bad_msg", f"missing or wrong-typed field {k!r}")
    if not valid_id(m["id"]):                        # §4.2
        raise WireError("bad_id", "id must match [A-Za-z0-9._:-]{1,128}")
    if m.get("re") is not None and not valid_id(m["re"]):
        raise WireError("bad_id", "re must match [A-Za-z0-9._:-]{1,128}")
    # §4.2, §9.3: every field signed before the body is newline-free, so the canonical string is a bijection
    if m.get("type") is not None and not (isinstance(m["type"], str) and TYPE_RE.fullmatch(m["type"])):
        raise WireError("bad_id", "type must be a media type (type/subtype[;param=value])")
    if m.get("bin_sha256") is not None and not (isinstance(m["bin_sha256"], str) and SHA256_RE.fullmatch(m["bin_sha256"])):
        raise WireError("bad_id", "bin_sha256 must be 64 lower-case hex digits")
    if "ts" in m and (not isinstance(m["ts"], (int, float)) or isinstance(m["ts"], bool)
                      or not math.isfinite(m["ts"]) or not 0 <= m["ts"] < 1e11):
        raise WireError("bad_msg", "ts must be a number of Unix seconds")
    if "ttl" in m and (not isinstance(m["ttl"], int) or isinstance(m["ttl"], bool) or not -2 ** 31 <= m["ttl"] <= 2 ** 31):
        raise WireError("bad_msg", "ttl must be an integer number of seconds")
    if "via" in m and not (isinstance(m["via"], list) and all(isinstance(v, str) for v in m["via"])):
        raise WireError("bad_msg", "via must be a list of realms")
    if "hdr" in m and not isinstance(m["hdr"], dict):
        raise WireError("bad_msg", "hdr must be an object")


def expired(m: dict, now: float | None = None) -> bool:
    now = now if now is not None else time.time()
    return float(m.get("ts", now)) + int(m.get("ttl", DEFAULT_TTL)) < now


# Error classes from the addressing spec §9, plus transport-level ones.
CODES = ("no_such_authority", "authority_unreachable", "no_such_path", "path_gone",
         "not_delegated", "namespace_not_endpoint", "stale_instance", "refused",
         "bad_address", "expired", "routing_loop", "no_ack", "duplicate", "endpoint_offline",
         "link_down", "bin_unsupported", "bad_bin")


def ack(msg_id: str, status: str, reason: str = "", code: str | None = None, by: str | None = None) -> dict:
    """code: one of CODES; by: URI of the deepest resolver that produced it."""
    a = {"t": "ack", "id": msg_id, "status": status}
    if reason:
        a["reason"] = reason
    if code:
        a["code"] = code
    if by:
        a["by"] = by
    return a


def error(code: str, reason: str = "") -> dict:
    return {"t": "error", "code": code, "reason": reason}


class Conn:
    """A framed connection over asyncio streams."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._wlock = asyncio.Lock()
        self.closed = False

    async def send(self, frame: dict) -> None:
        if self.closed:
            raise WireError("closed")
        data = encode(frame)
        async with self._wlock:
            self.writer.write(data)
            await self.writer.drain()

    async def recv(self) -> dict | None:
        """Next frame, or None on clean EOF."""
        try:
            line = await self.reader.readline()
        except (asyncio.IncompleteReadError, ConnectionError):
            return None
        except ValueError:                         # LimitOverrunError: a line longer than STREAM_LIMIT
            raise WireError("frame_too_large")
        if not line:
            return None
        if len(line) > MAX_FRAME:
            raise WireError("frame_too_large")
        if not line.endswith(b"\n"):
            return None  # truncated at EOF
        line = line.strip()
        if not line:
            return await self.recv()
        frame = decode(line)
        if "bin" in frame:                         # the binary section follows the line (§22)
            n = frame["bin"]
            if not isinstance(n, int) or not 0 <= n <= MAX_BIN:
                raise WireError("bad_bin", "bin must be a length of at most 8 MiB")
            try:
                data = await self.reader.readexactly(n)
            except (asyncio.IncompleteReadError, ConnectionError):
                return None
            check_bin(frame, data)
            frame["_bin"] = data
        return frame

    async def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 2)
        except Exception:
            pass

    def peer_uid(self) -> int | None:
        """Unix-socket peer uid via SO_PEERCRED (Linux), else None."""
        import socket
        import struct
        sock = self.writer.get_extra_info("socket")
        if sock is None or sock.family != socket.AF_UNIX:
            return None
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", creds)
            return uid
        except OSError:
            return None
