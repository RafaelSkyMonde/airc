#!/usr/bin/env python3
# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Keeps schemas/airc-frames.schema.json honest (stdlib unittest, needs `jsonschema`).

(a) every JSON object in a fenced block of docs/airc-spec.md is validated against the def its `t` (or its shape)
    names; §18 and §19.10 vectors strictly, the other examples leniently (placeholder strings such as `…` and
    `<base64>` are not held against them);
(b) the whole tests/test_airc.py suite runs in-process with wire.RECORD set, and every frame and HTTPS body the
    reference sent or received is validated; a deviation the spec and the code disagree on is listed in
    KNOWN_DEVIATIONS (the schema follows the spec) and reported, not failed;
(c) negative cases: frames the schema must refuse.

    python3 tests/test_schema.py              # the whole thing (~1 min: it runs test_airc.py inside)
    AIRC_SCHEMA_QUICK=1 python3 tests/test_schema.py   # (b) runs a representative subset of test_airc.py
"""
import importlib
import io
import json
import os
import re
import sys
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(APP, "scripts"))
sys.path.insert(0, HERE)

try:
    import jsonschema
    from jsonschema import Draft202012Validator
except ImportError:                                   # pragma: no cover
    jsonschema = None

SCHEMA_PATH = os.path.join(APP, "schemas", "airc-frames.schema.json")
SPEC_PATH = os.path.join(APP, "docs", "airc-spec.md")

# Where the reference deviates from the spec, and the schema follows the spec (reported in the run, not failed).
# (frame def, json-pointer-ish path of the failing value or "" for the frame, substring of the validator message)
KNOWN_DEVIATIONS = [
    ("pong", "/n", "None is not of type",            # server.py:527 echoes n as null when the ping had none (§4.5: optional, echoed)
     "server.py pong echoes `n: null` when the ping carried no n; §4.5 says n is optional and echoed"),
    ("bindRequest", "/webhook", "does not match",     # the suite's webhook receiver is plain http on loopback
     "the reference accepts an http:// webhook on loopback for tests; §3.4.2 says https://"),
]
# Frame types the reference emits that are no protocol frame (not in the catalogue, not validated).
NON_PROTOCOL_T = {"admin",            # adminpage.py: the admin page's JSON view
                  "alias", "aliased", "aliases",   # a local aircd's fleet aliases (operations.md): a site convenience, never on the wire between realms
                  "x", "nonsense"}    # test_airc.py sends these to provoke the unknown-frame error (§3.2)


def load_schema() -> dict:
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        return json.load(f)


_validators: dict = {}


def validator_for(name: str | None = None):
    """A validator for one `$defs` entry, or for the root (any frame by `t`) when name is None."""
    if name not in _validators:
        schema = load_schema()
        if name is None:
            _validators[name] = Draft202012Validator(schema)
        else:
            if name not in schema["$defs"]:
                raise KeyError(f"no $defs entry {name!r}")
            sub = {"$schema": schema["$schema"], "$id": schema["$id"] + f"#def-{name}", "$ref": f"#/$defs/{name}",
                   "$defs": schema["$defs"]}
            _validators[name] = Draft202012Validator(sub)
    return _validators[name]


def errors(name, obj) -> list:
    return sorted(validator_for(name).iter_errors(obj), key=lambda e: list(e.absolute_path))


def path_of(err) -> str:
    return "/" + "/".join(str(p) for p in err.absolute_path) if err.absolute_path else ""


def fmt(err) -> str:
    return f"{path_of(err) or '<frame>'}: {err.message[:200]}"


def is_uri(v) -> bool:
    return isinstance(v, str) and v.startswith("airc://")


def defs_for(obj: dict) -> list[str]:
    """Which `$defs` an object is checked against. Frames by `t`; records by shape."""
    t = obj.get("t")
    if t == "msg":
        return ["msg", "msgWire" if is_uri(obj.get("from")) and is_uri(obj.get("to")) else "msgClient"]
    if t == "e2e-keys":
        return ["e2eKeys"]
    if t == "error" and "error" in obj:                       # the 409 name_held body (§4.3.1)
        return ["error", "nameHeldError"]
    if t == "workspace" and "ok" in obj and "realm" not in obj and "id" not in obj:
        return ["workspaceOpResult"]
    if isinstance(t, str):
        return [t] if t in load_schema()["$defs"] else []
    # no `t`: a record or an HTTPS body
    if "action" in obj and "link" in obj:
        return ["linkControlBody"]
    if obj.get("action") in ("redeem", "revoke-layer"):
        return ["passportControlBody"]
    if "token_hash" in obj or ("scope" in obj and "uses" in obj and "state" in obj):
        return ["passportRecord"]
    if "a" in obj and "b" in obj and "state" in obj:
        return ["linkRecord"]
    if "suite" in obj and "enc" in obj:
        return ["e2eEnvelope"]
    if "sender" in obj and "body" in obj:
        return ["e2ePlaintext"]
    if "names" in obj and ("mode" in obj or "take_over" in obj or len(obj) == 1):
        return ["bindRequest"]
    if "statuses" in obj:
        return ["statusRequest"]
    if "op" in obj and "pub" not in obj:
        return ["workspaceOp"]
    if "code" in obj and "pub" in obj:
        return ["workspaceJoin"]
    if "name" in obj and "pub" in obj:
        return ["workspaceRegister"]
    if "ok" in obj and ("keys_revoked" in obj or "recovery" in obj or "deleted" in obj or len(obj) == 1):
        return ["workspaceOpResult"]
    if "endpoint" in obj and ("delete" in obj or "close" in obj or "name" in obj or "about" in obj):
        return ["profileRecord"]
    return []


def classify(where, obj) -> list[tuple[str, object]]:
    """(def, object) pairs to validate for one recorded item: a frame, a record, or a list of acks."""
    if isinstance(obj, list):
        if obj and all(isinstance(x, dict) and x.get("t") == "ack" for x in obj):
            return [("ackList", obj)] + [("ack", x) for x in obj]
        return [p for x in obj if isinstance(x, dict) for p in classify(where, x)]
    if not isinstance(obj, dict):
        return []
    if "@context" in obj and "verificationMethod" in obj:         # §24 DID documents (no `t`)
        return [("didDocument", obj)]
    out = [(d, obj) for d in defs_for(obj)]
    # the bodies of control messages are JSON text with a schema of their own
    if obj.get("t") == "msg" and isinstance(obj.get("body"), str):
        bt = obj.get("type")
        name = {"application/airc-link+json": "linkControlBody", "application/airc-passport+json": "passportControlBody",
                "application/airc-e2e+json": "e2eEnvelope", "application/airc-file+json": "fileBody",
                "application/airc-receipt+json": "receiptBody"}.get(bt)
        if name:
            try:
                out.append((name, json.loads(obj["body"])))
            except ValueError:
                pass
    return out


# ---------------------------------------------------------------------------------------------------------------
# (a) spec examples and test vectors


def spec_blocks() -> list[tuple[str, int, str, str]]:
    """(section heading, line number, fence info, text) for every fenced block of the spec whose text starts with `{`."""
    out = []
    heading, fence, start, buf = "", None, 0, []
    with open(SPEC_PATH, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if fence is None:
                if line.startswith("#"):
                    heading = line.strip("# \n")
                elif line.startswith("```"):
                    fence, start, buf = line.strip()[3:], n, []
            elif line.startswith("```"):
                text = "".join(buf)
                if text.lstrip().startswith("{"):
                    out.append((heading, start, fence, text))
                fence = None
            else:
                buf.append(line)
    return out


def objects_in(text: str) -> list[dict]:
    """Every JSON object in a block (blocks hold several, one per line or several per line); a block with `…` in
    place of a value does not parse and yields nothing."""
    dec, out, i = json.JSONDecoder(), [], 0
    while True:
        j = text.find("{", i)
        if j < 0:
            return out
        try:
            obj, end = dec.raw_decode(text, j)
        except ValueError:
            return out
        if isinstance(obj, dict):
            out.append(obj)
        i = end


def placeholder(err) -> bool:
    """An example value standing in for a real one: `…`, `<base64 …>`, `k…`."""
    v = err.instance
    if isinstance(v, str):
        return "…" in v or v.startswith("<") or v == "…"
    return False


@unittest.skipIf(jsonschema is None, "jsonschema is not installed: pip install jsonschema (the schema tests need it)")
class SchemaItselfTests(unittest.TestCase):
    def test_schema_is_valid_draft_2020_12(self):
        schema = load_schema()
        Draft202012Validator.check_schema(schema)
        self.assertEqual(schema["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertEqual(schema["$id"], "https://airc.dev/docs/schema/airc-frames.schema.json")

    def test_every_catalogue_frame_has_a_def_and_a_description(self):
        defs = load_schema()["$defs"]
        for t in ("hello", "welcome", "msg", "msgWire", "msgClient", "ack", "bind", "bound", "ping", "pong", "link", "linked",
                  "passport", "passported", "error", "subscribe", "subscribed", "event", "stat", "stats", "keys", "keyed",
                  "profile", "profiled", "capabilities", "inbox", "acked", "events", "workspace", "e2eKeys", "displaced",
                  "send", "sent", "acks"):
            self.assertIn(t, defs)
            self.assertTrue(defs[t].get("description"), f"{t} has no description")

    def test_root_discriminates_on_t(self):
        root = validator_for(None)
        self.assertTrue(root.is_valid({"t": "ping"}))
        self.assertFalse(root.is_valid({"t": "nonsuch"}))
        self.assertFalse(root.is_valid({"id": "x"}))


@unittest.skipIf(jsonschema is None, "jsonschema is not installed")
class SpecVectorTests(unittest.TestCase):
    """Every JSON object in the spec's fenced blocks validates. §18 and §19.10 are vectors: strict. Other sections are
    examples with placeholders: lenient on placeholder strings."""

    STRICT = ("18.", "19.10")

    def test_spec_examples_validate(self):
        seen, failures, skipped = 0, [], []
        for heading, line, fence, text in spec_blocks():
            strict = heading.startswith(self.STRICT)
            if heading.startswith("Appendix B"):          # the rule engine is not part of the protocol
                continue
            for obj in objects_in(text):
                if "t" not in obj and "id" in obj and "from" in obj and "body" in obj:
                    # §18.2's signing vector is a message without `t`; check it as the frame it stands for
                    obj = {"t": "msg", **obj}
                pairs = classify("spec", obj)
                if not pairs:
                    skipped.append(f"line {line} ({heading}): no def for keys {sorted(obj)[:6]}")
                    continue
                for name, o in pairs:
                    seen += 1
                    errs = [e for e in errors(name, o) if strict or not placeholder(e)]
                    if errs:
                        failures.append(f"spec line {line} ({heading}) as {name}: " + "; ".join(fmt(e) for e in errs[:4]))
        print(f"\n  spec: {seen} object/def checks from fenced blocks; {len(skipped)} objects with no def")
        for s in skipped:
            print("    skipped", s)
        self.assertGreaterEqual(seen, 20, "the spec parser found too few examples; did the fences change?")
        self.assertFalse(failures, "\n" + "\n".join(failures))

    def test_section_18_vectors_present(self):
        """The §18.2 message, the §18.6 offer/accept controls and framed messages, the §19.10 key record and envelope."""
        found = {h.split(" ")[0] for h, _, _, text in spec_blocks() if objects_in(text)}
        for want in ("18.2", "18.6", "19.10", "3.4.1", "3.4.2", "4.3", "4.9", "21.1", "22."):
            self.assertTrue(any(f.startswith(want) for f in found), f"no parsed JSON example under §{want}: {sorted(found)}")


# ---------------------------------------------------------------------------------------------------------------
# (b) everything the reference implementation sends and receives


class _JsonProxy(types.ModuleType):
    """Stands in for `json` inside airc.httpbind / airc.httpclient: HTTPS bodies and WebSocket text frames go through
    json.dumps/json.loads there rather than wire.encode/decode, so this records them too."""

    def __init__(self, record):
        super().__init__("json")
        self._record = record

    def __getattr__(self, k):
        return getattr(json, k)

    def dumps(self, obj, *a, **kw):
        if isinstance(obj, (dict, list)):
            self._record.append(("http.dumps", obj))
        return json.dumps(obj, *a, **kw)

    def loads(self, s, *a, **kw):
        obj = json.loads(s, *a, **kw)
        if isinstance(obj, (dict, list)):
            self._record.append(("http.loads", obj))
        return obj


class Recorder:
    """Records every frame the in-process reference code sends or receives: through wire.encode/decode/loads/frame_bytes
    (stream frames, the HTTPS bodies the server reads) and through the `json` module inside airc.httpbind and
    airc.httpclient (HTTPS responses and requests, WebSocket text frames). A context manager, or start()/stop().
    tests/edge_interop.py and scripts/qa_realm.py --schema use it too."""

    def __init__(self):
        self.records: list = []
        self._saved = None

    def start(self) -> "Recorder":
        from airc import wire, httpbind, httpclient
        self._mods = (wire, httpbind, httpclient)
        self._saved = (wire.RECORD, httpbind.json, httpclient.json)
        proxy = _JsonProxy(self.records)
        wire.RECORD, httpbind.json, httpclient.json = self.records, proxy, proxy
        return self

    def stop(self) -> None:
        if self._saved is not None:
            wire, httpbind, httpclient = self._mods
            wire.RECORD, httpbind.json, httpclient.json = self._saved
            self._saved = None

    __enter__ = start

    def __exit__(self, *exc):
        self.stop()


class Report:
    """What validate_records found: counts per def, distinct violations, known deviations seen, unknown frame types,
    and `extras`: fields seen in frames that their def does not list (allowed by §3.2, shown so that spec and code
    can be compared)."""

    def __init__(self):
        self.counts: dict = {}
        self.failures: list = []
        self.deviations: dict = {}
        self.unknown: dict = {}
        self.extras: dict = {}
        self.refused = 0          # violations in frames a server refused: the suite's deliberate bad inputs

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def lines(self, prefix: str = "  ") -> list[str]:
        out = [f"{prefix}{self.total} frame/def checks over {len(self.counts)} defs: "
               + ", ".join(f"{k} {v}" for k, v in sorted(self.counts.items()))]
        for why, n in self.deviations.items():
            out.append(f"{prefix}known deviation ({n}x, schema follows the spec): {why}")
        if self.refused:
            out.append(f"{prefix}{self.refused} violations were in frames a server refused (the suite's deliberate bad inputs)")
        if self.unknown:
            out.append(f"{prefix}frames with a `t` the schema does not know: {self.unknown}")
        for name, keys in sorted(self.extras.items()):
            out.append(f"{prefix}fields not in the spec's {name}: " + ", ".join(f"{k} ({n}x)" for k, n in sorted(keys.items())))
        for f in self.failures:
            out.append(f"{prefix}violation: {f}")
        return out


def known_props(name: str, _seen=None) -> set:
    """The property names a def lists, following `$ref`, `allOf`, `if/then/else` and `oneOf/anyOf` one level down."""
    defs = load_schema()["$defs"]
    _seen = _seen if _seen is not None else set()
    if name in _seen or name not in defs:
        return set()
    _seen.add(name)
    out = set()

    def walk(node):
        if not isinstance(node, dict):
            return
        out.update(node.get("properties", {}).keys())
        if "$ref" in node:
            out.update(known_props(node["$ref"].rsplit("/", 1)[-1], _seen))
        for k in ("allOf", "oneOf", "anyOf"):
            for sub in node.get(k, []):
                walk(sub)
        for k in ("then", "else"):
            walk(node.get(k))
    walk(defs[name])
    return out


REFUSAL_CODES = {"bad_request", "bad_address", "refused", "unauthorized", "name_held", "channel_taken", "bad_bind",
                 "expired", "bad_bin", "e2e_sender", "e2e_decrypt", "e2e_no_key"}


def refused_ids(records) -> set:
    """Ids of messages a server answered with a failed ack for a malformed or refused frame: the suite sends those on
    purpose (bad ids, hashes, ttls), and the schema must flag them, so they are not counted as violations."""
    out = set()
    for _, obj in records:
        items = obj if isinstance(obj, list) else [obj]
        for it in items:
            if isinstance(it, dict) and it.get("t") == "ack" and it.get("status") == "failed" and it.get("code") in REFUSAL_CODES:
                out.add(it.get("id"))
    return out


def refused_request(records, i, lookahead=6) -> bool:
    """A non-message request (link, passport, hello, bind) was refused if one of the next few recorded frames is an
    error, or an answer with ok false."""
    for _, nxt in records[i + 1:i + 1 + lookahead]:
        items = nxt if isinstance(nxt, list) else [nxt]
        for it in items:
            if isinstance(it, dict) and (it.get("t") == "error" or it.get("ok") is False):
                return True
    return False


def validate_records(records, known=KNOWN_DEVIATIONS, non_protocol=NON_PROTOCOL_T) -> Report:
    rep = Report()
    failures = set()
    refused = refused_ids(records)
    records = list(records)
    for i, (where, obj) in enumerate(records):
        items = [obj] if isinstance(obj, dict) else [x for x in obj if isinstance(x, dict)] if isinstance(obj, list) else []
        for it in items:
            t = it.get("t")
            if isinstance(t, str) and not defs_for(it) and t not in non_protocol:
                rep.unknown[t] = rep.unknown.get(t, 0) + 1
        obj_refused = isinstance(obj, dict) and obj.get("t") == "msg" and obj.get("id") in refused
        for name, o in classify(where, obj):
            rep.counts[name] = rep.counts.get(name, 0) + 1
            if isinstance(o, dict) and name not in ("msg",):            # msg is counted under msgWire/msgClient
                for k in set(o) - known_props(name):
                    rep.extras.setdefault(name, {})[k] = rep.extras.setdefault(name, {}).get(k, 0) + 1
            for e in errors(name, o):
                p = path_of(e)
                for dn, dp, dmsg, why in known:
                    if dn == name and p == dp and dmsg in e.message:
                        rep.deviations[why] = rep.deviations.get(why, 0) + 1
                        break
                else:
                    if obj_refused:
                        rep.refused += 1; continue               # a deliberately bad message (or its body) the server failed
                    if isinstance(o, dict) and o.get("t") in ("link", "passport", "hello", "bind", "keys", "profile") and refused_request(records, i):
                        rep.refused += 1; continue               # a deliberately bad request the server answered with an error
                    failures.add(f"{where} {name}: {fmt(e)}\n      {json.dumps(o, ensure_ascii=False)[:400]}")
    rep.failures = sorted(failures)
    return rep


QUICK_CLASSES = ("RoutingTests", "LinkTests", "PassportTests", "KnockTests", "ChallengeTests", "EventAndRelayTests",
                 "FrontDoorTests", "ProfileTests", "InboxHopTests", "HttpBindingTests", "E2ETests",
                 "EndpointSignedControlTests", "SpecConformanceTests", "McpTunnelTests")


def run_reference_suite() -> tuple[list, unittest.TestResult]:
    """Runs tests/test_airc.py in-process with recording on; returns (records, result)."""
    mod = importlib.import_module("test_airc")
    loader = unittest.TestLoader()
    if os.environ.get("AIRC_SCHEMA_QUICK"):
        suite = unittest.TestSuite(loader.loadTestsFromTestCase(getattr(mod, c)) for c in QUICK_CLASSES)
    else:
        suite = loader.loadTestsFromModule(mod)
    with Recorder() as rec:
        result = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
    return rec.records, result


@unittest.skipIf(jsonschema is None, "jsonschema is not installed")
class RecordedFrameTests(unittest.TestCase):
    """Every frame the reference's own test suite exchanged validates against the schema."""

    @classmethod
    def setUpClass(cls):
        cls.records, cls.result = run_reference_suite()

    def test_reference_suite_passed(self):
        r = self.result
        shown = "\n".join(f"--- {t}\n" + "\n".join(tb.strip().splitlines()[-8:]) for t, tb in (r.errors + r.failures)[:3])
        self.assertTrue(r.wasSuccessful(), f"test_airc.py failed inside the schema run: {len(r.failures)} failures, "
                                           f"{len(r.errors)} errors; first of them:\n{shown}")
        self.assertGreater(r.testsRun, 10)

    def test_every_recorded_frame_validates(self):
        rep = validate_records(self.records)
        print(f"\n  recorded: {len(self.records)} items")
        print("\n".join(rep.lines()))
        self.assertGreater(rep.total, 500, "too few frames recorded; is the hook in wire.py still wired?")
        self.assertFalse(rep.unknown, f"frames with a `t` the schema does not know: {rep.unknown}")
        # a representative sample of the catalogue must have been exercised
        for must in ("hello", "welcome", "msgWire", "msgClient", "ack", "bind", "bound", "link", "linked", "passport",
                     "passported", "error", "keys", "keyed", "profile", "profiled", "event", "capabilities", "inbox",
                     "acked", "linkControlBody", "passportControlBody", "e2eEnvelope"):
            self.assertIn(must, rep.counts, f"no {must} frame was recorded")
        self.assertFalse(rep.failures, f"{len(rep.failures)} distinct schema violations:\n" + "\n".join(rep.failures[:40]))


# ---------------------------------------------------------------------------------------------------------------
# (c) frames the schema must refuse


@unittest.skipIf(jsonschema is None, "jsonschema is not installed")
class NegativeTests(unittest.TestCase):
    MSG = {"t": "msg", "id": "0f5a3c2e-9b1d-4e77-a6c8-1d2e3f4a5b6c", "from": "airc://example.com/alice/x",
           "to": "airc://partner.example/support/desk", "ts": 1790380000.123, "body": "hello", "type": "text/plain"}
    H = "b33f4304b9a6bd81704e55c473a4133a4922f034c1c489cb05428cc1140b042c"

    def refuse(self, name, obj, why):
        self.assertTrue(errors(name, obj), f"{name} accepted {why}: {json.dumps(obj)[:200]}")

    def accept(self, name, obj):
        errs = errors(name, obj)
        self.assertFalse(errs, f"{name} refused a good frame: " + "; ".join(fmt(e) for e in errs))

    def test_msg(self):
        self.accept("msgWire", self.MSG)
        self.accept("msgWire", {**self.MSG, "bin": 12, "bin_sha256": self.H, "ttl": 600, "re": "a.b:c-d_e",
                                "via": ["example.com"], "hdr": {"sig": ["ed25519:65b60673:QUJD"], "airc-link": "L7f3a9c1e", "x": {"k": 1}}})
        for bad, why in (({**self.MSG, "id": "a b"}, "a space in id"), ({**self.MSG, "id": ""}, "an empty id"),
                         ({**self.MSG, "id": "x" * 129}, "a 129-character id"), ({**self.MSG, "id": "a/b"}, "a slash in id"),
                         ({**self.MSG, "re": "a\nb"}, "a newline in re"),
                         ({**self.MSG, "type": "t\nX"}, "a newline in type (§18.2)"), ({**self.MSG, "type": "text"}, "a type without a slash"),
                         ({**self.MSG, "type": "text/plain; charset=\"utf-8\""}, "quotes in a type parameter"),
                         ({**self.MSG, "bin": 12, "bin_sha256": self.H.upper()}, "an upper-case hash"),
                         ({**self.MSG, "bin": 12, "bin_sha256": self.H[:-1]}, "a 63-digit hash"),
                         ({**self.MSG, "bin": 12}, "bin without bin_sha256"), ({**self.MSG, "bin_sha256": self.H}, "bin_sha256 without bin"),
                         ({**self.MSG, "bin": 8388609, "bin_sha256": self.H}, "a bin over 8 MiB"), ({**self.MSG, "bin": -1, "bin_sha256": self.H}, "a negative bin"),
                         ({**self.MSG, "ts": "1790380000"}, "a string ts"), ({**self.MSG, "ttl": 1.5}, "a fractional ttl"),
                         ({**self.MSG, "ttl": -1}, "a negative ttl"),
                         ({**self.MSG, "via": "example.com"}, "via as a string"), ({**self.MSG, "via": ["a"] * 9}, "9 hops"),
                         ({**self.MSG, "hdr": {"sig": 1}}, "a numeric sig"), ({**self.MSG, "hdr": {"x": ["a"]}}, "a list-valued header"),
                         ({**self.MSG, "hdr": {"sig": "none:65b60673:QUJD"}}, "alg none"),
                         ({**self.MSG, "from": "alice/x"}, "a local-form from on the wire"), ({**self.MSG, "to": "//partner.example/support/desk"}, "a network-form to on the wire"),
                         ({**self.MSG, "to": "airc:foo"}, "airc:foo"), ({**self.MSG, "to": "airc://h/a//b"}, "an empty segment"),
                         ({**self.MSG, "to": "airc://h.com/a.b"}, "a dot in a segment"), ({**self.MSG, "to": "airc://h.com/-a"}, "a segment starting with -"),
                         ({**self.MSG, "to": "airc://h.com/alice/*"}, "a pattern as an address"),
                         ({k: v for k, v in self.MSG.items() if k != "body"}, "no body"), ({k: v for k, v in self.MSG.items() if k != "ts"}, "no ts on the wire")):
            self.refuse("msgWire", bad, why)
        # the client face takes local forms and no ts, but the same grammar otherwise
        self.accept("msgClient", {"t": "msg", "id": "1", "from": "alice/agent", "to": "//partner.example/support/desk", "body": "hi"})
        self.accept("msgClient", {"t": "msg", "id": "1", "from": "agent", "to": "airc://partner.example/support/desk#run-42", "body": "hi"})
        self.refuse("msgClient", {"t": "msg", "id": "1", "from": "/x", "to": "a", "body": "hi"}, "a single leading slash")
        self.refuse("msgClient", {"t": "msg", "id": "1", "from": "a", "to": "a b", "body": "hi"}, "a space in an address")
        self.refuse("msgClient", {"t": "msg", "id": "1", "from": "a", "to": "b", "body": "hi", "type": "t\nX"}, "a newline in type")

    def test_unknown_t_and_missing_t(self):
        root = validator_for(None)
        self.assertFalse(root.is_valid({"t": "mesg", "id": "1"}))
        self.assertFalse(root.is_valid({"t": 7}))
        self.assertFalse(root.is_valid({"id": "1", "status": "delivered"}))
        self.assertTrue(root.is_valid({"t": "ack", "id": "1", "status": "delivered"}))

    def test_ack(self):
        self.accept("ack", {"t": "ack", "id": "1", "status": "queued", "code": "endpoint_offline", "by": "airc://r.test/_resolver", "reason": "x"})
        self.accept("ack", {"t": "ack", "id": "1", "status": "failed", "code": "challenge",
                            "challenges": [{"id": "eyJ9.c2ln", "kind": "pow", "bits": 16}]})
        self.refuse("ack", {"t": "ack", "id": "1", "status": "ok"}, "status ok")
        self.refuse("ack", {"t": "ack", "id": "1", "status": "failed", "code": "nonsuch"}, "an unknown code")
        self.refuse("ack", {"t": "ack", "id": "1\n2", "status": "failed"}, "a newline in id")
        self.refuse("ack", {"t": "ack", "status": "failed"}, "no id")
        self.refuse("ack", {"t": "ack", "id": "1", "status": "failed", "by": "r.test/_resolver"}, "a non-URI by")
        self.refuse("ack", {"t": "ack", "id": "1", "status": "failed", "challenges": []}, "an empty challenges list")

    def test_hello_welcome(self):
        self.accept("hello", {"t": "hello", "proto": "airc/0.1", "role": "client", "agent": "x/1", "features": ["bin"]})
        self.accept("hello", {"t": "hello", "proto": "airc/0.1", "role": "peer", "realm": "example.com", "ts": 1790380000,
                              "nonce": "6f1d2c3b4a596877", "sig": "ed25519:65b60673:U/Yt"})
        self.refuse("hello", {"t": "hello", "proto": "airc/0.1", "role": "peer"}, "a peer hello without realm")
        self.refuse("hello", {"t": "hello", "proto": "airc/0.1", "role": "server"}, "role server")
        self.refuse("hello", {"t": "hello", "proto": "0.1", "role": "client"}, "proto without the airc/ prefix")
        self.refuse("hello", {"t": "hello", "role": "client"}, "no proto")
        self.refuse("hello", {"t": "hello", "proto": "airc/0.1", "role": "peer", "realm": "example.com", "ts": 1790380000.5}, "a fractional ts")
        self.accept("welcome", {"t": "welcome", "realm": "example.com", "proto": "airc/0.1", "ns": ["alice"], "features": ["keys", "leases"]})
        self.accept("welcome", {"t": "welcome", "realm": "example.com", "proto": "airc/0.1", "push": "ws"})
        self.refuse("welcome", {"t": "welcome", "proto": "airc/0.1"}, "no realm")
        self.refuse("welcome", {"t": "welcome", "realm": "example.com", "proto": "airc/0.1", "kid": "65B60673"}, "an upper-case kid")
        self.refuse("welcome", {"t": "welcome", "realm": "example.com", "proto": "airc/0.1", "push": "poll"}, "push other than ws")

    def test_bind_bound(self):
        self.accept("bind", {"t": "bind", "names": ["alice/", "bob/research", "carol/*", "**"]})
        self.accept("bind", {"t": "bind", "names": [], "take_over": True})
        self.accept("bindRequest", {"names": ["alice/agent"], "mode": "webhook", "webhook": "https://x.example/hook"})
        self.accept("bound", {"t": "bound", "names": ["//example.com/alice/", "airc://example.com/bob/research"], "mode": "pull", "front": {"alice": "bot"}})
        self.refuse("bind", {"t": "bind"}, "no names")
        self.refuse("bind", {"t": "bind", "names": "alice/"}, "names as a string")
        self.refuse("bind", {"t": "bind", "names": ["/alice"]}, "a leading slash")
        self.refuse("bind", {"t": "bind", "names": ["a b"]}, "a space")
        self.refuse("bind", {"t": "bind", "names": ["alice/"], "mode": "poll"}, "mode poll")
        self.refuse("bindRequest", {"names": ["alice/agent"], "mode": "webhook", "webhook": "http://x.example/hook"}, "a plain-http webhook")
        self.refuse("bound", {"t": "bound", "names": ["alice/"]}, "a relative bound name")

    def test_link_linked(self):
        self.accept("link", {"t": "link", "op": "offer", "as": "alice/x", "peer": "//partner.example/support/desk", "label": "vendor",
                             "expires": "30d", "direction": "both", "credential": "WR-1", "contact": {"email": "a@x"}})
        self.accept("link", {"t": "link", "op": "accept", "as": "support/desk", "id": "L7f3a9c1e", "token": "Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE",
                             "expires_at": 1790990000, "link_ttl": 86400, "auth": [{"key": "QUJD", "sig": "QUJD"}]})
        self.accept("link", {"t": "link", "op": "revoke", "as": "alice/x", "key": "35vPT1d3o6aHoyLHExDUrA"})
        self.accept("link", {"t": "link", "op": "list"})
        self.refuse("link", {"t": "link", "op": "offer", "as": "alice/x"}, "an offer without peer")
        self.refuse("link", {"t": "link", "op": "accept", "as": "x"}, "an accept without id")
        self.refuse("link", {"t": "link", "op": "accept", "as": "x", "id": "7f3a9c1e"}, "a link id without L")
        self.refuse("link", {"t": "link", "op": "revoke", "as": "alice/x"}, "a revoke with neither id nor key")
        self.refuse("link", {"t": "link", "op": "knock", "as": "x", "peer": "y"}, "op knock")
        self.refuse("link", {"t": "link", "op": "offer", "as": "x", "peer": "y", "direction": "a-to-b"}, "a bad direction")
        self.refuse("link", {"t": "link", "op": "offer", "as": "x", "peer": "y", "label": "L" * 201}, "a 201-character label")
        self.refuse("link", {"t": "link", "op": "offer", "as": "x", "peer": "y", "credential": "c" * 1001}, "a 1001-character credential")
        self.refuse("link", {"t": "link", "op": "offer", "as": "x", "peer": "y", "expires": "soon"}, "expires soon")
        rec = {"id": "L7f3a9c1e", "a": "airc://example.com/alice/x", "b": "airc://partner.example/support/desk", "direction": "both",
               "label": "vendor", "created": 1790380000.1, "expires": None, "state": "pending", "offered_by": "airc://example.com/alice/x"}
        self.accept("linked", {"t": "linked", "ok": True, "link": rec, "delivery": "delivered"})
        self.accept("linkControlBody", {"action": "offer", "link": rec, "e2e": {"ik": "QUJD"}})
        self.refuse("linked", {"t": "linked", "link": rec}, "no ok")
        self.refuse("linked", {"t": "linked", "ok": True, "link": {**rec, "state": "open"}}, "state open")
        self.refuse("linked", {"t": "linked", "ok": True, "link": {**rec, "id": "L7F3A9C1E"}}, "an upper-case link id")
        self.refuse("linked", {"t": "linked", "ok": True, "delivery": "sent"}, "delivery sent")
        self.refuse("linkControlBody", {"action": "grant", "link": rec}, "a grant without passport_auth")
        self.refuse("linkControlBody", {"action": "offer"}, "a control without link")

    def test_passport_passported(self):
        new = {"t": "passport", "op": "new", "as": "alice/x", "token": "Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE", "expires_at": 1790984800,
               "uses": 1, "to": "//partner.example/**", "link_ttl": 2592000, "auth": [{"key": "QUJD", "sig": "QUJD"}]}
        self.accept("passport", new)
        self.accept("passport", {"t": "passport", "op": "redeem", "as": "support/desk",
                                 "passport": "https://airc.example.com/alice/x#passport=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE.35vPT1d3o6aHoyLHExDUrA"})
        self.accept("passport", {"t": "passport", "op": "revoke", "id": "P3f9a1c2e", "and_links": True})
        self.refuse("passport", {k: v for k, v in new.items() if k != "token"}, "new without token")
        self.refuse("passport", {k: v for k, v in new.items() if k != "expires_at"}, "new without expires_at")
        self.refuse("passport", {**new, "token": "short"}, "a 5-character token")
        self.refuse("passport", {**new, "uses": 0}, "uses 0")
        self.refuse("passport", {**new, "to": "partner.example/**"}, "a bind_to pattern without //")
        self.refuse("passport", {**new, "op": "issue"}, "op issue")
        self.refuse("passport", {"t": "passport", "op": "redeem", "as": "x", "passport": "airc://example.com/alice/x"}, "an address as a passport")
        self.refuse("passport", {"t": "passport", "op": "revoke", "id": "L3f9a1c2e"}, "a link id as a passport id")
        self.accept("passported", {"t": "passported", "ok": True, "status": "delivered", "reason": "link L7f3a9c1e granted", "code": None})
        self.refuse("passported", {"t": "passported"}, "no ok")
        self.refuse("passported", {"t": "passported", "ok": True, "passport": {"id": "P3f9a1c2e", "scope": "airc://e.com/a/x", "direction": "both", "state": "used"}}, "state used")
        self.accept("passportControlBody", {"action": "redeem", "scope": "airc://example.com/alice/x", "token": "Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE",
                                            "redeemer": "airc://partner.example/support/desk", "redemption": "r1"})
        self.refuse("passportControlBody", {"action": "redeem", "scope": "airc://example.com/alice/x",
                                            "redeemer": "airc://partner.example/support/desk", "redemption": "r1"}, "a redeem with neither token nor reference")
        self.refuse("passportControlBody", {"action": "redeem", "scope": "airc://example.com/alice/x", "token": "Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE",
                                            "redeemer": "airc://partner.example/support/desk", "redemption": "r" * 201}, "a 201-character redemption")

    def test_error_ping_misc(self):
        self.accept("error", {"t": "error", "code": "forbidden", "reason": "alice/ is outside your namespaces"})
        self.accept("error", {"t": "error", "code": "my_own_code"})       # §14.2: open over HTTPS
        self.refuse("error", {"t": "error", "reason": "x"}, "no code")
        self.refuse("error", {"t": "error", "code": ""}, "an empty code")
        self.accept("ping", {"t": "ping", "n": 7})
        self.accept("pong", {"t": "pong", "rid": "r1"})
        self.refuse("pong", {"t": "pong", "n": None}, "n null")
        self.accept("capabilities", {"t": "capabilities", "realm": "airc.dev", "proto": "airc/0.1", "bindings": ["https"], "kids": ["65b60673"],
                                     "nonce": "6f1d2c3b4a596877", "ts": 1790380000, "sig": "ed25519:65b60673:QUJD", "features": []})
        self.refuse("capabilities", {"t": "capabilities", "realm": "airc.dev", "proto": "airc/0.1", "bindings": ["smtp"], "kids": [],
                                     "nonce": "n", "ts": 1, "sig": "ed25519:65b60673:QUJD"}, "binding smtp")
        self.refuse("capabilities", {"t": "capabilities", "realm": "airc.dev", "proto": "airc/0.1", "bindings": ["https"], "kids": [],
                                     "nonce": "n", "ts": 1}, "no sig")
        self.accept("e2eEnvelope", {"v": 1, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582a", "enc": "QUJD", "ct": "QUJD"})
        self.accept("e2eEnvelope", {"v": 2, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582a", "enc": "QUJD"})
        self.refuse("e2eEnvelope", {"v": 1, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582a", "enc": "QUJD"}, "v1 without ct")
        self.refuse("e2eEnvelope", {"v": 3, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582a", "enc": "QUJD"}, "v3")
        self.refuse("e2eEnvelope", {"v": 1, "suite": "aes", "kid": "7222582a", "enc": "QUJD", "ct": "QUJD"}, "another suite")
        self.refuse("e2eEnvelope", {"v": 1, "suite": "hpke-x25519-sha256-chacha20poly1305", "kid": "7222582", "enc": "QUJD", "ct": "QUJD"}, "a 7-digit kid")
        self.accept("fileBody", {"v": 1, "name": "hello.txt", "type": "text/plain", "size": 12, "sha256": self.H, "enc": "identity"})
        self.refuse("fileBody", {"v": 1, "name": "hello.txt", "type": "text/plain", "size": 12, "sha256": self.H, "enc": "zip"}, "enc zip")
        self.accept("keys", {"t": "keys", "op": "get", "endpoint": "airc://example.com/alice/x"})
        self.refuse("keys", {"t": "keys", "op": "publish"}, "publish without record")
        self.refuse("keys", {"t": "keys", "op": "rotate"}, "op rotate")
        self.accept("profile", {"t": "profile", "op": "status", "statuses": [{"endpoint": "alice/x", "status": "push-active"}]})
        self.accept("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot", "name": "bot", "ts": 1790380000})
        self.accept("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot", "delete": True})
        self.refuse("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot"}, "a record without ts")
        self.refuse("profile", {"t": "profile", "op": "status", "statuses": [{"endpoint": "alice/x", "status": "busy"}]}, "status busy")
        self.refuse("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot", "ts": 1, "name": "x" * 65}, "a 65-character name")
        self.refuse("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot", "ts": 1, "icon": "a b"}, "whitespace in icon")
        self.refuse("profile", {"t": "profile", "endpoint": "airc://example.com/alice/bot", "ts": 1, "image": "data:image/gif;base64,QUJD"}, "a gif image")
        self.accept("workspaceRegister", {"name": "acme-labs", "pub": "ebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ="})
        self.refuse("workspaceRegister", {"name": "_acme", "pub": "QUJD"}, "a name starting with _")
        self.refuse("workspaceRegister", {"name": "acme.labs", "pub": "QUJD"}, "a dot in the name")
        self.accept("workspaceJoin", {"code": "airc-join:1;i=airc.dev;w=acme;t=Zk3fQ9uT2mH7wLp4Rb8yNc6VdX1aS0gE", "pub": "QUJD"})
        self.refuse("workspaceJoin", {"code": "join me", "pub": "QUJD"}, "a free-text code")
        self.accept("workspaceOp", {"op": "join-code", "uses": 5, "expires": "2d"})
        self.refuse("workspaceOp", {"op": "join-code", "uses": 21}, "21 uses")
        self.refuse("workspaceOp", {"op": "delete"}, "delete without confirm")
        self.refuse("workspaceOp", {"op": "revoke-key"}, "revoke-key without kid")
        self.accept("event", {"t": "event", "ts": 1790380000.123, "kind": "msg.delivered", "id": "x", "from": "airc://a.test/b/c",
                              "to": "airc://d.test/e", "status": "delivered", "hop": "client", "bytes": 42})
        self.refuse("event", {"t": "event", "kind": "msg.delivered"}, "no ts")
        self.refuse("event", {"t": "event", "ts": 1, "kind": "msg.delivered", "hop": "relay"}, "hop relay")
        self.accept("inbox", {"t": "inbox"})
        self.accept("inbox", {"t": "inbox", "msgs": [self.MSG], "displaced": ["//example.com/alice/x"]})
        self.refuse("inbox", {"t": "inbox", "msgs": [{**self.MSG, "from": "alice/x"}]}, "a local-form message in the inbox")
        self.accept("acked", {"t": "acked", "n": 2})
        self.refuse("acked", {"t": "acked"}, "no n")
        self.accept("send", {"t": "send", "rid": "1", "msg": {"t": "msg", "id": "1", "from": "alice/x", "to": "bob", "body": "hi"}})
        self.refuse("send", {"t": "send", "rid": "1"}, "send without msg")
        self.accept("displaced", {"t": "displaced", "names": ["//example.com/alice/x"]})
        self.refuse("displaced", {"t": "displaced"}, "no names")


if __name__ == "__main__":
    unittest.main(verbosity=2)
