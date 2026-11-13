# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Agent Cards (spec §21.5): A2A-style JSON documents for the realm and for every endpoint that has an
address page, built from what the server already publishes, and signed with the realm key as a JWS over the
JCS (RFC 8785) canonical form, with `kid` naming the realm's DID (§24). Stdlib only."""
from __future__ import annotations

import base64
import json

from . import did as DID

SPEC_URL = "https://airc.dev/docs/transport"
CARD_PATH = "/.well-known/agent-card.json"
MEDIA_TYPE = "application/json"


def jcs(obj) -> bytes:
    """RFC 8785 canonical JSON for the values cards contain (strings, booleans, null, integers, arrays, objects).
    Keys are sorted by UTF-16 code units; Python's str ordering matches for the BMP, which is all a card holds."""
    def enc(o):
        if o is None or isinstance(o, bool):
            return json.dumps(o)
        if isinstance(o, int):
            return str(o)
        if isinstance(o, float):
            raise ValueError("cards carry no floats")
        if isinstance(o, str):
            return json.dumps(o, ensure_ascii=False)
        if isinstance(o, (list, tuple)):
            return "[" + ",".join(enc(x) for x in o) + "]"
        if isinstance(o, dict):
            keys = sorted(o, key=lambda k: k.encode("utf-16-be"))
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + enc(o[k]) for k in keys) + "}"
        raise TypeError(type(o).__name__)
    return enc(obj).encode("utf-8")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _interface(address: str, spec_draft: str) -> dict:
    return {"url": address, "protocolBinding": "AIRC", "protocolVersion": spec_draft}


def _capabilities(params: dict | None = None) -> dict:
    ext = {"uri": SPEC_URL, "required": True,
           "description": "AIRC: the interface is an AIRC address; reaching it needs a link or a passport (spec §11, §12)"}
    if params:
        ext["params"] = params
    return {"streaming": False, "pushNotifications": False, "extendedAgentCard": False, "extensions": [ext]}


def realm_card(realm: str, host: str, spec_draft: str, version: str, cfg: dict | None = None, skills: list | None = None) -> dict:
    """§21.5 the realm's card. `cfg` is the `cards` section of the config: description, provider
    {organization, url}, documentation_url, skills."""
    cfg = cfg or {}
    card = {"name": realm, "description": str(cfg.get("description") or f"{realm}: an AIRC realm"),
            "version": version, "documentationUrl": str(cfg.get("documentation_url") or f"https://{host}/"),
            "supportedInterfaces": [_interface(f"airc://{realm}/", spec_draft)],
            "capabilities": _capabilities({"consent": "link-or-passport", "page": f"https://{host}/"}),
            "securityRequirements": [], "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "skills": list(skills if skills is not None else cfg.get("skills") or [])}
    prov = cfg.get("provider") or {}
    if prov.get("organization"):
        card["provider"] = {"organization": str(prov["organization"]), "url": str(prov.get("url") or f"https://{host}/")}
    return card


def endpoint_card(realm: str, host: str, ns: str, agent: str, profile: dict | None, keyrec: dict | None,
                  spec_draft: str, version: str, cfg: dict | None = None) -> dict:
    """§21.5 an endpoint's card from its profile (name, about, skills, picture) and key record (DID)."""
    cfg = cfg or {}
    address = f"airc://{realm}/{ns}/{agent}"
    page = f"https://{host}/{ns}/{agent}"
    prof = profile or {}
    params = {"consent": "link-or-passport", "page": page}
    if keyrec and keyrec.get("ik"):
        params["did"] = DID.web_did(host, ns, agent)
        params["didKey"] = DID.did_key(keyrec["ik"])
    card = {"name": str(prof.get("name") or agent), "description": str(prof.get("about") or f"{address}, an AIRC agent"),
            "version": version, "documentationUrl": page,
            "supportedInterfaces": [_interface(address, spec_draft)],
            "capabilities": _capabilities(params), "securityRequirements": [],
            "defaultInputModes": ["text/plain"], "defaultOutputModes": ["text/plain"],
            "skills": [dict(s) for s in (prof.get("skills") or [])]}
    if prof.get("image"):
        card["iconUrl"] = f"https://{host}/airc/v0/profile/image?endpoint={address}"
    prov = cfg.get("provider") or {}
    if prov.get("organization"):
        card["provider"] = {"organization": str(prov["organization"]), "url": str(prov.get("url") or f"https://{host}/")}
    return card


def signing_input(card: dict, protected_b64: str) -> bytes:
    body = {k: v for k, v in card.items() if k != "signatures"}
    return (protected_b64 + "." + b64url(jcs(body))).encode("ascii")


def sign_card(card: dict, sign_raw, kid_did: str) -> dict:
    """Attach the §21.5 signature: `sign_raw(bytes) -> bytes` is the realm key's ed25519 signature."""
    protected = b64url(json.dumps({"alg": "EdDSA", "kid": kid_did}, separators=(",", ":")).encode())
    sig = sign_raw(signing_input(card, protected))
    out = dict(card)
    out["signatures"] = [{"protected": protected, "signature": b64url(sig)}]
    return out


def verify_card(card: dict, verify_raw) -> bool:
    """`verify_raw(data: bytes, sig: bytes) -> bool` with the key the signature's `kid` resolves to."""
    for s in card.get("signatures") or []:
        try:
            pad = "=" * (-len(s["signature"]) % 4)
            if verify_raw(signing_input(card, s["protected"]), base64.urlsafe_b64decode(s["signature"] + pad)):
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def protected_kid(card: dict) -> str | None:
    for s in card.get("signatures") or []:
        try:
            pad = "=" * (-len(s["protected"]) % 4)
            return json.loads(base64.urlsafe_b64decode(s["protected"] + pad)).get("kid")
        except Exception:  # noqa: BLE001
            continue
    return None
