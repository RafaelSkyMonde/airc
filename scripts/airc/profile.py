# Copyright © 2026 Rafael Baptista. Part of the AIRC reference implementation.
# Licensed under the AIRC Public Preview License 1.0 (https://airc.dev/license), ends 2027-05-01; see LICENSE.
"""Profiles and address pages (spec §21).

A profile is a few public facts an endpoint publishes about itself (name, a one-line about, an
icon, a short text). The server stores it and lists the endpoint in its workspace's directory
(§20.2). A server with an HTTPS face serves a page at every address it holds: /<ws>/<agent> says
who the agent is and how to reach it, /<ws> shows the directory. Pages come as HTML, or markdown
for agents (.md, or Accept: text/markdown). Profile fields are untrusted: escaped in HTML, and
presented as the owner's claims.
"""
from __future__ import annotations

import html
import re
import unicodedata

NAME_MAX, ABOUT_MAX, ICON_MAX_BYTES, TEXT_MAX, IMAGE_MAX = 64, 200, 32, 2000, 24 * 1024
# skills (§21.1): at most SKILLS_MAX entries of {id, name, description, tags, examples}, the shape of an A2A AgentSkill
SKILLS_MAX, SKILL_ID_MAX, SKILL_TAGS_MAX, SKILL_TAG_MAX, SKILL_EXAMPLES_MAX = 16, 32, 8, 32, 4
_SKILL_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
IMAGE_TYPES = {"image/png": b"\x89PNG\r\n\x1a\n", "image/jpeg": b"\xff\xd8\xff", "image/webp": b"RIFF"}
SITE = "https://airc.dev"
# The credit the AIRC Public Preview License 1.0 (LICENSE §4) requires on every page that identifies an endpoint,
# workspace or realm and explains how to reach it, in the page and in its markdown and plain-text variants. On by
# default in the reference server, so that anyone running it complies out of the box.
CREDIT_URL = "https://www.airc.dev/"
CREDIT_MD = f"Uses the [AIRC protocol]({CREDIT_URL}), developed by Rafael Baptista. Learn more at airc.dev."
CREDIT_HTML = f'Uses the <a href="{CREDIT_URL}">AIRC protocol</a>, developed by Rafael Baptista. Learn more at airc.dev.'


def with_credit(md: str) -> str:
    """An address page's markdown, ending with the license's credit line (LICENSE §4)."""
    return md.rstrip() + "\n\n" + CREDIT_MD + "\n"

QUICKSTART = f"{SITE}/#talk-to-an-airc-agent-from-anywhere"
DEFAULT_ICON = "🤖"

# §21.2 status: what publishers may set, and how pages say each one
PUBLISHED_STATUSES = ("push-active", "push-inactive")
STATUS_WORDS = {"push-active": "running", "push-inactive": "not running", "pull": "polls", "offline": "offline"}
STATUS_LINES = {
    "push-active": "running now; messages reach me within seconds",
    "push-inactive": "not running at the moment; messages wait for me, and I read them when I start",
    "pull": "my workspace collects messages by polling, so an answer may take a while",
    "offline": "unknown for the last few minutes; messages are queued",
}

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def validate(rec: dict) -> tuple[bool, str]:
    """Check a profile record's fields (§21.1); endpoint ownership is the server's to check."""
    if not isinstance(rec, dict):
        return False, "a profile is a JSON object"
    if not isinstance(rec.get("endpoint"), str) or not rec["endpoint"]:
        return False, "endpoint is required"
    if not isinstance(rec.get("ts"), (int, float)):
        return False, "ts is required (seconds)"
    for field, cap in (("name", NAME_MAX), ("about", ABOUT_MAX), ("text", TEXT_MAX)):
        v = rec.get(field)
        if v is None:
            continue
        if not isinstance(v, str) or len(v) > cap:
            return False, f"{field} must be a string of at most {cap} characters"
        if _CTRL.search(v) or (field != "text" and "\n" in v):
            return False, f"{field} has control characters" + ("" if field == "text" else " or newlines")
    icon = rec.get("icon")
    if icon is not None and (not isinstance(icon, str) or len(icon.encode()) > ICON_MAX_BYTES or not icon
                             or any(ch.isspace() for ch in icon) or _CTRL.search(icon)):
        return False, f"icon must be one emoji (at most {ICON_MAX_BYTES} bytes, no spaces)"
    if rec.get("image") is not None and image_bytes(rec["image"]) is None:
        return False, f"image must be a data: URI (png, webp or jpeg, base64) of at most {IMAGE_MAX // 1024} KB whose bytes match its type"
    if rec.get("skills") is not None:
        ok, why = validate_skills(rec["skills"])
        if not ok:
            return False, why
    return True, ""


def validate_skills(skills) -> tuple[bool, str]:
    """§21.1 skills: a list of at most 16 {id, name, description?, tags?, examples?}; ids unique."""
    if not isinstance(skills, list) or len(skills) > SKILLS_MAX:
        return False, f"skills must be a list of at most {SKILLS_MAX} entries"
    seen = set()
    for sk in skills:
        if not isinstance(sk, dict):
            return False, "each skill is an object"
        sid = sk.get("id")
        if not isinstance(sid, str) or not _SKILL_ID.match(sid):
            return False, f"a skill id is 1 to {SKILL_ID_MAX} letters, digits, _ or -, starting with a letter or digit"
        if sid in seen:
            return False, f"duplicate skill id {sid!r}"
        seen.add(sid)
        for field, cap in (("name", NAME_MAX), ("description", ABOUT_MAX)):
            v = sk.get(field)
            if field == "name" and not isinstance(v, str):
                return False, "a skill needs a name"
            if v is not None and (not isinstance(v, str) or not v or len(v) > cap or "\n" in v or _CTRL.search(v)):
                return False, f"a skill's {field} is one line of at most {cap} characters"
        for field, n, cap in (("tags", SKILL_TAGS_MAX, SKILL_TAG_MAX), ("examples", SKILL_EXAMPLES_MAX, ABOUT_MAX)):
            v = sk.get(field)
            if v is None:
                continue
            if not isinstance(v, list) or len(v) > n or not all(isinstance(x, str) and x and len(x) <= cap and "\n" not in x and not _CTRL.search(x) for x in v):
                return False, f"a skill's {field} is a list of at most {n} one-line strings of at most {cap} characters"
        extra = set(sk) - {"id", "name", "description", "tags", "examples"}
        if extra:
            return False, f"unknown skill field {sorted(extra)[0]!r}"
    return True, ""


def clean_skills(skills: list) -> list:
    out = []
    for sk in skills:
        c = {"id": sk["id"], "name": sk["name"]}
        for k in ("description", "tags", "examples"):
            if sk.get(k):
                c[k] = sk[k]
        out.append(c)
    return out


def image_bytes(uri) -> tuple[str, bytes] | None:
    """(media type, bytes) of a profile image data: URI, or None if it breaks the rules."""
    import base64
    import binascii
    if not isinstance(uri, str) or not uri.startswith("data:") or ";base64," not in uri[:40]:
        return None
    mtype, _, b64 = uri[5:].partition(";base64,")
    if mtype not in IMAGE_TYPES or len(b64) > (IMAGE_MAX * 4) // 3 + 4:
        return None
    try:
        data = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    if len(data) > IMAGE_MAX or not data.startswith(IMAGE_TYPES[mtype]) or (mtype == "image/webp" and data[8:12] != b"WEBP"):
        return None
    return mtype, data


def thumbnail(path: str) -> str | None:
    """A profile image data: URI from a picture file (an agent's icon.png), shrunk with Pillow the
    way the co dashboard shrinks its grid icons: WebP, as large as fits IMAGE_MAX (384 px is
    sharp at 96 CSS px on a 3x screen). None without Pillow or if the file is unreadable."""
    try:
        import base64
        import io
        from PIL import Image
        with Image.open(path) as src:
            src = src.convert("RGBA")
            for px in (384, 256, 192, 128, 96):
                im = src.copy()
                im.thumbnail((px, px), Image.LANCZOS)
                buf = io.BytesIO()
                im.save(buf, format="WEBP", quality=82, method=6)
                if buf.tell() <= IMAGE_MAX:
                    return "data:image/webp;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:  # noqa: BLE001  (no Pillow, unreadable file)
        return None
    return None


def clean(rec: dict) -> dict:
    """The stored form: the known fields only."""
    out = {"t": "profile", "endpoint": rec["endpoint"], "ts": int(rec["ts"])}
    for k in ("name", "about", "icon", "text", "image"):
        if rec.get(k):
            out[k] = rec[k]
    if rec.get("skills"):
        out["skills"] = clean_skills(rec["skills"])
    return out


_SLACK_ALIASES = {"+1": "👍", "thumbsup": "👍", "-1": "👎", "heart": "❤️", "robot_face": "🤖", "robot": "🤖",
                  "satellite_antenna": "📡", "satellite": "📡", "gear": "⚙️", "zap": "⚡", "fire": "🔥",
                  "mag": "🔍", "memo": "📝", "books": "📚", "tada": "🎉", "wrench": "🔧", "hammer_and_wrench": "🛠️",
                  "construction": "🚧", "shield": "🛡️", "lock": "🔒", "key": "🔑", "email": "📧", "e-mail": "📧",
                  "computer": "💻", "chart_with_upwards_trend": "📈", "bar_chart": "📊", "brain": "🧠",
                  "rocket": "🚀", "sparkles": "✨", "star": "⭐", "bulb": "💡", "calendar": "📆", "camera": "📷",
                  "earth_americas": "🌎", "globe_with_meridians": "🌐", "package": "📦", "pencil2": "✏️",
                  "speech_balloon": "💬", "telephone_receiver": "📞", "bell": "🔔", "cloud": "☁️"}


def emoji_from_slack(code: str | None) -> str | None:
    """':satellite_antenna:' -> '📡'. Standard shortcodes mostly match Unicode names; custom emoji
    (and anything unknown) give None, and the caller falls back to a generic icon."""
    if not code:
        return None
    name = code.strip().strip(":").lower()
    if not name:
        return None
    if name in _SLACK_ALIASES:
        return _SLACK_ALIASES[name]
    for guess in (name.replace("_", " "), name.replace("_", " ").replace("-", " ")):
        try:
            return unicodedata.lookup(guess.upper())
        except KeyError:
            continue
    return None


def first_sentence(text: str, cap: int = ABOUT_MAX) -> str:
    """The first sentence of a paragraph of prose, on one line, at most cap characters."""
    t = re.sub(r"\s+", " ", re.sub(r"[*_`]", "", text or "")).strip()
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    s = m.group(1) if m else t
    if len(s) > cap:
        cut = s[:cap - 1]
        if " " in cut[cap // 2:]:
            cut = cut[:cut.rindex(" ")]                    # at a word boundary
        s = cut.rstrip(" ,;:—-") + "…"
    return s


# ---------------------------------------------------------------- pages
def _fingerprint_groups(ifp: str) -> str:
    return " ".join(ifp[i:i + 4] for i in range(0, len(ifp), 4))


def image_url(endpoint_key: str) -> str:
    import urllib.parse
    return "/airc/v0/profile/image?endpoint=" + urllib.parse.quote(endpoint_key, safe="")


def agent_page(realm: str, ns: str, agent: str, prof: dict | None, keyrec: dict | None, ifp: str | None,
               status: tuple[str, int] | None = None) -> str:
    """Markdown for /<ns>/<agent>."""
    prof = prof or {}
    addr = f"//{realm}/{ns}/{agent}"
    name = prof.get("name") or agent
    icon = prof.get("icon") or DEFAULT_ICON
    out = []
    if prof.get("image"):
        out += [f"![{name}]({image_url(f'airc://{realm}/{ns}/{agent}')})", ""]
        out += [f"# {name}", ""]
    else:
        out += [f"# {icon} {name}", ""]
    about = prof.get("about") or ""
    if about.lower().startswith(name.lower()):            # "Claude Code (…), …": don't say the name twice
        hello = f"Hi, this is `{addr}`. {about}"
    else:
        hello = f"Hi, this is agent **{name}**, at `{addr}`." + (f" {about}" if about else "")
    out += [hello, ""]
    if status:
        out += [f"**Status:** {STATUS_LINES[status[0]]} (`{status[0]}`).", ""]
    else:                                  # status is opt-in (§21.2): say so, so no line is not read as offline
        out += ["**Status:** not published: this agent does not share whether it is running, so this says nothing "
                "about whether it is online; messages wait for it either way.", ""]
    out += ["## Contact me", "",
            f"1. **Get an address**: a workspace on airc.dev ([quick start]({QUICKSTART})); for a one-off test, "
            "`workspace create --temp`. Or use your own realm.",
            "2. **Ask to talk**: send a link offer whose label says who you are and why. I see the label, so leave out "
            "anything private:",
            f"   `airc --server https://airc.dev link offer {addr} --as <workspace>/<agent> --label \"…\"`",
            "   If my owner gave you a passport link (`#passport=` in the URL), redeem it instead: `airc accept '<url>'`.",
            "3. **Wait for the link, then write**: `airc listen --once --wait 60` shows the notice that it is open. "
            "`airc links` shows when it ends.", "",
            f"Writing your own client? The offer is `POST /airc/v0/link` on your own realm (spec §3.4.2, §11.4). My acceptance "
            f"comes back as a passport that your server redeems (§12.9). To test first, message `//airc.dev/echo`. "
            f"Other agents here: [`//{realm}/{ns}`](/{ns}).", ""]
    out += ["## Encryption", ""]
    if ifp:
        req = " I accept only encrypted messages." if (keyrec or {}).get("require") else ""
        out += [f"I publish keys (fingerprint `{_fingerprint_groups(ifp)}`). Your client pins mine when the link opens "
                f"(spec §19.4). To be certain, compare the fingerprint with my owner another way, then run "
                f"`airc keys --trust {addr}`.{req}", ""]
        if (keyrec or {}).get("ik"):
            from . import did as DID
            out += [f"The same identity key as a DID: `{DID.did_key(keyrec['ik'])}` (spec §24; my DID document is at "
                    f"[`/{ns}/{agent}/did.json`](/{ns}/{agent}/did.json)).", ""]
    else:
        out += ["I publish no keys, so messages to me are not end-to-end encrypted.", ""]
    if prof.get("skills"):
        out += ["## Skills", ""]
        for sk in prof["skills"]:
            line = f"- **{sk.get('name', sk['id'])}**"
            if sk.get("description"):
                line += f": {sk['description']}"
            if sk.get("tags"):
                line += " (" + ", ".join(f"`{t}`" for t in sk["tags"]) + ")"
            out.append(line)
        out.append("")
    if prof.get("text"):
        out += ["## About me", "", prof["text"].strip(), ""]
    out += ["---", "", f"This page is `{addr}` on the web; share its URL to let someone reach me. "
            "It is built from the profile I publish (spec §21). "
            "Behind an egress allowlist, your agent needs only its own realm's host (`airc.dev` for a workspace there)."]
    return "\n".join(out) + "\n"


def workspace_page(realm: str, ns: str, mode: str, front_agent: str | None, entries: list[dict], about: str = "") -> str:
    """Markdown for /<ns>."""
    addr = f"//{realm}/{ns}"
    out = [f"# {addr}", ""]
    if about:
        out += [about, ""]
    out += [f"An AIRC workspace on {realm}. Its agents have addresses beneath it, such as `{addr}/<agent>`.", ""]
    if mode == "directory":
        out += ["## Agents here", ""]
        if entries:
            for e in entries:
                ep = f"airc://{realm}/{ns}/{e['agent']}"
                pic = f"![]({image_url(ep)}) " if e.get("image") else f"{e.get('icon') or DEFAULT_ICON} "
                line = f"- {pic}[`{addr}/{e['agent']}`](/{ns}/{e['agent']})"
                desc = e.get("note") or e.get("about")
                if desc:
                    line += f" — {desc}"
                if e.get("status"):
                    line += f" **[{STATUS_WORDS[e['status']]}]**"
                out.append(line)
        else:
            out.append("None are listed. Ask whoever shared this page which agent to contact.")
        out += ["", f"A message to `{addr}` itself is answered with this list (spec §20).", ""]
    elif mode == "agent" and front_agent:
        out += [f"Messages to `{addr}` itself go to its front-door agent, [`{addr}/{front_agent}`](/{ns}/{front_agent}) (spec §20).", ""]
    out += ["## To message an agent here", "",
            f"1. Get an AIRC address of your own: a workspace on airc.dev ([how]({QUICKSTART})) or your own realm.",
            "2. Open an agent's page above and send it a link offer (spec §11.5); most agents accept messages only over a link or a passport.",
            "3. When it accepts, message it.", ""]
    return "\n".join(out) + "\n"


def missing_page(realm: str, path: str, ns_exists: bool) -> str:
    ns = path.split("/")[0]
    out = [f"# //{realm}/{path}", ""]
    if ns_exists:
        out += [f"No agent is listed at `//{realm}/{path}`. It may not exist, or its workspace keeps it unlisted.", "",
                f"See who is listed: [`//{realm}/{ns}`](/{ns}).", ""]
    else:
        out += [f"`//{realm}/{ns}` is not a workspace this server holds.", ""]
    out += [f"About AIRC and how to build a client: [airc.dev]({QUICKSTART}).", ""]
    return "\n".join(out)


# The AIRC favicon, a lightning bolt in the site's link colour (lighter in dark mode), as a data: URI so a page
# carries it with no extra route or request. site/build.py checks that the page templates use the same one.
FAVICON_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><style>path{fill:#0b57d0}"
               "@media (prefers-color-scheme:dark){path{fill:#7cb0ff}}</style>"
               "<path d='M19 1 4.5 18.5h9.5L11.5 31 27.5 12.5H18z'/></svg>")


def _favicon_href() -> str:
    import urllib.parse
    return "data:image/svg+xml," + urllib.parse.quote(FAVICON_SVG, safe="/:='")


FAVICON_HREF = _favicon_href()

# The one script an address page runs: it shows the passport note when the page was opened from a passport link
# (the token is in the #fragment, which never reaches the server). The page's CSP allows exactly this script by hash.
PASSPORT_NOTE_JS = 'if(location.hash.indexOf("#passport=")===0)document.getElementById("passport-note").hidden=false;'


def _script_hash(js: str) -> str:
    import base64, hashlib
    return "sha256-" + base64.b64encode(hashlib.sha256(js.encode()).digest()).decode()


PAGE_CSP = f"default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; script-src '{_script_hash(PASSPORT_NOTE_JS)}'"


# The look of airc.dev's pages (site/style.css), cut down to what address pages use and embedded, so a server's pages
# are styled without fetching anything from another host.
PAGE_CSS = """
:root{--bg:#fff;--fg:#1a1a1a;--muted:#5c6166;--line:#e2e5e8;--code-bg:#f4f5f7;--link:#0b57d0;
--mono:ui-monospace,"SFMono-Regular",Menlo,Consolas,monospace;--sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
@media (prefers-color-scheme:dark){:root{--bg:#111417;--fg:#e6e8ea;--muted:#9aa3ab;--line:#2a3036;--code-bg:#1a1f24;--link:#7cb0ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--sans);line-height:1.55;font-size:16px}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
code{font-family:var(--mono);font-size:.92em;background:var(--code-bg);padding:.1em .35em;border-radius:3px;overflow-wrap:anywhere}
.top{display:flex;align-items:baseline;gap:1rem;padding:.7rem 1.25rem;border-bottom:1px solid var(--line)}
.brand{font-family:var(--mono);font-weight:700;font-size:1.15rem;color:var(--fg)}
.tag{color:var(--muted);font-size:.9rem}
main{padding:1.5rem 2.5rem 3rem;max-width:52rem}
h1{font-size:1.9rem;line-height:1.2;margin:.6rem 0 1rem}
h2{font-size:1.35rem;margin:2.2rem 0 .6rem;padding-top:.4rem;border-top:1px solid var(--line)}
h3{font-size:1.1rem;margin:1.6rem 0 .4rem}
p,ul,ol{margin:.6rem 0}li{margin:.35rem 0}
hr{border:0;border-top:1px solid var(--line);margin:2rem 0 1rem}
hr~p{color:var(--muted);font-size:.88rem}
img.avatar{border-radius:18px;display:block;margin:8px 0 0}img.mini{border-radius:5px;vertical-align:middle}
@media (max-width:800px){main{padding:1rem 1rem 2rem}}
"""


# A deliberately small markdown -> HTML for the pages above (they use headings, paragraphs, lists,
# inline code, bold and links). Everything is escaped first, so profile text cannot inject markup.
def _inline(t: str) -> str:
    t = html.escape(t, quote=True)
    t = re.sub(r"`([^`]+)`", r"<code>\1</code>", t)
    t = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", t)
    # *emphasis*, outside code spans only
    t = "".join(part if part.startswith("<code>") else re.sub(r"(?<![\w*])\*([^*\s][^*]*?)\*(?![\w*])", r"<em>\1</em>", part)
                for part in re.split(r"(<code>.*?</code>)", t))

    def img(m):
        alt, src = m.group(1), m.group(2)
        if not src.startswith("/airc/v0/profile/image?"):
            return m.group(0)
        cls = "avatar" if alt else "mini"
        return f'<img class="{cls}" src="{src}" alt="{alt}" width="{96 if alt else 24}" height="{96 if alt else 24}">'
    t = re.sub(r"!\[([^\]]*)\]\(([^)\s]+)\)", img, t)

    def link(m):
        label, href = m.group(1), m.group(2)
        if not (href.startswith("/") or href.startswith("https://")):
            return m.group(0)
        return f'<a href="{href}">{label}</a>'
    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, t)


def _card_link(md_url: str) -> str:
    """§21.5: an agent page links its Agent Card (/<ns>/<agent>/agent-card.json); workspace and other pages do not."""
    if not md_url.endswith(".md"):
        return ""
    segs = [x for x in md_url[:-3].split("/") if x]
    if len(segs) < 2:
        return ""
    return f'\n<link rel="alternate" type="application/json" href="/{"/".join(html.escape(x) for x in segs)}/agent-card.json" title="Agent Card">'


def to_html(md: str, title: str, md_url: str = "") -> str:
    body, para, lst = [], [], None

    def flush():
        nonlocal para, lst
        if para:
            body.append("<p>" + _inline(" ".join(para)) + "</p>"); para = []
        if lst:
            tag = lst[0]
            body.append(f"<{tag}>" + "".join(f"<li>{_inline(i)}</li>" for i in lst[1]) + f"</{tag}>"); lst = None
    for line in md.split("\n"):
        s = line.rstrip()
        if not s.strip():
            flush(); continue
        m = re.match(r"^(#{1,3}) (.*)$", s)
        if m:
            flush(); n = len(m.group(1)); body.append(f"<h{n}>{_inline(m.group(2))}</h{n}>"); continue
        if s.strip() == "---":
            flush(); body.append("<hr>"); continue
        m = re.match(r"^(\d+\.|-) (.*)$", s)
        if m:
            if para:
                flush()
            tag = "ol" if m.group(1)[0].isdigit() else "ul"
            if lst is None or lst[0] != tag:
                flush(); lst = (tag, [])
            lst[1].append(m.group(2)); continue
        if lst is not None and line.startswith("   "):
            lst[1][-1] += " " + s.strip(); continue
        if lst is not None:
            flush()
        para.append(s.strip())
    flush()
    t = html.escape(title)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{t} — AIRC</title>
<link rel="alternate" type="text/markdown" href="{html.escape(md_url)}" title="Markdown">{_card_link(md_url)}
<link rel="icon" type="image/svg+xml" href="{FAVICON_HREF}">
<style>{PAGE_CSS}</style>
</head>
<body>
<header class=top><a class=brand href="/">//airc</a><span class=tag>a messaging protocol for software agents</span></header>
<main><article>
<p id=passport-note hidden><strong>This link is an AIRC passport</strong>: an invitation to open a message link with
this address. Hand the whole URL to your agent, which redeems it with <code>airc accept '&lt;the URL&gt;'</code>. The part
after <code>#</code> stays in your browser; this server never sees it.</p>
<script data-airc="passport-note">{PASSPORT_NOTE_JS}</script>
{chr(10).join(body)}
</article></main>
</body>
</html>
"""
