#!/usr/bin/env python3
"""Mask secrets in text before it goes to an LLM, and put them back in the answer.

    veil mask   < log.txt   > masked.txt      a secret becomes {{API_KEY_3f9a12bc}}
    veil unmask < reply.txt > restored.txt    and back, also on a streamed reply

A placeholder is the kind plus 8 hex digits of an HMAC-SHA256 of the value under a
local random key: the same value always gets the same one, and without the key it
says nothing about the value. Pairs live in $VEIL_HOME/map.json (default
~/.config/veil, mode 600); no command prints them. POSIX only. The token rules are
ported from yetone/magpie internal/redact/redact.go (MIT, see NOTICE).
"""
from __future__ import annotations

import argparse
import codecs
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from pathlib import Path

# Token formats as (kind, pattern). Where a pattern has a group, only the group
# is masked: the 0x of a hex key and the user of a URL stay readable.
FORMATS = [
    ("PRIVATE_KEY", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]+?"
                    r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
    ("API_KEY", r"(?<![\w-])sk-(?:ant-|proj-|or-|svcacct-|admin-)?[\w-]{20,}"),
    ("API_KEY", r"(?<![\w-])(?:(?:sk|rk)_live_[0-9A-Za-z]{20,}|AIza[\w-]{35}|hf_[A-Za-z0-9]{30,}"
                r"|gsk_[A-Za-z0-9]{40,}|xai-[A-Za-z0-9]{40,}|npm_[A-Za-z0-9]{36}|pypi-[\w-]{50,}"
                r"|dop_v1_[a-f0-9]{64}|SG\.[\w-]{22}\.[\w-]{43})"),
    ("GIT_TOKEN", r"(?<![\w-])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{40,}|glpat-[\w-]{20,})"),
    ("SLACK_TOKEN", r"(?<![\w-])xox[abposr]-[0-9A-Za-z-]{10,}"),
    ("AWS_KEY_ID", r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
    ("JWT", r"(?<![\w-])eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]{8,}"),
    ("BOT_TOKEN", r"(?<![0-9])[0-9]{8,12}:[\w-]{35}(?![\w-])"),
    ("HEX_KEY", r"(?<!\w)(?:0x)?([0-9a-fA-F]{64})(?!\w)"),
    ("PASSWORD", r"[A-Za-z][A-Za-z0-9+.-]*://[^\s:@/?#\"'<>]+:([^\s@/?#\"'<>]{3,})@"),
    ("TOKEN", r"\b(?:Bearer|Basic)[ \t]+([\w.~+/=-]{16,})"),
]
FORMAT_RES = [(kind, re.compile(p, re.A)) for kind, p in FORMATS]

# A name holds a secret when, in snake case (apiKey and api-key read as api_key),
# it contains one of STRONG_WORDS or WEAK_WORDS, or is or ends in _ + one of the
# suffixes; unless it says the value is public or is about the secret
# (token_type, key_path). Code calls many things a key (sorted(key=...),
# {"key": "id"}), so under a weak name only a value with letters and digits counts.
STRONG_WORDS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "api_key",
                "accesskey", "access_key", "privatekey", "private_key", "privkey", "priv_key",
                "credential", "mnemonic", "seed_phrase", "authorization")
STRONG_SUFFIXES = ("pass", "pwd")
WEAK_WORDS = ("cookie", "webhook")
WEAK_SUFFIXES = ("key", "pk", "auth", "dsn")
PUBLIC_WORDS = ("public", "publishable")
ABOUT_SUFFIXES = ("_type", "_name", "_path", "_file", "_dir", "_id", "_len", "_length", "_size",
                  "_count", "_ttl", "_expiry", "_expires", "_expires_at", "_expires_in",
                  "_format", "_kind", "_env", "_header")

# NAME = value, NAME: value, "name": "value", export NAME=..., but not == or :=
ASSIGN_RE = re.compile(r"""(?<![\w.])([A-Za-z_][\w.-]*)(\\?["'])?[ \t]*(?<![=!<>])([:=])(?!=)[ \t]*""", re.A)
FLAG_RE = re.compile(r"(?<![\w-])--([A-Za-z][\w-]*)[ \t]+(?![-\s])", re.A)  # --token value
LINE_PREFIX = re.compile(r"[ \t]*(?:export[ \t]+)?")
QUOTED = [re.compile(r'\\"(.*?)\\"'), re.compile(r'"((?:[^"\\\n]|\\.)*)"'),
          re.compile(r"'([^'\n]*)'"), re.compile(r"`([^`\n]*)`")]
OPEN_QUOTE = re.compile(r"""(?:\\?["'`])?""")
BARE = re.compile(r"""(?:[^\s"'`\\&]|\\(?!["'])|&(?![A-Za-z_]\w*=))+""", re.A)
AUTH_SCHEMES = {"bearer", "basic", "token", "bot", "digest"}

# Values that stand for a secret rather than being one: references, calls,
# types, empty or already-masked fields.
LITERALS = {"none", "null", "nil", "true", "false", "undefined", "required", "optional",
            "string", "bytes", "redacted", "hidden", "masked", "lambda"}
REFERENCE = re.compile(r"[$%{<\[(*]|(?:self|this|os|process|env|config|cfg|settings|args|opts"
                       r"|options|params|request|req|ctx|secrets|vars|form)\.|[A-Za-z_][\w.]*[(\[]",
                       re.A | re.I)
NUMBER = re.compile(r"[+-]?\d[\d.,_:/TZ+-]*")  # 4096, 0.25, 1,000, 2026-10-14T12:00:00Z
DOTTED = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", re.A)  # http.cookies, api.example.com

PLACEHOLDER_RE = re.compile(r"\{\{[A-Z][A-Z0-9_]*_[0-9a-f]{8,64}\}\}")
# A placeholder's body as a model may write it back: case changed, braces dropped.
BODY_RE = re.compile(r"(?<!\w)[A-Za-z]\w*_[0-9a-fA-F]{8,64}(?!\w)", re.A)
# What the end of a stream chunk may be if a placeholder is still arriving.
HOLD_RE = re.compile(r"\{{0,2}[ \t]{0,2}\w*[ \t]{0,2}\}?", re.A)
HOLD_MAX = 96  # longer than any placeholder with its braces and spaces
LEFT_BRACES = re.compile(r"\{{0,2}[ \t]{0,2}\Z")
RIGHT_BRACES = re.compile(r"[ \t]{0,2}\}{0,2}")
WORD_PAIR = re.compile(r"\w\w", re.A)
SECRETISH_MIN = 8


class VeilError(Exception):
    pass


def _warn(msg: str) -> None:
    print(f"veil: {msg}", file=sys.stderr)


def _tighten(path: Path, mode: int) -> None:
    if path.stat().st_mode & 0o077:
        os.chmod(path, mode)
        _warn(f"{path.name} was readable by others, set to {mode:o}")


class Store:
    """The local key and the placeholder -> value map of one VEIL_HOME."""

    def __init__(self, home: Path) -> None:
        self.home = Path(home)
        self.map_path = self.home / "map.json"
        self.values: dict[str, str] = {}
        if self.map_path.exists():
            _tighten(self.map_path, 0o600)
            try:
                self.values = json.loads(self.map_path.read_text(encoding="ascii"))["values"]
            except (ValueError, KeyError, TypeError) as e:
                # a map that is there but unreadable is unknown, never empty
                raise VeilError(f"{self.map_path} is not a veil map ({e}); fix or move it") from None
        self.by_value = {v: p for p, v in self.values.items()}
        self.dirty, self._key = False, b""

    def key(self) -> bytes:
        if not self._key:
            path = self.home / "key"
            if not path.exists():
                self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(secrets.token_bytes(32))
                    os.fsync(f.fileno())
            _tighten(path, 0o600)
            self._key = path.read_bytes()
            if len(self._key) != 32:
                raise VeilError(f"{path} is not a 32-byte key; fix or move it")
        return self._key

    def placeholder(self, kind: str, value: str) -> str:
        if value in self.by_value:
            return self.by_value[value]
        h = hmac.new(self.key(), value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()
        for n in range(8, 65, 4):  # a longer hash only if another value holds this one
            p = "{{%s_%s}}" % (kind, h[:n])
            if p not in self.values:
                break
        self.values[p] = value
        self.by_value[value] = p
        self.dirty = True
        return p

    def save(self) -> None:
        if not self.dirty:
            return
        self.home.mkdir(mode=0o700, parents=True, exist_ok=True)
        tmp = self.map_path.with_name("map.json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            json.dump({"version": 1, "values": self.values}, f, indent=0)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.map_path)
        dfd = os.open(self.home, os.O_RDONLY)  # so the rename itself survives a power cut
        os.fsync(dfd)
        os.close(dfd)
        self.dirty = False


@contextlib.contextmanager
def locked(home: Path):
    """Create home if needed and hold its lock: two masks never lose each other's values."""
    home = Path(home)
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(home / ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _name_strength(name: str) -> int:
    """2 for a name that holds a secret (DB_PASSWORD), 1 for one that may (cache_key), else 0."""
    n = re.sub(r"[.-]", "_", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)).lower()
    if any(w in n for w in PUBLIC_WORDS) or n.endswith(ABOUT_SUFFIXES):
        return 0
    if any(w in n for w in STRONG_WORDS) or any(n == s or n.endswith("_" + s) for s in STRONG_SUFFIXES):
        return 2
    weak = any(w in n for w in WEAK_WORDS) or any(n == s or n.endswith("_" + s) for s in WEAK_SUFFIXES)
    return 1 if weak else 0


def _plausible(v: str, min_len: int = 6) -> bool:
    return not (len(v) < min_len or v.lower() in LITERALS or NUMBER.fullmatch(v)
                or not v.strip("*xX.#•_-") or REFERENCE.match(v) or DOTTED.fullmatch(v))


def _secretish(v: str) -> bool:
    return len(v) >= SECRETISH_MIN and re.search(r"\d", v) is not None and re.search(r"[A-Za-z]", v) is not None


def _spreads(v: str) -> bool:
    """A value random enough to mask wherever it shows up again: three of lower, upper,
    digit, symbol, or 16+ chars of letters and digits. Not hide_cookie2 or PasswordMgr."""
    classes = sum(re.search(c, v) is not None for c in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w.-]"))
    return len(v) >= SECRETISH_MIN and (classes >= 3 or (len(v) >= 16 and _secretish(v)))


def _value_at(s: str, i: int, rest_of_line: bool):
    """Span of the value that starts at s[i]: quoted, one word, or the rest of the line."""
    for q in QUOTED:
        m = q.match(s, i)
        if m:
            return m.span(1)
    m = BARE.match(s, OPEN_QUOTE.match(s, i).end())  # a quote that never closes: the word after it
    if not m:
        return None
    a, b = m.span()
    if s[a:b].lower() in AUTH_SCHEMES:  # Authorization: Bearer <token>
        gap = re.compile(r"[ \t]+").match(s, b)
        return _value_at(s, gap.end(), rest_of_line) if gap else None
    if rest_of_line:  # password: words with spaces, as YAML and headers have them
        eol = s.find("\n", a)
        line = s[a:eol if eol >= 0 else len(s)]
        b = a + len(re.split(r"[ \t]+#", line, maxsplit=1)[0].rstrip())
    while b > a and s[b - 1] in ",;:)]}>":
        b -= 1
    return (a, b) if b > a else None


def _pick(spans):
    """Non-overlapping spans: the first to start wins, then the longest, then the lower rank."""
    out, last = [], 0
    for sp in sorted(spans, key=lambda t: (t[0], t[0] - t[1], t[3])):
        if sp[0] >= last:
            out.append(sp)
            last = sp[1]
    return out


def mask_text(text: str, store: Store):
    """Return (masked text, {kind: replacements}). New values go into store; call store.save()."""
    taken = [m.span() for m in PLACEHOLDER_RE.finditer(text)]

    def free(a, b):
        return b > a and not any(a < z and b > y for y, z in taken)

    found = [(*m.span(1 if rx.groups else 0), kind, rank)  # (start, end, kind, rank)
             for rank, (kind, rx) in enumerate(FORMAT_RES) for m in rx.finditer(text)]
    found = [f for f in found if f[2] != "PASSWORD" or _plausible(text[f[0]:f[1]], 3)]
    formats = list(found)

    def format_covers(a, b):  # pk=0x<hex>: the hex rule's span, not 0x+hex as a SECRET
        return any(y >= a and z <= b and (b - a) - (z - y) <= 2 for y, z, _, _ in formats)

    for rx in (ASSIGN_RE, FLAG_RE):
        for m in rx.finditer(text):
            strength = _name_strength(m.group(1))
            if not strength:
                continue
            line_start = text.rfind("\n", 0, m.start()) + 1
            rest = rx is ASSIGN_RE and m.group(3) == ":" and LINE_PREFIX.fullmatch(text, line_start, m.start())
            span = _value_at(text, m.end(), bool(rest))
            v = text[span[0]:span[1]] if span else ""
            if span and _plausible(v) and (strength == 2 or _secretish(v)) and not format_covers(*span):
                found.append((*span, "SECRET", 100))

    picked = _pick(sp for sp in found if free(sp[0], sp[1]))
    for a, b, kind, _ in picked:
        store.placeholder(kind, text[a:b])
    known = sorted((v for v in store.by_value if _spreads(v)), key=len, reverse=True)
    if known:
        known_re = re.compile("|".join(map(re.escape, known)))
        picked = _pick(picked + [(*m.span(), "", 200) for m in known_re.finditer(text)
                                 if free(*m.span())])

    out, last, counts = [], 0, {}
    for a, b, kind, _ in picked:
        p = store.placeholder(kind, text[a:b])
        k = p[2:p.rindex("_")]
        counts[k] = counts.get(k, 0) + 1
        out += [text[last:a], p]
        last = b
    out.append(text[last:])
    return "".join(out), counts


def _braces(s: str, a: int, z: int, lo: int = 0):
    """Widen the body s[a:z] over {{ }}, or {{ } or { }}, with up to two spaces inside.
    A lone { or } on one side is the text's own and stays."""
    left = LEFT_BRACES.search(s, max(lo, a - 4), a).group()
    right = RIGHT_BRACES.match(s, z, z + 4).group()
    nl, nr = left.count("{"), right.count("}")
    if nl == 2 or (nl == 1 and nr):
        a -= len(left)
    if nr == 2 or (nr == 1 and nl):
        z += len(right)
    return a, z


def unmask_text(s: str, values: dict, start: int = 0, end: int | None = None) -> str:
    """s[start:end] with placeholders swapped back; s around it is read as context."""
    end = len(s) if end is None else end
    out, last = [], start
    for m in BODY_RE.finditer(s, start, end):
        kind, _, h = m.group().rpartition("_")
        v = values.get("{{%s_%s}}" % (kind.upper(), h.lower()))  # as mask wrote it, whatever the case
        a, z = _braces(s, m.start(), m.end(), start)
        if v is None or a < last or z > end:
            continue
        out += [s[last:a], v]
        last = z
    out.append(s[last:end])
    return "".join(out)


class Unmasker:
    """Unmask a stream: feed() chunks, then flush(). The output is the same as
    unmask_text() of the whole text, however it was split."""

    def __init__(self, values: dict) -> None:
        self.values, self.buf, self.done = values, "", 0

    def feed(self, chunk: str) -> str:
        self.buf += chunk
        return self._emit(self._cut())

    def flush(self) -> str:
        return self._emit(len(self.buf))

    def _cut(self) -> int:
        """Where the text that can no longer change ends: before a tail that may be
        the start of a placeholder, and never inside one already there."""
        s, n = self.buf, len(self.buf)
        cut = next((i for i in range(max(self.done, n - HOLD_MAX), n)  # not inside a word
                    if not (i and WORD_PAIR.match(s, i - 1)) and HOLD_RE.fullmatch(s, i)), n)
        for m in BODY_RE.finditer(s, max(self.done, cut - HOLD_MAX)):
            a, z = _braces(s, m.start(), m.end(), self.done)
            if a < cut < z:
                cut = a
        return cut

    def _emit(self, cut: int) -> str:
        out = unmask_text(self.buf, self.values, self.done, cut)
        keep = max(0, cut - 8)  # a few emitted chars stay as context for the next chunk
        self.buf, self.done = self.buf[keep:], cut - keep
        return out


def unmask_stream(read, out, values: dict) -> None:
    """read() returns bytes, b"" at the end; out, a binary file, gets the output as it is ready."""
    dec = codecs.getincrementaldecoder("utf-8")("surrogateescape")
    um = Unmasker(values)
    while True:
        data = read()
        piece = um.feed(dec.decode(data, final=not data)) + ("" if data else um.flush())
        if piece:
            out.write(piece.encode("utf-8", "surrogateescape"))
            out.flush()
        if not data:
            return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="veil", description="Mask secrets for an LLM, unmask its answer.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    home = Path(os.environ.get("VEIL_HOME") or Path.home() / ".config" / "veil")
    for name, text in (("mask", "stdin -> stdout with secrets replaced by placeholders"),
                       ("unmask", "stdin -> stdout with placeholders replaced by the values")):
        sub.add_parser(name, help=text, description=text).add_argument(
            "--home", type=Path, default=home, help=f"where the key and map.json live (default {home})")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "mask":
            text = sys.stdin.buffer.read().decode("utf-8", "surrogateescape")
            with locked(args.home):
                store = Store(args.home)
                masked, counts = mask_text(text, store)
                store.save()
            sys.stdout.buffer.write(masked.encode("utf-8", "surrogateescape"))
            detail = ", ".join(f"{k} {n}" for k, n in sorted(counts.items()))
            _warn(f"masked {sum(counts.values())}" + (f" ({detail})" if detail else ""))
        else:
            values = Store(args.home).values if args.home.exists() else {}
            unmask_stream(lambda: os.read(sys.stdin.fileno(), 65536), sys.stdout.buffer, values)
    except (VeilError, OSError) as e:
        _warn(str(e))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
