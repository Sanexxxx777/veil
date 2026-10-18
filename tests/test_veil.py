#!/usr/bin/env python3
"""Tests for veil. Run: python3 tests/test_veil.py

Every secret here is synthetic. Token-shaped ones are assembled at run time from a
seeded generator, so no string in this file looks like a real token to a secret scanner.
"""

import atexit
import hashlib
import hmac
import io
import json
import os
import random
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import veil  # noqa: E402

FAILED = []
CHECKS = [0]
TMP = Path(tempfile.mkdtemp(prefix="veil-test-"))
atexit.register(shutil.rmtree, TMP, True)
rnd = random.Random(20261014)
ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def check(name: str, ok: bool, detail: str = "") -> None:
    CHECKS[0] += 1
    if not ok:
        FAILED.append(f"{name}: {detail}" if detail else name)


def rs(n: int, alphabet: str = ALNUM) -> str:
    return "".join(rnd.choice(alphabet) for _ in range(n))


def home(name: str) -> Path:
    return TMP / name


def cli(args, stdin: bytes = b"", h: Path = None):
    env = dict(os.environ, VEIL_HOME=str(h or home("cli")))
    p = subprocess.run([sys.executable, str(ROOT / "veil.py")] + args, input=stdin,
                       capture_output=True, env=env)
    return p.returncode, p.stdout, p.stderr


# ---- synthetic secrets, one per detector -----------------------------------------
pem_body = "\n".join(rs(64, ALNUM + "+/") for _ in range(4))
FAKES = {
    "pem": ("PRIVATE_KEY", "-----BEGIN RSA " + "PRIVATE KEY-----\n" + pem_body + "\n-----END RSA " + "PRIVATE KEY-----"),
    "sk_ant": ("API_KEY", "sk-" + "ant-api03-" + rs(60, ALNUM + "-_")),
    "sk_proj": ("API_KEY", "sk-" + "proj-" + rs(48)),
    "deepseek": ("API_KEY", "sk-" + rs(32, "0123456789abcdef")),
    "google": ("API_KEY", "AI" + "za" + rs(35)),
    "groq": ("API_KEY", "gs" + "k_" + rs(52)),
    "stripe": ("API_KEY", "sk" + "_live_" + rs(24)),
    "github": ("GIT_TOKEN", "gh" + "p_" + rs(36)),
    "github_pat": ("GIT_TOKEN", "github" + "_pat_" + rs(82, ALNUM + "_")),
    "slack": ("SLACK_TOKEN", "xo" + "xb-" + rs(12, "0123456789") + "-" + rs(24)),
    "aws": ("AWS_KEY_ID", "AK" + "IA" + rs(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")),
    "jwt": ("JWT", "ey" + "J" + rs(20) + ".ey" + "J" + rs(40) + "." + rs(43, ALNUM + "-_")),
    "telegram": ("BOT_TOKEN", rs(10, "0123456789") + ":" + "AA" + rs(33, ALNUM + "-_")),
    "hex": ("HEX_KEY", rs(64, "0123456789abcdef")),
}

for name, (kind, value) in FAKES.items():
    st = veil.Store(home("formats"))
    masked, counts = veil.mask_text(f"before {value} after\n", st)
    check(f"format {name}: value gone", value not in masked, masked[:120])
    check(f"format {name}: kind {kind}", counts == {kind: 1}, str(counts))

st = veil.Store(home("formats"))
hexkey = FAKES["hex"][1]
masked, _ = veil.mask_text(f"pk=0x{hexkey}\n", st)
check("0x stays visible, hex is HEX_KEY", masked.startswith("pk=0x{{HEX_KEY_"), masked)
for near in (rs(63, "0123456789abcdef"), rs(65, "0123456789abcdef"), rs(40, "0123456789abcdef")):
    check(f"{len(near)}-hex left alone", veil.mask_text(near, st)[0] == near)
url_pw = rs(14)
masked, counts = veil.mask_text(f"DSN postgres://bob:{url_pw}@db:5432/app\n", st)
check("url password masked, user kept", url_pw not in masked and "bob:{{PASSWORD_" in masked, masked)
fresh_pw, fresh_hex = rs(14), rs(64, "0123456789abcdef")  # not in any map yet
masked, _ = veil.mask_text(f"REDIS_URL=redis://:{fresh_pw}@10.0.0.5:6379/0\n", veil.Store(home("fresh")))
check("url password with an empty user", fresh_pw not in masked and "://:{{PASSWORD_" in masked, masked)
masked, _ = veil.mask_text(f"key 0X{fresh_hex} end\n", veil.Store(home("fresh")))
check("0X prefix: hex still masked", masked.startswith("key 0X{{HEX_KEY_"), masked)
cut_pem = "boot\n" + FAKES["pem"][1].split("-----END")[0][:150]  # a log window that ends mid-key
masked, counts = veil.mask_text(cut_pem, st)
check("a key block cut off before END is masked to the end", masked.startswith("boot\n{{PRIVATE_KEY_") and masked.endswith("}}")
      and counts == {"PRIVATE_KEY": 1}, masked)
cst = veil.Store(home("cut"))  # a home that has not seen the key: no known value masks it
old = cst.placeholder("API_KEY", FAKES["sk_proj"][1])  # written by an earlier mask
text = cut_pem + "\n" + old + " retry\n"
masked, counts = veil.mask_text(text, cst)
check("a cut key stops at a placeholder already there", masked.startswith("boot\n{{PRIVATE_KEY_")
      and masked.endswith("}}\n" + old + " retry\n") and counts == {"PRIVATE_KEY": 1}
      and veil.unmask_text(masked, cst.values) == text.replace(old, FAKES["sk_proj"][1]), masked)
cert = "-----BEGIN CERTIFICATE-----\n" + rs(64, ALNUM + "+/") + "\n-----END CERTIFICATE-----\n"
masked, counts = veil.mask_text(cut_pem + "\n" + cert, cst)
check("a cut key stops at the next BEGIN, the certificate stays", masked.startswith("boot\n{{PRIVATE_KEY_")
      and masked.endswith("}}\n" + cert) and counts == {"PRIVATE_KEY": 1}, masked)
pub = rs(64, ALNUM + "+/") + "\n-----END PUBLIC KEY-----\n"
text = ("12:00:01 worker up\n" + pem_body.split("\n", 1)[1] + "\n-----END RSA " + "PRIVATE KEY-----\n"
        + "12:00:02 ready\n" + pub)  # tail -n cut the BEGIN line and the first body line off
masked, counts = veil.mask_text(text, cst)
check("a key cut at the top: its lines and END masked, the lines around and a public key stay",
      masked.startswith("12:00:01 worker up\n{{PRIVATE_KEY_") and masked.endswith("}}\n12:00:02 ready\n" + pub)
      and counts == {"PRIVATE_KEY": 1} and veil.unmask_text(masked, cst.values) == text, masked)
text = ("log a\r\n\r\nDEK-Info: AES-128-CBC," + rs(16, "0123456789ABCDEF") + "\r\n\r\n"
        + pem_body.replace("\n", "\r\n") + "\r\n-----END RSA " + "PRIVATE KEY-----\r\nlog b\r\n")
masked, counts = veil.mask_text(text, cst)
check("a key cut inside its headers: header, blank line, body and END go together (CRLF)",
      masked.startswith("log a\r\n\r\n{{PRIVATE_KEY_") and masked.endswith("}}\r\nlog b\r\n")
      and counts == {"PRIVATE_KEY": 1}, masked)
masked, _ = veil.mask_text(f"users:\n  - password: two words {url_pw}\n", st)
check("YAML list item: the whole value", "two words" not in masked and url_pw not in masked, masked)
bearer = rs(40, ALNUM + "._-")
masked, counts = veil.mask_text(f"Authorization: Bearer {bearer}\n", st)
check("Authorization header: TOKEN, scheme kept", bearer not in masked and "Bearer {{TOKEN_" in masked
      and counts == {"TOKEN": 1}, masked)
sk = FAKES["sk_proj"][1]
masked, counts = veil.mask_text(f"OPENAI_API_KEY={sk}\n", st)
check("NAME=<known format>: the format's kind wins", counts == {"API_KEY": 1}, str(counts))

# ---- secret names ------------------------------------------------------------------
P = ["Q" + rs(16, ALNUM + "!%^") + "7" for _ in range(14)]  # a letter and a digit, always
POSITIVE = [
    (f"DB_PASSWORD={P[0]}\n", P[0]),
    (f'export API_KEY="{P[1]}"\n', P[1]),
    (f'{{"client_secret": "{P[2]}", "id": 7}}\n', P[2]),
    (f'log line {{\\"token\\": \\"{P[3]}\\"}}\n', P[3]),
    ("password: two words " + P[4] + "  # yaml comment\n", "two words " + P[4]),
    (f"run.sh --password {P[5]} --verbose\n", P[5]),
    (f'GET "https://x.example/api?api_key={P[6]}&page=2"\n', P[6]),
    (f"Cookie: sid={P[7]}; theme=dark\n", f"sid={P[7]}; theme=dark"),
    (f'sessionKey: "{P[8]}"\n', P[8]),
    (f"WALLET_PK={P[9]}\n", P[9]),
    (f"X-Auth-Token: {P[10]}\n", P[10]),
    (f"DISCORD_WEBHOOK=https://discord.example/api/webhooks/123/{P[11]}\n", None),
    (f"2026-10-14 12:00 the password: {P[12]} was rejected\n", P[12]),
    (f"POLY_PASSPHRASE='{P[13]}'\n", P[13]),
    ("DB_PASS=hunter22\n", "hunter22"),
    (f"accessToken: {P[0]}\n", P[0]),
]
for text, value in POSITIVE:
    st = veil.Store(home("names"))
    masked, counts = veil.mask_text(text, st)
    secret = value or text.split("=", 1)[1].strip()
    check(f"name rule masks: {text.strip()[:40]}", secret not in masked and counts, masked)
    check(f"name rule round-trips: {text.strip()[:40]}", veil.unmask_text(masked, st.values) == text)
masked, _ = veil.mask_text(POSITIVE[6][0], veil.Store(home("names")))
check("query string: the next parameter stays", "&page=2" in masked, masked)
masked, _ = veil.mask_text("password=\\" + P[1] + "\n", veil.Store(home("names")))
check("a leading backslash belongs to the value", masked.startswith("password={{SECRET_"), masked)

NEGATIVE = [
    "max_tokens=4096\n", '"total_tokens": 123456,\n', 'token = os.environ["API_TOKEN"]\n',
    "password = getpass()\n", "secret: None\n", f'if token == "{rs(12)}":\n',
    "PASSWORD=********\n", "api_key: ${API_KEY}\n", "public_key=abcdef123456\n",
    "token_expires_at=2026-10-14T12:00:00Z\n", "GB_TOKEN=\n", "password: <your password>\n",
    "api_key = settings.API_KEY\n", "password: Optional[str] = None\n",
    "def login(user, password=None):\n", "items.sort(key=lambda x: x[1])\n", '{"key": "user_name"}\n',
    "token_type = 'invalid-mime-parameters'\n", "KALSHI_KEY_PATH=/root/bot/key.pem\n",
    "'Cookie': 'http.cookies',\n", "handler.password_mgr = urllib.request.HTTPPasswordMgr\n",
]
for text in NEGATIVE:
    masked, counts = veil.mask_text(text, veil.Store(home("names")))
    check(f"left alone: {text.strip()}", masked == text and not counts, masked)

# ---- text that already holds placeholders ------------------------------------------
# A span over a placeholder from an earlier mask used to be dropped whole, and the rest
# of the secret stayed readable. Now the parts around the placeholder are masked.
ast = veil.Store(home("around"))
old = ast.placeholder("API_KEY", FAKES["sk_proj"][1])
alien = "{{API_KEY_%s}}" % rs(8, "0123456789abcdef")  # from another home, unknown here
pw = ["Zq8" + rs(9) for _ in range(10)]  # one each: a value masked once is masked anywhere
key_lines = pem_body.split("\n")
AROUND = [  # (text, readable before, still there after)
    (f"password: {pw[0]} horse {old}\n", [pw[0], "horse"], [" " + old]),
    (f"password: {old} {pw[1]} horse\n", [pw[1], "horse"], [old]),
    (f'{{"token": "{pw[2]}-{old}", "client_secret": "{old}-{pw[3]}"}}\n', [pw[2], pw[3]], [old]),
    (f"run.sh --token {pw[4]}{old} --verbose\n", [pw[4]], [old, " --verbose"]),
    (f"db: connect postgres://bob:{old}{pw[5]}@db:5432/app failed\nredis://:${{REDIS_PW}}@cache\n", [pw[5]],
     [old, "@db:5432/app failed", ":${REDIS_PW}@"]),
    (f"password: {alien} {pw[6]} horse\n{alien}: retry later\n", [pw[6], "horse"], [f"\n{alien}: retry later\n"]),
    ("boot\nComment: " + old + "\n" + pem_body + "\n-----END RSA " + "PRIVATE KEY-----\nup\n", key_lines, [old]),
    ("boot\n-----BEGIN RSA " + "PRIVATE KEY-----" + old + "\n" + pem_body[:150], key_lines[:2], [old]),
]
for text, before, after in AROUND:
    masked, counts = veil.mask_text(text, ast)
    check(f"around a placeholder: {text.strip()[:40]}", not [s for s in before if s in masked]
          and all(s in masked for s in after) and veil.mask_text(masked, ast)[0] == masked
          and veil.unmask_text(masked, ast.values) == veil.unmask_text(text, ast.values), masked)
text = (f"password: {pw[8]} horse {old}\n"
        f"secrets: {old} ... {old}\n"  # punctuation between two placeholders stays
        f"WALLET_PK=0x{FAKES['hex'][1]}\n"  # the 0x stays, also in a mask of masked text
        f"api_keys: [{FAKES['aws'][1]}, {pw[9]}]\n"  # a list is not a value: no part of it later either
        f"DB_PASSWORD: correct horse {P[1]}\n"
        f"token=correct horse {P[1]}tail9\n")  # one word under token: the rest is not its value
masked, _ = veil.mask_text(text, ast)
twice, counts2 = veil.mask_text(masked, ast)
check("masked text masked again: nothing new, a value read as it was before it was masked",
      pw[8] not in masked and f"{old} ... {old}" in masked and "WALLET_PK=0x{{HEX_KEY_" in masked
      and twice == masked and not counts2, twice)

# ---- determinism, known values, keys -----------------------------------------------
v = "tok_" + rs(30)
st = veil.Store(home("det"))
masked, _ = veil.mask_text(f"API_TOKEN={v}\nretry with API_TOKEN={v}\n", st)
st.save()
p = st.by_value[v]
check("same value, same placeholder", masked.count(p) == 2, masked)
again, counts = veil.mask_text(f"the server echoed {v} back\n", veil.Store(home("det")))
check("a known value is masked anywhere in a later run", again == f"the server echoed {p} back\n", again)
st = veil.Store(home("spread"))
veil.mask_text("Cookie: hide_cookie2\nDB_PASSWORD=PasswordMgrWithRealm\n", st)
plain = "if policy.hide_cookie2: use(PasswordMgrWithRealm)\n"
check("a word-like value is masked only where a rule finds it", veil.mask_text(plain, st)[0] == plain)
other = veil.Store(home("det-other"))
p2 = other.placeholder("SECRET", v)
check("another home (another key) gives another placeholder", p2 != p, p2)
check("an unknown placeholder is left as is", veil.unmask_text(masked, other.values) == masked)
key = (home("det") / "key").read_bytes()
expect = "{{SECRET_%s}}" % hmac.new(key, v.encode(), hashlib.sha256).hexdigest()[:8]
check("placeholder = kind + keyed HMAC, nothing of the value", p == expect, f"{p} {expect}")
check("placeholder shares no 6 chars with the value",
      not any(v[i:i + 6] in p for i in range(len(v) - 5)), p)

st = veil.Store(home("collide"))
h8 = hmac.new(st.key(), b"first-value-xyz", hashlib.sha256).hexdigest()
st.values["{{SECRET_%s}}" % h8[:8]] = "someone-else"
st.by_value["someone-else"] = "{{SECRET_%s}}" % h8[:8]
p = st.placeholder("SECRET", "first-value-xyz")
check("hash collision: a longer placeholder, never a shared one", p == "{{SECRET_%s}}" % h8[:12], p)
check("collision round-trips", veil.unmask_text(f"a {p} b", st.values) == "a first-value-xyz b")

# ---- round trip, idempotence, mangled forms --------------------------------------
corpus_parts = [f"{k}: {val}" for k, (_, val) in FAKES.items()] + [t for t, _ in POSITIVE]
corpus = ("\r\n".join(corpus_parts[:6]) + "\n" + "\n".join(corpus_parts[6:])
          + f"\nbraces {{{sk}}} {{{{{sk}}}}} {{ {sk} }} tab\t{sk}\t\nПароль: {P[0]} — ok\n")
st = veil.Store(home("rt"))
masked, counts = veil.mask_text(corpus, st)
check("round trip (API) is exact", veil.unmask_text(masked, st.values) == corpus)
check("no secret survives masking", not [k for k, (_, val) in FAKES.items() if val in masked]
      and not [x for x in P if x in masked])
twice, counts2 = veil.mask_text(masked, st)
check("mask is idempotent", twice == masked and not counts2, str(counts2))
hexv = rs(16, "0123456789abcdef")  # a known value that also looks like a placeholder's hash
st.placeholder("SECRET", hexv)
got, _ = veil.mask_text(f"see {{{{SECRET_{hexv}}}}} and {hexv}\n", st)
check("nothing is masked inside a placeholder already there",
      got.startswith(f"see {{{{SECRET_{hexv}}}}} and {{{{SECRET_") and got.count(hexv) == 1, got)

p = st.by_value[sk]
body = p[2:-2]
kind, h = body.rsplit("_", 1)
for form, want in [
    (f"{{{{ {body} }}}}", sk), (body, sk), (body.lower(), sk), (f"{kind}_{h.upper()}", sk),
    (f"{{{body}}}", sk), (f"{{{{{body}}}", sk), (f"{{{body}}}}}", sk), (f"x {{{body} y", f"x {{{sk} y"),
    (f"`{p}`.", f"`{sk}`."), (f"{body}_tail", f"{body}_tail"), (f"pre{body}", f"pre{body}"),
    (f"{{{{   {body}   }}}}", f"{{{{   {sk}   }}}}"), (f"{{   {body}}}", f"{{   {sk}}}"),
]:
    got = veil.unmask_text(form, st.values)
    check(f"unmask form {form!r}", got == want, got)

# streaming: every split point, then random multi-splits, must equal the whole
reply = (masked + f"\nThe model wrote {{{{ {body} }}}} and {body.lower()} and {{{body}}}"
         + f" and {{{{   {body}   }}}} and {{   {body}}}.\n" + "Пароль " + st.by_value[P[0]] + "!")
whole = veil.unmask_text(reply, st.values)


def streamed(text, cuts):
    um, out, prev = veil.Unmasker(st.values), [], 0
    for c in cuts + [len(text)]:
        out.append(um.feed(text[prev:c]))
        prev = c
    return "".join(out) + um.flush()


bad = [i for i in range(len(reply) + 1) if streamed(reply, [i]) != whole]
check("stream: one split at every position", not bad, f"{len(bad)} positions, first {bad[:5]}")
bad = []
for _ in range(300):
    cuts = sorted(rnd.sample(range(len(reply)), rnd.randint(2, 60)))
    if streamed(reply, cuts) != whole:
        bad.append(cuts)
check("stream: 300 random multi-splits", not bad, str(bad[:1]))
check("stream: one char at a time", streamed(reply, list(range(1, len(reply)))) == whole)

glued = "w" * 120 + body + " end"  # one long word: no placeholder in it, wherever it is cut
check("stream: a cut inside a long word does not start a placeholder",
      streamed(glued, [120]) == glued == veil.unmask_text(glued, st.values))
long_tail = "x " + body + "0" * 96  # one word: the body is not a placeholder here
check("stream: a long word is never cut right after a placeholder-like prefix",
      streamed(long_tail, []) == long_tail == veil.unmask_text(long_tail, st.values))

raw = reply.encode("utf-8")
for step in (1, 2, 3, 7):
    chunks = [raw[i:i + step] for i in range(0, len(raw), step)] + [b""]
    got = io.BytesIO()
    veil.unmask_stream(iter(chunks).__next__, got, st.values)
    check(f"unmask_stream bytes, step {step} (splits UTF-8)", got.getvalue() == whole.encode("utf-8"))

# ---- CLI: files, modes, output -----------------------------------------------------
h = home("cli")
raw = corpus.encode("utf-8") + b"\nbad bytes \xff\xfe kept, next to " + sk.encode() + b"\xff\n"
rc, out, err = cli(["mask"], raw, h)
check("cli mask exit 0", rc == 0, err.decode(errors="replace"))
leaked = [k for k, (_, val) in FAKES.items() if val.encode() in out + err]
check("cli mask: no secret on stdout or stderr", not leaked and P[0].encode() not in out + err, str(leaked))
check("cli mask: count on stderr", err.startswith(b"veil: masked "), err.decode(errors="replace"))
rc, back, err2 = cli(["unmask"], out, h)
check("cli round trip is byte-identical (CRLF, invalid UTF-8)", rc == 0 and back == raw)
check("cli unmask prints nothing else", err2 == b"", err2.decode(errors="replace"))
mode = lambda p: stat.S_IMODE(p.stat().st_mode)  # noqa: E731
check("home is 700", mode(h) == 0o700, oct(mode(h)))
check("map.json is 600", mode(h / "map.json") == 0o600, oct(mode(h / "map.json")))
check("key is 600, 32 bytes", mode(h / "key") == 0o600 and len((h / "key").read_bytes()) == 32)

os.chmod(h / "map.json", 0o644)
rc, out2, err = cli(["mask"], raw, h)
check("a readable map is set back to 600 with a warning",
      mode(h / "map.json") == 0o600 and b"readable by others" in err and out2 == out, err.decode())

bad_home = home("corrupt")
bad_home.mkdir()
(bad_home / "map.json").write_text("{not json")
rc, out, err = cli(["mask"], b"API_TOKEN=" + rs(20).encode() + b"\n", bad_home)
check("corrupt map: exit 2, map untouched", rc == 2 and (bad_home / "map.json").read_text() == "{not json",
      err.decode())
rc, out, _ = cli(["unmask"], b"plain {{SECRET_0123abcd}} text", home("never-created"))
check("unmask without a map passes text through", rc == 0 and out == b"plain {{SECRET_0123abcd}} text")
check("unmask does not create a home", not home("never-created").exists())
short = home("shortkey")
short.mkdir()
(short / "key").write_bytes(b"x" * 5)
rc, _, err = cli(["mask"], b"API_TOKEN=" + rs(20).encode() + b"\n", short)
check("short key file: exit 2", rc == 2 and b"32-byte" in err, err.decode())
empty = home("emptykey")
empty.mkdir()
(empty / "key").write_bytes(b"")  # left by a crash between create and write
rc, _, err = cli(["mask"], b"API_TOKEN=" + rs(20).encode() + b"\n", empty)
check("empty key file is replaced", rc == 0 and len((empty / "key").read_bytes()) == 32, err.decode())
pipe = subprocess.run(f'"{sys.executable}" "{ROOT / "veil.py"}" unmask --home "{h}" | head -c 10',
                      shell=True, input=b"x" * 2_000_000, capture_output=True)
check("a reader that leaves early: no traceback", pipe.stderr == b"", pipe.stderr.decode()[-200:])

# two masks at once must not lose each other's values
par = home("parallel")
vals = ["API_TOKEN=" + rs(24) + "\n" for _ in range(8)]
procs = [subprocess.Popen([sys.executable, str(ROOT / "veil.py"), "mask", "--home", str(par)],
                          stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
         for _ in vals]
for pr, t in zip(procs, vals):
    pr.stdin.write(t.encode())
    pr.stdin.close()
for pr in procs:
    pr.wait()
stored = set(json.loads((par / "map.json").read_text())["values"].values())
check("8 concurrent masks keep all 8 values", {t[10:-1] for t in vals} <= stored, f"{len(stored)} stored")

if FAILED:
    print(f"FAILED {len(FAILED)}")
    for line in FAILED:
        print("  -", line)
    raise SystemExit(1)
print(f"all {CHECKS[0]} checks passed")
