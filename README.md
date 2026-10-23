# tg-relay

> Single-file webhook-to-Telegram relay: signed JSON in, Telegram message out. Daily Tools #17.

## Why

You run a cron job, a deploy script, or an uptime check on a VPS and want a Telegram
ping when it finishes — without Docker, without a cloud function, without a third-party
service. `tg-relay` is one Node.js file (stdlib only) that listens for JSON webhooks,
verifies an HMAC-SHA256 signature, renders the payload through a `{{dot.path}}`
template, and forwards it to your Telegram bot.

Closest alternatives found on GitHub (`HoraceBury/telegram-webhook-relay`,
`rizkychi/webhook-relay`, `mjanssen19/tradingview-telegram-bridge`) are thin
forwarders or are tied to a platform (Cloudflare Workers, TradingView), and none
combine signature verification, message templating, rate limiting, dedupe, retry with
`retry_after` support, and a dry-run mode in a single dependency-free file that also
runs on Termux.

## Install

```bash
git clone https://github.com/Kayzenn123/tg-relay.git
cd tg-relay
# no dependencies — Node.js >= 18 only
```

Requires: Node >= 18

## Usage

```bash
TG_RELAY_TOKEN=<bot-token> TG_RELAY_CHAT=<chat-id> tg-relay --port 8765
curl -X POST localhost:8765/hook -H 'Content-Type: application/json' \
  -d '{"event":"deploy","status":"ok"}'
```

| Flag | Function | Default |
|---|---|---|
| `--port <PORT>` | HTTP listen port (or `TG_RELAY_PORT`) | `8765` |
| `--path <PATH>` | webhook endpoint path | `/hook` |
| `--token <TOKEN>` | Telegram bot token (or `TG_RELAY_TOKEN`) | — |
| `--chat <CHAT_ID>` | destination chat id (or `TG_RELAY_CHAT`) | — |
| `--secret <SECRET>` | HMAC-SHA256 secret (or `TG_RELAY_SECRET`) | off |
| `--template <FILE>` | message template file with `{{dot.path}}` | auto-format |
| `--title <TPL>` | one-line title template (no `--template`) | — |
| `--format <FMT>` | `markdown` (MarkdownV2, values escaped) or `plain` | `markdown` |
| `--max-body <BYTES>` | max webhook body size | `1048576` |
| `--rate <N>` | max messages per minute | `30` |
| `--dedupe <SEC>` | ignore identical messages within N seconds (`0` = off) | `60` |
| `--timeout <SEC>` | Telegram request timeout | `10` |
| `--dry-run` | print the message instead of sending (no token needed) | off |
| `--help`, `--version` | | |

Signed webhooks: send header `x-hook-signature: sha256=<hex hmac of the raw body>`.
Exit codes: `0` ok · `1` runtime error · `2` argument misuse.

## Example output

Command (scenario 1 — a GitHub-style push webhook relayed to Telegram):

```bash
TG_RELAY_TOKEN=<bot-token> TG_RELAY_CHAT=-10099 node bin/tg-relay.js --port 18765 &
curl -s -X POST localhost:18765/hook -d @examples/push.json
```

Output (real, copied from an actual run):

```text
{"ok":true,"action":"sent","attempts":1}
```

What the Telegram Bot API received:

```text
chat_id: -10099, parse_mode: MarkdownV2
text:
```
commits: [{"author":"Kayzenn123","id":"a1b2c3d","message":"feat: add HMAC verification"},{"author":"Kayzenn123","id":"e4f5g6h","message":"docs: add README with real run output"}]
compare: https://github.com/Kayzenn123/tg-relay/compare/v1...main
event: push
pusher: {"name":"Kayzenn123"}
repository: {"default_branch":"main","full_name":"Kayzenn123/tg-relay"}
```
```

Command (scenario 2 — custom template + HMAC signature, MarkdownV2 escaping):

```bash
printf 'Deploy *{{deploy.app}}* ke {{deploy.env}}: {{deploy.status}}' > tpl.txt
TG_RELAY_SECRET=<secret> node bin/tg-relay.js --template tpl.txt &
curl -s -X POST localhost:8765/hook -H "x-hook-signature: sha256=<hmac>" \
  -d '{"deploy":{"app":"toko_online","env":"production","status":"sukses_100%"}}'
curl -s -X POST localhost:8765/hook -d '{"deploy":{"app":"x"}}'   # no signature
```

Output (real, copied from an actual run):

```text
{"ok":true,"action":"sent","attempts":1}
{"ok":false,"error":"invalid signature"}
```

Message delivered to Telegram (values escaped, template markup kept):

```text
Deploy *toko\_online* ke production: sukses\_100%
```

Command (scenario 3 — dedupe and dry-run):

```bash
curl -s -X POST localhost:8765/hook -d '{"alert":"disk penuh","host":"vps-1"}'
curl -s -X POST localhost:8765/hook -d '{"alert":"disk penuh","host":"vps-1"}'
node bin/tg-relay.js --dry-run &
curl -s -X POST localhost:8766/hook -d '{"event":"coba-dry-run","x":1}'
```

Output (real, copied from an actual run):

```text
{"ok":true,"action":"sent","attempts":1}
{"ok":true,"action":"duplicate-ignored"}
{"ok":true,"action":"dry-run","text":"```\nevent: coba-dry-run\nx: 1\n```"}
```

## How it works

1. A single `http` server accepts `POST` to the webhook path (others get 404/405).
2. The raw body is checked against the byte limit, HMAC-verified with
   `crypto.timingSafeEqual` when a secret is set, then parsed as JSON.
3. The message is rendered from the template (`{{a.b.0.c}}` dot-paths, `{{@raw}}`
   for the whole payload); values are escaped for MarkdownV2 unless `--format plain`.
4. A token-bucket rate limiter and a SHA-256 dedupe window decide whether the
   message goes out; sending retries 429/5xx/network errors up to 3 times,
   honoring Telegram's `retry_after`. All logs go to stderr; results to stdout as JSON.

## Limitations

- One destination chat per process; run more instances for more chats.
- Template values that literally contain `{{...}}` are rendered a second time and may be substituted unexpectedly.
- No persistent queue: messages dropped by rate limiting are not retried later.
- Telegram message cap (4096 chars) truncates long payloads with a `…(truncated)` marker.
- The default auto-format is a flat key list — use `--template` for anything prettier.

## Development

```bash
npm test   # node --test, 31 tests, runs twice green
```

## License

MIT

---
Ringkasan (Bahasa Indonesia): tg-relay adalah relay webhook-ke-Telegram dalam satu file Node.js tanpa dependensi. Terima POST JSON, verifikasi signature HMAC-SHA256, render pesan lewat template `{{dot.path}}`, lalu teruskan ke bot Telegram dengan rate-limit, dedupe, dan retry. Cocok untuk notifikasi cron job, deploy script, atau uptime check di VPS/Termux. Coba tanpa akun Telegram via `--dry-run`. Batasan utama: satu chat tujuan per proses, template sederhana, dan tidak ada antrean persisten.
