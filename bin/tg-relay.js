#!/usr/bin/env node
/**
 * tg-relay — relay webhook HTTP (JSON) ke Telegram. Satu file, nol dependensi.
 *
 * Terima POST JSON, verifikasi HMAC-SHA256 (opsional), render pesan lewat
 * template dot-path, teruskan ke Bot Telegram dengan rate-limit, dedupe,
 * dan retry yang menghormati `retry_after` Telegram.
 */
'use strict';

const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');

const VERSION = '1.0.0';
const DEFAULT_PORT = 8765;
const DEFAULT_PATH = '/hook';
const DEFAULT_API_BASE = 'https://api.telegram.org';
const MAX_MESSAGE = 4096; // batas Telegram

// ---------------------------------------------------------------------------
// Util murni (diekspos untuk tes)
// ---------------------------------------------------------------------------

/** Ambil nilai dari objek lewat dot-path, mis. "a.b.0.c". */
function getPath(obj, path) {
  if (path === '@raw') return obj;
  return String(path).split('.').reduce((acc, key) => {
    if (acc === null || acc === undefined) return undefined;
    if (Array.isArray(acc) && /^\d+$/.test(key)) return acc[Number(key)];
    return Object.prototype.hasOwnProperty.call(acc, key) ? acc[key] : undefined;
  }, obj);
}

/** Render template {{dot.path}} dari objek. Nilai yang hilang jadi string kosong. */
function renderTemplate(tpl, obj, { escape = null } = {}) {
  return String(tpl).replace(/\{\{\s*([^{}]+?)\s*\}\}/g, (m, expr) => {
    const val = getPath(obj, expr.trim());
    if (val === undefined || val === null) return '';
    const s = typeof val === 'object' ? JSON.stringify(val) : String(val);
    return escape ? escape(s) : s;
  });
}

/** Escape nilai agar aman di dalam pesan Telegram MarkdownV2. */
function escapeMarkdownV2(s) {
  return String(s).replace(/([\\_\*\[\]\(\)\~\`\>\#\+\-\=\|\{\}\.\!])/g, '\\$1');
}

/** Format otomatis: daftar key scalar top-level, sisanya ringkas. */
function autoFormat(obj, maxLen = 3000) {
  if (obj === null || typeof obj !== 'object') return String(obj);
  const lines = [];
  for (const [k, v] of Object.entries(obj)) {
    let s = typeof v === 'object' ? JSON.stringify(v) : String(v);
    if (s.length > 200) s = s.slice(0, 200) + '…';
    lines.push(`${k}: ${s}`);
  }
  let out = lines.join('\n');
  if (out.length > maxLen) out = out.slice(0, maxLen) + '\n…(truncated)';
  return out || '(empty object)';
}

/** Potong pesan ke batas Telegram dengan penanda. */
function truncateMessage(s, max = MAX_MESSAGE) {
  s = String(s);
  return s.length > max ? s.slice(0, max - 14) + '\n…(truncated)' : s;
}

/**
 * Verifikasi header signature "sha256=<hex>" terhadap HMAC-SHA256 raw body.
 * Tanpa secret -> {ok:true} (verifikasi dimatikan). timing-safe.
 */
function verifySignature(rawBody, secret, headerValue) {
  if (!secret) return { ok: true, skipped: true };
  if (!headerValue) return { ok: false, error: 'missing signature header' };
  const m = /^sha256=([0-9a-fA-F]{64})$/.exec(String(headerValue).trim());
  if (!m) return { ok: false, error: 'malformed signature header' };
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
  let actual;
  try {
    actual = Buffer.from(m[1], 'hex');
  } catch {
    return { ok: false, error: 'malformed signature header' };
  }
  if (actual.length !== expected.length) return { ok: false, error: 'bad signature' };
  return crypto.timingSafeEqual(actual, expected)
    ? { ok: true }
    : { ok: false, error: 'bad signature' };
}

/** Token bucket sederhana: izinkan `perMinute` aksi per menit. */
function createRateLimiter({ perMinute = 30, now = () => Date.now() } = {}) {
  let tokens = perMinute;
  let last = now();
  return {
    allow() {
      const t = now();
      tokens = Math.min(perMinute, tokens + ((t - last) / 60000) * perMinute);
      last = t;
      if (tokens >= 1) {
        tokens -= 1;
        return true;
      }
      return false;
    },
  };
}

/** Dedupe: tandai key yang sudah terlihat dalam jendela detik. */
function createDedupe({ windowSec = 60, now = () => Date.now() } = {}) {
  const seen = new Map();
  return {
    seen(key) {
      const t = now();
      for (const [k, exp] of seen) if (exp <= t) seen.delete(k);
      if (seen.has(key)) return true;
      seen.set(key, t + windowSec * 1000);
      return false;
    },
  };
}

function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// Pengiriman ke Telegram (stdlib https, bisa dioverride TG_API_BASE buat tes)
// ---------------------------------------------------------------------------

function postJson(url, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const body = JSON.stringify(payload);
    const req = lib.request(
      {
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: u.pathname + u.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'User-Agent': 'tg-relay/' + VERSION,
        },
        timeout: timeoutMs,
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(data);
          } catch {
            /* abaikan */
          }
          resolve({ status: res.statusCode, json, raw: data });
        });
      }
    );
    req.on('timeout', () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * Kirim pesan ke Telegram. Retry 429/5xx/network error (maks 3 percobaan),
 * menghormati retry_after. Kembalikan {ok, attempts}.
 */
async function sendTelegram({
  apiBase,
  token,
  chatId,
  text,
  parseMode,
  timeoutMs = 10000,
  maxAttempts = 3,
}) {
  const url = `${apiBase.replace(/\/$/, '')}/bot${token}/sendMessage`;
  const payload = {
    chat_id: chatId,
    text,
    disable_web_page_preview: true,
  };
  if (parseMode) payload.parse_mode = parseMode;
  let lastError = 'unknown error';
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    let res;
    try {
      res = await postJson(url, payload, timeoutMs);
    } catch (e) {
      lastError = e.message || String(e);
      if (attempt < maxAttempts) await sleep(1000 * attempt);
      continue;
    }
    if (res.status === 200 && res.json && res.json.ok) {
      return { ok: true, attempts: attempt };
    }
    lastError = (res.json && (res.json.description || JSON.stringify(res.json))) ||
      `HTTP ${res.status}`;
    const retryAfter = res.json && res.json.parameters && res.json.parameters.retry_after;
    const shouldRetry =
      res.status === 429 || res.status >= 500 || res.status === 408;
    if (!shouldRetry || attempt === maxAttempts) break;
    await sleep((Number(retryAfter) > 0 ? Number(retryAfter) : attempt) * 1000);
  }
  return { ok: false, error: lastError };
}

// ---------------------------------------------------------------------------
// Parsing argumen (tanpa dependensi)
// ---------------------------------------------------------------------------

const FLAG_DEFS = [
  ['port', 'PORT', 'port HTTP server', String(DEFAULT_PORT)],
  ['path', 'PATH', 'path endpoint webhook', DEFAULT_PATH],
  ['token', 'TOKEN', 'token Bot Telegram (atau env TG_RELAY_TOKEN)'],
  ['chat', 'CHAT_ID', 'chat id tujuan (atau env TG_RELAY_CHAT)'],
  ['secret', 'SECRET', 'secret HMAC-SHA256 (atau env TG_RELAY_SECRET)'],
  ['template', 'FILE', 'file template pesan ({{dot.path}})'],
  ['title', 'TPL', 'template judul satu baris, dipakai bila --template absen'],
  ['format', 'FMT', 'markdown | plain', 'markdown'],
  ['max-body', 'BYTES', 'batas ukuran body webhook', '1048576'],
  ['rate', 'N', 'maks pesan per menit', '30'],
  ['dedupe', 'SEC', 'jendela dedupe detik (0 = mati)', '60'],
  ['timeout', 'SEC', 'timeout request ke Telegram', '10'],
  ['dry-run', null, 'jangan kirim, cetak pesan yang akan dikirim', false],
  ['help', null, 'tampilkan bantuan', false],
  ['version', null, 'tampilkan versi', false],
];

function parseArgs(argv, env = process.env) {
  const opts = {};
  const errors = [];
  const boolFlags = new Set(FLAG_DEFS.filter((f) => f[1] === null).map((f) => f[0]));
  const known = new Set(FLAG_DEFS.map((f) => f[0]));
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') break;
    const m = /^--([a-z-]+)(?:=(.*))?$/.exec(a);
    if (!m) {
      errors.push(`argumen tak dikenal: ${a}`);
      continue;
    }
    const name = m[1];
    if (!known.has(name)) {
      errors.push(`flag tak dikenal: --${name}`);
      continue;
    }
    if (boolFlags.has(name)) {
      if (m[2] !== undefined) errors.push(`--${name} tidak menerima nilai`);
      opts[name] = true;
    } else if (m[2] !== undefined) {
      opts[name] = m[2];
    } else if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) {
      opts[name] = argv[++i];
    } else {
      errors.push(`--${name} butuh nilai`);
    }
  }
  if (errors.length) return { errors };
  const cfg = {
    port: numOpt(opts.port ?? env.TG_RELAY_PORT, DEFAULT_PORT, 'port'),
    path: opts.path || DEFAULT_PATH,
    token: opts.token || env.TG_RELAY_TOKEN || '',
    chat: opts.chat || env.TG_RELAY_CHAT || '',
    secret: opts.secret || env.TG_RELAY_SECRET || '',
    templateFile: opts.template || '',
    title: opts.title || '',
    format: opts.format || 'markdown',
    maxBody: numOpt(opts['max-body'], 1048576, 'max-body'),
    rate: numOpt(opts.rate, 30, 'rate'),
    dedupe: numOpt(opts.dedupe, 60, 'dedupe'),
    timeoutMs: numOpt(opts.timeout, 10, 'timeout') * 1000,
    dryRun: Boolean(opts['dry-run']),
    help: Boolean(opts.help),
    version: Boolean(opts.version),
    apiBase: env.TG_API_BASE || DEFAULT_API_BASE,
  };
  if (cfg.help || cfg.version) return { cfg };
  for (const bad of [cfg.port, cfg.maxBody, cfg.rate, cfg.dedupe, cfg.timeoutMs]) {
    if (!Number.isFinite(bad) || bad < 0) return { errors: ['nilai numerik tidak valid'] };
  }
  if (cfg.port === 0 || cfg.port > 65535) return { errors: ['port harus 1-65535'] };
  if (!['markdown', 'plain'].includes(cfg.format)) {
    return { errors: ['--format harus markdown atau plain'] };
  }
  if (!cfg.dryRun) {
    if (!cfg.token) return { errors: ['token bot wajib: --token atau env TG_RELAY_TOKEN'] };
    if (!cfg.chat) return { errors: ['chat id wajib: --chat atau env TG_RELAY_CHAT'] };
  }
  return { cfg };
}

function numOpt(v, dflt, _name) {
  if (v === undefined || v === null || v === '') return dflt;
  const n = Number(v);
  return n;
}

function helpText() {
  const lines = [
    'tg-relay v' + VERSION + ' — relay webhook HTTP (JSON) ke Telegram.',
    '',
    'Pakai:',
    '  TG_RELAY_TOKEN=xxx TG_RELAY_CHAT=123 tg-relay [opsi]',
    '  curl -X POST localhost:8765/hook -d \'{"event":"deploy","status":"ok"}\'',
    '',
    'Opsi:',
  ];
  for (const [name, arg, desc, dflt] of FLAG_DEFS) {
    const a = arg ? ` <${arg}>` : '';
    const d = dflt !== undefined && dflt !== false ? ` (default: ${dflt})` : '';
    lines.push(`  --${name}${a}  ${desc}${d}`);
  }
  lines.push(
    '',
    'Header signature: x-hook-signature: sha256=<hmac-sha256-hex dari raw body>.',
    'Template: {{dot.path}} dari JSON body; {{@raw}} = seluruh body.',
    'Env: TG_RELAY_TOKEN TG_RELAY_CHAT TG_RELAY_SECRET TG_RELAY_PORT TG_API_BASE.',
    'Exit: 0 ok · 1 runtime error · 2 salah pakai argumen.'
  );
  return lines.join('\n');
}

function log(...a) {
  const ts = new Date().toISOString();
  process.stderr.write(`[${ts}] ` + a.join(' ') + '\n');
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

function createServer(cfg) {
  const limiter = createRateLimiter({ perMinute: cfg.rate });
  const dedupe = createDedupe({ windowSec: cfg.dedupe });
  let template = null;
  if (cfg.templateFile) {
    try {
      template = fs.readFileSync(cfg.templateFile, 'utf8');
    } catch (e) {
      throw new Error(`tidak bisa baca --template ${cfg.templateFile}: ${e.message}`);
    }
  }

  const server = http.createServer((req, res) => {
    const send = (code, obj) => {
      res.writeHead(code, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(obj));
    };

    let urlPath = '/';
    try {
      urlPath = new URL(req.url, 'http://x').pathname;
    } catch {
      /* pakai default */
    }
    if (urlPath !== cfg.path) return send(404, { ok: false, error: 'not found' });
    if (req.method !== 'POST') return send(405, { ok: false, error: 'method not allowed' });

    const chunks = [];
    let size = 0;
    let aborted = false;
    req.on('data', (c) => {
      if (aborted) return;
      size += c.length;
      if (size > cfg.maxBody) {
        aborted = true;
        log('tolak: body melebihi batas', cfg.maxBody, 'byte');
        send(413, { ok: false, error: 'body too large' });
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', async () => {
      if (aborted) return;
      const raw = Buffer.concat(chunks);

      // 1. Verifikasi signature
      const sig = verifySignature(raw, cfg.secret, req.headers['x-hook-signature']);
      if (!sig.ok) {
        log('tolak: signature tidak valid —', sig.error);
        return send(401, { ok: false, error: 'invalid signature' });
      }

      // 2. Parse JSON
      let body;
      try {
        body = JSON.parse(raw.toString('utf8'));
      } catch {
        log('tolak: body bukan JSON valid');
        return send(400, { ok: false, error: 'invalid JSON' });
      }

      // 3. Render pesan
      const esc = cfg.format === 'markdown' ? escapeMarkdownV2 : null;
      let text;
      if (template) {
        text = renderTemplate(template, body, { escape: esc });
      } else if (cfg.title) {
        const t = renderTemplate(cfg.title, body, { escape: esc });
        const b = renderTemplate(autoFormat(body), body, { escape: esc });
        text = cfg.format === 'markdown' ? `*${t}*\n${b}` : `${t}\n${b}`;
      } else {
        const b = renderTemplate(autoFormat(body), body, { escape: esc });
        text = cfg.format === 'markdown' ? '```\n' + b + '\n```' : b;
      }
      text = truncateMessage(text.trim() || '(empty message)');

      // 4. Rate limit
      if (!limiter.allow()) {
        log('drop: rate limit terlampaui');
        return send(429, { ok: false, error: 'rate limit exceeded' });
      }

      // 5. Dedupe
      const key = sha256Hex(cfg.chat + '\n' + text);
      if (cfg.dedupe > 0 && dedupe.seen(key)) {
        log('lewati: duplikat dalam jendela dedupe');
        return send(200, { ok: true, action: 'duplicate-ignored' });
      }

      // 6. Kirim (atau dry-run)
      if (cfg.dryRun) {
        log('[dry-run] ke chat', cfg.chat || '-', ':', JSON.stringify(text.slice(0, 200)));
        return send(200, { ok: true, action: 'dry-run', text });
      }
      const r = await sendTelegram({
        apiBase: cfg.apiBase,
        token: cfg.token,
        chatId: cfg.chat,
        text,
        parseMode: cfg.format === 'markdown' ? 'MarkdownV2' : undefined,
        timeoutMs: cfg.timeoutMs,
      });
      if (r.ok) {
        log('terkirim ke chat', cfg.chat, `(attempt ${r.attempts})`);
        return send(200, { ok: true, action: 'sent', attempts: r.attempts });
      }
      log('gagal kirim ke Telegram:', r.error);
      return send(502, { ok: false, error: 'telegram send failed: ' + r.error });
    });
    req.on('error', () => {
      /* koneksi diputus klien; abaikan diam-diam */
    });
  });

  return server;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main(argv) {
  const { cfg, errors } = parseArgs(argv);
  if (errors) {
    process.stderr.write('Error: ' + errors.join('; ') + '\n');
    process.stderr.write('Jalankan `tg-relay --help` untuk bantuan.\n');
    process.exit(2);
  }
  if (cfg.help) {
    process.stdout.write(helpText() + '\n');
    return;
  }
  if (cfg.version) {
    process.stdout.write('tg-relay ' + VERSION + '\n');
    return;
  }
  let server;
  try {
    server = createServer(cfg);
  } catch (e) {
    process.stderr.write('Error: ' + e.message + '\n');
    process.exit(1);
  }
  server.on('error', (e) => {
    process.stderr.write('Error: tidak bisa listen di port ' + cfg.port + ': ' + e.message + '\n');
    process.exit(1);
  });
  server.listen(cfg.port, () => {
    log(
      `tg-relay v${VERSION} listen di :${cfg.port}${cfg.path}` +
        (cfg.dryRun ? ' [dry-run]' : ` -> Telegram chat ${cfg.chat}`) +
        (cfg.secret ? ' [HMAC on]' : '')
    );
  });
}

if (require.main === module) main(process.argv.slice(2));

module.exports = {
  VERSION,
  getPath,
  renderTemplate,
  escapeMarkdownV2,
  autoFormat,
  truncateMessage,
  verifySignature,
  createRateLimiter,
  createDedupe,
  sha256Hex,
  parseArgs,
  createServer,
  sendTelegram,
};
