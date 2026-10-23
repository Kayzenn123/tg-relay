'use strict';
/* Tes tg-relay. Semua offline: server Telegram di-mock secara lokal. */
const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const tg = require('../bin/tg-relay.js');
const BIN = path.join(__dirname, '..', 'bin', 'tg-relay.js');

/** Mock server Telegram: catat request, jawab sesuai `responder`. */
function mockTelegram(responder) {
  const calls = [];
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      calls.push({ url: req.url, body: JSON.parse(body) });
      const r = responder(calls.length, JSON.parse(body));
      res.writeHead(r.status || 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(r.json));
    });
  });
  return { server, calls };
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
}

function postHook(port, payload, headers = {}, raw = null) {
  return new Promise((resolve, reject) => {
    const body = raw !== null ? raw : JSON.stringify(payload);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path: '/hook',
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
      },
      (res) => {
        let data = '';
        res.on('data', (c) => (data += c));
        res.on('end', () => resolve({ status: res.statusCode, json: JSON.parse(data) }));
      }
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function signed(body, secret) {
  const h = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return { 'x-hook-signature': 'sha256=' + h };
}

describe('renderTemplate', () => {
  it('dot-path bersarang + index array', () => {
    const o = { event: { repo: 'x', tags: ['a', 'b'] } };
    assert.equal(tg.renderTemplate('{{event.repo}}#{{event.tags.1}}', o), 'x#b');
  });
  it('nilai hilang jadi string kosong', () => {
    assert.equal(tg.renderTemplate('a{{no.such.key}}b', { x: 1 }), 'ab');
  });
  it('@raw menyisipkan seluruh body', () => {
    assert.equal(tg.renderTemplate('{{@raw}}', { a: 1 }), '{"a":1}');
  });
  it('escape diterapkan ke nilai', () => {
    const out = tg.renderTemplate('*{{t}}*', { t: 'a_b' }, { escape: tg.escapeMarkdownV2 });
    assert.equal(out, '*a\\_b*');
  });
});

describe('escapeMarkdownV2', () => {
  it('semua karakter spesial di-escape', () => {
    const specials = '_*[]()~`>#+-=|{}.!';
    const out = tg.escapeMarkdownV2(specials);
    assert.equal(out, specials.split('').map((c) => '\\' + c).join(''));
  });
});

describe('verifySignature', () => {
  const secret = 's3cr3t';
  const body = Buffer.from('{"a":1}');
  const good = 'sha256=' + crypto.createHmac('sha256', secret).update(body).digest('hex');
  it('signature benar lolos', () => assert.equal(tg.verifySignature(body, secret, good).ok, true));
  it('signature salah ditolak', () => {
    const r = tg.verifySignature(body, secret, 'sha256=' + '0'.repeat(64));
    assert.equal(r.ok, false);
  });
  it('header hilang ditolak', () => {
    assert.equal(tg.verifySignature(body, secret, undefined).ok, false);
  });
  it('header malformed ditolak', () => {
    assert.equal(tg.verifySignature(body, secret, 'sha256=xyz').ok, false);
  });
  it('tanpa secret verifikasi dilewati', () => {
    assert.deepEqual(tg.verifySignature(body, '', undefined), { ok: true, skipped: true });
  });
});

describe('autoFormat & truncate', () => {
  it('key scalar jadi baris', () => {
    const out = tg.autoFormat({ event: 'push', n: 3 });
    assert.match(out, /event: push/);
    assert.match(out, /n: 3/);
  });
  it('nilai panjang dipotong', () => {
    const out = tg.autoFormat({ big: 'x'.repeat(500) });
    assert.ok(out.length < 300);
    assert.match(out, /…/);
  });
  it('pesan > 4096 char dipotong dengan penanda', () => {
    const out = tg.truncateMessage('y'.repeat(5000));
    assert.ok(out.length <= 4096);
    assert.match(out, /truncated/);
  });
});

describe('createRateLimiter', () => {
  it('izinkan N lalu blokir, pulih setelah semenit', () => {
    let t = 0;
    const rl = tg.createRateLimiter({ perMinute: 2, now: () => t });
    assert.equal(rl.allow(), true);
    assert.equal(rl.allow(), true);
    assert.equal(rl.allow(), false);
    t += 61000;
    assert.equal(rl.allow(), true);
  });
});

describe('createDedupe', () => {
  it('duplikat dalam jendela terdeteksi, kedaluwarsa setelahnya', () => {
    let t = 0;
    const d = tg.createDedupe({ windowSec: 60, now: () => t });
    assert.equal(d.seen('k'), false);
    assert.equal(d.seen('k'), true);
    assert.equal(d.seen('lain'), false);
    t += 61000;
    assert.equal(d.seen('k'), false);
  });
});

describe('parseArgs', () => {
  it('env jadi fallback token/chat', () => {
    const { cfg, errors } = tg.parseArgs([], { TG_RELAY_TOKEN: 'T', TG_RELAY_CHAT: '1' });
    assert.equal(errors, undefined);
    assert.equal(cfg.token, 'T');
    assert.equal(cfg.chat, '1');
  });
  it('dry-run tidak butuh token', () => {
    const { cfg, errors } = tg.parseArgs(['--dry-run'], {});
    assert.equal(errors, undefined);
    assert.equal(cfg.dryRun, true);
  });
  it('tanpa token & bukan dry-run -> error', () => {
    const { errors } = tg.parseArgs(['--chat', '1'], {});
    assert.ok(errors && errors.length > 0);
  });
  it('flag tak dikenal -> error', () => {
    const { errors } = tg.parseArgs(['--ngawur'], { TG_RELAY_TOKEN: 'T', TG_RELAY_CHAT: '1' });
    assert.ok(errors && errors.some((e) => e.includes('tak dikenal')));
  });
  it('--format selain markdown/plain -> error', () => {
    const { errors } = tg.parseArgs(['--format', 'html', '--dry-run'], {});
    assert.ok(errors && errors.length > 0);
  });
});

describe('CLI process', () => {
  it('--version cetak versi, exit 0', () => {
    const r = spawnSync('node', [BIN, '--version'], { encoding: 'utf8' });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /tg-relay 1\.0\.0/);
  });
  it('--help cetak bantuan, exit 0', () => {
    const r = spawnSync('node', [BIN, '--help'], { encoding: 'utf8' });
    assert.equal(r.status, 0);
    assert.match(r.stdout, /--token/);
  });
  it('flag salah -> exit 2 tanpa stack trace', () => {
    const r = spawnSync('node', [BIN, '--ngawur'], { encoding: 'utf8' });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /flag tak dikenal/);
    assert.doesNotMatch(r.stderr, /at .*\(/);
  });
});

describe('end-to-end (mock Telegram lokal)', () => {
  let tgMock, tgPort, calls;
  before(async () => {
    const m = mockTelegram(() => ({ json: { ok: true, result: { message_id: 7 } } }));
    tgMock = m.server;
    calls = m.calls;
    tgPort = await listen(tgMock);
  });
  after(() => {
    tgMock.close();
  });

  function baseCfg(extra = {}) {
    return {
      port: 0,
      path: '/hook',
      token: 'DUMMY',
      chat: '12345',
      secret: '',
      templateFile: '',
      title: '',
      format: 'markdown',
      maxBody: 1048576,
      rate: 1000,
      dedupe: 0,
      timeoutMs: 5000,
      dryRun: false,
      help: false,
      version: false,
      apiBase: `http://127.0.0.1:${tgPort}`,
      ...extra,
    };
  }

  async function withServer(cfg, fn) {
    const server = tg.createServer(cfg);
    const port = await listen(server);
    try {
      await fn(port);
    } finally {
      server.close();
    }
  }

  it('webhook valid -> terkirim ke Telegram', async () => {
    await withServer(baseCfg(), async (port) => {
      const r = await postHook(port, { event: 'deploy', status: 'ok' });
      assert.equal(r.status, 200);
      assert.equal(r.json.action, 'sent');
      assert.equal(calls.length, 1);
      assert.equal(calls[0].body.chat_id, '12345');
      assert.equal(calls[0].body.parse_mode, 'MarkdownV2');
      assert.match(calls[0].body.text, /event: deploy/);
      assert.match(calls[0].url, /\/botDUMMY\/sendMessage/);
    });
  });

  it('template custom + HMAC valid', async () => {
    const tplPath = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'tg-')), 't.txt');
    fs.writeFileSync(tplPath, 'Rilis {{event.version}} oleh {{event.author}}!');
    const secret = 'kunci';
    await withServer(baseCfg({ secret, templateFile: tplPath, format: 'plain' }), async (port) => {
      const body = JSON.stringify({ event: { version: 'v2', author: 'zen' } });
      const r = await postHook(port, null, signed(body, secret), body);
      assert.equal(r.status, 200);
      assert.equal(calls[calls.length - 1].body.text, 'Rilis v2 oleh zen!');
      assert.equal(calls[calls.length - 1].body.parse_mode, undefined);
    });
  });

  it('signature salah -> 401, tidak terkirim', async () => {
    const before = calls.length;
    await withServer(baseCfg({ secret: 'kunci' }), async (port) => {
      const r = await postHook(port, { a: 1 }, { 'x-hook-signature': 'sha256=' + '0'.repeat(64) });
      assert.equal(r.status, 401);
    });
    assert.equal(calls.length, before);
  });

  it('body bukan JSON -> 400', async () => {
    await withServer(baseCfg(), async (port) => {
      const r = await postHook(port, null, {}, 'bukan json {{{');
      assert.equal(r.status, 400);
    });
  });

  it('path salah -> 404, method salah -> 405', async () => {
    await withServer(baseCfg(), async (port) => {
      const nf = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/salah`, (res) => resolve(res.statusCode)).on('error', reject);
      });
      assert.equal(nf, 404);
      const mna = await new Promise((resolve, reject) => {
        http.get(`http://127.0.0.1:${port}/hook`, (res) => resolve(res.statusCode)).on('error', reject);
      });
      assert.equal(mna, 405);
    });
  });

  it('duplikat dalam jendela dedupe hanya dikirim sekali', async () => {
    const before = calls.length;
    await withServer(baseCfg({ dedupe: 60 }), async (port) => {
      const p = { event: 'ping', id: 42 };
      const r1 = await postHook(port, p);
      const r2 = await postHook(port, p);
      assert.equal(r1.json.action, 'sent');
      assert.equal(r2.json.action, 'duplicate-ignored');
    });
    assert.equal(calls.length, before + 1);
  });

  it('retry saat Telegram 429 lalu sukses', async () => {
    let n = 0;
    const flaky = mockTelegram(() => {
      n++;
      return n === 1
        ? { status: 429, json: { ok: false, error_code: 429, parameters: { retry_after: 0 } } }
        : { json: { ok: true } };
    });
    const fp = await listen(flaky.server);
    try {
      await withServer(baseCfg({ apiBase: `http://127.0.0.1:${fp}` }), async (port) => {
        const r = await postHook(port, { event: 'retry-me' });
        assert.equal(r.status, 200);
        assert.equal(r.json.attempts, 2);
      });
      assert.equal(n, 2);
    } finally {
      flaky.server.close();
    }
  });

  it('dry-run: tidak ada request ke Telegram', async () => {
    const before = calls.length;
    await withServer(baseCfg({ dryRun: true, token: '', chat: '' }), async (port) => {
      const r = await postHook(port, { event: 'coba' });
      assert.equal(r.status, 200);
      assert.equal(r.json.action, 'dry-run');
      assert.match(r.json.text, /event: coba/);
    });
    assert.equal(calls.length, before);
  });
});
