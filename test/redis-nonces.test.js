import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { encodeCommand, RespParser, RedisNonceStore } from '../src/redis-nonces.js';

test('encodeCommand emits canonical RESP2 arrays', () => {
  const buf = encodeCommand(['SET', 'k', 'v']);
  assert.equal(buf.toString(), '*3\r\n$3\r\nSET\r\n$1\r\nk\r\n$1\r\nv\r\n');
});

test('RespParser handles every reply type and split-chunk delivery', () => {
  const p = new RespParser();
  const full = Buffer.from(
    '+OK\r\n-ERR bad\r\n:42\r\n$5\r\nhello\r\n$-1\r\n*2\r\n$1\r\na\r\n:7\r\n',
    'utf8'
  );

  // feed one byte at a time — the parser must only emit when complete
  const got = [];
  for (const b of full) {
    p.push(Buffer.from([b]));
    for (;;) {
      const r = p.next();
      if (r === undefined) break;
      got.push(r);
    }
  }
  assert.deepEqual(got, ['OK', { error: 'ERR bad' }, 42, 'hello', null, ['a', 7]]);
  assert.equal(p.pendingBytes, 0);

  // bulk string containing CRLF inside its body must not confuse framing
  const p2 = new RespParser();
  p2.push(Buffer.from('$4\r\na\r\nb\r\n', 'utf8'));
  assert.equal(p2.next(), 'a\r\nb');
  assert.equal(p2.next(), undefined);
});

// The fixture runs as a separate child process — the store's synchronous
// worker bridge blocks the main thread while a reply crosses TCP, which is
// only safe when the server is foreign, exactly like real Redis.
const FIXTURE = fileURLToPath(new URL('./fixtures/mini-redis.mjs', import.meta.url));

async function startMiniRedis({ withTtl = false } = {}) {
  const child = spawn(process.execPath, [FIXTURE, withTtl ? '1' : '0'], {
    stdio: ['ignore', 'pipe', 'pipe']
  });
  const port = await new Promise((resolve, reject) => {
    let buf = '';
    child.stdout.on('data', (d) => {
      buf += d;
      const m = buf.match(/READY (\d+)/);
      if (m) resolve(Number(m[1]));
    });
    child.stderr.on('data', (d) => process.stderr.write(d));
    child.on('exit', (code) => reject(new Error(`mini-redis fixture exited early (${code})`)));
  });
  return { child, port };
}

function stopMiniRedis(handle) {
  if (!handle.child.killed) handle.child.kill();
}

test('RedisNonceStore claims atomically across two instances against one server', async () => {
  const handle = await startMiniRedis();
  const { port } = handle;
  const a = new RedisNonceStore({ url: `redis://127.0.0.1:${port}` });
  const b = new RedisNonceStore({ url: `redis://127.0.0.1:${port}` });
  try {
    const key = 'demo-app:' + 'ab'.repeat(16);
    assert.equal(a.claimIfAbsent(key), true);
    assert.equal(b.claimIfAbsent(key), false, 'second verifier instance must lose the race');
    assert.equal(b.has(key), true);
    assert.equal(a.has(key), true);

    b.add('demo-app:' + 'cd'.repeat(16));
    assert.equal(a.size() + b.size() >= 2, true, 'shared counter spans both instances');

    const fresh = 'demo-app:' + 'ef'.repeat(16);
    assert.equal(a.claimIfAbsent(fresh), true);
    assert.equal(a.claimIfAbsent(fresh), false);
  } finally {
    await Promise.allSettled([a.close(), b.close()]);
    stopMiniRedis(handle);
  }
});

test('RedisNonceStore TTL option is forwarded as PX', async () => {
  const handle = await startMiniRedis({ withTtl: true });
  try {
    const store = new RedisNonceStore({ url: `redis://127.0.0.1:${handle.port}`, ttlMs: 60_000 });
    try {
      assert.equal(store.claimIfAbsent('demo-app:' + '01'.repeat(16)), true);
      assert.equal(store.ttlMs, 60_000);
    } finally {
      await store.close().catch(() => {});
    }
  } finally {
    stopMiniRedis(handle);
  }
});

test('RedisNonceStore fails closed when no server answers', () => {
  // port 1 on localhost refuses connections almost instantly everywhere
  assert.throws(() => new RedisNonceStore({ url: 'redis://127.0.0.1:1', connectTimeoutMs: 300 }), /cannot reach/);
});
