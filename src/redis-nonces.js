import net from 'node:net';
import { Worker } from 'node:worker_threads';

/**
 * RedisNonceStore — distributed, horizontally scalable nonce store.
 *
 * Same synchronous interface as InMemory/File stores (claimIfAbsent/has/
 * add/size), but the state lives in Redis so N verifier instances behind a
 * load balancer share one replay-protection domain. Atomicity comes from
 * Redis's single-threaded command execution: claims use `SET key val NX`,
 * which is indivisible server-side, so two instances can never both win the
 * same nonce — the same guarantee FileNonceStore provides for one machine,
 * now across machines.
 *
 * Zero dependencies: this file contains a minimal RESP2 client and a
 * worker-thread bridge that turns async socket I/O into blocking calls,
 * so the deterministic 9-step verify pipeline stays synchronous exactly
 * like every other store. The bridge uses Atomics.wait — the same
 * fail-closed pattern FileNonceStore uses for lock acquisition.
 *
 * Privacy: only opaque nonce keys (app_id:hex32) are ever sent to Redis.
 * No events, no subjects, no weights, no signatures. Optional TTL gives
 * deployments GC: replay protection only needs to outlive the protocol's
 * TIMESTAMP_FRESHNESS window (SPEC.md), so expiring old claims after that
 * window is safe and is recommended in production.
 *
 * Fail-closed: construction throws if the server is unreachable; any I/O
 * error or timeout mid-operation throws instead of allowing a claim through.
 */

const HEADER_I32 = 6; // i32 slots before the payload region
const PAYLOAD_CAP = 8192;

export function encodeCommand(args) {
  let out = `*${args.length}\r\n`;
  for (const a of args) {
    const s = String(a);
    out += `$${Buffer.byteLength(s, 'utf8')}\r\n${s}\r\n`;
  }
  return Buffer.from(out, 'utf8');
}

const UNSET = Symbol('unset');

export class RespParser {
  constructor() {
    this.buf = Buffer.alloc(0);
    this.off = 0;
  }

  push(chunk) {
    this.buf = this.off === 0
      ? Buffer.concat([this.buf, chunk])
      : Buffer.concat([this.buf.subarray(this.off), chunk]);
    this.off = 0;
  }

  get pendingBytes() {
    return this.buf.length - this.off;
  }

  // Returns the next complete reply, or undefined when more bytes are needed.
  next() {
    const start = this.off;
    const reply = this._readOne();
    if (reply === UNSET) {
      this.off = start;
      return undefined;
    }
    return reply;
  }

  _line() {
    const nl = this.buf.indexOf(13, this.off + 1); // \r
    if (nl === -1 || nl + 1 >= this.buf.length) return undefined;
    return { line: this.buf.toString('utf8', this.off + 1, nl), end: nl + 2 };
  }

  _readOne() {
    if (this.off >= this.buf.length) return UNSET;
    const type = String.fromCharCode(this.buf[this.off]);
    const head = this._line();
    if (head === undefined) return UNSET;
    switch (type) {
      case '+': this.off = head.end; return head.line;
      case '-': this.off = head.end; return { error: head.line };
      case ':': this.off = head.end; return Number(head.line);
      case '$': {
        const n = Number(head.line);
        if (n === -1) { this.off = head.end; return null; }
        const bodyStart = head.end;
        const totalEnd = bodyStart + n + 2;
        if (this.buf.length < totalEnd) return UNSET;
        const s = this.buf.toString('utf8', bodyStart, bodyStart + n);
        this.off = totalEnd;
        return s;
      }
      case '*': {
        const n = Number(head.line);
        if (n === -1) { this.off = head.end; return null; }
        const arr = [];
        this.off = head.end;
        for (let i = 0; i < n; i++) {
          const v = this.next();
          if (v === undefined) return UNSET;
          arr.push(v);
        }
        return arr;
      }
      default:
        throw new Error(`RespParser: unknown reply type ${JSON.stringify(type)}`);
    }
  }
}

// The worker owns the socket so the main thread can block on Atomics.wait
// while the reply travels over TCP. Protocol (shared SAB):
//   i32[0] SEQ   — op counter set by main; worker waits for changes; -1 quits
//   i32[1] READY — 1 once connected+PINGed, -1 on connect failure
//   i32[2] DONE  — seq of the last completed op; worker notifies on change
//   i32[3] STATUS— 0 ok, 1 error
//   i32[4] RLEN  — reply byte length written into the payload region
//   i32[5] CLEN  — command byte length (main writes before bumping SEQ)
// Payload region follows at byte offset HEADER_I32*4.
const WORKER_SRC = [
  "const net = require('node:net');",
  'const { workerData } = require("node:worker_threads");',
  'const I = new Int32Array(workerData.sab);',
  'const P = Buffer.from(workerData.sab, ' + (HEADER_I32 * 4) + ', ' + PAYLOAD_CAP + ');',
  'let sock = null; let rx = null;',
  'function connect() {',
  '  return new Promise((resolve, reject) => {',
  '    const s = net.connect({ host: workerData.host, port: workerData.port });',
  '    let opened = false;',
  '    const timer = setTimeout(() => { s.destroy(); reject(new Error("connect timeout")); }, workerData.connectTimeoutMs);',
  '    s.on("connect", () => {});',
  '    s.on("data", (c) => { if (rx) rx(c); });',
  '    s.on("error", (e) => { if (!opened) { clearTimeout(timer); reject(e); } else if (rx) rx(Buffer.alloc(0)); s._dead = true; });',
  '    s.on("close", () => { if (!opened) { clearTimeout(timer); reject(new Error("closed")); } sock = null; rx = null; });',
  '    s.on("ready", () => { opened = true; clearTimeout(timer); resolve(s); });',
  '  });',
  '}',
  'function roundTrip(s, cmd) {',
  '  return new Promise((resolve, reject) => {',
  '    const acc = [];',
  '    const parser = { buf: Buffer.alloc(0), off: 0 };',
  '    rx = (c) => {',
  '      parser.buf = c.length ? Buffer.concat([parser.buf, c]) : parser.buf;',
  '      for (;;) {',
  '        const r = readReply(parser);',
  '        if (r === undefined) return;',
  '        rx = null;',
  '        return resolve(r);',
  '      }',
  '    };',
  '    s.write(cmd, (err) => { if (err) { rx = null; reject(err); } });',
  '  });',
  '}',
  // Minimal inline reader (mirrors RespParser in the main module).
  'function readReply(p) {',
  '  if (p.off >= p.buf.length) return undefined;',
  '  const t = String.fromCharCode(p.buf[p.off]);',
  '  const nl = p.buf.indexOf(13, p.off + 1);',
  '  if (nl === -1 || nl + 1 >= p.buf.length) return undefined;',
  '  const line = p.buf.toString("utf8", p.off + 1, nl);',
  '  if (t === "+" || t === "-" || t === ":") { p.off = nl + 2; return t === "-" ? { error: line } : t === ":" ? Number(line) : line; }',
  '  if (t === "$") { const n = Number(line); if (n === -1) { p.off = nl + 2; return null; } const e = nl + 2 + n + 2; if (p.buf.length < e) return undefined; const s = p.buf.toString("utf8", nl + 2, nl + 2 + n); p.off = e; return s; }',
  '  if (t === "*") { const n = Number(line); if (n === -1) { p.off = nl + 2; return null; } const arr = []; p.off = nl + 2; for (let i = 0; i < n; i++) { const v = readReply(p); if (v === undefined) return undefined; arr.push(v); } return arr; }',
  '  return { error: "bad reply type" };',
  '}',
  '(async () => {',
  '  try {',
  '    sock = await connect();',
  '    if (workerData.password) {',
  '      const r = await roundTrip(sock, encode(Array.of("AUTH", workerData.password)));',
  '      if (r && r.error) throw new Error(r.error);',
  '    }',
  '    if (workerData.db) {',
  '      const r = await roundTrip(sock, encode(["SELECT", String(workerData.db)]));',
  '      if (r && r.error) throw new Error(r.error);',
  '    }',
  '    const pong = await roundTrip(sock, encode(["PING"]));',
  '    if (pong !== "PONG") throw new Error("handshake PING failed");',
  '    Atomics.store(I, 1, 1); Atomics.notify(I, 1);',
  '  } catch (e) {',
  '    Atomics.store(I, 1, -1); Atomics.notify(I, 1);',
  '    Atomics.store(I, 3, 1);',
  '    const msg = Buffer.from(String((e && e.message) || e), "utf8");',
  '    msg.copy(P, 0); Atomics.store(I, 4, Math.min(msg.length, ' + PAYLOAD_CAP + '));',
  '    return;',
  '  }',
  '  let seen = 0;',
  '  for (;;) {',
  '    Atomics.wait(I, 0, seen);',
  '    const seq = Atomics.load(I, 0);',
  '    if (seq === seen) continue;',
  '    seen = seq;',
  '    if (seq === -1) { try { sock.end(); } catch {} return; }',
  '    let status = 0; let out = null;',
  '    try {',
  '      if (!sock || sock._dead) { sock = await connect(); }',
  '      const len = Atomics.load(I, 5);',
  '      const cmd = P.toString("latin1", 0, len);',
  '      out = await roundTrip(sock, Buffer.from(cmd, "latin1"));',
  '      if (out && out.error) status = 1;',
  '    } catch (e) { status = 1; out = { error: String((e && e.message) || e) }; }',
  '    const text = out === null ? "" : typeof out === "string" ? out : JSON.stringify(out);',
  '    const bytes = Buffer.from(text, "utf8");',
  '    bytes.copy(P, 0);',
  '    Atomics.store(I, 4, Math.min(bytes.length, ' + PAYLOAD_CAP + '));',
  '    Atomics.store(I, 3, status);',
  '    Atomics.store(I, 2, seq);',
  '    Atomics.notify(I, 2);',
  '  }',
  '})();',
  'function encode(args) {',
  '  let o = "*" + args.length + "\\r\\n";',
  '  for (const a of args) { const s = String(a); o += "$" + Buffer.byteLength(s) + "\\r\\n" + s + "\\r\\n"; }',
  '  return Buffer.from(o, "utf8");',
  '}'
].join('\n');

export class RedisNonceStore {
  static get WORKER_SRC() { return WORKER_SRC; }
  constructor({
    url = process.env.REDIS_URL ?? 'redis://127.0.0.1:6379',
    keyPrefix = 'piproof:nonce:',
    ttlMs = null,
    timeoutMs = 5000,
    connectTimeoutMs = 2000
  } = {}) {
    this.keyPrefix = keyPrefix;
    this.ttlMs = ttlMs;
    this.timeoutMs = timeoutMs;
    this.claims = 0;
    this.counterKey = `${keyPrefix}__count__`;

    const u = new URL(url);
    this.sab = new SharedArrayBuffer(HEADER_I32 * 4 + PAYLOAD_CAP);
    this.i32 = new Int32Array(this.sab);
    this.payload = Buffer.from(this.sab, HEADER_I32 * 4, PAYLOAD_CAP);

    this.worker = new Worker(WORKER_SRC, { eval: true, workerData: {
      sab: this.sab,
      host: u.hostname,
      port: Number(u.port || 6379),
      password: decodeURIComponent(u.password || ''),
      db: u.pathname && u.pathname !== '/' ? Number(u.pathname.slice(1)) || 0 : 0,
      connectTimeoutMs
    } });

    Atomics.wait(this.i32, 1, 0, Math.max(connectTimeoutMs * 2, timeoutMs));
    const ready = Atomics.load(this.i32, 1);
    if (ready !== 1) {
      const msg = ready === -1
        ? Buffer.from(this.sab, HEADER_I32 * 4, PAYLOAD_CAP).toString('utf8', 0, Atomics.load(this.i32, 4))
        : `no connection within ${timeoutMs}ms`;
      try { void this.worker.terminate(); } catch { /* already gone */ }
      throw new Error(`RedisNonceStore: cannot reach ${url} — ${msg}`);
    }
  }

  _call(cmdArgs) {
    const cmd = encodeCommand(cmdArgs);
    if (cmd.length > PAYLOAD_CAP) throw new Error(`RedisNonceStore: command exceeds ${PAYLOAD_CAP} bytes`);
    const seq = Atomics.load(this.i32, 0) + 1;
    cmd.copy(this.payload, 0);
    Atomics.store(this.i32, 5, cmd.length);
    Atomics.store(this.i32, 0, seq);
    Atomics.notify(this.i32, 0);
    const prevDone = Atomics.load(this.i32, 2);
    const woken = Atomics.wait(this.i32, 2, prevDone, this.timeoutMs);
    if (woken === 'timed-out') {
      throw new Error(`RedisNonceStore: no reply within ${this.timeoutMs}ms for ${cmdArgs[0]} (fail-closed)`);
    }
    const status = Atomics.load(this.i32, 3);
    const text = this.payload.toString('utf8', 0, Atomics.load(this.i32, 4));
    if (status !== 0) throw new Error(`RedisNonceStore: ${cmdArgs[0]} failed — ${text}`);
    try { return JSON.parse(text); } catch { return text; }
  }

  claimIfAbsent(key) {
    const k = this.keyPrefix + key;
    const args = ['SET', k, '1'];
    if (this.ttlMs != null) args.push('PX', String(Math.floor(this.ttlMs)));
    args.push('NX');
    const reply = this._call(args);
    if (reply === 'OK') { this.claims++; this._bump(1); return true; }
    return false;
  }

  has(key) {
    const n = this._call(['EXISTS', this.keyPrefix + key]);
    return Number(n) > 0;
  }

  add(key) {
    const reply = this._call(['SET', this.keyPrefix + key, '1']);
    if (reply !== 'OK') throw new Error(`RedisNonceStore: SET rejected — ${JSON.stringify(reply)}`);
    this._bump(1);
  }

  size() {
    const v = this._call(['GET', this.counterKey]);
    return v == null ? 0 : Number(v);
  }

  _bump(delta) {
    try { this._call(['INCRBY', this.counterKey, String(delta)]); } catch { /* size is advisory */ }
  }

  async close({ graceMs = 2000 } = {}) {
    const done = new Promise((resolve) => this.worker.once('exit', resolve));
    Atomics.store(this.i32, 5, 0);
    Atomics.store(this.i32, 0, -1);
    Atomics.notify(this.i32, 0);
    const t = setTimeout(() => { void this.worker.terminate(); }, graceMs);
    try { await done; } finally { clearTimeout(t); }
  }
}
