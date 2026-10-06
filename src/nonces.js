import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export const NONCE_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}:[0-9a-f]{32}$/;

function sleepSync(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

export class InMemoryNonceStore {
  constructor() {
    this.seen = new Set();
    this.claims = 0;
  }

  // Atomic test-and-set. Within a single process this is indivisible because
  // the check and the add happen synchronously on one event-loop turn; no other
  // code can observe the state between them.
  claimIfAbsent(key) {
    if (this.seen.has(key)) return false;
    this.seen.add(key);
    this.claims++;
    return true;
  }

  has(key) {
    return this.seen.has(key);
  }

  add(key) {
    this.seen.add(key);
  }

  size() {
    return this.seen.size;
  }
}

// Durable, cross-process-safe nonce store built only on Node stdlib.
//
// Guarantees (precise — see docs/FORMAL_MODEL.md INV-03 and SECURITY.md):
//   - mutual exclusion across processes via an O_EXCL lockfile whose owner is
//     recorded (pid + hostname + acquisition time). Takeover of a stuck lock
//     is liveness-aware: on the same host a lock held by a LIVE process is
//     never stolen, so a slow fsync cannot cause double-accept; only locks
//     whose owner is provably dead (ESRCH) are taken over, after the stale
//     window. Locks from other hosts or legacy/unparseable locks fall back to
//     time-based takeover as a documented last resort (shared volumes should
//     run RedisNonceStore instead — see docs/NONCE_STORES.md).
//   - crash durability via write + fsync before the lock is released: a claim
//     that returned true survives a hard restart (fail-closed replay window)
//   - corruption tolerance: malformed or truncated trailing lines are skipped
//     and counted instead of crashing the verifier
//
// Explicit non-goals (see SECURITY.md): no network replication, no TTL/GC of
// old claims beyond compact(), no multi-file sharding.
export class FileNonceStore extends InMemoryNonceStore {
  constructor(filePath, { lockTimeoutMs = 5000, staleLockMs = 10_000 } = {}) {
    super();
    this.filePath = filePath;
    this.lockPath = `${filePath}.lock`;
    this.lockTimeoutMs = lockTimeoutMs;
    this.staleLockMs = staleLockMs;
    this.corruptLines = 0;
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    this._load();
  }

  _load() {
    if (!fs.existsSync(this.filePath)) return;
    const raw = fs.readFileSync(this.filePath, 'utf8');
    const lines = raw.split('\n');
    // Every persisted claim ends with '\n'; a final line lacking one is a
    // torn write from a crash mid-append and must not be trusted.
    if (lines[lines.length - 1] === '') {
      lines.pop();
    } else if (lines.length > 0 && lines[lines.length - 1] !== '') {
      this.corruptLines++;
      lines.pop();
    }
    for (const line of lines) {
      const key = line.trim();
      if (!key) continue;
      if (!NONCE_KEY_PATTERN.test(key)) {
        this.corruptLines++;
        continue;
      }
      this.seen.add(key);
    }
  }

  // Reads the lock owner record, if any. Returns null for legacy/empty or
  // unparseable lock files — those predate ownership records and are handled
  // by time-based takeover only.
  _readLockOwner() {
    let raw;
    try {
      raw = fs.readFileSync(this.lockPath, 'utf8');
    } catch {
      return null; // lock vanished between stat and read
    }
    try {
      const rec = JSON.parse(raw);
      if (rec && typeof rec === 'object' && Number.isFinite(rec.pid) && typeof rec.host === 'string') {
        return { pid: rec.pid, host: rec.host };
      }
    } catch {
      /* fall through */
    }
    return null;
  }

  // True when the pid belongs to a live process on this machine. process.kill
  // with signal 0 performs a permission check without signalling: ESRCH means
  // no such process (dead), EPERM means the process exists but is owned by
  // another user (alive), and success obviously means alive.
  _pidAlive(pid) {
    if (!Number.isInteger(pid) || pid <= 0) return false;
    try {
      process.kill(pid, 0);
      return true;
    } catch (err) {
      return err.code === 'EPERM';
    }
  }

  _acquireLock() {
    const deadline = Date.now() + this.lockTimeoutMs;
    const self = this;
    for (;;) {
      try {
        const fd = fs.openSync(this.lockPath, 'wx');
        // Record ownership immediately. A crash in the microseconds before
        // this write leaves an empty lock file, which the anonymous-lock path
        // below handles via the stale window.
        try {
          fs.writeSync(
            fd,
            JSON.stringify({ v: 1, pid: process.pid, host: os.hostname(), acquiredAt: Date.now() }) + '\n',
            null,
            'utf8'
          );
        } catch {
          /* lock file still functions as an O_EXCL mutex without the record */
        }
        return fd;
      } catch (err) {
        if (err.code !== 'EEXIST') throw err;
        const owner = self._readLockOwner();
        let age = Infinity;
        try {
          age = Date.now() - fs.statSync(this.lockPath).mtimeMs;
        } catch {
          continue; // lock vanished between stat and everything else
        }
        if (owner && owner.host === os.hostname()) {
          if (self._pidAlive(owner.pid)) {
            // Same-host live owner: NEVER take over, regardless of age. A
            // wedged-but-alive verifier keeps its mutual exclusion; we wait.
            if (Date.now() > deadline) {
              throw new Error(
                `FileNonceStore: ${this.lockPath} is held by live process ${owner.pid} ` +
                  `(waited ${this.lockTimeoutMs}ms) — refusing to steal a live lock`
              );
            }
            sleepSync(5);
            continue;
          }
          // Owner recorded but provably dead on this host: crash residue.
          if (age > this.staleLockMs) {
            try {
              fs.unlinkSync(this.lockPath);
            } catch {
              /* someone else reclaimed it first */
            }
            continue;
          }
        } else {
          // Foreign-host owner (shared volume), or anonymous/legacy lock:
          // liveness cannot be verified across hosts, so fall back to the
          // stale window as a documented last resort. Deployments that share
          // a volume between hosts should run RedisNonceStore instead
          // (docs/NONCE_STORES.md); there, FileNonceStore is not the safety
          // mechanism at all.
          if (age > this.staleLockMs) {
            try {
              fs.unlinkSync(this.lockPath);
            } catch {
              /* someone else reclaimed it first */
            }
            continue;
          }
        }
        if (Date.now() > deadline) {
          throw new Error(`FileNonceStore: could not acquire ${this.lockPath} within ${this.lockTimeoutMs}ms`);
        }
        sleepSync(5);
      }
    }
  }

  _releaseLock(fd) {
    fs.closeSync(fd);
    fs.unlinkSync(this.lockPath);
  }

  _appendDurably(key) {
    const fd = fs.openSync(this.filePath, 'a');
    try {
      fs.writeSync(fd, key + '\n', null, 'utf8');
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  // Atomic ACROSS processes: re-reads the log under the exclusive lock, so a
  // claim is decided against the freshest durable state, then appended+fsynced
  // before any other contender can enter.
  claimIfAbsent(key) {
    const fd = this._acquireLock();
    try {
      this.seen = new Set();
      this.corruptLines = 0;
      this._load();
      if (!NONCE_KEY_PATTERN.test(key)) {
        throw new TypeError(`FileNonceStore: refusing to persist malformed nonce key: ${JSON.stringify(key)}`);
      }
      if (this.seen.has(key)) return false;
      this._appendDurably(key);
      this.seen.add(key);
      this.claims++;
      return true;
    } finally {
      this._releaseLock(fd);
    }
  }

  // Rewrite the log as sorted unique keys through temp-file + atomic rename.
  compact() {
    const fd = this._acquireLock();
    try {
      this.seen = new Set();
      this.corruptLines = 0;
      this._load();
      const tmp = `${this.filePath}.tmp`;
      const tmpFd = fs.openSync(tmp, 'w');
      try {
        fs.writeSync(tmpFd, [...this.seen].sort().join('\n') + (this.seen.size ? '\n' : ''), null, 'utf8');
        fs.fsyncSync(tmpFd);
      } finally {
        fs.closeSync(tmpFd);
      }
      fs.renameSync(tmp, this.filePath);
    } finally {
      this._releaseLock(fd);
    }
  }
}
