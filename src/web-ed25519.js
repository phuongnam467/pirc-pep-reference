// Pure-JS Ed25519 verification (RFC 8032) + SHA-512 — browser-safe L0 primitive.
//
// WHY THIS EXISTS: the public gateway verifies documents entirely inside the
// visitor's browser, so the document never travels to any server. Node's
// crypto module is unavailable there, and adding a dependency would break the
// repository's zero-runtime-dependencies policy — so this file implements the
// minimum cryptography needed to CHECK signatures (never to create them).
//
// Design notes:
// - Verify-only. There is no signing path here by construction; issuers keep
//   using src/keys.js (Node crypto / RFC 8032 implementations).
// - All magic constants are DERIVED, not transcribed: SHA-512's H/K tables are
//   computed from fractional parts of square/cube roots of the first primes,
//   and Ed25519's curve parameters follow from p = 2^255-19 alone. Fewer
//   memorized hex strings means fewer places for silent transcription bugs;
//   the test suite cross-checks every operation against node:crypto.
// - Strict decoding: signatures with S >= L are rejected (canonical S), and
//   point decompression failures are hard rejections — malleability has no
//   room here.

// ---------------------------------------------------------------------------
// small big-int helpers
// ---------------------------------------------------------------------------

const MASK64 = (1n << 64n) - 1n;

function bitLength(n) {
  let len = 0;
  while (n > 0n) {
    n >>= 1n;
    len++;
  }
  return len;
}

/** Integer square root via Newton's method (exact for n >= 0). */
function isqrt(n) {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 2) + 1);
  for (;;) {
    const y = (x + n / x) >> 1n;
    if (y >= x) return x;
    x = y;
  }
}

/** Integer cube root via Newton's method (exact for n >= 0). */
function icbrt(n) {
  if (n < 2n) return n;
  let x = 1n << BigInt(Math.ceil(bitLength(n) / 3) + 1);
  for (;;) {
    const y = (2n * x + n / (x * x)) / 3n;
    if (y >= x) return x;
    x = y;
  }
}

function firstNPrimes(n) {
  const primes = [];
  let candidate = 2;
  while (primes.length < n) {
    let isPrime = true;
    for (const p of primes) {
      if (p * p > candidate) break;
      if (candidate % p === 0) {
        isPrime = false;
        break;
      }
    }
    if (isPrime) primes.push(candidate);
    candidate++;
  }
  return primes;
}

// floor(frac(sqrt(prime)) * 2^64): shift left by 128 bits, take integer sqrt,
// subtract the whole part shifted up — yields exactly the 64 fraction bits.
function fracSqrt64(prime) {
  const shifted = BigInt(prime) << 128n;
  const root = isqrt(shifted);
  return root & MASK64;
}

function fracCbrt64(prime) {
  const shifted = BigInt(prime) << 192n;
  const root = icbrt(shifted);
  return root & MASK64;
}

// ---------------------------------------------------------------------------
// SHA-512
// ---------------------------------------------------------------------------

const PRIMES_80 = firstNPrimes(80);
const SHA512_H = firstNPrimes(8).map(fracSqrt64);
const SHA512_K = PRIMES_80.map(fracCbrt64);

function rotr64(x, n) {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK64;
}
function shr64(x, n) {
  return x >> BigInt(n);
}

export function sha512(message) {
  const msgLen = message.length;
  const bitLenHi = Math.floor((msgLen / 0x20000000) | 0); // bits/2^32, fits JS number
  const bitLenLo = (msgLen << 3) >>> 0;

  // padding: message || 0x80 || zeros || 128-bit length
  const paddedLen = msgLen + 1 + 16 <= 128 ? 128 : (Math.floor((msgLen + 17) / 128) + 1) * 128;
  const block = new Uint8Array(paddedLen);
  block.set(message);
  block[msgLen] = 0x80;
  const dv = new DataView(block.buffer);
  dv.setUint32(paddedLen - 16, bitLenHi);
  dv.setUint32(paddedLen - 8, 0);
  dv.setUint32(paddedLen - 4, bitLenLo >>> 0);

  let h0 = SHA512_H[0], h1 = SHA512_H[1], h2 = SHA512_H[2], h3 = SHA512_H[3];
  let h4 = SHA512_H[4], h5 = SHA512_H[5], h6 = SHA512_H[6], h7 = SHA512_H[7];

  const w = new Array(80);
  for (let off = 0; off < paddedLen; off += 128) {
    for (let i = 0; i < 16; i++) {
      w[i] = dv.getBigUint64(off + i * 8);
    }
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ shr64(w[i - 15], 7);
      const s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ shr64(w[i - 2], 6);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & MASK64;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA512_K[i] + w[i]) & MASK64;
      const S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & MASK64;
      h = g; g = f; f = e; e = (d + t1) & MASK64;
      d = c; c = b; b = a; a = (t1 + t2) & MASK64;
    }
    h0 = (h0 + a) & MASK64; h1 = (h1 + b) & MASK64; h2 = (h2 + c) & MASK64; h3 = (h3 + d) & MASK64;
    h4 = (h4 + e) & MASK64; h5 = (h5 + f) & MASK64; h6 = (h6 + g) & MASK64; h7 = (h7 + h) & MASK64;
  }

  const out = new Uint8Array(64);
  const odv = new DataView(out.buffer);
  odv.setBigUint64(0, h0); odv.setBigUint64(8, h1); odv.setBigUint64(16, h2); odv.setBigUint64(24, h3);
  odv.setBigUint64(32, h4); odv.setBigUint64(40, h5); odv.setBigUint64(48, h6); odv.setBigUint64(56, h7);
  return out;
}

// ---------------------------------------------------------------------------
// Ed25519 curve arithmetic (twisted Edwards, a = -1, extended coordinates)
// ---------------------------------------------------------------------------

const P = (1n << 255n) - 19n;

function modInv(a, m) {
  // extended Euclid; assumes gcd(a, m) === 1
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % m) + m) % m;
}

// d = -121665/121666 mod p — derived, never transcribed.
const D = ((((-121665n) % P) + P) * modInv(121666n, P)) % P;
const TWO_D = (2n * D) % P;
// L: group order of the base point.
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
// SQRT_M1 = 2^((p-1)/4) mod p — the standard square root of -1 on this field.
const SQRT_M1 = modPow(2n, (P - 1n) / 4n, P);

function modPow(base, exp, m) {
  let result = 1n;
  let b = base % m;
  while (exp > 0n) {
    if (exp & 1n) result = (result * b) % m;
    b = (b * b) % m;
    exp >>= 1n;
  }
  return result;
}

// Base point: By = 4/5 mod p, Bx recovered with an even sign bit (RFC 8032).
const BASE_Y = (4n * modInv(5n, P)) % P;

/**
 * Recover x from y and the low-sign bit. Returns null when the encoding is
 * not on the curve — callers MUST reject.
 */
function recoverX(y, sign) {
  if (y >= P) return null;
  const y2 = (y * y) % P;
  const u = (y2 - 1n + P) % P;
  const v = (D * y2 + 1n) % P; // never 0 mod p: d is a non-square, y^2 is a square
  const x2 = (u * modInv(v, P)) % P;
  // p ≡ 5 (mod 8): candidate root via the (p+3)/8 exponent, corrected by √-1.
  let x = modPow(x2, (P + 3n) / 8n, P);
  if ((x * x - x2) % P !== 0n) {
    x = (x * SQRT_M1) % P;
    if ((x * x - x2) % P !== 0n) return null;
  }
  if ((x & 1n) !== BigInt(sign)) x = (P - x) % P;
  return x;
}

const BASE_X = recoverX(BASE_Y, 0);
if (BASE_X === null) throw new Error('web-ed25519: base point derivation failed');

// Point = [X, Y, Z, T] with x = X/Z, y = Y/Z, xy = T/Z.
const IDENTITY = [0n, 1n, 1n, 0n];

function ptAdd(p1, p2) {
  const [x1, y1, z1, t1] = p1;
  const [x2, y2, z2, t2] = p2;
  const a = ((y1 - x1) * (y2 - x2)) % P;
  const b = ((y1 + x1) * (y2 + x2)) % P;
  const c = (t1 * t2 * TWO_D) % P;
  const dd = (z1 * z2 * 2n) % P;
  const e = b - a;
  const f = dd - c;
  const g = dd + c;
  const h = b + a;
  return [(e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P];
}

function ptEqual(p1, p2) {
  const [x1, y1, z1] = p1;
  const [x2, y2, z2] = p2;
  return (x1 * z2 - x2 * z1) % P === 0n && (y1 * z2 - y2 * z1) % P === 0n;
}

function ptMul(k, point) {
  let acc = IDENTITY;
  let q = point;
  let n = k;
  while (n > 0n) {
    if (n & 1n) acc = ptAdd(acc, q);
    q = ptAdd(q, q);
    n >>= 1n;
  }
  return acc;
}

function bytesToLeInt(bytes) {
  let out = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    out = (out << 8n) | BigInt(bytes[i]);
  }
  return out;
}

function decompressPoint(bytes) {
  if (bytes.length !== 32) return null;
  const sign = bytes[31] >> 7;
  const yBytes = bytes.slice();
  yBytes[31] &= 0x7f;
  const y = bytesToLeInt(yBytes);
  const x = recoverX(y, sign);
  if (x === null) return null;
  return [x, y, 1n, (x * y) % P];
}

/**
 * RFC 8032 Ed25519 signature verification. Returns true only when every
 * decode step succeeds AND the group equation [S]B = R + [k]A holds with
 * canonical S < L.
 *
 * @param {Uint8Array} publicKey  32-byte compressed public key
 * @param {Uint8Array} message    raw signed bytes
 * @param {Uint8Array} signature  64-byte R||S
 */
export function ed25519Verify(publicKey, message, signature) {
  if (!(publicKey instanceof Uint8Array) || !(message instanceof Uint8Array) || !(signature instanceof Uint8Array)) {
    throw new TypeError('ed25519Verify expects Uint8Array arguments');
  }
  if (publicKey.length !== 32 || signature.length !== 64) return false;

  const aPoint = decompressPoint(publicKey);
  if (aPoint === null) return false;
  const rPoint = decompressPoint(signature.slice(0, 32));
  if (rPoint === null) return false;

  const s = bytesToLeInt(signature.slice(32));
  if (s >= L) return false;

  const hInput = new Uint8Array(32 + publicKey.length + message.length);
  hInput.set(signature.slice(0, 32), 0);
  hInput.set(publicKey, 32);
  hInput.set(message, 32 + publicKey.length);
  const k = bytesToLeInt(sha512(hInput));

  return ptEqual(ptMul(s, [BASE_X, BASE_Y, 1n, (BASE_X * BASE_Y) % P]), ptAdd(rPoint, ptMul(k, aPoint)));
}
