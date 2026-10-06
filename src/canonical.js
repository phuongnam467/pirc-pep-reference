export class CanonicalError extends Error {
  constructor(message) {
    super(message);
    this.name = 'CanonicalError';
  }
}

// The envelope's own depth is 2; this cap is a generous resource guard so a
// hostile document can never drive unbounded recursion before schema
// validation has its turn.
const MAX_DEPTH = 64;

export function canonicalize(value, depth = 0) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalError(`canonicalization depth exceeded ${MAX_DEPTH}`);
  }
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  const t = typeof value;
  if (t === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new CanonicalError(`non-canonical number: ${value}`);
    }
    return String(value);
  }
  if (t === 'string') return JSON.stringify(value.normalize('NFC'));
  if (Array.isArray(value)) return '[' + value.map((v) => canonicalize(v, depth + 1)).join(',') + ']';
  if (t === 'object') {
    // Hardening: two distinct raw keys can normalize (NFC) to the same string
    // ("e\u0301" and "\u00e9" both become "é"). Sorting happens on raw keys,
    // serialization on normalized ones, so such collisions would silently
    // merge distinct fields into one canonical entry. Reject them instead.
    const seen = new Set();
    for (const raw of Object.keys(value)) {
      const norm = raw.normalize('NFC');
      if (seen.has(norm)) {
        throw new CanonicalError(`normalized key collision under NFC: ${JSON.stringify(raw)}`);
      }
      seen.add(norm);
    }
    // Profile v1.1: sort the NFC FORMS, not the raw keys. Sorting raw keys
    // while serializing their NFC forms made canonicalization deterministic
    // per value but NOT a fixed point: canon(parse(canon(x))) could reorder
    // keys whenever normalization changed a key's sort position, silently
    // breaking isCanonical() on documents the protocol itself produced.
    // With NFC-form sorting, the emitted key text IS the sort key, so the
    // canonical form is idempotent under parse -> canonicalize. (Found by
    // scripts/fuzz.mjs cross-checking the property suite; see CHANGELOG
    // v0.15.0.)
    const entries = Object.keys(value)
      .map((raw) => [raw, raw.normalize('NFC')])
      .sort((a, b) => (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
    return '{' + entries.map(([raw, norm]) => JSON.stringify(norm) + ':' + canonicalize(value[raw], depth + 1)).join(',') + '}';
  }
  throw new CanonicalError(`unsupported type: ${t}`);
}

export function isCanonical(text) {
  try {
    return canonicalize(JSON.parse(text)) === text;
  } catch {
    return false;
  }
}
