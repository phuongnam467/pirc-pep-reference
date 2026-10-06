import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSnapshot } from '../app/server.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const out = resolve(here, '../app/snapshot.json');

const snapshot = buildSnapshot(Date.now());
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(snapshot, null, 2) + '\n', 'utf8');
console.log(`static snapshot written to app/snapshot.json (generated ${new Date().toISOString()})`);
