// Runtime adapter only. The pure constructor remains the sole SQL selector.
import { readFileSync, writeFileSync } from 'node:fs';
import { buildReferences } from './reference-build.mjs';

if (process.argv.length !== 4) throw new Error('expected owned input/output paths');
const encoded = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const decode = value => typeof value === 'string'
  ? Buffer.from(value, 'base64')
  : Object.fromEntries(Object.entries(value).map(([name, data]) => [name, decode(data)]));
writeFileSync(process.argv[3], JSON.stringify(buildReferences(decode(encoded))), { flag: 'wx', mode: 0o600 });
