'use strict';
// Synthetic protocol fixture only. No authentication or credential operations.
const fs = require('node:fs');
const modes = new Set(['valid', 'malformed', 'trailing', 'cancel-writer', 'eof-alive']);
const mode = process.argv[2];
if (process.argv.length !== 3 || !modes.has(mode)) process.exit(64);
const markers = [
  ['setup-runtime', 59], ['principal-runtime', 78], ['scalar-invoker', 110],
  ['scalar-wronghash', 110], ['scalar-repeat', 110], ['assertion-root', 147],
  ['assertion-wronghash', 147], ['assertion-repeat', 147], ['recipient-root', 147],
  ['typed-inventory', 187], ['typed-wronghash', 187], ['typed-repeat', 187], ['rollback', 198],
];
const protocol = Buffer.from(markers.map(([id, line]) =>
  `psql:positive-auth.sql:${line}: NOTICE:  positive-auth:${id}:PASS\n`).join(''), 'ascii');
// This known synthetic input is never copied into output evidence/receipts.
const canary = Buffer.from('PRIVATE_PIPE_PROBE_SYNTHETIC_CANARY_8A19\n', 'ascii');
if (mode === 'eof-alive') {
  fs.closeSync(1);
  fs.closeSync(2);
  setTimeout(() => {}, 30000);
} else if (mode === 'cancel-writer') {
  let index = 0;
  const timer = setInterval(() => {
    if (index < protocol.length) {
      process.stderr.write(protocol.subarray(index, ++index));
    } else {
      clearInterval(timer);
    }
  }, 10);
  setTimeout(() => {}, 30000);
} else {
  const payload = mode === 'valid' ? protocol : mode === 'malformed' ? canary :
    Buffer.concat([protocol, canary]);
  process.stderr.write(payload, () => { process.exitCode = 0; });
}
