import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export function createTempModule(source, filename = 'module.mjs') {
  const directory = mkdtempSync(join(tmpdir(), 'lomi-authority-test-'));
  const path = join(directory, filename);
  writeFileSync(path, source);
  return {
    url: pathToFileURL(path).href,
    cleanup() {
      rmSync(directory, { recursive: true, force: true });
    },
  };
}
