import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, cp, symlink, appendFile, rm, readFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative, isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

test('client check mode detects tampered declarations without changing them',async()=>{
  const temporary=await mkdtemp(join(tmpdir(),'lomi-contract-check-'));
  const source=fileURLToPath(new URL('../',import.meta.url));
  const pkg=join(temporary,'packages/remote-contracts');
  try {
    await mkdir(pkg,{recursive:true});
    for(const file of ['scripts','src','package.json','package-lock.json','node_modules']) await symlink(join(source,file),join(pkg,file));
    // The generator uses its own script URL, so copy scripts rather than symlink.
    await rm(join(pkg,'scripts'));
    await cp(join(source,'scripts'),join(pkg,'scripts'),{recursive:true});
    await symlink(fileURLToPath(new URL('../../../contracts/',import.meta.url)),join(temporary,'contracts'));
    await cp(join(source,'generated'),join(pkg,'generated'),{recursive:true});
    const run=()=>spawnSync(process.execPath,[join(pkg,'scripts/generate.mjs'),'--check'],{encoding:'utf8'});
    assert.equal(run().status,0);
    const target=join(pkg,'generated/index.d.ts');
    await appendFile(target,'// deliberate tamper\n');
    const failed=run();
    assert.notEqual(failed.status,0);
    assert.match(failed.stderr,/generated client drift: index\.d\.ts/);
    assert.match(await readFile(target,'utf8'),/deliberate tamper/);
  } finally { await rm(temporary,{recursive:true,force:true}); }
});

test('root compatibility manifest hashes generated clients and canonical inputs',async()=>{
  const contracts=new URL('../../../contracts/',import.meta.url);
  const manifest=JSON.parse(await readFile(new URL('compatibility-manifest.json',contracts),'utf8'));
  assert.equal(manifest.manifestSelfHash,false);
  assert.equal(manifest.terminalProfile.qualified,false);
  assert.equal(manifest.pathBase,'repository');
  const repository=await realpath(fileURLToPath(new URL('../',contracts)));
  for(const [path,expected] of Object.entries(manifest.artifacts)) {
    assert.equal(isAbsolute(path),false,path);
    assert.equal(path.split('/').some(segment=>segment==='..'),false,path);
    const actualPath=await realpath(join(repository,path));
    const location=relative(repository,actualPath);
    assert.equal(isAbsolute(location)||location==='..'||location.startsWith('../'),false,path);
    const actual=createHash('sha256').update(await readFile(actualPath)).digest('hex');
    assert.equal(actual,expected,path);
  }
});
