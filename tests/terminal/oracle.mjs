// Development oracle only. The Rust candidate never starts Node.
import xterm from '@xterm/headless';
import { spawnSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
const root = fileURLToPath(new URL('../..', import.meta.url));
const run = spawnSync('cargo', ['run', '--locked', '--quiet', '-p', 'lomi-terminal-spike', '--', 'fixtures'], { cwd: root, encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
if (run.status !== 0) { process.stderr.write(run.stderr); process.exit(run.status ?? 2); }
const input = JSON.parse(run.stdout);
const write = (t, bytes) => new Promise(resolve => t.write(Uint8Array.from(bytes), resolve));
const terminal = (rows, cols) => new xterm.Terminal({rows,cols,scrollback:input.scrollback,allowProposedApi:true});
function buffer(b, cols) {
  const lines = [];
  for (let y = 0; y < b.length; y++) {
    const line = b.getLine(y), cells = [];
    for (let x = 0; x < cols; x++) {
      const c = line.getCell(x);
      cells.push([c.getChars(),c.getWidth(),c.getFgColorMode(),c.getFgColor(),c.getBgColorMode(),c.getBgColor(),c.isBold(),c.isItalic(),c.isUnderline(),c.isInverse()]);
    }
    lines.push({wrapped:line.isWrapped,cells});
  }
  return {cursorX:b.cursorX,cursorY:b.cursorY,baseY:b.baseY,lines};
}
function view(t) {
  return {rows:t.rows,cols:t.cols,active:t.buffer.active.type,normal:buffer(t.buffer.normal,t.cols),
    // A never-created alternate buffer and an empty alternate buffer are equivalent.
    alternate:buffer(t.buffer.alternate,t.cols),modes:t.modes};
}
const cases = [];
for (const {fixture:f,restore,size} of input.cases) {
  const reference=terminal(input.rows,input.cols), resumed=terminal(size[0],size[1]);
  const titleA=[],titleB=[];
  reference.onTitleChange(t=>titleA.push(t)); resumed.onTitleChange(t=>titleB.push(t));
  await write(reference,f.prefix);
  if(f.resize_before) reference.resize(f.resize_before[1],f.resize_before[0]);
  await write(resumed,restore);
  const before=JSON.stringify(view(reference))===JSON.stringify(view(resumed));
  // Title state is compared after snapshot and continuation, not event history.
  if(f.resize_live) {reference.resize(f.resize_live[1],f.resize_live[0]);resumed.resize(f.resize_live[1],f.resize_live[0]);}
  await write(reference,f.live); await write(resumed,f.live);
  const state=JSON.stringify(view(reference))===JSON.stringify(view(resumed));
  const title=(titleA.at(-1)??'')===(titleB.at(-1)??'');
  const passed=before&&state&&title;
  cases.push({id:f.id,passed,status:passed?'passed':'failed',checkpointEquivalent:before,continuationEquivalent:state,titleEquivalent:title});
  reference.dispose();resumed.dispose();
}
// Test-only adapter based on lomi/src/terminal-input-source.ts at
// 2cef452c39eb8b455c8d2ae1251310dc870c50bb. The exact xterm private API is
// intentionally checked: parser replies must be dropped while user input flows.
function classify(t, listener) {
  const service=t._core?.coreService;
  assert.equal(typeof service?.triggerDataEvent,'function');
  const original=service.triggerDataEvent; let human=false;
  function classified(data, wasUserInput=false) {
    const previous=human; human=wasUserInput;
    try { original.call(this,data,wasUserInput); } finally { human=previous; }
  }
  service.triggerDataEvent=classified;
  const subscription=t.onData(data=>listener(data,human));
  return ()=>{subscription.dispose(); if(service.triggerDataEvent===classified)service.triggerDataEvent=original;};
}
let rawReplies=0,forwardedReplies=0,humanInputs=0;
for (let i=0;i<2;i++) {
  const observer=terminal(input.rows,input.cols),received=[];
  const dispose=classify(observer,(data,human)=>{
    if(human){humanInputs++;received.push(data);} else {rawReplies++;}
  });
  await write(observer,[...Buffer.from('\x1b[6n\x1b[c')]);
  assert.equal(rawReplies,(i+1)*2,'each observer must actually generate both parser replies');
  observer._core.coreService.triggerDataEvent('synthetic key',true);
  assert.deepEqual(received,['synthetic key'],'user input must remain eligible for the control owner');
  forwardedReplies+=received.filter(data=>data!=='synthetic key').length;
  dispose(); observer._core.coreService.triggerDataEvent('after dispose',true);
  assert.deepEqual(received,['synthetic key']);
  observer.dispose();
}
assert.equal(humanInputs,2);
assert.equal(forwardedReplies,0);
const report={stage:'S0.1',candidate:input.candidate,profile:input.profile,oracle:'@xterm/headless=6.0.0',qualified:false,
  cases,replyFilterProbe:{observers:2,rawReplies,forwardedReplies,humanInputs,productionHostOwnership:'not qualified'},
  missingQualification:['full hidden state equality','OSC 52 side-effect isolation','real CLI fixtures','multi-hour soak','production host DSR/DA ownership'],
  decision:'rejected; regression success only asserts known counterexamples'};
console.log(JSON.stringify(report,null,2));
if(process.argv.includes('--regression')) {
  const expectedPasses = new Set(['normal_ascii','unicode_cells','colors_modes']);
  assert.equal(cases.length,13);
  for(const c of cases) assert.equal(c.passed,expectedPasses.has(c.id),c.id);
} else if(process.argv.includes('--qualify')) process.exit(report.qualified?0:1);
else process.exit(2);
