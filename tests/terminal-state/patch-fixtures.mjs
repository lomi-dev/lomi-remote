import { snapshot, blank } from './fixtures.mjs';
export function fixture() {
  const old = snapshot({ sessionEpoch: 'abcdefab-cdef-4abc-8def-abcdefabcdef' });
  const plan = b => ({ baseY: 0, lineCount: 3, previousBaseY: 0, previousLineCount: 3, retainedStart: 0, retainedLines: 3, cursor: b.cursor, savedCursor: b.savedCursor, rows: [] });
  const { active, modes, title, cursorStyle, colors } = old;
  const patch = { profile: old.profile, version: 1, format: 'grid-patch-v1', sessionEpoch: old.sessionEpoch, previousSequence: '0', sequence: '1', outputOffset: '8', rows: 3, cols: 8, update: { kind: 'sparse', metadata: structuredClone({ active, modes, title, cursorStyle, colors }), normal: plan(old.normal), alternate: plan(old.alternate) } };
  patch.update.normal.rows = [{ index: 0, wrapped: false, cells: [{ index: 0, repeat: 1, cell: blank({ text: '界', width: 2 }) }, { index: 1, repeat: 1, cell: blank({ width: 0 }) }, { index: 2, repeat: 2, cell: blank({ text: 'é', flags: ['bold'] }) }] }];
  return { old, patch };
}
export function negativeCases() {
  const mutations = [
    p => p.extra = true, p => p.format = 'unknown', p => p.sessionEpoch = '22222222-2222-4222-8222-222222222222', p => p.sequence = '2', p => p.previousSequence = '18446744073709551615', p => p.sequence = 1, p => p.sequence = '1\n', p => p.previousSequence = '0\n', p => p.outputOffset = '-1', p => p.rows = 2,
    p => p.update.normal.previousLineCount = 4, p => p.update.normal.retainedStart = 4, p => p.update.normal.retainedLines = 4, p => p.update.normal.lineCount = 999999, p => p.update.normal.baseY = 4097,
    p => p.update.normal.rows.push(structuredClone(p.update.normal.rows[0])), p => p.update.normal.rows[0].cells[0].repeat = 0, p => p.update.normal.rows[0].cells[0].repeat = 999999, p => p.update.normal.rows[0].cells[1].index = 0, p => p.update.normal.rows[0].cells[1].cell.width = 1, p => p.update.normal.rows[0].cells[2].cell.text = '\x1b', p => p.update.normal.rows[0].cells[2].extra = 1,
    p => { p.update.normal.retainedLines = 2; }, p => p.update.metadata.extra = true, p => p.update.metadata.colors[268] = { r: 1, g: 2, b: 3 }, p => p.update.metadata.title = 'x'.repeat(8 * 1024 * 1024 + 1),
  ];
  const { old, patch } = fixture();
  return { old, patches: mutations.map(mutate => { const p = structuredClone(patch); mutate(p); return p; }) };
}
export function expansionCase() {
  const old = snapshot({ cols: 512, rows: 32, sessionEpoch: fixture().old.sessionEpoch });
  const { patch } = fixture();
  patch.rows = 32;
  patch.cols = 512;
  const cell = blank({ text: 'x', hyperlink: { id: 'i'.repeat(512), uri: 'https://example.invalid/' + 'x'.repeat(4000) } });
  const buffer = () => ({ baseY: 0, lineCount: 32, previousBaseY: 0, previousLineCount: 32, retainedStart: 0, retainedLines: 32, cursor: { x: 0, y: 0 }, savedCursor: { x: 0, y: 0 }, rows: Array.from({ length: 32 }, (_, index) => ({ index, wrapped: false, cells: [{ index: 0, repeat: 512, cell }] })) });
  patch.update.normal = buffer();
  patch.update.alternate = buffer();
  return { old, patch };
}

// Legacy snapshots accept opaque text epochs. Match each legacy baseline to its
// bad patch so only the new production epoch syntax can reject these cases.
export function epochCases() {
  const epoch = fixture().old.sessionEpoch;
  return [epoch.toUpperCase(), epoch.replaceAll('-', ''), 'urn:uuid:' + epoch,
    '00000000-0000-0000-0000-000000000000', '{' + epoch + '}'].map(sessionEpoch => {
      const {old,patch}=fixture();old.sessionEpoch=sessionEpoch;patch.sessionEpoch=sessionEpoch;
      return {old,patch};
    });
}
