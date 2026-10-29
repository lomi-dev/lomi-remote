// TEST SOURCE ONLY. Not run locally; future Windows namespace/admission required.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { buildReferences, extractRootLiterals, extractHelperTransitions, sha256, BASELINE_FILES, CANDIDATE_FILES, PREPARATION_FILES } from './reference-build.mjs';

const root = new URL('../../', import.meta.url);
const candidateRoot = new URL('staging/consumer-derivatives/', root);
const prepRoot = new URL('artifacts/consumer-derivatives-plan/bcf93985-5a17-463a-aa2e-2446fb413e93/', root);
const sourceRoot = new URL('tests/consumer-derivatives/', root);
const read = (base, name) => readFileSync(new URL(name, base));
const record = (base, names) => Object.fromEntries(names.map(name => [name, read(base, name)]));
function admittedFixture() {
  // All paths are fixed public fixture names. No .env, operator config, archive
  // extraction, network, executable invocation or current target source lookup.
  return {
    baselineReceipt: read(root, 'artifacts/channel-transport-runtime/fc66ad64-9dc2-4285-8895-72d4d1a436d8/runtime-proof.json'),
    baselineFiles: record(new URL('frozen-public/', prepRoot), BASELINE_FILES),
    candidateManifest: read(candidateRoot, 'candidate-source-sha256.json'),
    candidateFiles: record(candidateRoot, CANDIDATE_FILES),
    catalogContract: read(candidateRoot, 'catalog-contract.pending.json'),
    helperContract: read(candidateRoot, 'helper-seal.pending.json'),
    preparationManifest: read(prepRoot, 'preparation-source-sha256.json'),
    preparationFiles: record(new URL('qualification-source/', prepRoot), PREPARATION_FILES),
  };
}
function rootFixture() {
  const input = admittedFixture();
  return { sql: input.candidateFiles['operator-three-roots.candidate.sql'].toString('utf8'), pins: JSON.parse(input.catalogContract).roots };
}

test('source-chosen old/new transcripts preserve exact emitted root bytes and ordering', () => {
  const input = admittedFixture(); const built = buildReferences(input);
  assert.equal(built.status, 'PREPARED_NOT_EXECUTED');
  assert.equal(built.executionIncluded, false); assert.equal(built.pinsFilled, false);
  assert.equal(built.referenceOld.steps.filter(s => s.id.startsWith('migration:')).length, 24);
  assert.equal(built.referenceOld.steps.filter(s => s.id.startsWith('baseline-ops:')).length, 6);
  const steps = built.referenceNew.steps;
  const bootstrap = steps.findIndex(s => s.id === 'ownership-bootstrap:ONCE-BEFORE-SEAL');
  const groupIndex = steps.findIndex(s => s.kind === 'transaction-group');
  const group = steps[groupIndex];
  const helper = group.fragments.findIndex(s => s.id === 'reference-only:helper-owner:0');
  const literal = group.fragments.findIndex(s => s.id === 'reference-only:root-literal:0');
  assert.ok(bootstrap >= 0 && bootstrap < groupIndex && helper >= 0 && helper < literal);
  for (const s of group.fragments.filter(s => s.id.startsWith('reference-only:root-literal:'))) {
    assert.ok(input.candidateFiles['operator-three-roots.candidate.sql'].toString().includes(s.sql));
    assert.equal(sha256(s.sql), s.emittedSha256);
    assert.ok(s.sql.startsWith('CREATE OR REPLACE FUNCTION'));
  }
  assert.equal(built.sourceCorrelations.rootLiterals.length, 3);
  for (const item of built.sourceCorrelations.rootLiterals) {
    assert.equal(item.hashAdapter.version, 1);
    assert.match(item.hashAdapter.reason, /source correlation only/);
    assert.match(item.literalSha256, /^[0-9a-f]{64}$/);
  }
});

test('all transition fragments and global lock form one indivisible immutable same-session script', () => {
  const input = admittedFixture(); const built = buildReferences(input);
  const groups = built.referenceNew.steps.filter(step => step.kind === 'transaction-group');
  assert.equal(groups.length, 1);
  const [group] = groups;
  assert.equal(group.database, built.referenceNew.database);
  assert.equal(group.role, 'e2_owner');
  for (const flag of ['singleScript', 'sameSession', 'noInterleaving', 'onAnyErrorRollbackAndStop']) assert.equal(group[flag], true);
  assert.equal(group.fragments[0].sql, 'BEGIN;');
  assert.equal(group.fragments[1].id, 'reference-only:global-lock');
  assert.equal(group.fragments.at(-1).sql, 'COMMIT;');
  assert.equal(group.fragments.filter(f => f.id.startsWith('reference-only:body-owner:')).length, 1);
  assert.equal(group.fragments.filter(f => f.id.startsWith('reference-only:helper-owner:')).length, 2);
  assert.equal(group.fragments.filter(f => f.id.startsWith('reference-only:helper-acl:')).length, 3);
  assert.equal(group.fragments.filter(f => f.id.startsWith('reference-only:root-literal:')).length, 3);
  assert.equal(group.fragments.filter(f => f.id.startsWith('reference-only:root-acl:')).length, 2);
  assert.equal(group.sql, group.fragments.map(f => f.sql).join(group.fragmentSeparator));
  assert.equal(sha256(group.sql), group.emittedSha256);
  assert.ok(Object.isFrozen(group) && Object.isFrozen(group.fragments));
  for (const fragment of group.fragments) {
    assert.ok(Object.isFrozen(fragment) && Object.isFrozen(fragment.source));
    assert.equal(sha256(fragment.sql), fragment.emittedSha256);
    if (fragment.source.name) assert.ok(input.candidateFiles[fragment.source.name].toString().includes(fragment.sql));
  }
  assert.throws(() => { group.fragments[0].sql = 'COMMIT;'; }, TypeError);
  assert.throws(() => { group.fragments.reverse(); }, TypeError);
  const outside = built.referenceNew.steps.filter(step => step !== group);
  assert.ok(outside.every(step => !step.id.startsWith('reference-only:')));
  assert.ok(outside.every(step => step.sql !== 'BEGIN;' && step.sql !== 'COMMIT;'));
  for (const fragment of group.fragments) assert.ok(outside.every(step => step.id !== fragment.id));
  for (const fragment of group.fragments.filter(f => /:(?:body-owner|helper-owner|root-literal):/.test(f.id))) {
    assert.ok(outside.every(step => !step.sql.includes(fragment.sql)));
  }
  assert.equal(built.referenceOld.steps.filter(step => step.kind === 'transaction-group').length, 0);
});

test('missing literal root rejects', () => {
  const { sql, pins } = rootFixture();
  assert.throws(() => extractRootLiterals(sql.replace(' EXECUTE $literal1$', ' REMOVED $literal1$'), pins));
});
test('duplicate literal root rejects', () => {
  const { sql, pins } = rootFixture();
  assert.throws(() => extractRootLiterals(sql + '\n EXECUTE $literal0$duplicate$literal0$;', pins));
});
test('extra literal and arbitrary dynamic SQL reject', () => {
  const { sql, pins } = rootFixture();
  assert.throws(() => extractRootLiterals(sql + '\n EXECUTE $literal3$SELECT 1$literal3$;', pins));
  assert.throws(() => extractRootLiterals(sql + "\n EXECUTE 'arbitrary';", pins));
});
test('wrong root and unauthorized prefix whitespace reject', () => {
  const { sql, pins } = rootFixture();
  assert.throws(() => extractRootLiterals(sql.replace('CREATE OR REPLACE FUNCTION public.lomi_consumer_inventory(', 'CREATE OR REPLACE FUNCTION public.other('), pins));
  assert.throws(() => extractRootLiterals(sql.replace('$literal0$CREATE OR REPLACE', '$literal0$ CREATE OR REPLACE'), pins));
});
test('altered body or manifest source digest rejects', () => {
  const { sql, pins } = rootFixture();
  assert.throws(() => extractRootLiterals(sql.replace("'inventory unavailable'", "'altered inventory'"), pins));
  const changed = structuredClone(pins); changed[0].new_source_sha256 = '0'.repeat(64);
  assert.throws(() => extractRootLiterals(sql, changed));
});
test('helper transition missing duplicate extra or wrong owner rejects', () => {
  const sql = read(candidateRoot, 'operator-seal-auth-helpers.candidate.sql').toString();
  assert.equal(extractHelperTransitions(sql).owners.length, 2);
  assert.throws(() => extractHelperTransitions(sql.replace('ALTER FUNCTION public.lomi_consumer_principal_live_v2(', 'REMOVED FUNCTION public.lomi_consumer_principal_live_v2(')));
  const statement = extractHelperTransitions(sql).owners[0];
  assert.throws(() => extractHelperTransitions(sql + '\n ' + statement));
  assert.throws(() => extractHelperTransitions(sql + '\n GRANT CREATE ON SCHEMA public TO lomi_migrator;'));
  assert.throws(() => extractHelperTransitions(sql + '\nGRANT lomi_consumer_auth_body_owner TO fixture_unexpected;'));
  assert.throws(() => extractHelperTransitions(sql.replace(statement, statement.replace('OWNER TO lomi_consumer_auth_body_owner', 'OWNER TO lomi_migrator'))));
});
test('whole-file admission rejects operator body change before extraction', () => {
  const input = admittedFixture();
  input.candidateFiles['operator-three-roots.candidate.sql'] = Buffer.concat([input.candidateFiles['operator-three-roots.candidate.sql'], Buffer.from('\n-- changed')]);
  assert.throws(() => buildReferences(input), /source hash mismatch/);
});
test('old snapshot mismatch and frozen migration mismatch reject', () => {
  const input = admittedFixture();
  input.candidateFiles['lomi_consumer_inventory.old-source.sql'] = Buffer.from('wrong snapshot');
  assert.throws(() => buildReferences(input), /source hash mismatch/);
  const other = admittedFixture();
  other.baselineFiles['prisma/migrations/202610190006_consumer_inventory/migration.sql'] = Buffer.from('wrong baseline');
  assert.throws(() => buildReferences(other), /source hash mismatch/);
});
test('missing or extra per-file input and target catalog reject', () => {
  const missing = admittedFixture(); delete missing.candidateFiles['authority-core.candidate.sql'];
  assert.throws(() => buildReferences(missing), /named input/);
  const extra = admittedFixture(); extra.baselineFiles['operator-config.json'] = Buffer.from('{}');
  assert.throws(() => buildReferences(extra), /named input/);
  const target = admittedFixture(); target.targetCatalog = { arbitrary: true };
  assert.throws(() => buildReferences(target), /named input/);
});
test('NULL operators are neither emitted nor filled or executed', () => {
  const input = admittedFixture(); const oldCatalog = Buffer.from(input.catalogContract); const oldHelper = Buffer.from(input.helperContract);
  const built = buildReferences(input);
  for (const step of [...built.referenceOld.steps, ...built.referenceNew.steps]) {
    assert.ok(!step.sql.includes('DO $operator$'));
    assert.ok(!step.sql.includes('DO $seal_helpers$'));
    assert.ok(!step.sql.includes('$pins$'));
    assert.ok(!step.sql.includes('$helper_pins$'));
  }
  assert.deepEqual(input.catalogContract, oldCatalog); assert.deepEqual(input.helperContract, oldHelper);
  assert.equal(built.catalogInputAccepted, false);
});
test('builder has only standard-library crypto and no process/filesystem/SQL executor', () => {
  const source = read(sourceRoot, 'reference-build.mjs').toString();
  assert.deepEqual([...source.matchAll(/^import .* from '([^']+)';$/gm)].map(m => m[1]), ['node:crypto']);
  assert.ok(!/\b(?:eval|execSync|spawn|readFile|writeFile|connect)\s*\(/.test(source));
});
