// PREPARED_NOT_EXECUTED. Pure source constructor; no filesystem/process/SQL API.
import { createHash } from 'node:crypto';

export const ADMISSION_HASHES = Object.freeze({
  baselineReceipt: '282bf110f833225d1d3848f6d8e9e3d33c0c1b904b049ad025d2100b0ea7d0d9',
  baselineArchive: 'a2c82079ec12250dbfcd9d33fa9d3af10235a85ff5468ef940050cd90f83d668',
  candidateManifest: '2f932457ab6935a3803596b103162cfdc60654f8d1b1d01481ceb89b17703a60',
  preparationManifest: '8ff761e792ad74fffa6892807caf5bab32b5d7aa3b2e644302397cbd945c8f51',
  catalogContract: '73060abdf88539f315e1b6bdf252c6db7380fb6e4e005a84805f6d7898d7bb74',
  helperContract: '331ae9af4e930618f0be87adbcb5a5d92d45712bedc40de8223eaeb8ab797f2f',
});

const migrations = [
  '20260926193514_init', '20260926195341_github_login_profile',
  '20260926201532_auth_query_indexes_and_session_status_guard',
  '20260926202500_session_insert_guard_only', '202609270001_desktop_browser_login',
  '202609300001_remote_auth_foundation', '202609300002_remote_live_control',
  '202609300003_remote_live_retention', '202609300004_remote_workspaces',
  '202610010001_mobile_consumers', '202610120001_push_notifications',
  '202610120002_push_project_throttle', '202610140001_terminal_push_notifications',
  '202610190001_remote_enrollment_foundation', '202610190002_host_credentials',
  '202610190003_finalized_host_identity', '202610190004_consumer_authority',
  '202610190005_host_runtime', '202610190006_consumer_inventory',
  '202610190007_pairing_proposals', '202610190008_pairing_decisions',
  '202610190009_pairing_peer_reads_and_grant_revocation',
  '202610190010_channel_admissions', '202610190011_channel_transport',
].map(name => `prisma/migrations/${name}/migration.sql`);
const ops = ['database-permissions.sql', 'remote-database-permissions.sql', 'push-database-permissions.sql'].map(name => `ops/${name}`);
export const BASELINE_FILES = Object.freeze([...migrations, ...ops, 'test/run_host_credentials_runtime.py']);
export const CANDIDATE_FILES = Object.freeze([
  '012-derivative-authority.candidate.sql', 'APPROVAL_FLOW_CONTRACT.md', 'CONTRACT.md',
  'SEALING_AND_PLANS.md', 'approval-intent.candidate.sql', 'authority-core.candidate.sql',
  'build_candidate.py', 'lomi_consumer_assertion_recheck.old-source.sql',
  'lomi_consumer_inventory.old-source.sql', 'lomi_consumer_recipient_recheck.old-source.sql',
  'operator-seal-auth-helpers.candidate.sql', 'operator-three-roots.candidate.sql',
  'typed-entrypoints.candidate.sql', 'validate_candidate.py',
]);
export const PREPARATION_FILES = Object.freeze([
  'prepare.py', 'validate.py', 'inputs.lock.json', 'acceptance.json', 'fixture-ops.sql',
  'fixture-ownership-bootstrap.sql', 'catalog-discovery.sql', 'README.md',
]);
const ROOTS = Object.freeze([
  { name: 'lomi_consumer_inventory', signature: 'public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)', migration: migrations[18] },
  { name: 'lomi_consumer_assertion_recheck', signature: 'public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)', migration: migrations[19] },
  { name: 'lomi_consumer_recipient_recheck', signature: 'public.lomi_consumer_recipient_recheck(uuid,uuid)', migration: migrations[20] },
]);
const HELPERS = Object.freeze([
  'public.lomi_consumer_principal_live_v2(public.consumer_authorization)',
  'public.lomi_consumer_scalar_recheck_v2(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
]);
const BODY_OWNER = 'lomi_consumer_auth_body_owner';
const CREATE_ROLE = `CREATE ROLE ${BODY_OWNER} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;`;
const REVOKE_HELPERS = `REVOKE ALL ON FUNCTION ${HELPERS.join(',')}\n  FROM PUBLIC,lomi_migrator,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner,lomi_remote_pairing_write_owner,lomi_remote_inventory_owner;`;
const GRANT_HELPERS = [
  `GRANT EXECUTE ON FUNCTION ${HELPERS[0]} TO lomi_runtime,lomi_remote_inventory_owner;`,
  `GRANT EXECUTE ON FUNCTION ${HELPERS[1]} TO lomi_remote_inventory_owner;`,
];
const ROOT_ACL = [
  `REVOKE ALL ON FUNCTION ${ROOTS[0].signature} FROM PUBLIC,lomi_runtime,lomi_remote_api,lomi_remote_exchange,lomi_remote_runtime_owner;`,
  `GRANT EXECUTE ON FUNCTION ${ROOTS[0].signature} TO lomi_remote_pairing_write_owner;`,
];
const INPUT_KEYS = ['baselineReceipt', 'baselineFiles', 'candidateManifest', 'candidateFiles', 'catalogContract', 'helperContract', 'preparationManifest', 'preparationFiles'];

function requireCondition(ok, message) { if (!ok) throw new Error(message); }
export function sha256(data) { return createHash('sha256').update(data).digest('hex'); }
function bytes(value, label) {
  requireCondition(value instanceof Uint8Array, `${label}: admitted bytes required`);
  requireCondition(value.byteLength <= 16 * 1024 * 1024, `${label}: bounded input exceeded`);
  return Buffer.from(value);
}
function text(value, label) {
  const data = bytes(value, label); const result = data.toString('utf8');
  requireCondition(Buffer.from(result, 'utf8').equals(data), `${label}: invalid UTF8`);
  return result;
}
function checked(value, digest, label) {
  const data = bytes(value, label);
  requireCondition(/^[0-9a-f]{64}$/.test(digest ?? '') && sha256(data) === digest, `${label}: source hash mismatch`);
  return text(data, label);
}
function json(value, digest, label) { return JSON.parse(checked(value, digest, label)); }
function exactKeys(value, expected, label) {
  requireCondition(value !== null && typeof value === 'object' && !Array.isArray(value), `${label}: record required`);
  const keys = Object.keys(value).sort(); const names = [...expected].sort();
  requireCondition(keys.length === names.length && keys.every((x, i) => x === names[i]), `${label}: missing or extra named input`);
}
function checkNullPins(records, keys, label) {
  requireCondition(Array.isArray(records), `${label}: records required`);
  for (const record of records) for (const key of keys) requireCondition(record[key] === null, `${label}: original pins must stay NULL`);
}
function uniqueSlice(source, opening, closing, label) {
  const start = source.indexOf(opening);
  requireCondition(start >= 0 && source.indexOf(opening, start + opening.length) < 0, `${label}: missing or duplicate opening`);
  const end = source.indexOf(closing, start + opening.length);
  requireCondition(end >= 0, `${label}: missing closing`);
  return { start, end: end + closing.length, sql: source.slice(start + opening.length, end) };
}
function functionSource(source, name) {
  const opening = `CREATE FUNCTION public.${name}(`;
  const start = source.indexOf(opening);
  requireCondition(start >= 0 && source.indexOf(opening, start + opening.length) < 0, `${name}: missing or duplicate definition`);
  const end = source.indexOf('\nEND $$;', start);
  requireCondition(end >= 0, `${name}: missing exact function terminator`);
  return source.slice(start, end + '\nEND $$;'.length);
}
function exactStatement(source, statement, label) {
  requireCondition(source.split(statement).length === 2, `${label}: missing or duplicate literal statement`);
  return statement;
}

// Low-level parsers are not admission APIs. buildReferences verifies the pinned
// entire operator/manifest before calling them. Their SQL output is untouched.
export function extractRootLiterals(operatorSql, rootPins) {
  requireCondition(rootPins.length === 3 && rootPins.every((p, i) => p.signature === ROOTS[i].signature), 'root allowlist mismatch');
  const tags = [...operatorSql.matchAll(/^ EXECUTE \$(literal[0-9]+)\$/gm)].map(m => m[1]);
  requireCondition(tags.join(',') === 'literal0,literal1,literal2', 'missing, extra or duplicate literal root');
  const roots = ROOTS.map((root, i) => {
    const slice = uniqueSlice(operatorSql, ` EXECUTE $literal${i}$`, `$literal${i}$;`, root.name);
    const prefix = `CREATE OR REPLACE FUNCTION public.${root.name}(`;
    requireCondition(slice.sql.startsWith(prefix) && slice.sql.endsWith('\nEND $$;'), `${root.name}: wrong root/prefix/terminator`);
    requireCondition((slice.sql.match(/CREATE OR REPLACE FUNCTION public\./g) ?? []).length === 1, `${root.name}: extra root definition`);
    // Source correlation only: the reviewed manifest was generated from CREATE
    // FUNCTION, whereas the reviewed emitted literal says CREATE OR REPLACE.
    // No emitted byte or catalog definition is changed by this hash adapter.
    const manifestHash = createHash('sha256').update('CREATE FUNCTION').update(slice.sql.slice('CREATE OR REPLACE FUNCTION'.length)).digest('hex');
    requireCondition(manifestHash === rootPins[i].new_source_sha256, `${root.name}: altered literal body`);
    return { ...root, sql: slice.sql, literalSha256: sha256(slice.sql), manifestCreateFormSha256: manifestHash,
      hashAdapter: { version: 1, reason: 'reviewed manifest CREATE header differs from reviewed operator CREATE OR REPLACE header; source correlation only', emittedPrefix: 'CREATE OR REPLACE FUNCTION', manifestPrefix: 'CREATE FUNCTION' }, range: slice };
  });
  let outside = operatorSql;
  for (const root of [...roots].reverse()) outside = outside.slice(0, root.range.start) + outside.slice(root.range.end);
  requireCondition(!/^\s*EXECUTE\b/m.test(outside), 'unexpected dynamic SQL outside the three fixed literals');
  return roots.map(({ range, ...root }) => root);
}

export function extractHelperTransitions(operatorSql) {
  const owners = HELPERS.map(signature => `ALTER FUNCTION ${signature} OWNER TO ${BODY_OWNER};`);
  const allowed = [CREATE_ROLE, ...owners, REVOKE_HELPERS, ...GRANT_HELPERS];
  for (const statement of allowed) exactStatement(operatorSql, statement, 'helper transition');
  const ddlLines = [...operatorSql.matchAll(/^ *(?:ALTER\b|CREATE\b|REVOKE\b|GRANT\b|DROP\b|EXECUTE\b).*$/gm)].map(m => m[0].replace(/^ */, ''));
  requireCondition(ddlLines.length === 6, 'unexpected helper transition statement');
  requireCondition(ddlLines.every(line => allowed.some(statement => statement.split('\n')[0] === line)), 'wrong helper owner/ACL transition');
  requireCondition(!/^\s*EXECUTE\b/m.test(operatorSql), 'dynamic helper SQL prohibited');
  requireCondition(operatorSql.indexOf(owners[0]) < operatorSql.indexOf(owners[1]) && operatorSql.indexOf(owners[1]) < operatorSql.indexOf(REVOKE_HELPERS), 'helper transition order mismatch');
  return { role: CREATE_ROLE, owners, acl: [REVOKE_HELPERS, ...GRANT_HELPERS] };
}

function entry(id, sql, source, scope = 'database') {
  return { id, scope, role: 'e2_owner', sql, emittedSha256: sha256(sql), source };
}
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}
function transitionGroup(fragments) {
  // One executable unit. Fragment SQL is retained verbatim; only a separating
  // newline is inserted between fragments. Metadata must never be scheduled.
  const sql = fragments.map(fragment => fragment.sql).join('\n');
  return deepFreeze({
    ...entry('reference-only:atomic-new-transition', sql, { kind: 'reviewed-literal-transaction-group' }),
    kind: 'transaction-group', database: 'lomi_derivative_reference_new',
    singleScript: true, sameSession: true, noInterleaving: true,
    onAnyErrorRollbackAndStop: true,
    fragmentSeparator: '\n', fragments,
    schedulingRule: 'Execute sql once on this database/role/session; fragments are immutable provenance metadata, never independent work items. Stop on every SQL error, roll back on the retained connection and stop the fixture stage.',
  });
}
function admittedFiles(files, names, hashes, label) {
  exactKeys(files, names, label);
  return Object.fromEntries(names.map(name => [name, checked(files[name], hashes[name], `${label}/${name}`)]));
}

export function buildReferences(input) {
  exactKeys(input, INPUT_KEYS, 'constructor');
  const receipt = json(input.baselineReceipt, ADMISSION_HASHES.baselineReceipt, 'FC66 receipt');
  requireCondition(receipt.runId === 'fc66ad64-9dc2-4285-8895-72d4d1a436d8' && receipt.shutdownAndCleanupCompleted === true && receipt.liveSourceChangedDuringRun === false, 'baseline is not the closed FC66 source run');
  requireCondition(receipt.frozenInputsArchiveSha256 === ADMISSION_HASHES.baselineArchive, 'wrong frozen baseline archive');
  const manifest = json(input.candidateManifest, ADMISSION_HASHES.candidateManifest, 'reviewed candidate manifest');
  const prepManifest = json(input.preparationManifest, ADMISSION_HASHES.preparationManifest, 'reviewed preparation manifest');
  exactKeys(manifest, CANDIDATE_FILES, 'candidate manifest'); exactKeys(prepManifest, PREPARATION_FILES, 'preparation manifest');
  const baseline = admittedFiles(input.baselineFiles, BASELINE_FILES, receipt.sourceInputSha256Before, 'frozen baseline');
  const candidate = admittedFiles(input.candidateFiles, CANDIDATE_FILES, manifest, 'reviewed candidate');
  const prep = admittedFiles(input.preparationFiles, PREPARATION_FILES, prepManifest, 'reviewed preparation');
  const lock = JSON.parse(prep['inputs.lock.json']);
  requireCondition(lock.baselineReceipt.sha256 === ADMISSION_HASHES.baselineReceipt && lock.baselineArchive.sha256 === ADMISSION_HASHES.baselineArchive && lock.candidateManifest.sha256 === ADMISSION_HASHES.candidateManifest, 'preparation admission chain mismatch');
  const catalog = json(input.catalogContract, ADMISSION_HASHES.catalogContract, 'NULL catalog contract');
  const helpers = json(input.helperContract, ADMISSION_HASHES.helperContract, 'NULL helper contract');
  checkNullPins(catalog.roots, ['old_catalog_sha256', 'new_catalog_sha256', 'old_acl', 'new_acl'], 'root pins');
  checkNullPins(catalog.prerequisites, ['catalog_sha256', 'acl'], 'prerequisite pins');
  checkNullPins(helpers.helpers, ['old_catalog_sha256', 'new_catalog_sha256', 'old_acl', 'new_acl'], 'helper pins');
  requireCondition(helpers.helpers.length === 2 && helpers.helpers.every((h, i) => h.signature === HELPERS[i] && h.old_owner === 'lomi_migrator' && h.new_owner === BODY_OWNER), 'helper ownership allowlist mismatch');
  const predecessor = ROOTS.map((root, i) => {
    const original = functionSource(baseline[root.migration], root.name);
    requireCondition(candidate[`${root.name}.old-source.sql`] === original + '\n', `${root.name}: old snapshot mismatch`);
    requireCondition(sha256(original) === catalog.roots[i].old_source_sha256, `${root.name}: frozen source digest mismatch`);
    return { signature: root.signature, source: root.migration, sourceSha256: sha256(original) };
  });
  for (const helper of helpers.helpers) {
    const name = helper.signature.slice('public.'.length).split('(')[0];
    requireCondition(sha256(functionSource(candidate['authority-core.candidate.sql'], name)) === helper.source_sha256, `${name}: wrong helper body`);
  }
  const roots = extractRootLiterals(candidate['operator-three-roots.candidate.sql'], catalog.roots);
  const helperTransitions = extractHelperTransitions(candidate['operator-seal-auth-helpers.candidate.sql']);
  for (const sql of ROOT_ACL) exactStatement(candidate['operator-three-roots.candidate.sql'], sql, 'root ACL');

  const bootstrap = prep['fixture-ownership-bootstrap.sql'];
  const actualOwners = [...bootstrap.matchAll(/^ALTER FUNCTION (.+) OWNER TO (\w+);$/gm)].map(m => [m[1], m[2]]);
  const expectedOwners = catalog.prerequisites.map(p => [p.signature, p.owner === BODY_OWNER ? 'lomi_migrator' : p.owner]);
  requireCondition(JSON.stringify(actualOwners) === JSON.stringify(expectedOwners) && actualOwners.length === 24, 'one-time bootstrap ownership ordering mismatch');

  const sourceOf = (kind, name) => ({ kind, name, sourceSha256: sha256((kind === 'baseline' ? baseline : kind === 'candidate' ? candidate : prep)[name]) });
  const common = [];
  for (const name of migrations) common.push(entry(`migration:${name}`, baseline[name], sourceOf('baseline', name)));
  for (let pass = 0; pass < 2; pass++) for (const name of ops) common.push(entry(`baseline-ops:${pass}:${name}`, baseline[name], sourceOf('baseline', name)));
  for (const name of ['approval-intent.candidate.sql', '012-derivative-authority.candidate.sql', 'authority-core.candidate.sql', 'typed-entrypoints.candidate.sql']) common.push(entry(`candidate:${name}`, candidate[name], sourceOf('candidate', name)));
  common.push(entry('ownership-bootstrap:ONCE-BEFORE-SEAL', bootstrap, sourceOf('preparation', 'fixture-ownership-bootstrap.sql')));
  common.push(entry('candidate-fixture-ops:initial', prep['fixture-ops.sql'], sourceOf('preparation', 'fixture-ops.sql')));
  const oldSteps = common.map(step => ({ ...step, source: { ...step.source } }));
  const helperSource = sourceOf('candidate', 'operator-seal-auth-helpers.candidate.sql');
  const rootSource = sourceOf('candidate', 'operator-three-roots.candidate.sql');
  const transition = transitionGroup([
    entry('reference-only:transition:BEGIN', 'BEGIN;', { kind: 'fixed-reference-transaction' }),
    entry('reference-only:global-lock', "SELECT pg_advisory_xact_lock(hashtextextended('lomi-auth:device-mutations-and-revoke-all:v1',0));", { kind: 'fixed-reference-transaction' }),
    entry('reference-only:body-owner:CREATE-ONCE', helperTransitions.role, helperSource, 'cluster'),
    ...helperTransitions.owners.map((sql, i) => entry(`reference-only:helper-owner:${i}`, sql, helperSource)),
    ...helperTransitions.acl.map((sql, i) => entry(`reference-only:helper-acl:${i}`, sql, helperSource)),
    ...roots.map((root, i) => entry(`reference-only:root-literal:${i}`, root.sql, { ...rootSource, signature: root.signature, literalSha256: root.literalSha256 })),
    ...ROOT_ACL.map((sql, i) => entry(`reference-only:root-acl:${i}`, sql, rootSource)),
    entry('reference-only:transition:COMMIT', 'COMMIT;', { kind: 'fixed-reference-transaction' }),
  ]);
  const newSteps = [
    ...common.map(step => ({ ...step, source: { ...step.source } })),
    transition,
  ];
  return {
    status: 'PREPARED_NOT_EXECUTED', executionIncluded: false, catalogInputAccepted: false, pinsFilled: false,
    admission: { ...ADMISSION_HASHES },
    clusterPrecondition: 'Future admitted Windows-owned PostgreSQL18.6 fixture only. Create the four synthetic baseline roles exactly once before either baseline-ops sequence. Both reference DBs share that cluster and role OIDs. Body-owner role must be absent before the single atomic reference-new transition; its CREATE is inside that transaction. Never drop/repair an existing role.',
    referenceOld: { database: 'lomi_derivative_reference_old', steps: oldSteps },
    referenceNew: { database: 'lomi_derivative_reference_new', steps: newSteps },
    sourceCorrelations: { predecessor, rootLiterals: roots.map(({ sql, ...metadata }) => metadata), helpers: helpers.helpers.map(h => ({ signature: h.signature, sourceSha256: h.source_sha256 })) },
    catalogVerification: 'Future separate raw catalog capture and reference-versus-target equality; constructor neither receives nor approves catalog records. Original NULL pins remain untouched.',
    ownershipBootstrapRule: 'Exactly once per reference database before helper transitions; forbidden after sealing. Its temporary schema CREATE grants must be proven revoked by actual PostgreSQL.',
  };
}
