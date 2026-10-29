"""Separately admitted, private PostgreSQL S0–S4 fixture; never seals target pins.

Importing this module starts no children. CLI execution requires prior root
appointment admission; --appointment records that decision, it cannot grant it.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import importlib.util
import json
import os
import resource
import shutil
import signal
import sys
import tarfile
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PLAN = ROOT / 'artifacts/consumer-derivatives-plan/bcf93985-5a17-463a-aa2e-2446fb413e93'
PREP_HASH = '8ff761e792ad74fffa6892807caf5bab32b5d7aa3b2e644302397cbd945c8f51'
LEDGER_FIXTURE_HASH = '096e8221d552af558cb2446f866077f4402c5956169227881a1ed8ed0e7060a4'
NODE_HASH = '5d9d3872911e2340a43b707962e68143de8a4e8d54628845c0c4f2de1fb7cd5c'
CONSTRUCTOR_HASH = '234375d742689565cd1e3dcc7200a0e21d21c15eabe6e8a6ae44fcd29c991aa7'
PREP_NAMES = {'prepare.py', 'validate.py', 'inputs.lock.json', 'acceptance.json',
              'fixture-ops.sql', 'fixture-ownership-bootstrap.sql', 'catalog-discovery.sql', 'README.md'}
DATABASES = ('lomi_derivative_fixture', 'lomi_derivative_reference_old', 'lomi_derivative_reference_new')
ROLES = {'lomi_push_worker', 'e2_owner', 'lomi_migrator', 'lomi_runtime', 'lomi_remote_api', 'lomi_remote_exchange',
         'lomi_remote_runtime_owner', 'lomi_remote_inventory_owner', 'lomi_remote_pairing_write_owner',
         'lomi_consumer_auth_body_owner'}
ROLE_SQL = ('CREATE ROLE lomi_migrator NOLOGIN; CREATE ROLE lomi_runtime LOGIN NOSUPERUSER '
            'NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT; CREATE ROLE lomi_remote_api NOLOGIN; '
            'CREATE ROLE lomi_remote_exchange NOLOGIN;')
ROOT_SIGNATURES = (
    'public.lomi_consumer_inventory(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
    'public.lomi_consumer_assertion_recheck(uuid,uuid,text,text,bigint,bigint,boolean,bytea)',
    'public.lomi_consumer_recipient_recheck(uuid,uuid)')

# Exact CREATE ROLE statements are checked against hash-admitted public source
# by admit_sources(), rather than inferred from a target role catalog.
SEALED_ROLE_SUFFIX = ' NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;'
ROLE_SOURCE_STATEMENTS = {
    'ops/database-permissions.sql': ['CREATE ROLE ' + name + SEALED_ROLE_SUFFIX for name in
        ('lomi_remote_runtime_owner', 'lomi_remote_inventory_owner', 'lomi_remote_pairing_write_owner')],
    'ops/remote-database-permissions.sql': ['CREATE ROLE ' + name + SEALED_ROLE_SUFFIX for name in
        ('lomi_remote_runtime_owner', 'lomi_remote_inventory_owner', 'lomi_remote_pairing_write_owner')],
    'ops/push-database-permissions.sql': ['CREATE ROLE lomi_push_worker NOLOGIN;'],
}
PROTECTED_RELATIONS = {('public', name) for name in ('consumer_approval_intent',
    'consumer_approval_consumed_proof', 'consumer_derivative_consent', 'consumer_authorization')}


def expected_role(name):
    require(name in ROLES, 'unknown fixture role')
    superuser = name == 'e2_owner'
    return dict(login=name in ('e2_owner', 'lomi_runtime'),
                inherit=name in ('e2_owner', 'lomi_migrator', 'lomi_remote_api', 'lomi_remote_exchange', 'lomi_push_worker'),
                super=superuser, createRole=superuser, createDb=superuser,
                replication=superuser, bypassRls=superuser, config=None)


class AppointmentDeadline(TimeoutError):
    pass


def remaining_budget(started, limit=900):
    remaining = limit - (time.monotonic() - started)
    if remaining <= 0:
        raise AppointmentDeadline('original appointment deadline reached')
    return remaining


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, message):
    if not ok:
        raise ValueError(message)


def checked(path, expected=None):
    path = Path(path)
    require(not any(p.is_symlink() for p in [path, *path.parents]), 'symlink input rejected')
    require(path.is_file(), 'missing named input: ' + str(path))
    data = path.read_bytes()
    require(expected is None or digest(data) == expected, 'source hash mismatch: ' + str(path))
    return data


def toolchain(lock):
    base = ROOT / lock['toolchainRoot']
    hashes = {}
    for name, expected in {**lock['toolchainCoreSha256'], **lock['toolchainInitdbSha256']}.items():
        hashes[name] = digest(checked(base / 'Postgres.app' / name, expected))
    for name, expected in [('summary.json', lock['toolchainSummarySha256']),
                           ('acquisition-receipt.json', lock['acquisitionReceiptSha256'])]:
        hashes[name] = digest(checked(base / name, expected))
    return hashes


def admit_sources():
    """S0: named public bytes only, no executable/version probe or child."""
    prep_manifest = checked(PLAN / 'preparation-source-sha256.json', PREP_HASH)
    prep_hashes = json.loads(prep_manifest)
    require(set(prep_hashes) == PREP_NAMES, 'preparation allowlist changed')
    prep = {name: checked(PLAN / 'qualification-source' / name, sha) for name, sha in prep_hashes.items()}
    lock = json.loads(prep['inputs.lock.json'])
    receipt = checked(ROOT / lock['baselineReceipt']['path'], lock['baselineReceipt']['sha256'])
    archive_path = ROOT / lock['baselineArchive']['path']
    checked(archive_path, lock['baselineArchive']['sha256'])
    side = json.loads(checked(ROOT / lock['toolchainSidecar']['path'], lock['toolchainSidecar']['sha256']))
    require(side['coreSha256Before'] == side['coreSha256After'] and
            side['defaultInitdbScriptSha256Before'] == side['defaultInitdbScriptSha256After'], 'sidecar drift')
    baseline = {}
    with tarfile.open(archive_path, 'r:gz') as archive:
        for name, sha in lock['publicArchiveMembers'].items():
            require(not Path(name).is_absolute() and '..' not in Path(name).parts, 'unsafe member')
            members = [m for m in archive.getmembers() if m.name == name]
            require(len(members) == 1 and members[0].isfile(), 'duplicate/nonregular public member')
            data = archive.extractfile(members[0]).read(16 * 1024 * 1024 + 1)
            require(len(data) <= 16 * 1024 * 1024 and digest(data) == sha, 'archive member mismatch')
            baseline[name] = data
    require(len(baseline) == 28, 'expected exactly 28 frozen inputs')
    candidate_path = ROOT / 'staging/consumer-derivatives'
    candidate_manifest = checked(ROOT / lock['candidateManifest']['path'], lock['candidateManifest']['sha256'])
    candidate_hashes = json.loads(candidate_manifest)
    require(len(candidate_hashes) == 14, 'expected fourteen candidate sources')
    candidate = {name: checked(candidate_path / name, sha) for name, sha in candidate_hashes.items()}
    contracts = {name: checked(candidate_path / name, sha) for name, sha in lock['candidateCatalogFiles'].items()}
    catalog = json.loads(contracts['catalog-contract.pending.json'])
    helper = json.loads(contracts['helper-seal.pending.json'])
    for row in catalog['roots'] + helper['helpers']:
        require(all(row[k] is None for k in ('old_catalog_sha256', 'new_catalog_sha256', 'old_acl', 'new_acl')), 'pins filled')
    require(all(row['catalog_sha256'] is None and row['acl'] is None for row in catalog['prerequisites']), 'prerequisite pins filled')
    require(ROLE_SQL.encode() in baseline['test/run_host_credentials_runtime.py'], 'frozen role recipe changed')
    for name, statements in ROLE_SOURCE_STATEMENTS.items():
        require(all(statement.encode() in baseline[name] for statement in statements), 'frozen role source changed')
    require(('CREATE ROLE lomi_consumer_auth_body_owner' + SEALED_ROLE_SUFFIX).encode() in
            candidate['operator-seal-auth-helpers.candidate.sql'], 'body-owner role source changed')
    checked(HERE / 'reference-build.mjs', CONSTRUCTOR_HASH)
    support = ROOT / lock['ownedProcessSource']['path']
    checked(support, lock['ownedProcessSource']['sha256'])
    tools = toolchain(lock)
    inputs = dict(baselineReceipt=receipt, baselineFiles=baseline, candidateManifest=candidate_manifest,
                  candidateFiles=candidate, catalogContract=contracts['catalog-contract.pending.json'],
                  helperContract=contracts['helper-seal.pending.json'], preparationManifest=prep_manifest,
                  preparationFiles=prep)
    return lock, inputs, tools, support


def encode_inputs(value):
    return base64.b64encode(value).decode('ascii') if isinstance(value, bytes) else {
        name: encode_inputs(data) for name, data in value.items()}


def protected_relation_map(rows):
    result = {}
    identities = set()
    for row in rows:
        if row.get('kind') != 'relationIdentity':
            continue
        require(set(row) == {'kind', 'oid', 'catalogKey', 'schema', 'name'}, 'unexpected relation identity fields')
        oid, identity = row['oid'], (row['schema'], row['name'])
        require(isinstance(oid, str) and oid.isascii() and oid.isdecimal() and int(oid) > 0,
                'invalid relation OID')
        require(oid not in result and identity not in identities, 'duplicate relation identity')
        require(identity in PROTECTED_RELATIONS, 'unknown protected relation identity')
        catalog_key = row['catalogKey']
        require(isinstance(catalog_key, str) and catalog_key in (row['name'], row['schema'] + '.' + row['name']),
                'unexpected regclass identity rendering')
        require(catalog_key not in result, 'duplicate relation catalog key')
        result[oid] = identity
        result[catalog_key] = identity
        identities.add(identity)
    require(identities == PROTECTED_RELATIONS, 'incomplete protected relation identity map')
    return result


def canonical(rows, relation_map=None):
    def stable(row):
        if row.get('kind') == 'protectedAcl':
            require(relation_map is not None and row['relation'] in relation_map, 'unmapped protected relation OID')
            return dict(row, relation=list(relation_map[row['relation']]))
        if row.get('kind') == 'relationIdentity':
            return {k: v for k, v in row.items() if k not in ('oid', 'catalogKey')}
        if row.get('kind') == 'trigger' and row['internal']:
            # Preserve raw evidence. Only comparison uses semantic constraint
            # identity: PostgreSQL's internal trigger names embed database OIDs.
            return {k: v for k, v in row.items() if k not in ('name', 'definition')}
        return row
    return sorted(json.dumps(stable(row), sort_keys=True, separators=(',', ':')) for row in rows)


def parse_catalog(text):
    rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    require(bool(rows), 'empty catalog capture')
    for row in rows:
        if row.get('kind') == 'function':
            require(digest(bytes.fromhex(row['definitionUtf8Hex'])) == row['catalogSha256'], 'raw definition hash mismatch')
    return rows


def reject_authority_drift(rows):
    """Reject unknown grants/defaults/roles rather than repairing their baseline."""
    for row in rows:
        if row.get('kind') == 'role':
            require(row['name'] in ROLES, 'unknown fixture role')
            expected = expected_role(row['name'])
            require(all(key in row and row[key] == value for key, value in expected.items()),
                    'unexpected exact role attributes/config')
        if row.get('kind') == 'membership':
            require(row['role'].startswith('pg_') and row['member'].startswith('pg_'), 'fixture role membership prohibited')
        if row.get('kind') == 'defaultAcl':
            # Frozen scripts are admitted sources; no unknown principal may be
            # laundered through a baseline/default/column grant.
            require(row['owner'] in ROLES and row['grantee'] in ROLES | {'PUBLIC'} and row['grantor'] in ROLES,
                    'unknown default privilege')
        if row.get('kind') in ('objectAcl', 'columnAcl'):
            require(row['grantee'] in ROLES | {'PUBLIC'} and row['grantor'] in ROLES, 'unknown object privilege')
        if row.get('kind') == 'schemaAuthority' and row['role'] in ROLES - {'e2_owner'}:
            require(not row['create'], 'retained schema CREATE')


def predecessor_query(catalog_sql):
    # Keep the pinned discovery SELECT byte-identical; replace only its explicit
    # expected signature VALUES list to capture the three pre-install roots.
    suffix = catalog_sql.split('), functions AS (', 1)[1].split(';', 1)[0] + ';'
    return 'WITH expected(signature) AS (VALUES\n' + ',\n'.join(" ('" + s + "')" for s in ROOT_SIGNATURES) + '), functions AS (' + suffix


class Fixture:
    def __init__(self, owned, lock, work, evidence, appointment, node):
        self.owned, self.lock, self.work, self.evidence = owned, lock, work, evidence
        self.node = node
        self.started = time.monotonic()
        self.pg = ROOT / lock['toolchainRoot'] / 'Postgres.app/Contents/Versions/18/bin'
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(work / 'home'), 'TMPDIR': str(work / 'tmp'),
                    'LANG': 'C', 'LC_ALL': 'C', 'TZ': 'UTC'}
        self.events = []
        self.evidence_errors = []
        self.start_attempted = False
        self.marker = {'runId': evidence.name, 'appointment': appointment, 'data': str(work / 'data'),
                       'socket': str(work / 'socket'), 'port': 55439}
        self.marker_path = work / 'owned-cluster.json'
        self.marker_path.write_text(json.dumps(self.marker))
        self.sequence = 0

    def command(self, label, argv, expected=(0,), cleanup=False):
        remaining = remaining_budget(self.started, 900 if cleanup else 840)
        self.sequence += 1
        result = self.owned.run_owned([str(a) for a in argv], cwd=str(self.work), env=self.env,
                                      timeout=min(60, remaining))
        clean = lambda s: s.replace(str(self.work), '<owned>').replace(str(ROOT), '<repo>')
        entry = {'id': self.sequence, 'label': label, 'argv': [clean(str(a)) for a in argv],
                 'returncode': result.returncode, 'stdout': clean(result.stdout), 'stderr': clean(result.stderr)}
        self.events.append(entry)
        if cleanup:
            self.try_save('commands.json', self.events)
        else:
            self.save('commands.json', self.events)
        require(result.returncode in expected, 'command failed: ' + label)
        return result.stdout

    def save(self, name, value):
        path = self.evidence / name
        path.write_text(json.dumps(value, indent=2) + '\n')
        return digest(path.read_bytes())

    def try_save(self, name, value):
        try:
            return self.save(name, value)
        except AppointmentDeadline:
            raise
        except Exception as exc:
            self.evidence_errors.append(name + ': ' + type(exc).__name__ + ': ' + str(exc))
            return None

    def sql(self, database, label, sql):
        require(database in (*DATABASES, 'postgres'), 'unknown fixture database')
        path = self.work / f'sql-{self.sequence + 1}.sql'
        path.write_text(sql)
        result = self.command(label, [self.pg / 'psql', '-X', '--no-password', '-qAt',
            '-h', self.work / 'socket', '-p', '55439', '-U', 'e2_owner', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose',
            '-d', database, '-f', path])
        # Exact SQL source and outputs are independent evidence, never expected pins.
        self.save(f'sql-{self.sequence}.json', {'database': database, 'label': label,
                    'sql': sql, 'sqlSha256': digest(sql.encode()), 'stdout': result})
        return result

    def capture(self, database, label, sql):
        rows = parse_catalog(self.sql(database, label, sql))
        reject_authority_drift(rows)
        self.save(label + '.json', rows)
        return rows

    def pid_identity(self):
        require(json.loads(self.marker_path.read_text()) == self.marker, 'owned marker changed')
        data = self.work / 'data'
        require(not data.is_symlink() and data.parent == self.work, 'owned data path changed')
        pidfile = data / 'postmaster.pid'
        if not pidfile.exists():
            return None
        require(not pidfile.is_symlink(), 'pid file symlink')
        lines = pidfile.read_text().splitlines()
        require(len(lines) >= 6 and int(lines[0]) > 1 and lines[1] == str(data) and
                lines[3] == '55439' and lines[4] == str(self.work / 'socket') and lines[5] == '',
                'postmaster identity not bound to owned data/socket-only marker')
        return lines[:6]

    def cleanup(self):
        # PostgreSQL deliberately creates another session; never signal its
        # numeric PID or use the ordinary child's process group as its identity.
        # Only this private marked data directory authorizes dedicated pg_ctl.
        if self.start_attempted:
            identity = self.pid_identity()
            if identity is not None:
                self.command('owned-cluster-stop', [self.pg / 'pg_ctl', '-D', self.work / 'data',
                             '-m', 'immediate', '-w', '-t', '20', 'stop'], cleanup=True)
            self.command('owned-cluster-status', [self.pg / 'pg_ctl', '-D', self.work / 'data', 'status'],
                         expected=(3,), cleanup=True)
            require(not (self.work / 'data/postmaster.pid').exists(), 'owned postmaster still present')
            require(not list((self.work / 'socket').iterdir()), 'owned socket/listener remains')
        return {'completed': True, 'pgCtlStatus': 3 if self.start_attempted else 'NOT_STARTED',
                'postmasterPidAbsent': not (self.work / 'data/postmaster.pid').exists(),
                'socketDirectoryEmpty': not list((self.work / 'socket').iterdir()),
                'clients': 'sequential synchronous owned commands; none retained'}


def baseline_steps_with_ledger(steps, ledger_sql):
    """One explicit empty fixture after 24 migrations, before unchanged ops."""
    require(len(steps) == 36 and all(step['id'].startswith('migration:') for step in steps[:24])
            and all(step['id'].startswith('baseline-ops:') for step in steps[24:30]), 'baseline schedule changed')
    require(digest(ledger_sql.encode()) == LEDGER_FIXTURE_HASH, 'ledger fixture source changed')
    ledger = {'id': 'fixture-only:empty-prisma-ledger:ONCE', 'role': 'e2_owner', 'sql': ledger_sql,
              'emittedSha256': LEDGER_FIXTURE_HASH,
              'source': {'kind': 'explicit-empty-fixture-compatibility', 'name': 'pg-s0-s4-ledger-fixture.sql',
                         'sourceSha256': LEDGER_FIXTURE_HASH, 'prismaLedgerQualified': False}}
    return [*steps[:24], ledger, *steps[24:30]]


def execute(fixture, inputs):
    f = fixture
    f.save('stage-S0.json', {'status': 'PASS', 'postgresInvocations': 0, 'childInvocations': 0,
                           'sourceClosure': source_closure(), 'pinsFilled': False})
    encoded = f.work / 'constructor-input.json'
    encoded.write_text(json.dumps(encode_inputs(inputs)))
    output = f.work / 'reference-transcripts.json'
    f.command('pinned-pure-reference-constructor', [f.node, HERE / 'pg-s0-s4-bridge.mjs', encoded, output])
    built = json.loads(output.read_text())
    require(built['pinsFilled'] is False and built['catalogInputAccepted'] is False, 'constructor boundary changed')
    f.save('reference-transcripts.json', built)
    old, new = built['referenceOld']['steps'], built['referenceNew']['steps']
    require(len(old) == 36 and len(new) == 37 and new[-1]['kind'] == 'transaction-group', 'unexpected schedule')
    group = new[-1]
    require(all(group[k] is True for k in ('singleScript', 'sameSession', 'noInterleaving', 'onAnyErrorRollbackAndStop')),
            'transition is not an indivisible work item')
    for step in [*old, *new]:
        require(step['role'] == 'e2_owner' and digest(step['sql'].encode()) == step['emittedSha256'], 'SQL transcript drift')
    for binary in ('postgres', 'initdb', 'pg_ctl', 'psql'):
        version = f.command(binary + '-version', [f.pg / binary, '--version']).strip()
        require(version == binary + ' (PostgreSQL) 18.6 (Postgres.app)', 'unexpected actual PG version')
    f.command('owned-initdb', [f.pg / 'initdb', '-D', f.work / 'data', '-U', 'e2_owner',
              '--auth=trust', '--no-locale', '-E', 'UTF8'])
    f.start_attempted = True
    options = ("-h '' -k " + str(f.work / 'socket') + ' -p 55439 -c max_connections=2 '
               '-c superuser_reserved_connections=0 -c reserved_connections=0 '
               '-c unix_socket_permissions=0700 -c statement_timeout=55000 -c lock_timeout=10000 '
               '-c idle_in_transaction_session_timeout=55000')
    f.command('owned-cluster-start', [f.pg / 'pg_ctl', '-D', f.work / 'data', '-l', f.work / 'postgres.log',
              '-o', options, '-w', '-t', '30', 'start'])
    require(f.pid_identity() is not None, 'missing owned postmaster identity')
    settings = json.loads(f.sql('postgres', 'socket-only-settings', "SELECT json_build_object("
        "'listen',current_setting('listen_addresses'),'socket',current_setting('unix_socket_directories'),"
        "'data',current_setting('data_directory'),'max',current_setting('max_connections'),"
        "'port',current_setting('port'));"))
    require(settings == {'listen': '', 'socket': str(f.work / 'socket'), 'data': str(f.work / 'data'),
                         'max': '2', 'port': '55439'}, 'socket-only or connection bound mismatch')
    f.save('stage-S1.json', {'status': 'PASS', 'socketOnly': True, 'maxConnections': 2})
    f.sql('postgres', 'frozen-four-synthetic-roles', ROLE_SQL)
    for database in DATABASES:
        f.sql('postgres', 'create-' + database, 'CREATE DATABASE ' + database + ' TEMPLATE template0;')
    catalog_sql = inputs['preparationFiles']['catalog-discovery.sql'].decode()
    metadata_sql = checked(HERE / 'pg-s0-s4-metadata.sql').decode()
    pred_sql = predecessor_query(catalog_sql)
    baseline = {}
    ledger_sql = checked(HERE / 'pg-s0-s4-ledger-fixture.sql', LEDGER_FIXTURE_HASH).decode()
    baseline_steps = baseline_steps_with_ledger(old, ledger_sql)
    f.save('baseline-sql-schedule.json', {'steps': baseline_steps, 'prismaLedgerQualified': False})
    # Independent replay from constructor-selected source bytes, no target-catalog input.
    for database in DATABASES:
        for step in baseline_steps:
            result = f.sql(database, database + ':' + step['id'], step['sql'])
            if step['id'] == 'fixture-only:empty-prisma-ledger:ONCE':
                require(result.strip() == '0', 'fixture ledger must be empty')
        baseline[database] = f.capture(database, database + '-predecessors', pred_sql)
        f.capture(database, database + '-baseline-metadata', metadata_sql)
    expected = canonical(baseline[DATABASES[1]])
    require(all(canonical(rows) == expected for rows in baseline.values()), 'frozen predecessor inequality')
    require(len(baseline[DATABASES[0]]) == 3, 'missing predecessor function')
    f.save('stage-S2.json', {'status': 'PASS', 'predecessorEquality': True, 'prismaLedgerQualified': False})
    for database in DATABASES:
        for step in old[30:]:
            f.sql(database, database + ':' + step['id'], step['sql'])
    absent = f.sql('postgres', 'body-owner-must-be-absent',
                   "SELECT count(*) FROM pg_roles WHERE rolname='lomi_consumer_auth_body_owner';").strip()
    require(absent == '0', 'body owner already exists; no drop/repair allowed')
    # One psql process/session executes the whole BEGIN..COMMIT script. An error
    # stops psql and connection closure rolls back its open transaction.
    f.sql(DATABASES[2], group['id'], group['sql'])
    f.save('stage-S3.json', {'status': 'PASS', 'bootstrapCountPerDatabase': 1,
                           'referenceNewAtomicScriptSha256': group['emittedSha256']})
    catalogs, metadata = {}, {}
    for database in DATABASES:
        require(f.sql(database, database + '-ledger-still-empty',
                      'SELECT count(*) FROM public._prisma_migrations;').strip() == '0', 'fixture ledger gained rows')
        catalogs[database] = f.capture(database, database + '-catalog', catalog_sql)
        metadata[database] = f.capture(database, database + '-metadata', metadata_sql)
        functions = [r for r in catalogs[database] if r['kind'] == 'function']
        require(len(functions) == 27 and len({r['signature'] for r in functions}) == 27, 'incomplete function closure')
    relation_maps = {database: protected_relation_map(metadata[database]) for database in DATABASES}
    equality = {'catalog': canonical(catalogs[DATABASES[0]], relation_maps[DATABASES[0]]) ==
                           canonical(catalogs[DATABASES[1]], relation_maps[DATABASES[1]]),
                'metadata': canonical(metadata[DATABASES[0]]) == canonical(metadata[DATABASES[1]])}
    require(all(equality.values()), 'target-old differs from source-built reference-old')
    contract = json.loads(inputs['catalogContract'])
    helper = json.loads(inputs['helperContract'])
    for database in DATABASES:
        records = {r['signature']: r for r in catalogs[database] if r['kind'] == 'function'}
        is_new = database == DATABASES[2]
        for pin in contract['roots'] + helper['helpers']:
            require(records[pin['signature']]['owner'] == pin.get('new_owner' if is_new else 'old_owner', pin.get('owner')), 'root/helper owner mismatch')
        for pin in contract['prerequisites']:
            owner = pin['owner']
            if not is_new and owner == 'lomi_consumer_auth_body_owner':
                owner = 'lomi_migrator'
            require(records[pin['signature']]['owner'] == owner, 'prerequisite owner mismatch')
    return {'status': 'PROVISIONAL_S4_PENDING_ROOT_REVIEW', 'authoritative': False, 'lastStage': 'S4',
            'stages': {s: 'PASS' for s in ('S0', 'S1', 'S2', 'S3', 'S4')},
            'laterStages': {s: 'NOT_RUN' for s in ('S5', 'S6', 'S7', 'S8')},
            'targetOldEquality': equality, 'sourceCorrelations': built['sourceCorrelations'], 'constructorAdmission': built['admission'],
            'prismaLedgerQualified': False, 'ledgerFixtureSha256': LEDGER_FIXTURE_HASH,
            'pinsFilled': False, 'derivedCopies': [], 'derivedCopyDeltas': [], 'measuredOperatorsExecuted': False,
            'qualification': {k: False for k in ('HTTP', 'BetterAuth', 'UI', 'Prisma012', 'production')},
            'scopeDeviation': 'S4 stops before pin filling; root must review this concrete manifest before any S5 work'}


def publish_completion(fixture, manifest_sha):
    """Atomic candidate receipt; only an EXTERNAL successful exit can admit it.

    A deadline after rename can leave this receipt present. It never proves the
    controller exit; the caller must retain that independent result/envelope.
    """
    require(len(manifest_sha) == 64, 'missing final manifest digest')
    remaining_budget(fixture.started)
    receipt = {'status': 'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO',
               'runId': fixture.evidence.name, 'manifestSha256': manifest_sha,
               'requiresOwnedControllerExitCode': 0, 'originalOuterDeadlineSeconds': 900,
               'manifestAloneIsAdmission': False, 'receiptAloneIsAdmission': False}
    pending = fixture.evidence / 'completion-receipt.pending.json'
    with pending.open('x') as stream:
        stream.write(json.dumps(receipt, indent=2) + '\n')
    os.replace(pending, fixture.evidence / 'completion-receipt.json')
    remaining_budget(fixture.started)
    return receipt


def completion_is_admissible(manifest_bytes, receipt, controller):
    """Pure S4 completion gate; controller data MUST come from the owning root.

    The fixture must never manufacture its own controller-exit envelope. This
    gate does not authorize S5 or substitute for root review of the manifest.
    """
    manifest = json.loads(manifest_bytes)
    elapsed = controller.get('elapsedSeconds')
    return (manifest.get('status') == 'PROVISIONAL_S4_PENDING_ROOT_REVIEW'
            and manifest.get('authoritative') is False
            and manifest.get('cleanup', {}).get('completed') is True
            and all(manifest.get('stages', {}).get(s) == 'PASS' for s in ('S0', 'S1', 'S2', 'S3', 'S4'))
            and receipt.get('status') == 'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO'
            and receipt.get('manifestSha256') == digest(manifest_bytes)
            and receipt.get('runId') == manifest.get('runId') == controller.get('runId')
            and receipt.get('requiresOwnedControllerExitCode') == 0
            and receipt.get('originalOuterDeadlineSeconds') == 900
            and type(controller.get('ownedControllerExitCode')) is int
            and controller.get('ownedControllerExitCode') == 0
            and controller.get('completed') is True
            and controller.get('originalOuterDeadlineSeconds') == 900
            and isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool) and 0 <= elapsed < 900)


def source_closure():
    names = ('pg-s0-s4.py', 'pg-s0-s4-bridge.mjs', 'pg-s0-s4-metadata.sql', 'pg-s0-s4.md',
             'pg-s0-s4.test.py', 'pg-s0-s4-ledger-fixture.sql', 'reference-build.mjs')
    return {name: digest(checked(HERE / name)) for name in names}


def main():
    appointment_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appointment', required=True, help='record of prior explicit root S0-S4 admission')
    parser.add_argument('--node', required=True, type=Path, help='absolute Node executable used only for pure constructor')
    args = parser.parse_args()
    def interrupted(signum, frame):
        if signum == signal.SIGALRM:
            raise AppointmentDeadline('original appointment watchdog expired')
        raise InterruptedError('fixture interrupted by signal ' + str(signum))
    signal.signal(signal.SIGALRM, interrupted)
    signal.setitimer(signal.ITIMER_REAL, remaining_budget(appointment_started, 840))
    require(bool(args.appointment.strip()), 'appointment record required')
    require(args.node.is_absolute(), 'absolute Node path required')
    node = args.node.resolve(strict=True)
    node_sha = digest(checked(node, NODE_HASH))
    require(os.access(node, os.X_OK), 'Node is not executable')
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # S0 precedes importing even the pinned process helper and every child.
    lock, inputs, tools_before, support = admit_sources()
    sources_before = source_closure()
    spec = importlib.util.spec_from_file_location('consumer_derivative_owned_process', support)
    owned = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owned)
    owned.initialize_process_ownership()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    require(shutil.disk_usage('/private/tmp').free >= 2 * 1024**3, 'need 2 GiB free space')
    run_id = str(uuid.uuid4())
    evidence = ROOT / 'artifacts/consumer-derivatives-s0-s4' / run_id
    evidence.mkdir(parents=True, exist_ok=False)
    work = Path(tempfile.mkdtemp(prefix='lcd-', dir='/private/tmp'))
    for name in ('home', 'tmp', 'socket'):
        (work / name).mkdir(mode=0o700)
    f = Fixture(owned, lock, work, evidence, args.appointment, node)
    f.started = appointment_started
    manifest = {'status': 'FAILED', 'authoritative': False, 'stages': {}, 'lastStage': None, 'pinsFilled': False,
                'measuredOperatorsExecuted': False, 'prismaLedgerQualified': False,
                'laterStages': {s: 'NOT_RUN' for s in ('S5', 'S6', 'S7', 'S8')},
                'qualification': {k: False for k in ('HTTP', 'BetterAuth', 'UI', 'Prisma012', 'production')}}
    error = None
    inputs_unchanged = False
    tools_after = None
    completion_receipt = None
    try:
        manifest = execute(f, inputs)
    except BaseException as exc:
        error = exc
        manifest['error'] = type(exc).__name__ + ': ' + str(exc).replace(str(work), '<owned>')
    finally:
        # Replace the normal-work 840s alarm with the remainder of the ORIGINAL
        # 900s appointment, including mandatory stop and all final hashes/I/O.
        # No evidence write can precede or prevent mandatory owned cleanup.
        signal.setitimer(signal.ITIMER_REAL, max(0.001, 900 - (time.monotonic() - appointment_started)))
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        try:
            manifest['cleanup'] = f.cleanup()
        except BaseException as exc:
            error = error or exc
            manifest['cleanup'] = {'completed': False, 'status': 'UNKNOWN',
                                   'error': type(exc).__name__ + ': ' + str(exc)}
        try:
            remaining_budget(appointment_started)
            for binary in ('postgres', 'initdb', 'pg_ctl', 'psql'):
                version = f.command(binary + '-version-after', [f.pg / binary, '--version'], cleanup=True).strip()
                require(version == binary + ' (PostgreSQL) 18.6 (Postgres.app)', 'actual PG version changed')
            tools_after = toolchain(lock)
            require(tools_after == tools_before, 'toolchain changed during fixture')
            require(source_closure() == sources_before, 'driver/constructor source changed')
            admit_sources()  # Final named sources/archive/NULL pins, under the original watchdog.
            require(digest(checked(node)) == node_sha, 'constructor executable changed')
            remaining_budget(appointment_started)
            inputs_unchanged = True
            completed = [s for s in ('S0', 'S1', 'S2', 'S3') if (evidence / ('stage-' + s + '.json')).is_file()]
            if f.evidence_errors:
                error = error or OSError('evidence writes failed')
            if error is not None:
                manifest['status'] = 'UNKNOWN_DEADLINE' if isinstance(error, AppointmentDeadline) else 'FAILED'
                manifest['stages'] = {s: ('PASS' if s in completed else 'NOT_COMPLETED') for s in ('S0', 'S1', 'S2', 'S3', 'S4')}
                manifest['lastStage'] = completed[-1] if completed else None
            manifest.update(runId=run_id, appointment=args.appointment, sourceSha256=sources_before,
                            toolchainSha256Before=tools_before, toolchainSha256After=tools_after, nodeSha256=node_sha,
                            elapsedSeconds=round(time.monotonic() - f.started, 3),
                            originalInputsUnchanged=inputs_unchanged, evidenceWriteErrors=f.evidence_errors,
                            privateOwnedDirectoryRetained=error is not None)
            manifest['evidenceSha256'] = {p.name: digest(p.read_bytes()) for p in evidence.iterdir()
                                          if p.name != 'transition-manifest.json' and p.is_file()}
            remaining_budget(appointment_started)
            manifest['authoritative'] = False
            manifest['completionGate'] = 'Matching atomic completion receipt AND independently retained owned-controller exit0 within original900s; manifest alone is never admission'
            manifest_sha = f.save('transition-manifest.json', manifest)
            remaining_budget(appointment_started)  # Includes the final evidence write/hash.
            if manifest.get('cleanup', {}).get('completed') and error is None:
                shutil.rmtree(work)
            remaining_budget(appointment_started)
            if error is None:
                completion_receipt = publish_completion(f, manifest_sha)
            remaining_budget(appointment_started)
        except BaseException as exc:
            error = error or exc
            manifest['status'] = 'UNKNOWN_DEADLINE' if isinstance(exc, AppointmentDeadline) else 'FAILED'
            manifest['finalVerification'] = 'UNKNOWN_DEADLINE' if isinstance(exc, AppointmentDeadline) else 'FAILED'
            manifest['finalizationError'] = type(exc).__name__ + ': ' + str(exc).replace(str(work), '<owned>')
            manifest['privateOwnedDirectoryRetained'] = work.exists()
            # A full disk may prevent any failure manifest. Keep errors buffered
            # for stdout; no I/O retry is allowed after the original deadline.
            try:
                remaining_budget(appointment_started)
                f.try_save('transition-manifest.json', manifest)
                remaining_budget(appointment_started)
            except AppointmentDeadline:
                manifest['status'] = 'UNKNOWN_DEADLINE'
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps({'status': manifest['status'], 'manifest': str(evidence / 'transition-manifest.json'),
                      'cleanup': manifest.get('cleanup', {}).get('completed', False),
                      'evidenceWriteErrors': f.evidence_errors,
                      'completionReceiptPublished': completion_receipt is not None,
                      'requiresExternalOwnedControllerExitZero': True}))
    if error:
        raise SystemExit(1)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    main()
