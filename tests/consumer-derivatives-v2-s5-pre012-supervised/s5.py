"""Source-only in-process guardian driver. Runtime needs separate root admission.

This executable is the sole PostgreSQL owner and runs the 18-case fixture in
its own main thread. It never executes the frozen controller or owned helper.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import math
import re
import stat
import resource
import shutil
import sys
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FROZEN = ROOT / 'tests/consumer-derivatives-v2-s5-pre012-extended'
PYTHON = Path('/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14')
PYTHON_SHA = '81c87d90892fe12428ee3b78a675c57c62d6c479236fb359ad5b2d7f07c38b2c'
BASE_SHA = '478790888adf7dea8a9ef4a06e5054eda79b2851ff9f9544699dcd831458d8f2'
FROZEN_SHA = '555394b569208d8fdce28554454fdda41256c91ea49c7b71d2c9af4fa43d09bf'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # dataclasses needs a registered module; import itself starts no processes.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def checked(path, pin):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)) or sha(path.read_bytes()) != pin:
        raise ValueError('source substitution: ' + str(path))


def dependencies():
    checked(FROZEN / 's5.py', FROZEN_SHA)
    checked(ROOT / 'tests/consumer-derivatives-v2/pg-s0-s4.py', BASE_SHA)
    lock_path = HERE / 'inputs.lock.json'
    if lock_path.is_symlink():raise ValueError('source lock symlink')
    lock = json.loads(lock_path.read_bytes())
    actual = {p.name for p in HERE.iterdir()}
    if actual != set(lock['localSha256']) | {'inputs.lock.json'}:
        raise ValueError('successor source allowlist')
    for name, pin in lock['localSha256'].items():checked(HERE / name, pin)
    for name, pin in lock['dependenciesSha256'].items():checked(ROOT / name, pin)
    frozen = load_module('supervised_frozen_dependencies', FROZEN / 's5.py')
    return frozen.dependencies()


class OwnedAdapter:
    """Instance adapter for the frozen Fixture's run_owned interface."""
    def __init__(self, guardian):
        self.guardian = guardian;self.last_child = None;self.last_result = None

    def run_owned(self, argv, *, cwd, env, timeout):
        g = self.guardian
        if cwd != str(g.work) or env != g.env:
            raise ValueError('fixture command ownership environment')
        argv = [str(a) for a in argv]
        names = [name for name, tool in g.tools.items() if argv[0] == str(tool.path)]
        if len(names) != 1:raise ValueError('pinned tool allowlist')
        name = names[0];args = argv[1:]
        if args == ['--version'] and name in ('postgres', 'initdb', 'pg_ctl', 'psql'):
            child = g.tool_version(name)
        elif name == 'initdb' and args == ['-D', str(g.work/'data'), '-U', 'e2_owner', '--auth=trust', '--no-locale', '-E', 'UTF8']:
            child = g.initialize()
        elif name == 'node' and args == [str(ROOT/'tests/consumer-derivatives-v2/pg-s0-s4-bridge.mjs'), str(g.work/'constructor-input.json'), str(g.work/'reference-transcripts.json')]:
            child = g.run_node(*args)
        elif name == 'psql' and len(args) == 17:
            database, path = args[14], Path(args[16])
            wanted = ['-X', '--no-password', '-qAt', '-h', str(g.work/'socket'), '-p', '55439', '-U', 'e2_owner', '-v', 'ON_ERROR_STOP=1', '-v', 'VERBOSITY=verbose', '-d', database, '-f', str(path)]
            if args != wanted:raise ValueError('invalid psql fixture argv')
            child = g.psql(database, path, expected=(0, 3))
        else:raise ValueError('unsupported frozen fixture command')
        result = g.result(child)
        if result.evidenceComplete is not True:raise ValueError('incomplete owned command evidence')
        self.last_child = child;self.last_result = result
        return result


def fixture_class(base, recorder):
    recorded = recorder.fixture_class(base.Fixture)
    class SupervisedFixture(recorded):
        def __init__(self, guardian, *args, raw_log_policy=None, **kwargs):
            self.guardian = guardian;self.raw_log_policy = raw_log_policy
            super().__init__(OwnedAdapter(guardian), *args, **kwargs)
            self.started = guardian.started

        def command(self, *args, **kwargs):
            try:
                output = super().command(*args, **kwargs)
                result = self.owned.last_result;child = self.owned.last_child
                # Preserve exact returned legacy text before deleting raw logs.
                # commands.json still has the frozen path-cleaned strings.
                self.save('owned-result-'+str(self.sequence)+'.json', [
                    dict(stream='stdout',stdout=self.recording_store.compact(result.stdout),rawSha256=result.stdoutSha256),
                    dict(stream='stderr',stdout=self.recording_store.compact(result.stderr),rawSha256=result.stderrSha256)])
                self.guardian.retire_result(child,stdout_sha256=result.stdoutSha256,
                    stderr_sha256=result.stderrSha256)
                return output
            finally:
                self.owned.last_child = None;self.owned.last_result = None

        def start_foreground_postgres(self):
            if self.raw_log_policy is None:raise ValueError('raw-log policy required before foreground PG')
            admitted_files = self.raw_log_policy.admit_fixture_files(self.work/'data')
            self.save('initial-fixture-file-admission.json',admitted_files)
            self.start_attempted = True
            record = self.guardian.start_postgres()
            self.guardian.wait_startup()
            self.guardian.verify_pg_identity()
            # This records a real retained launch, never a synthetic command.
            self.save('foreground-postgres.json', dict(
                argv=list(record.argv), retainedHandlePid=record.handle.pid,
                driverInProcess=True, startupConfirmed=True))

        def cleanup(self):
            # Recorder exceptions cannot intercept the guardian's owned cleanup.
            return self.guardian.cleanup()
    return SupervisedFixture


def publish_receipt(store, manifest_sha, index_sha, guardian):
    if not guardian.observe_qualification():raise ValueError('original900 qualification closed')
    receipt = dict(status='REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO', runId=store.root.name,
        manifestSha256=manifest_sha, storageIndexSha256=index_sha,
        driverInProcess=True, extendedCount=18, originalOuterDeadlineSeconds=900,
        requiresOwnedControllerExitCode=0, manifestAloneIsAdmission=False,
        receiptAloneIsAdmission=False)
    pending = store.root / 'completion-receipt.pending.json'
    with os.fdopen(os.open(pending,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600),'wb') as stream:
        stream.write(receipt_bytes(receipt))
    os.replace(pending, store.root / 'completion-receipt.json')
    if not guardian.observe_qualification():raise ValueError('original900 qualification closed')
    return receipt


def receipt_bytes(receipt):
    return (json.dumps(receipt, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def stored_completion_bytes(reader, name):
    """Read only the two reader-validated exclusions, with a bounded stable fd."""
    if name not in ('transition-manifest.json', 'completion-receipt.json'):
        raise ValueError('completion filename allowlist')
    path = reader.root/name
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid() or before.st_nlink != 1
            or before.st_size > reader.item_limit):raise ValueError('completion file identity')
        raw = stream.read(reader.item_limit+1)
        after = os.fstat(stream.fileno())
        final = path.lstat()
        key = lambda item:(item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns)
        if key(before) != key(after) or key(after) != key(final) or len(raw) != before.st_size:
            raise ValueError('completion file changed')
        return raw


def resource_metadata_is_admissible(value):
    if type(value) is not dict:return False
    fixed = {'inheritedHardFileBytes':32*1024**2,'rawLogLogicalReservationBytes':512*1024**2,
        'cleanupReservedBytes':128*1024**2,'perChildPairReservationBytes':64*1024**2,
        'compactEvidenceBytes':256*1024**2}
    if any(type(value.get(k)) is not int or value[k] != expected for k,expected in fixed.items()):return False
    if not all(value.get(k) is True for k in ('prepared','installed','parentSigxfszIgnored')):return False
    current = value.get('currentReservedBytes')
    if type(current) is not int or not 0 <= current <= 512*1024**2:return False
    admission = value.get('fixtureFileAdmission')
    return (type(admission) is dict and admission.get('allInitialFilesWithinHardCap') is True
        and type(admission.get('observedWalSegmentBytes')) is list
        and len(admission['observedWalSegmentBytes']) == 1
        and type(admission['observedWalSegmentBytes'][0]) is int
        and admission['observedWalSegmentBytes'][0] == 16*1024**2
        and type(admission.get('initialRegularFiles')) is int and admission['initialRegularFiles'] > 0
        and type(admission.get('largestInitialFileBytes')) is int
        and 16*1024**2 <= admission['largestInitialFileBytes'] <= 32*1024**2)


def completion_is_admissible(manifest_bytes, receipt, controller, reader):
    """Match stored run evidence to independent actual outer observations."""
    receipt_fields = {'status','runId','manifestSha256','storageIndexSha256',
        'driverInProcess','extendedCount','originalOuterDeadlineSeconds',
        'requiresOwnedControllerExitCode','manifestAloneIsAdmission','receiptAloneIsAdmission'}
    controller_fields = {'runId','manifestSha256','storageIndexSha256','driverInProcess',
        'ownedControllerExitCode','completed','originalOuterDeadlineSeconds','elapsedSeconds'}
    if (type(manifest_bytes) is not bytes or type(receipt) is not dict
        or type(controller) is not dict or set(receipt) != receipt_fields
        or set(controller) != controller_fields):return False
    if reader.validate() is not True:return False
    try:
        if stored_completion_bytes(reader,'transition-manifest.json') != manifest_bytes:return False
        if stored_completion_bytes(reader,'completion-receipt.json') != receipt_bytes(receipt):return False
    except (OSError, ValueError, TypeError):return False
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:raise ValueError('duplicate manifest key')
            result[key] = value
        return result
    try:
        m = json.loads(manifest_bytes,object_pairs_hook=pairs,
            parse_constant=lambda value:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
        run_id = receipt['runId']
        if type(run_id) is not str or str(uuid.UUID(run_id)) != run_id:return False
    except (ValueError, TypeError):return False
    if (type(m) is not dict or type(m.get('qualification')) is not dict
        or type(m.get('cleanup')) is not dict):return False
    for value in (receipt['manifestSha256'],receipt['storageIndexSha256'],
                  controller['manifestSha256'],controller['storageIndexSha256'],m.get('storageIndexSha256')):
        if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:return False
    elapsed = controller['elapsedSeconds']
    if not (run_id == reader.root.name == m.get('runId') == controller['runId']
        and m.get('status') == 'PROVISIONAL_PRE012_EXTENDED_SUBSET_PENDING_ROOT_REVIEW'
        and m.get('authoritative') is False and m.get('driverInProcess') is True
        and m.get('fullS5Qualified') is False and m.get('qualification', {}).get('S5') is False
        and m.get('stages') == {'PRE012_PREFIX':'PASS','PRE012_EXTENDED_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'}
        and m.get('boundedSubsetCompleted') is True and m.get('extendedCompleted') is True
        and type(m.get('extendedCount')) is int and m['extendedCount'] == 18
        and m.get('first012Committed') is True and m.get('originalInputsUnchanged') is True
        and type(m.get('remainingConstructibleCases')) is int and m['remainingConstructibleCases'] == 4
        and m.get('cleanup', {}).get('completed') is True
        and m.get('cleanup', {}).get('qualificationEligible') is True
        and m.get('cleanup', {}).get('qualificationDeadlineExpired') is False
        and m.get('cleanup', {}).get('evidenceErrors') == []
        and m.get('cleanup', {}).get('ownershipUnresolved') is False
        and m.get('recordingComplete') is True and m.get('evidenceWriteErrors') == []
        and resource_metadata_is_admissible(m.get('rawLogResourcePolicy'))
        and receipt['status'] == 'REQUIRES_EXTERNAL_CONTROLLER_EXIT_ZERO'
        and receipt['driverInProcess'] is True and type(receipt['extendedCount']) is int and receipt['extendedCount'] == 18
        and receipt['manifestAloneIsAdmission'] is False and receipt['receiptAloneIsAdmission'] is False
        and receipt['manifestSha256'] == sha(manifest_bytes) == controller['manifestSha256']
        and receipt['storageIndexSha256'] == m['storageIndexSha256'] == controller['storageIndexSha256'] == reader.index_pin
        and type(receipt['requiresOwnedControllerExitCode']) is int and receipt['requiresOwnedControllerExitCode'] == 0
        and type(receipt['originalOuterDeadlineSeconds']) is int and receipt['originalOuterDeadlineSeconds'] == 900
        and type(controller['originalOuterDeadlineSeconds']) is int and controller['originalOuterDeadlineSeconds'] == 900
        and type(controller['ownedControllerExitCode']) is int and controller['ownedControllerExitCode'] == 0
        and controller['completed'] is True and controller['driverInProcess'] is True
        and type(elapsed) in (int,float) and 0 <= elapsed < 900 and math.isfinite(elapsed)):return False
    results = reader.read('extended-results.json')
    cases = reader.read('extended-source-cases.json')
    if type(results) is not list or type(cases) is not list or not all(type(x) is dict for x in results+cases):return False
    accepted = (len(results) == len(cases) == 18 and len({r['id'] for r in results}) == 18
        and [r['id'] for r in results] == [c['id'] for c in cases]
        and cases[-1]['kind'] == 'reapply'
        and all(r['status'] == 'PASS' and r['sqlstate'] == '55000'
            and r['allThreeDatabasesRawRollback'] is True for r in results))
    # Recheck exclusions/index after decoding results, so a late replacement
    # cannot rebind this supplied tuple to another stored run.
    return (accepted and reader.validate() is True
        and stored_completion_bytes(reader,'transition-manifest.json') == manifest_bytes
        and stored_completion_bytes(reader,'completion-receipt.json') == receipt_bytes(receipt))


def run_s5(base,f,inputs,constructor,admitted,derived,manifest):
    lock=dependencies();prior_dir=ROOT/'tests/consumer-derivatives-v2-s5-pre012'
    prefix=load_module('extended_prefix',HERE/'prefix.py')
    protocol=load_module('extended_protocol',prior_dir/'cases.py')
    model=load_module('extended_cases',HERE/'cases.py')
    predecessor=load_module('extended_predecessor',ROOT/'tests/consumer-derivatives-v2/predecessor-model.py')
    contract=json.loads(base.checked(ROOT/'staging/consumer-derivatives-v2/predecessor-contract.json'))
    reference=json.loads(base.checked(ROOT/lock['referenceRawCapture']))
    guard=predecessor.guard_sql(contract)
    projection=guard[guard.index(' SELECT coalesce('):guard.index(' IF actual IS DISTINCT')].replace(' INTO actual','',1)
    capture=base.checked(prior_dir/'raw-capture.sql').decode()+"SELECT jsonb_build_object('section','selected','rows',q.value) FROM ("+projection.strip().removesuffix(';')+") q(value);\n"
    manifest.update(prefix.execute(base,f,inputs))
    def snapshot(database,label):
        rows=f.capture(database,label,capture);sections=model.sections(rows)
        base.require(sections['ledger']==[{'count':0}] and sections['consumerRows']==[{'count':0}],'empty fixtures')
        base.require(not any(r['name'].startswith('fixture_pre012') for r in sections['objects']),'setup object present')
        return rows
    baseline={db:snapshot(db,'extended-baseline-'+db) for db in base.DATABASES}
    builtin_sql=base.checked(HERE/'builtin-trigger-identities.sql').decode();builtins=None
    for db in base.DATABASES:
        identities=f.capture(db,'builtin-trigger-identities-'+db,builtin_sql)
        actual=model.admit_builtins(identities,baseline[db])
        if builtins is None:builtins=actual
        else:base.require(actual==builtins,'cluster builtin identity mismatch')
    f.save('admitted-builtin-trigger-oid-map.json',builtins)
    def pristine(label,migrated=None):
        for db in base.DATABASES:
            rows=snapshot(db,label+'-'+db)
            base.require(rows==baseline[db],'raw same-DB catalog rollback mismatch')
            if db!=migrated:predecessor.admit_predecessors(model.sections(rows)['selected'],contract)
    cases=model.build(contract);f.save('extended-source-cases.json',cases);results=[]
    operator=base.checked(ROOT/'staging/consumer-derivatives-v2/012-derivative-authority.candidate.sql').decode()
    for index,case in enumerate(cases):
        pristine('before-'+case['id']);database=base.DATABASES[index%3];migrated=None
        if case['kind']=='reapply':
            base.require(index==17 and len(results)==17,'reapply must be last')
            first=model.first012_script(operator)
            f.save('first012-unchanged-script.json',dict(sql=first,unchanged012Sha256=constructor.sha(operator.encode())))
            output=f.sql(database,'first012-separate-commit',first)
            model.admit_first012_stdout(output)
            postfirst=snapshot(database,'post-first012-baseline-'+database)
            base.require(postfirst!=baseline[database],'first012 did not change baseline')
            base.require(len([r for r in model.sections(postfirst)['objects'] if r['name']=='consumer_derivative_consent'])==1,'first012 successor relation absent')
            baseline[database]=postfirst;migrated=database
            pristine('before-second012',migrated)
            manifest.update(first012Committed=True,first012Database=database)
        script=protocol.branch_sql(case,capture,operator);path=f.work/('extended-'+case['id']+'.sql');path.write_text(script)
        f.save('script-'+case['id']+'.json',dict(case=case,sql=script,unchanged012Sha256=constructor.sha(operator.encode())))
        stdout=f.command('extended-attempt-'+case['id'],[f.pg/'psql','-X','--no-password','-qAt','-h',f.work/'socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',database,'-f',path],expected=(3,))
        setup=protocol.parse_result(case,stdout,f.events[-1]['stderr'],base.parse_catalog)
        expected=model.expected_setup(case,baseline[database],setup,reference,builtins)
        f.save('setup-'+case['id']+'.json',setup);f.save('expected-setup-'+case['id']+'.json',expected)
        base.require(setup==expected,'undeclared setup catalog change')
        pristine('after-'+case['id'],migrated)
        results.append(dict(id=case['id'],status='PASS',allThreeDatabasesRawRollback=True,sqlstate='55000',baselineKind='post-first012' if migrated else 'pristine-pre012'))
        f.save('extended-results.json',results)
    manifest.update(status='PROVISIONAL_PRE012_EXTENDED_SUBSET_PENDING_ROOT_REVIEW',stages={'PRE012_PREFIX':'PASS','PRE012_EXTENDED_SUBSET':'SUBSET_PASS','S3':'NOT_RUN','S4':'NOT_RUN'},fullS5Qualified=False,boundedSubsetCompleted=True,extendedCompleted=True,extendedCount=18,qualification={'S5':False},priorAccepted10ChecksReexecuted=False,priorAccepted202ChecksReexecuted=False,prismaLedgerQualified=False,remainingConstructibleCases=4)
    return manifest



def main():
    started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--appointment', required=True)
    parser.add_argument('--node', required=True, type=Path)
    parser.add_argument('--derived', required=True, type=Path)
    args = parser.parse_args()
    if Path(sys.executable) != PYTHON or not (sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode):
        raise ValueError('pinned Python -I -S -B required')
    checked(PYTHON, PYTHON_SHA)
    dependencies()  # Entire source allowlist is checked before guardian import.
    frozen = load_module('supervised_frozen_constructor', FROZEN/'s5.py')
    constructor = frozen.load_constructor()
    admitted = constructor.load_admitted()
    base = load_module('supervised_pinned_base', ROOT/admitted[0]['driver'])
    base.require(bool(args.appointment.strip()) and args.node.is_absolute(), 'appointment/absolute Node required')
    node = args.node.resolve(strict=True);base.checked(node, base.NODE_HASH)
    derived, delta = constructor.construct()
    base.require(args.derived.is_dir() and not args.derived.is_symlink(), 'derived directory missing/symlink')
    base.require(set(p.name for p in args.derived.iterdir()) == set(derived)|{'derived-manifest.json'}, 'derived file allowlist')
    for name, raw in derived.items():base.require(base.checked(args.derived/name) == raw, 'derived source substitution')
    base.require(json.loads(base.checked(args.derived/'derived-manifest.json')) == delta, 'derived delta substitution')
    lock, inputs, tools_before, _unused_support_path = base.admit_sources()
    source_lock = (HERE/'inputs.lock.json').read_bytes()
    recorder = load_module('supervised_compact_recorder', ROOT/'tests/consumer-fixture-evidence/recording.py')
    guardian_module = load_module('supervised_pg_guardian', ROOT/'tests/consumer-pg-guardian/guardian.py')
    policy_module = load_module('supervised_resource_policy',HERE/'resource_policy.py')
    log_policy = policy_module.ResourcePolicy()
    os.umask(0o077);resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    base.require(shutil.disk_usage('/private/tmp').free >= 2*1024**3, 'need2GiB free space')
    evidence = ROOT/'artifacts/consumer-derivatives-v2-s5-pre012-supervised-runtime'/str(uuid.uuid4())
    evidence.parent.mkdir(parents=True, exist_ok=True)
    store = recorder.EvidenceStore(evidence)  # One shared256MiB format-v2 store.
    pg = ROOT/lock['toolchainRoot']/'Postgres.app/Contents/Versions/18/bin'
    tool_pins = {**lock['toolchainCoreSha256'], **lock['toolchainInitdbSha256']}
    tools = {name:guardian_module.Executable(pg/name, tool_pins['Contents/Versions/18/bin/'+name])
             for name in ('postgres', 'initdb', 'pg_ctl', 'psql')}
    tools['node'] = guardian_module.Executable(node, base.NODE_HASH)
    work = Path(tempfile.mkdtemp(prefix='lcd-s5-supervised-', dir='/private/tmp')).resolve()
    guardian = guardian_module.Guardian(work, tools, started=started, run_id=evidence.name,log_policy=log_policy)
    manifest = dict(status='FAILED', authoritative=False, driverInProcess=True,
        fullS5Qualified=False, boundedSubsetCompleted=False, extendedCompleted=False,
        stages={'PRE012_EXTENDED_SUBSET':'INCOMPLETE','S3':'NOT_RUN','S4':'NOT_RUN'},
        originalPinsModified=False, pinsFilled=False, measuredOperatorsExecuted=False,
        prismaLedgerQualified=False, privateOwnedDirectoryRetained=True,
        qualification={k:False for k in ('S5','HTTP','BetterAuth','UI','Prisma012','production')})
    error = None;fixture = None;completion = None
    # The guard includes installation and fixture construction; no child can
    # launch before Guardian's work registration and nonraising signal handlers.
    try:
        guardian.install()
        try:
            fixture = fixture_class(base, recorder)(guardian, lock, work, evidence,
                args.appointment, node, recording_store=store,raw_log_policy=log_policy)
            fixture.save('derived-manifest.json', delta)
            for name, raw in derived.items():store.save_bytes(name, raw)
            run_s5(base, fixture, inputs, constructor, admitted, derived, manifest)
        finally:
            if fixture is not None:fixture.cleanup()
    except BaseException as exc:
        error = exc
        manifest['error'] = type(exc).__name__ + ': ' + str(exc).replace(str(work), '<owned>')
    finally:
        # UNKNOWN cannot exit as the sole owner. This may retain the owner beyond
        # fixed960; it can never make a result after original900 qualify.
        cleanup = guardian.finish_owner()
    try:
        dependencies();constructor.load_admitted()
        base.require((HERE/'inputs.lock.json').read_bytes() == source_lock, 'source lock drift')
        tools_after = base.toolchain(lock)
        base.require(tools_after == tools_before, 'tool drift')
        base.checked(node, base.NODE_HASH)
        for name, raw in derived.items():base.require(base.checked(args.derived/name) == raw, 'derived source drift')
        base.require(json.loads(base.checked(args.derived/'derived-manifest.json')) == delta, 'delta drift')
        if fixture is None or fixture.evidence_errors or guardian.evidence_errors:
            raise ValueError('fixture/guardian evidence incomplete')
        manifest.update(cleanup=cleanup, runId=evidence.name, appointment=args.appointment,
            originalInputsUnchanged=True, sourceLockSha256=sha(source_lock),
            toolchainSha256Before=tools_before, toolchainSha256After=tools_after,
            elapsedSeconds=round(time.monotonic()-started, 6),
            evidenceWriteErrors=list(fixture.evidence_errors)+list(guardian.evidence_errors))
        if (error is not None or not cleanup['completed']
            or cleanup['qualificationEligible'] is not True
            or cleanup['qualificationDeadlineExpired'] is not False
            or not guardian.observe_qualification()):
            raise ValueError('unqualified fixture completion')
        cleanup_commands = [];cleanup_records = []
        for child in guardian.children:
            if child.name == 'pg_ctl' and child.argv[-1] in ('stop', 'status') and not child.retired:
                result = guardian.result(child)
                base.require(result.evidenceComplete is True, 'cleanup command evidence incomplete')
                cleanup_commands.append(dict(argv=list(result.argv), pid=result.pid,
                    returncode=result.returncode, stdout=result.stdout, stderr=result.stderr))
                cleanup_records.append((child,result))
        store.save('guardian-cleanup-commands.json', cleanup_commands)
        for child,result in cleanup_records:
            guardian.retire_result(child,stdout_sha256=result.stdoutSha256,stderr_sha256=result.stderrSha256)
        manifest['rawLogResourcePolicy'] = log_policy.metadata()
        base.require(resource_metadata_is_admissible(manifest['rawLogResourcePolicy']), 'resource metadata admission incomplete')
        hashes = store.seal()
        index_sha = hashes['storage-index.json']
        reader = recorder.EvidenceReader(evidence, expected_index_sha256=index_sha)
        base.require(reader.validate() is True, 'reader qualification incomplete')
        for name, raw in derived.items():base.require(reader.raw(name) == raw, 'derived recorded bytes drift')
        results = reader.read('extended-results.json')
        cases = reader.read('extended-source-cases.json')
        base.require(len(results) == len(cases) == 18
            and len({r['id'] for r in results}) == 18
            and [r['id'] for r in results] == [c['id'] for c in cases]
            and cases[-1]['kind'] == 'reapply'
            and all(r['status'] == 'PASS' and r['sqlstate'] == '55000'
                and r['allThreeDatabasesRawRollback'] is True for r in results), 'actual case completion')
        manifest.update(recordingComplete=True, storageIndexSha256=index_sha, evidenceSha256=hashes,
            completionGate='matching format-v2 reader + receipt + independently observed actual driver exit0 within original900; root review required')
        manifest_sha = store.save('transition-manifest.json', manifest)
        completion = publish_receipt(store, manifest_sha, index_sha, guardian)
        base.require(reader.validate() is True, 'reader qualification incomplete')
    except BaseException as exc:
        error = error or exc
        manifest.update(status='FAILED', fullS5Qualified=False, boundedSubsetCompleted=False,
            extendedCompleted=False, cleanup=cleanup, runId=evidence.name,
            rawLogResourcePolicy=log_policy.metadata(),
            recordingComplete=False, qualificationAllowed=False,
            finalizationError=type(exc).__name__+': '+str(exc).replace(str(work), '<owned>'))
        manifest['stages'] = {'PRE012_EXTENDED_SUBSET':'INCOMPLETE','S3':'NOT_RUN','S4':'NOT_RUN'}
        try:
            if not store.sealed:store.seal()
            store.save('transition-manifest.json', manifest)
        except BaseException:pass  # Work, index and owned evidence remain retained.
    print(json.dumps(dict(status=manifest['status'], manifest=str(evidence/'transition-manifest.json'),
        cleanup=cleanup['completed'], driverInProcess=True,
        completionReceiptPublished=completion is not None,
        requiresExternalOwnedControllerExitZero=True)))
    if error is not None:raise SystemExit(1)


if __name__ == '__main__':
    sys.dont_write_bytecode = True
    main()
