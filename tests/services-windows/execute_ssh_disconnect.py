#!/usr/bin/env python3
"""Execute only the specifically reviewed immutable SSH fixture plan."""
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid

from prepare_native import ROOT
sys.path.insert(0, str(ROOT / 'tools'))
from owned_process import initialize_process_ownership, run_owned

PLAN_NAME = 'ssh-disconnect-plan-024ed63f-3e57-4d10-bb27-619d3f6985cd.json'
PLAN_SHA = 'cc957af6461d8d471055a301a4e8f6e2f4fe531bbae6574909fd08406ef1981a'


def validate(phase, value):
    if not isinstance(value, dict) or value.get('phase') != phase or value.get('qualified') is not False:
        raise ValueError('invalid phase envelope')
    required = {
        'start': ('serviceRunningAtSshExit', 'manualStart', 'checkpointWritten'),
        'verify': ('unchangedOwnerSessionChildWorker', 'noInputReplayAcrossSshDisconnect',
                   'resize37x101', 'afterDetachInputObserved', 'onlyTwoExpectedInputWrites'),
        'cleanup': ('currentOwnerStopProofVerified', 'serviceAbsent', 'privateUuidDirectoryAbsent', 'checkpointRemoved'),
    }
    if not all(value.get(key) is True for key in required[phase]):
        raise ValueError('incomplete phase proof')
    if phase == 'start':
        for key in ('ownerEpoch', 'sessionEpoch'):
            if str(uuid.UUID(value[key])) != value[key]:
                raise ValueError('invalid epoch')
        for key in ('childPid', 'workerPid'):
            if type(value.get(key)) is not int or value[key] <= 0:
                raise ValueError('invalid synthetic PID observation')
        if type(value.get('inputWrites')) is not int or value['inputWrites'] != 0:
            raise ValueError('unexpected initial input')
    if phase == 'cleanup' and (type(value.get('ownedFixtureProcesses')) is not int or value['ownedFixtureProcesses'] != 0):
        raise ValueError('owned processes remain')


def execute(plan, evidence, runner=run_owned, pause=time.sleep):
    report = {'kind': 'windows-ssh-disconnect-synthetic-proof', 'runId': plan['runId'],
              'qualified': False, 'complete': False, 'passed': False, 'planSha256': PLAN_SHA,
              'snapshot': plan['snapshot'], 'sourceInventoryDigest': plan['sourceInventoryDigest'],
              'archiveDigest': plan['archiveDigest'], 'nativeProof': plan['nativeProof'],
              'nativeProofSha256': plan['nativeProofSha256'],
              'executorSha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'operations': [], 'not_run': ['abrupt network loss', 'Windows reboot/headless boot', 'logoff', 'other architectures']}
    start_valid = False
    cleanup_attempted = False
    completion_known = True
    verify_passed = False
    code = 1

    def save():
        evidence.write_text(json.dumps(report, indent=2) + '\n')

    def phase(command):
        nonlocal completion_known
        completion_known = False
        row = {'phase': command['phase'], 'command': command['command'],
               'scriptSha256': command['scriptSha256'], 'timeoutSeconds': command['timeoutSeconds'],
               'completionKnown': False, 'passed': False}
        report['operations'].append(row)
        save()
        started = time.monotonic()
        try:
            result = runner(command['command'], cwd=ROOT, timeout=command['timeoutSeconds'])
            row['exitCode'] = result.returncode
            # OpenSSH 255 and local signal exits cannot establish remote completion.
            completion_known = result.returncode >= 0 and result.returncode != 255
            row['completionKnown'] = completion_known
            if result.returncode != 0:
                raise RuntimeError('remote command failed')
            value = json.loads(result.stdout.lstrip('\ufeff'))
            validate(command['phase'], value)
            row['passed'] = True
            row['observation'] = value
            return value
        finally:
            row['durationSeconds'] = round(time.monotonic() - started, 3)
            save()

    save()
    try:
        report['start'] = phase(plan['commands'][0])
        start_valid = True
        # The first owned SSH process has exited before this gap or any new SSH.
        report['gapSeconds'] = 1
        pause(1)
        report['verify'] = phase(plan['commands'][1])
        verify_passed = True
        cleanup_attempted = True
        report['cleanup'] = phase(plan['commands'][2])
        code = 0
    except KeyboardInterrupt:
        report['errorClass'], code = 'KeyboardInterrupt', 130
        completion_known = False
    except BaseException as error:
        report['errorClass'] = type(error).__name__
    finally:
        if start_valid and not cleanup_attempted and completion_known:
            # A completed verify failure may use the independently owner-bound
            # reviewed cleanup command. Unknown completion must preserve state.
            cleanup_attempted = True
            try:
                report['cleanup'] = phase(plan['commands'][2])
            except BaseException as error:
                report['cleanupErrorClass'] = type(error).__name__
        if not cleanup_attempted or not report.get('cleanup'):
            report['cleanupDeferredUncertain'] = True
        report['remoteCompletionKnown'] = completion_known
        report['aggregate'] = {'startProofVerified': start_valid,
                               'freshSshContinuityVerified': verify_passed,
                               'currentOwnerCleanupAndAbsenceVerified': bool(report.get('cleanup'))}
        report.update(complete=code == 0, passed=code == 0, exitCode=code)
        save()
    return code


def main():
    initialize_process_ownership()
    path = ROOT / 'artifacts/windows' / PLAN_NAME
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != PLAN_SHA:
        raise ValueError('reviewed immutable plan hash mismatch')
    plan = json.loads(raw)
    if plan.get('executed') is not False or [c['phase'] for c in plan['commands']] != ['start', 'verify', 'cleanup']:
        raise ValueError('invalid reviewed plan')
    evidence = ROOT / 'artifacts/windows' / ('ssh-disconnect-' + plan['runId'] + '.json')
    native = ROOT / 'artifacts/windows' / plan['nativeProof']
    if hashlib.sha256(native.read_bytes()).hexdigest() != plan['nativeProofSha256']:
        raise ValueError('referenced separate native proof hash mismatch')
    # Atomically claim the one-use UUID before any remote operation.
    with evidence.open('x') as claim:
        json.dump({'qualified': False, 'complete': False, 'claimedRunId': plan['runId']}, claim)
    result = execute(plan, evidence)
    print(json.dumps({'exitCode': result, 'qualified': False, 'evidence': str(evidence.relative_to(ROOT))}))
    return result


if __name__ == '__main__':
    raise SystemExit(main())
