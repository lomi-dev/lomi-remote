#!/usr/bin/env python3
"""Generate reviewable commands only. This program never connects to Windows."""
import base64
import hashlib
import json
from pathlib import Path
import re
import uuid

from prepare_native import OPTIONS, PEER, ROOT

PROOF = ROOT / 'artifacts/windows/native-9bc026e3-4ede-46eb-a61c-fa1f1de91565.json'

COMMON = r"""$ErrorActionPreference='Stop';
. '__SOURCE__\tests\services-windows\Common.ps1';
Assert-Administrator;
$run='__RUN__'; $operator='__SID__';
$context=Get-FixtureContext $run $operator;
$checkpoint='__SOURCE__\ssh-owner-checkpoint-__RUN__.json';
function Read-Checkpoint {
    $f=Get-Item -LiteralPath $checkpoint -Force;
    if($f.PSIsContainer -or ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $f.Length -gt 4096){throw 'Invalid owned checkpoint file'};
    $c=Get-Content -LiteralPath $checkpoint -Raw|ConvertFrom-Json;
    $g=[Guid]::Empty;
    if($c.magic -cne 'lomi-ssh-owner-v1' -or $c.runId -cne $run -or
       -not [Guid]::TryParseExact($c.ownerEpoch,'D',[ref]$g) -or
       -not [Guid]::TryParseExact($c.sessionEpoch,'D',[ref]$g) -or
       $c.childPid -le 0 -or $c.workerPid -le 0 -or $c.inputWrites -ne 0){throw 'Invalid owned checkpoint schema'};
    $c
}
function Assert-Continuity($s,$c) {
    if($s.ownerEpoch -cne $c.ownerEpoch -or $s.sessionEpoch -cne $c.sessionEpoch -or
       $s.childPid -ne $c.childPid -or $s.observation.syntheticWorkerPid -ne $c.workerPid -or
       $s.jobActiveProcesses -ne 2 -or -not $s.observation.ready -or $s.inputReplayed){throw 'Owner/child/session continuity failed'}
}
"""

START = r"""
if(Test-Path -LiteralPath $checkpoint){throw 'Fresh checkpoint already exists'};
$binary='__SOURCE__\target\debug\lomi-windows-service-fixture.exe';
$null=& '__SOURCE__\tests\services-windows\Install-Fixture.ps1' -DisposableSyntheticResources -RunId $run -OperatorSid $operator -Binary $binary;
Start-OwnedFixture $context;
$null=Invoke-Fixture $context 'client' 'start';
$s=Wait-Fixture $context {param($s) $s.observation.ready -and $s.jobActiveProcesses -eq 2 -and $s.observation.syntheticWorkerPid -gt 0 -and $s.observation.modelNonemptyCells -gt 0};
if($s.observation.inputWrites -ne 0 -or $s.inputReplayed -or -not $s.localService -or $s.sessionId -ne 0){throw 'Initial fixture proof invalid'};
$service=Get-OwnedService $context;
if($service.State -ne 'Running' -or $service.StartMode -ne 'Manual'){throw 'Unexpected owned service state'};
$c=[ordered]@{magic='lomi-ssh-owner-v1';runId=$run;ownerEpoch=$s.ownerEpoch;sessionEpoch=$s.sessionEpoch;childPid=$s.childPid;workerPid=$s.observation.syntheticWorkerPid;inputWrites=$s.observation.inputWrites};
$bytes=[Text.UTF8Encoding]::new($false).GetBytes(($c|ConvertTo-Json -Compress));
$f=[IO.File]::Open($checkpoint,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);
try{$f.Write($bytes,0,$bytes.Length);$f.Flush($true)}finally{$f.Dispose()};
@{phase='start';qualified=$false;serviceRunningAtSshExit=$true;manualStart=$true;checkpointWritten=$true;ownerEpoch=$s.ownerEpoch;sessionEpoch=$s.sessionEpoch;childPid=$s.childPid;workerPid=$s.observation.syntheticWorkerPid;inputWrites=0}|ConvertTo-Json -Compress
# The remote PowerShell ends normally here. The dedicated SSH transport must
# return and close before the controller launches the independent verify command.
"""

VERIFY = r"""
Assert-FixtureRoot $context; $null=Get-OwnedService $context;
$c=Read-Checkpoint;
$s=Invoke-Fixture $context;
Assert-Continuity $s $c;
if($s.observation.inputWrites -ne $c.inputWrites){throw 'Input changed across SSH disconnect'};
$null=Invoke-Fixture $context 'client' 'resize';
$s=Wait-Fixture $context {param($s) $s.observation.resized -and $s.observation.modelRows -eq 37 -and $s.observation.modelCols -eq 101};
Assert-Continuity $s $c;
$null=Invoke-Fixture $context 'client' 'after-detach';
$s=Wait-Fixture $context {param($s) $s.observation.afterDetach};
Assert-Continuity $s $c;
if($s.observation.inputWrites -ne 2){throw 'Unexpected or replayed fixed input'};
@{phase='verify';qualified=$false;unchangedOwnerSessionChildWorker=$true;noInputReplayAcrossSshDisconnect=$true;resize37x101=$true;afterDetachInputObserved=$true;onlyTwoExpectedInputWrites=$true}|ConvertTo-Json -Compress
"""

CLEANUP = r"""
Assert-FixtureRoot $context;
$c=Read-Checkpoint;
$context.CleanupState.OwnerEpoch=$c.ownerEpoch;
$proof=Confirm-OwnedFixtureCleanup $context;
if($proof -isnot [bool] -or $proof -ne $true -or $context.CleanupState.ProvenEpoch -cne $c.ownerEpoch){throw 'Actual current-owner cleanup proof absent'};
$null=& '__SOURCE__\tests\services-windows\Remove-Fixture.ps1' -DisposableSyntheticResources -RunId $run -OperatorSid $operator;
$exe=$context.Exe.Replace('\','\\');
$serviceAbsent=$null -eq (Get-CimInstance Win32_Service -Filter ("Name='"+$context.Name+"'"));
$directoryAbsent=-not(Test-Path -LiteralPath $context.Root);
$processes=@(Get-CimInstance Win32_Process -Filter ("ExecutablePath='"+$exe+"'")).Count;
if(-not $serviceAbsent -or -not $directoryAbsent -or $processes -ne 0){throw 'Owned resources still exist'};
$null=Read-Checkpoint; Remove-Item -LiteralPath $checkpoint -Force;
@{phase='cleanup';qualified=$false;currentOwnerStopProofVerified=$true;serviceAbsent=$true;privateUuidDirectoryAbsent=$true;ownedFixtureProcesses=0;checkpointRemoved=$true}|ConvertTo-Json -Compress
"""


def main():
    proof = json.loads(PROOF.read_text())
    if proof.get('complete') is not True or proof.get('native', {}).get('cleanupVerified') is not True:
        raise ValueError('reviewed native proof incomplete')
    snapshot = proof['snapshot']
    prepared = json.loads((ROOT / 'artifacts/windows' / ('prepare-' + snapshot + '.json')).read_text())
    source = prepared['source']['sourceDirectory'].replace("'", "''")
    sid = proof['environment']['operatorSid']
    if not re.fullmatch(r'S-1-5-21-(\d+-){3}\d+', sid):
        raise ValueError('invalid explicit operator SID')
    run = str(uuid.uuid4())
    commands = []
    for name, body, timeout in [('start', START, 60), ('verify', VERIFY, 40), ('cleanup', CLEANUP, 40)]:
        # Windows OpenSSH's default cmd.exe wrapper has an 8191-character
        # command limit. START does not use either checkpoint helper function.
        prefix = COMMON.split('function Read-Checkpoint', 1)[0] if name == 'start' else COMMON
        script = prefix + body
        for marker, value in [('__SOURCE__', source), ('__RUN__', run), ('__SID__', sid)]:
            script = script.replace(marker, value)
        argv = ['ssh', *OPTIONS, '-T', '-oRequestTTY=no', '-oControlMaster=no', '-oControlPath=none',
                '-oControlPersist=no', PEER, 'powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive',
                '-ExecutionPolicy', 'Bypass', '-EncodedCommand', base64.b64encode(script.encode('utf-16-le')).decode()]
        if len(' '.join(argv[argv.index('powershell.exe'):])) > 7600:
            raise ValueError('remote PowerShell command exceeds bounded transport size')
        commands.append({'phase': name, 'command': argv, 'script': script, 'timeoutSeconds': timeout,
                         'scriptSha256': hashlib.sha256(script.encode()).hexdigest()})
    plan = {'kind': 'windows-ssh-disconnect-review-plan', 'runId': run, 'executed': False,
            'qualified': False, 'snapshot': snapshot, 'nativeProof': PROOF.name,
            'nativeProofSha256': hashlib.sha256(PROOF.read_bytes()).hexdigest(),
            'sourceInventoryDigest': prepared['sourceInventoryDigest'], 'archiveDigest': prepared['archiveDigest'],
            'commands': commands,
            'ordering': 'Wait for start SSH to return exit0 and parse its checkpoint proof, then wait 1 second, then launch verify using a new nonmultiplexed SSH transport. Launch cleanup only after the prior transport has completed and the checkpoint/current owner proof is available.',
            'failurePolicy': 'Any SSH timeout/interrupt or malformed first proof preserves the fixture and checkpoint; never run concurrent cleanup while a remote command may still be executing. A completed verify failure may run the reviewed cleanup phase, which independently binds actual last-stop proof to the recorded owner epoch before removal. Any uncertain cleanup preserves resources and marks the separate evidence incomplete.',
            'notPerformed': ['reboot', 'logoff', 'other SSH-session termination', 'autostart changes', 'default-toolchain changes', 'host SSH configuration changes']}
    output = ROOT / 'artifacts/windows' / ('ssh-disconnect-plan-' + run + '.json')
    output.write_text(json.dumps(plan, indent=2) + '\n')
    print(json.dumps({'executed': False, 'plan': str(output.relative_to(ROOT)), 'runId': run,
                      'planSha256': hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__ == '__main__':
    main()
