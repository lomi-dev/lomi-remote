"""Opt-in ordinary interactive Windows proof; never changes login/security policy."""
import hashlib
import json
import re
import time
import uuid
from datetime import datetime

SID = 'S-1-5-21-1379812509-1041957290-335626797-1005'
LAUNCH_STAGES = {'Admission', 'InstanceIdentity', 'Bind', 'Marker', 'Refresh', 'State', 'Readiness'}
LOGIN_ERRORS = {'LOGIN_INVALID_CONFIGURATION', 'LOGIN_OWNERSHIP_CONFLICT', 'LOGIN_TASK_SETUP_UNAVAILABLE', 'LOGIN_OPERATION_UNCERTAIN', 'LOGIN_HOST_NOT_READY', 'LOGIN_ORDINARY_CURRENT_ACCOUNT_REQUIRED', 'LOGIN_INTERACTIVE_SESSION_REQUIRED', 'LOGIN_MANAGED_HELPER_REQUIRED', 'LOGIN_NOT_INSTALLED'}

def wrapper_completed(state,before_last_run):
    if any(type(state.get(name)) is not int for name in ['state','instances','last']):
        raise RuntimeError('Malformed helper completion observation')
    try:
        before=datetime.fromisoformat(before_last_run)
        current=datetime.fromisoformat(state['lastRunTime'])
    except (KeyError,TypeError,ValueError) as error:
        raise RuntimeError('Helper execution timestamp missing') from error
    try:
        return state['state']==3 and state['instances']==0 and state['last'] not in (0x41301,0x41303) and current.year>=2000 and current>before
    except TypeError as error:
        raise RuntimeError('Inconsistent helper execution timestamps') from error

def wait_for_wrapper(poll,before_last_run,deadline,now=time.monotonic,sleep=time.sleep):
    while True:
        if now()>=deadline:raise RuntimeError('Helper completion unknown; preserve task/files, no forced termination')
        state=poll()
        if now()>=deadline:raise RuntimeError('Helper completion unknown; preserve task/files, no forced termination')
        if wrapper_completed(state,before_last_run):return state
        sleep(2)


def require_preflight(value):
    if value.get('sid') != SID or value.get('enabled') is not True or value.get('administrator') is not False:
        raise RuntimeError('Expected enabled ordinary test-user account required')
    if type(value.get('session')) is not int or value['session'] <= 0:
        raise RuntimeError('An active interactive test-user session is required; leave it logged in')


def preflight(evidence):
    script = r"""$ErrorActionPreference='Stop';$u=Get-LocalUser -Name 'test-user';$admin=@(Get-LocalGroupMember -SID 'S-1-5-32-544'|Where-Object{$_.SID.Value -eq $u.SID.Value}).Count -ne 0;$rows=@(& quser.exe 2>$null);if($LASTEXITCODE -ne 0){throw 'Session query failed'};$sessions=@(foreach($row in $rows){if($row -match '^\s*>?test-user\s+.*?\s(\d+)\s+Active\s'){[int]$Matches[1]}});$session=if($sessions.Count -eq 1){$sessions[0]}else{0};@{sid=$u.SID.Value;enabled=$u.Enabled;administrator=$admin;session=$session;sessionRows=$rows}|ConvertTo-Json -Compress"""
    value = json.loads(evidence.ps('readonly-ordinary-interactive-preflight', script))
    evidence.report['ordinaryPreflight'] = value
    evidence.save()
    require_preflight(value)
    return value


def require_result(value, run, session, fixture_diagnostics=False):
    if value.get('runId') != run or value.get('sid') != SID or value.get('session') != session or type(session) is not int or session <= 0 or value.get('administratorGroup') is not False:
        raise RuntimeError('Ordinary lifecycle identity not proved')
    for key in ('passed', 'complete', 'ordinaryInteractiveLifecycleQualified', 'productTaskAbsent', 'dataPreserved'):
        if value.get(key) is not True:
            raise RuntimeError('Ordinary lifecycle incomplete: ' + key)
    if value.get('logonTriggerQualified') is not False or value.get('visibleConsoleQualified') is not False:
        raise RuntimeError('Unsupported logon/console qualification')
    if value.get('fixtureDiagnostics') is not fixture_diagnostics:
        raise RuntimeError('Lifecycle feature qualification mismatch')
    if type(value.get('ownedHostsRemaining')) is not int or value['ownedHostsRemaining'] != 0:
        raise RuntimeError('Owned host remains')
    checks = {row['name'] for row in value.get('checks', []) if row.get('passed') is True}
    required = {'two-real-ipc-clients-same-runtime-sharing-disabled', 'actual-managed-helper-ordinary-interactive-session', 'stopped-restart-new-runtime-same-host-two-clients', 'running-restart-new-runtime-same-host-two-clients', 'initial-single-owned-host-and-task', 'stopped-restart-single-owned-host-and-task', 'running-restart-single-owned-host-and-task', 'private-owned-task-folder-and-profile-acls', 'uninstall-exact-folder-absent-data-preserved-no-hosts'}
    if not required <= checks:
        raise RuntimeError('Actual lifecycle checks missing')
    inventories=value.get('hostInventories',[])
    if len(inventories)!=3 or {row.get('label') for row in inventories}!={'initial','stopped-restart','running-restart'}:
        raise RuntimeError('All independent singleton inventories required')
    for row in inventories:
        expected={'cimExactHosts':1,'nativeExactHosts':1,'nativeUnreadableLiveCandidates':0,'folderTasks':1,'folderSubfolders':0}
        if any(type(row.get(key)) is not int or row[key]!=count for key,count in expected.items()) or type(row.get('schedulerInstances')) is not int or row['schedulerInstances'] not in (0,1) or type(row.get('schedulerState')) is not int or row.get('markerProcessBirthMatched') is not True or row.get('ownerSidMatched') is not True:
            raise RuntimeError('Independent singleton identity not proved')
    for name in ('restartRuntimes','restartRuns'):
        values=value.get(name,[])
        if len(values)!=3 or not all(isinstance(item,str) and item for item in values) or len(set(values))!=3:
            raise RuntimeError('Both restart generation transitions missing')
    operations=value.get('operations',[])
    if sum(operation.get('arguments')==['service','restart'] and operation.get('exitCode')==0 for operation in operations)!=2:
        raise RuntimeError('Both successful restart operations missing')
    for operation in value.get('operations',[]):
        if not fixture_diagnostics and operation.get('launchDiagnostics'):
            raise RuntimeError('Fixture diagnostics in default product evidence')
        for diagnostic in operation.get('launchDiagnostics',[]):
            if set(diagnostic)!={'stage','category'} or diagnostic['stage'] not in LAUNCH_STAGES or diagnostic['category'] not in LOGIN_ERRORS:
                raise RuntimeError('Unexpected launch diagnostic fields')


def require_cleanup(value):
    for key in ('helperTaskAbsent','ordinaryRootAbsent','stageAbsent','freshAbsenceAudit'):
        if value.get(key) is not True:
            raise RuntimeError('Ordinary cleanup incomplete: '+key)


def execute(evidence, source, binaries):
    """Only called with current frozen build directory, never CLI-supplied paths."""
    identity=preflight(evidence);run=evidence.report['runId'];session=identity['session']
    if str(uuid.UUID(run))!=run or "'" in source or not source.endswith('lomi-windows-login-'+run):
        raise ValueError('Canonical owned source required')
    hashes={item['name']:item['sha256'] for item in binaries}
    inputs=evidence.report['inputs']['files']
    scripts={name:inputs['tests/product-login-windows/'+name]['sha256'] for name in ('lifecycle.ps1','lifecycle-admin.ps1','lifecycle-identity.ps1')}
    if any(not re.fullmatch('[0-9a-f]{64}',value) for value in [*hashes.values(),*scripts.values()]):
        raise ValueError('Frozen binary/script hashes required')
    stage=rf'C:\ProgramData\LomiLoginProof-{run}'
    admin=source+r'\tests\product-login-windows\lifecycle-admin.ps1'
    arguments=f"-RunId '{run}' -Source '{source}' -ExpectedSid '{SID}' -ExpectedSession {session} -CliHash '{hashes['lomiremote.exe']}' -HelperHash '{hashes['lomiremote-host.exe']}' -ScriptHash '{scripts['lifecycle.ps1']}' -IdentityHash '{scripts['lifecycle-identity.ps1']}'"
    if evidence.report.get('fixtureDiagnostics') is True:arguments+=' -FixtureDiagnostics'
    def invoke(phase,extra=''):
        script=f"$ErrorActionPreference='Stop';$p='{admin}';if((Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant() -cne '{scripts['lifecycle-admin.ps1']}'){{throw 'Frozen admin runner changed'}};& $p -Phase '{phase}' {arguments} {extra}"
        return evidence.ps('ordinary-'+phase,script)
    invoke('stage')
    if preflight(evidence)['session']!=session:
        raise RuntimeError('Ordinary active session changed')
    evidence.report.pop('taskSchedulerMutations',None)
    evidence.report['taskSchedulerMutationsAttempted']=True
    evidence.save()
    evidence.report['helperTask']=json.loads(invoke('launch'));evidence.save()
    deadline=time.monotonic()+420
    before=evidence.report['helperTask'].get('identity',{}).get('beforeLastRunTime')
    if not isinstance(before,str):raise RuntimeError('Fresh helper execution baseline missing')
    state=wait_for_wrapper(lambda:json.loads(invoke('poll')),before,deadline)
    evidence.report['ordinaryHelperCompletion']=state;evidence.save()
    result_bytes=invoke('collect');value=json.loads(result_bytes)
    evidence.report['ordinaryLifecycle']=value
    evidence.report['ordinaryResultSha256']=hashlib.sha256(result_bytes.encode()).hexdigest()
    evidence.save();require_result(value,run,session,evidence.report.get('fixtureDiagnostics') is True)
    if state.get('last')!=0:raise RuntimeError('Ordinary helper did not exit successfully')
    result_hash=evidence.report['ordinaryResultSha256']
    inventory_bytes=invoke('inventory',f"-ResultHash '{result_hash}'");inventory=json.loads(inventory_bytes)
    if inventory.get('runId')!=run or inventory.get('root')!=value.get('root'):
        raise RuntimeError('Independent cleanup root mismatch')
    inventory_path=evidence.path.with_name(run+'.ordinary-inventory.json')
    inventory_path.write_text(inventory_bytes,encoding='utf-8')
    inventory_hash=hashlib.sha256(inventory_path.read_bytes()).hexdigest()
    evidence.report['ordinaryCleanupInventory']=inventory;evidence.report['ordinaryCleanupInventorySha256']=inventory_hash;evidence.save()
    evidence.transfer('transfer-pinned-ordinary-cleanup-inventory',inventory_path,stage+'/ordinary-inventory.json')
    cleanup=json.loads(invoke('delete-helper'));evidence.report['ordinaryCleanup']=cleanup;evidence.save()
    cleanup.update(json.loads(invoke('delete-root',f"-InventoryHash '{inventory_hash}' -ResultHash '{result_hash}'")));evidence.save()
    cleanup.update(json.loads(invoke('delete-stage',f"-InventoryHash '{inventory_hash}' -ResultHash '{result_hash}'")));evidence.save()
    installation=value.get('installation')
    if str(uuid.UUID(installation))!=installation:raise RuntimeError('Product installation UUID missing')
    root=inventory['root']
    if "'" in root:raise RuntimeError('Unexpected ordinary root')
    task='LomiLoginProof-'+run
    audit=f"$ErrorActionPreference='Stop';$s=New-Object -ComObject 'Schedule.Service';$s.Connect();foreach($path in @('task','folder')){{try{{if($path -eq 'task'){{$null=$s.GetFolder('\\').GetTask('{task}')}}else{{$null=$s.GetFolder('\\LomiRemote-{installation}')}};throw 'Owned task remains'}}catch{{if(($_.Exception.HResult -band 0xffffffffL) -notin @(0x80070002L,0x80070003L)){{throw}}}}}};if((Test-Path -LiteralPath '{root}') -or (Test-Path -LiteralPath '{stage}') -or @(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith('{root}\\',[StringComparison]::OrdinalIgnoreCase)}}).Count -ne 0){{throw 'Owned UUID resource remains'}};@{{freshAbsenceAudit=$true}}|ConvertTo-Json -Compress"
    cleanup.update(json.loads(evidence.ps('fresh-independent-task-file-process-absence-audit',audit)));evidence.save();require_cleanup(cleanup)
    return value
