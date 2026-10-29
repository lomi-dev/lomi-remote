#!/usr/bin/env python3
"""Exact never-run helper recovery, separate from successful lifecycle cleanup."""
from pathlib import Path
import argparse
import hashlib
import json
import sys
import uuid
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tools'))
from owned_process import initialize_process_ownership
from run_windows_git_wasi_spike import Evidence
from lifecycle import SID


def prepare_intent(failed):
    run=failed['runId']
    if failed.get('passed') is not False or failed.get('complete') is not False or failed.get('kind')!='native-windows-ordinary-login-lifecycle' or failed.get('taskSchedulerMutationsAttempted') is not True or str(uuid.UUID(run))!=run or failed.get('failure')!='ordinary-launch: command failed' or failed.get('ordinaryInteractiveLifecycleQualified') is not False:
        raise RuntimeError('Exact failed prelaunch receipt required')
    launches=[row for row in failed.get('operations',[]) if row.get('name')=='ordinary-launch']
    if len(launches)!=1 or launches[0].get('passed') is not False or launches[0].get('completionKnown') is not True or launches[0].get('exitCode')!=1:
        raise RuntimeError('Exact failed registration completion required')
    snapshot=failed.get('neverRunHelperSnapshot',{})
    if (snapshot.get('state')!=3 or snapshot.get('instances')!=0 or snapshot.get('last')!=267011
        or snapshot.get('lastRunTime')!='1999-11-30T00:00:00.0000000' or snapshot.get('sid')!=SID):
        raise RuntimeError('Exact never-run snapshot required')
    return {'failedRunId':run,'taskName':'LomiLoginProof-'+run,'xmlSha256':hashlib.sha256(snapshot['xml'].encode()).hexdigest(),'sddlSha256':hashlib.sha256(snapshot['sddl'].encode()).hexdigest(),'expectedLastRunTime':snapshot['lastRunTime'],'expectedLastTaskResult':267011,'expectedState':3,'expectedInstances':0,'expectedSid':SID}


def prepare(path):
    initialize_process_ownership()
    data=path.read_bytes();failed=json.loads(data);intent=prepare_intent(failed)
    run=intent['failedRunId'];recovery=str(uuid.uuid4())
    report={'format':1,'runId':recovery,'kind':'explicit-never-run-login-helper-recovery','passed':False,'complete':False,'operations':[],'intent':intent,'failedReceiptSha256':hashlib.sha256(data).hexdigest(),'productLifecycleQualified':False,'taskDeletionAttempted':False,'filesRetained':True}
    evidence=Evidence(path.with_name(recovery+'.recovery.json'),report)
    # Durable local intent precedes even the remote revalidation/deletion request.
    evidence.save()
    script=f"""$ErrorActionPreference='Stop';function Hash([string]$v){{$sha=[Security.Cryptography.SHA256]::Create();try{{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($v)))).Replace('-','').ToLowerInvariant()}}finally{{$sha.Dispose()}}}};$s=New-Object -ComObject 'Schedule.Service';$s.Connect();$r=$s.GetFolder('\\');$t=$r.GetTask('{intent['taskName']}');$d=$t.Definition;$sid=if($d.Principal.UserId.StartsWith('S-1-')){{$d.Principal.UserId}}else{{[Security.Principal.NTAccount]::new($d.Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}};if($t.Path -cne '\\{intent['taskName']}' -or $d.Data -cne '{run}' -or $sid -cne '{SID}' -or $d.Principal.LogonType -ne 3 -or $d.Principal.RunLevel -ne 0 -or $d.Actions.Count -ne 1 -or $d.Triggers.Count -ne 0 -or (Hash $t.Xml) -cne '{intent['xmlSha256']}' -or (Hash $t.GetSecurityDescriptor(7)) -cne '{intent['sddlSha256']}' -or $t.State -ne 3 -or $t.GetInstances(0).Count -ne 0 -or $t.LastTaskResult -ne 267011 -or $t.LastRunTime.ToString('o') -cne '{intent['expectedLastRunTime']}'){{throw 'Never-run exact ownership changed; preserve'}};$profiles=@(Get-CimInstance Win32_UserProfile|Where-Object{{$_.SID -ceq '{SID}'}});if($profiles.Count -ne 1){{throw 'Exact user profile missing'}};$ordinary=Join-Path $profiles[0].LocalPath 'AppData\\Local\\LomiLoginProof-{run}';if((Test-Path -LiteralPath $ordinary) -or @(Get-CimInstance Win32_Process|Where-Object{{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($ordinary+'\\',[StringComparison]::OrdinalIgnoreCase)}}).Count){{throw 'Unexpected ordinary execution state; preserve'}};$r.DeleteTask('{intent['taskName']}',0);try{{$null=$r.GetTask('{intent['taskName']}');throw 'Helper remains'}}catch{{if(($_.Exception.HResult -band 0xffffffffL) -notin @(0x80070002L,0x80070003L)){{throw}}}};@{{helperTaskAbsent=$true;ordinaryRootAbsent=$true;neverStarted=$true;filesRetained=$true}}|ConvertTo-Json -Compress"""
    script_path=evidence.path.with_suffix('.ps1');script_path.write_text(script,encoding='utf-8')
    report['scriptSha256']=hashlib.sha256(script_path.read_bytes()).hexdigest()
    audit=f"$ErrorActionPreference='Stop';$s=New-Object -ComObject 'Schedule.Service';$s.Connect();try{{$null=$s.GetFolder('\\').GetTask('{intent['taskName']}');throw 'Helper remains'}}catch{{if(($_.Exception.HResult -band 0xffffffffL) -notin @(0x80070002L,0x80070003L)){{throw}}}};@{{helperTaskAbsent=$true}}|ConvertTo-Json -Compress"
    audit_path=evidence.path.with_suffix('.audit.ps1');audit_path.write_text(audit,encoding='utf-8')
    report['auditSha256']=hashlib.sha256(audit_path.read_bytes()).hexdigest()
    report['failedReceiptPath']=str(path.relative_to(ROOT));evidence.save()
    return evidence.path


def execute(path):
    initialize_process_ownership()
    report=json.loads(path.read_text());intent=report['intent']
    failed_path=ROOT/report['failedReceiptPath'];failed_bytes=failed_path.read_bytes();failed=json.loads(failed_bytes)
    if hashlib.sha256(failed_bytes).hexdigest()!=report['failedReceiptSha256']:raise RuntimeError('Failed receipt changed after cleanup preparation')
    if prepare_intent(failed)!=intent or report.get('taskDeletionAttempted') is not False:
        raise RuntimeError('Prepared recovery intent changed or already attempted')
    script_path=path.with_suffix('.ps1');audit_path=path.with_suffix('.audit.ps1')
    if hashlib.sha256(script_path.read_bytes()).hexdigest()!=report['scriptSha256'] or hashlib.sha256(audit_path.read_bytes()).hexdigest()!=report['auditSha256']:
        raise RuntimeError('Frozen recovery script changed')
    evidence=Evidence(path,report);report['taskDeletionAttempted']=True;evidence.save()
    report['result']=json.loads(evidence.ps('revalidate-pinned-never-run-helper-and-delete-exact-task',script_path.read_text()))
    if any(report['result'].get(key) is not True for key in ['helperTaskAbsent','ordinaryRootAbsent','neverStarted']):
        raise RuntimeError('Never-run cleanup uncertain')
    report['freshAudit']=json.loads(evidence.ps('fresh-transport-never-run-helper-absence',audit_path.read_text()))
    if report['freshAudit'].get('helperTaskAbsent') is not True:raise RuntimeError('Fresh absence unproved')
    report['complete']=report['passed']=True;evidence.save()
    failed['neverRunRecoveryReceipt']=str(evidence.path.relative_to(ROOT));failed['neverRunHelperTaskRemoved']=True
    Evidence(failed_path,failed).save()
    return evidence.path

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('run_id');parser.add_argument('--execute-intent',action='store_true');args=parser.parse_args()
    run=str(uuid.UUID(args.run_id))
    if run!=args.run_id:parser.error('Canonical UUID required')
    if args.execute_intent:print(execute(ROOT/'artifacts/product-login-windows'/f'{run}.recovery.json'))
    else:print(prepare(ROOT/'artifacts/product-login-windows'/f'{run}.json'))
