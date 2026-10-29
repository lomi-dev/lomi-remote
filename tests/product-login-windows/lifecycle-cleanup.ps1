param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$CleanupId,[Parameter(Mandatory)][string]$Stage,[Parameter(Mandatory)][string]$ExpectedSid,[Parameter(Mandatory)][int]$ExpectedSession,[Parameter(Mandatory)][string]$Installation,[Parameter(Mandatory)][string]$CliHash,[Parameter(Mandatory)][string]$HelperHash,[Parameter(Mandatory)][string]$OriginalScriptHash,[Parameter(Mandatory)][string]$IdentityHash,[Parameter(Mandatory)][string]$ResultHash)
$ErrorActionPreference='Stop'
foreach($id in @($RunId,$CleanupId,$Installation)){if([Guid]::Parse($id).ToString('D') -cne $id){throw 'Canonical UUID required'}}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent();$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if($identity.User.Value -cne $ExpectedSid -or $ExpectedSid -cne 'S-1-5-21-1379812509-1041957290-335626797-1005' -or $session -ne $ExpectedSession -or $session -eq 0 -or $identity.Groups.Value -contains 'S-1-5-32-544'){throw 'Exact ordinary interactive token required'}
function Digest([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLowerInvariant()}
$original=Join-Path $Stage 'lifecycle.ps1';$native=Join-Path $Stage 'lifecycle-identity.ps1'
if((Digest $original) -cne $OriginalScriptHash -or (Digest $native) -cne $IdentityHash){throw 'Frozen cleanup functions changed'}
. $native
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($original,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Frozen helper parse failed'}
# Import only functions. Never execute the original top-level lifecycle again.
foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([ScriptBlock]::Create($node.Extent.Text))}
$root=Join-Path $env:LOCALAPPDATA "LomiLoginProof-$RunId";$profile=Join-Path $root 'host-profile';$registration=$profile+'-service-windows-login'
$exe=Join-Path $root 'lomiremote.exe';$helper=Join-Path $root 'lomiremote-host.exe';$oldResult=Join-Path $root 'lifecycle-result.json'
if((Digest $exe) -cne $CliHash -or (Digest $helper) -cne $HelperHash -or (Digest $oldResult) -cne $ResultHash){throw 'Original frozen artifact changed'}
$old=Get-Content -LiteralPath $oldResult -Raw|ConvertFrom-Json
if($old.runId -cne $RunId -or $old.sid -cne $ExpectedSid -or $old.session -ne $ExpectedSession -or $old.passed -ne $false -or $old.installation -cne $Installation){throw 'Original failed receipt changed'}
$rootIdentity=[LomiLoginFileIdentity]::Read($root)
foreach($key in @('volume','fileId','finalPath','links')){if($rootIdentity.$key -cne $old.rootIdentity.$key){throw 'Original root birth identity changed'}}
$recordPath=Join-Path $registration 'registration.json';$record=Get-Content -LiteralPath $recordPath -Raw|ConvertFrom-Json
if($record.version -ne 1 -or $record.installation -cne $Installation -or $record.sid -cne $ExpectedSid -or $record.profile -cne $profile -or $record.helper -cne $helper -or $record.registration -cne $registration -or $record.phase -cne 'Registered'){throw 'Product registration changed'}
$scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folderName="\LomiRemote-$Installation";$folder=$scheduler.GetFolder($folderName);$task=$folder.GetTask('Host');$definition=$task.Definition
$argument=if($registration -match '\s'){'"'+$registration+'"'}else{$registration};$expectedArguments='--managed-logon '+$argument+' '+$Installation
if($definition.Data -cne $Installation -or (Resolve-Sid $definition.Principal.UserId) -cne $ExpectedSid -or $definition.Principal.LogonType -ne 3 -or $definition.Principal.RunLevel -ne 0 -or $definition.Actions.Count -ne 1 -or $definition.Actions.Item(1).Path -cne $helper -or $definition.Actions.Item(1).Arguments -cne $expectedArguments -or $definition.Triggers.Count -ne 1 -or (Resolve-Sid $definition.Triggers.Item(1).UserId) -cne $ExpectedSid -or !(Private-Acl $task.GetSecurityDescriptor(7)) -or !(Private-Acl $folder.GetSecurityDescriptor(7))){throw 'Exact product task changed'}
$report=Join-Path $root "lifecycle-cleanup-$CleanupId.json"
$result=@{runId=$CleanupId;sourceRunId=$RunId;installation=$Installation;sid=$ExpectedSid;session=$session;passed=$false;complete=$false;checks=@();operations=@();filesRetained=$true;originalResultSha256=$ResultHash}
Save
try {
 $result.productTaskBeforeCleanup=@{state=[int]$task.State;instances=[int]$task.GetInstances(0).Count;last=[int]$task.LastTaskResult;lastRunTime=$task.LastRunTime.ToString('o')}
 $markerPath=Join-Path $registration 'managed-run.json'
 if(Test-Path -LiteralPath $markerPath){
  $marker=Get-Content -LiteralPath $markerPath -Raw|ConvertFrom-Json
  $result.markerBeforeCleanup=@{run=$marker.run;completion=$marker.completion;pid=$marker.pid;created=$marker.created;runtime=$marker.runtime}
  $result.markerProcessBeforeCleanup=@{present=$false;identityMatched=$false}
  $candidate=$null
  try {
   $candidate=[Diagnostics.Process]::GetProcessById([int]$marker.pid);$handle=$candidate.Handle
   $result.markerProcessBeforeCleanup.present=$true
   if(!$candidate.HasExited -and $candidate.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ceq $marker.created.ToString() -and $candidate.MainModule.FileName.Equals($helper,[StringComparison]::OrdinalIgnoreCase)){
    $process=Get-CimInstance Win32_Process -Filter "ProcessId=$($marker.pid)";$owner=Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
    $result.markerProcessBeforeCleanup.identityMatched=($owner.Sid -ceq $ExpectedSid -and $candidate.SessionId -eq $ExpectedSession)
    $result.markerProcessBeforeCleanup.session=$candidate.SessionId
   }
  }catch{$result.markerProcessBeforeCleanup.readError=$_.Exception.GetType().Name}finally{if($candidate){$candidate.Dispose()}}
 }
 try{$status=(Invoke-ProductCli @('status','--json'))|ConvertFrom-Json;$result.authenticatedStatusBeforeCleanup=$status.result;$result.readyRuntimeObserved=($status.result.Ok.type -ceq 'status')}catch{$result.readyRuntimeObserved=$false;$result.statusReadError=$_.Exception.GetType().Name}
 Save
 # Actual default CLI performs its own durable exact-task disable/stop/delete.
 # No Scheduler mutation or process signal is made by this ordinary helper.
 $null=Invoke-ProductCli @('service','uninstall')
 $absent=$false;try{$null=$scheduler.GetFolder($folderName)}catch{if(($_.Exception.HResult -band 0xffffffffL) -in @(0x80070002L,0x80070003L)){$absent=$true}else{throw}}
 Check 'actual-cli-uninstall-exact-folder-and-record-absent' ($absent -and !(Test-Path -LiteralPath $recordPath))
 Check 'zero-owned-gui-hosts-after-uninstall' (No-Owned-Host)
 Check 'original-failed-receipt-unchanged' ((Digest $oldResult) -ceq $ResultHash)
 $result.productTaskAbsent=$true;$result.ownedHostsRemaining=0;$result.complete=$true;$result.passed=$true;Save
} catch {$result.errorType=$_.Exception.GetType().Name;$result.errorId=$_.FullyQualifiedErrorId;$result.errorLine=$_.InvocationInfo.ScriptLineNumber;Save;exit 1}
