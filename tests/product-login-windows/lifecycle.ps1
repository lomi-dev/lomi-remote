param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Stage,[Parameter(Mandatory)][string]$ExpectedSid,[Parameter(Mandatory)][int]$ExpectedSession,[Parameter(Mandatory)][string]$CliHash,[Parameter(Mandatory)][string]$HelperHash,[switch]$FixtureDiagnostics)
$ErrorActionPreference='Stop'
if([Guid]::Parse($RunId).ToString('D') -cne $RunId){throw 'UUID required'}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$principal=[Security.Principal.WindowsPrincipal]::new($identity)
$session=[Diagnostics.Process]::GetCurrentProcess().SessionId
if($identity.User.Value -cne $ExpectedSid -or $session -ne $ExpectedSession -or $session -eq 0 -or $identity.Groups.Value -contains 'S-1-5-32-544' -or $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Ordinary interactive identity required'}
. (Join-Path $Stage 'lifecycle-identity.ps1')
$root=Join-Path $env:LOCALAPPDATA "LomiLoginProof-$RunId"
if(Test-Path -LiteralPath $root){throw 'Fresh ordinary-owned UUID root required'}
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("O:$ExpectedSid`D:P(A;OICI;FA;;;$ExpectedSid)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
$null=[IO.Directory]::CreateDirectory($root,$acl)
$result=@{fixtureDiagnostics=[bool]$FixtureDiagnostics;runId=$RunId;passed=$false;complete=$false;sid=$ExpectedSid;session=$session;administratorGroup=$false;ordinaryInteractiveLifecycleQualified=$false;logonTriggerQualified=$false;visibleConsoleQualified=$false;checks=@();operations=@();root=$root;rootIdentity=[LomiLoginFileIdentity]::Read($root);cleanupComplete=$false}
$report=Join-Path $root 'lifecycle-result.json'
function Save { [IO.File]::WriteAllText($report,($script:result|ConvertTo-Json -Depth 12 -Compress),[Text.UTF8Encoding]::new($false)) }
function Check([string]$name,[bool]$ok){if(!$ok){throw $name};$script:result.checks+=@{name=$name;passed=$true};Save}
function Hash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Closed-CliError([string]$text){
 $stages=@('Admission','InstanceIdentity','Bind','Marker','Refresh','State','Readiness')
 $categories=@('LOGIN_INVALID_CONFIGURATION','LOGIN_OWNERSHIP_CONFLICT','LOGIN_TASK_SETUP_UNAVAILABLE','LOGIN_OPERATION_UNCERTAIN','LOGIN_HOST_NOT_READY','LOGIN_ORDINARY_CURRENT_ACCOUNT_REQUIRED','LOGIN_INTERACTIVE_SESSION_REQUIRED','LOGIN_MANAGED_HELPER_REQUIRED','LOGIN_NOT_INSTALLED')
 $diagnostics=@();$codes=@();$unknown=$false
 foreach($line in @($text -split '\r?\n')){
  if(!$line){continue}
  if($line -cmatch '^LOGIN_FIXTURE_LAUNCH stage=([A-Za-z]+) category=([A-Z_]+)$' -and $Matches[1] -cin $stages -and $Matches[2] -cin $categories){$diagnostics+=@{stage=$Matches[1];category=$Matches[2]}}
  elseif($line -cin $categories -or $line -ceq 'DAEMON_UNAVAILABLE'){$codes+=$line}
  else{$unknown=$true}
 }
 @{diagnostics=$diagnostics;codes=$codes;unrecognized=$unknown}
}
# A timeout deliberately preserves the retained process and all durable state;
# neither its numeric PID nor Scheduler's engine PID authorizes a kill.
function Begin-Cli([string[]]$arguments){
 $info=[Diagnostics.ProcessStartInfo]::new($script:exe)
 $info.WorkingDirectory=$script:root;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $all=@('--profile-dir',$script:profile)+$arguments
 $info.Arguments=(@($all|ForEach-Object{if($_ -match '["\r\n]' -or $_.EndsWith('\')){throw 'Fixed argument required'};'"'+$_+'"'}) -join ' ')
 $p=[Diagnostics.Process]::new();$p.StartInfo=$info;$null=$p.Start()
 @{process=$p;output=$p.StandardOutput.ReadToEndAsync();error=$p.StandardError.ReadToEndAsync();arguments=$arguments}
}
function End-Cli($child){
 if(!$child.process.WaitForExit(60000)){throw 'CLI completion unknown; preserve running child'}
 if(![Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]@($child.output,$child.error),3000)){throw 'CLI drains incomplete'}
 $errorSummary=Closed-CliError $child.error.Result
 $value=@{arguments=$child.arguments;exitCode=$child.process.ExitCode;stdout=$child.output.Result;stderrCodes=$errorSummary.codes;launchDiagnostics=$errorSummary.diagnostics;unrecognizedStderr=$errorSummary.unrecognized}
 $child.process.Dispose();$script:result.operations+= $value;Save
 if($value.stdout.Length -gt 65536 -or $child.error.Result.Length -gt 65536 -or $errorSummary.unrecognized -or (!$FixtureDiagnostics -and $errorSummary.diagnostics.Count) -or $value.exitCode -ne 0){throw 'CLI operation failed'}
 $value.stdout
}
function Invoke-ProductCli([string[]]$arguments){End-Cli (Begin-Cli $arguments)}
function Resolve-Sid([string]$value){if($value.StartsWith('S-1-')){[Security.Principal.SecurityIdentifier]::new($value).Value}else{[Security.Principal.NTAccount]::new($value).Translate([Security.Principal.SecurityIdentifier]).Value}}
function Private-Acl([string]$descriptor){
 $d=[Security.AccessControl.RawSecurityDescriptor]::new($descriptor)
 if($d.Owner.Value -cne $ExpectedSid -or !$d.DiscretionaryAcl){return $false}
 $own=$false
 foreach($ace in $d.DiscretionaryAcl){if($ace.AceQualifier -eq 'AccessAllowed'){if($ace.SecurityIdentifier.Value -notin @($ExpectedSid,'S-1-5-18','S-1-5-32-544')){return $false};if($ace.SecurityIdentifier.Value -eq $ExpectedSid){$own=$true}}}
 $own
}
function No-Owned-Host { @(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.Equals($script:helper,[StringComparison]::OrdinalIgnoreCase)}).Count -eq 0 }
function Single-Inventory([int]$cimHosts,[int]$nativeHosts,[int]$unreadableLive,[int]$tasks,[int]$folders,[int]$instances){
 # GetInstances may report zero for the authenticated running product task.
 # Native/CIM identity and the registered task establish the singleton proof.
 $cimHosts -eq 1 -and $nativeHosts -eq 1 -and $unreadableLive -eq 0 -and $tasks -eq 1 -and $folders -eq 0 -and $instances -ge 0 -and $instances -le 1
}
function Assert-Single-Host([string]$label,[string]$runtime){
 $hosts=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.Equals($script:helper,[StringComparison]::OrdinalIgnoreCase)})
 $current=Get-Content -LiteralPath (Join-Path $script:registration 'managed-run.json') -Raw|ConvertFrom-Json
 $retained=@();$nativeHosts=@();$unreadableLive=0
 try {
  foreach($candidate in [Diagnostics.Process]::GetProcessesByName('lomiremote-host')){
   $retained+=$candidate
   try {
    $handle=$candidate.Handle
    if($candidate.HasExited){continue}
    if($candidate.MainModule.FileName.Equals($script:helper,[StringComparison]::OrdinalIgnoreCase)){$nativeHosts+=$candidate}
   }catch{
    $positivelyExited=$false;try{$positivelyExited=$candidate.HasExited}catch{}
    if(!$positivelyExited){$unreadableLive++}
   }
  }
  $inventory=@{label=$label;cimExactHosts=$hosts.Count;nativeExactHosts=$nativeHosts.Count;nativeUnreadableLiveCandidates=$unreadableLive;folderTasks=$script:folder.GetTasks(1).Count;folderSubfolders=$script:folder.GetFolders(0).Count;schedulerInstances=$script:task.GetInstances(0).Count;schedulerState=[int]$script:task.State}
  $single=Single-Inventory $inventory.cimExactHosts $inventory.nativeExactHosts $inventory.nativeUnreadableLiveCandidates $inventory.folderTasks $inventory.folderSubfolders $inventory.schedulerInstances
  $birthMatches=$false;$ownerMatches=$false
  if($nativeHosts.Count -eq 1){$p=$nativeHosts[0];$birthMatches=(!$p.HasExited -and $p.Id -eq $current.pid -and $p.SessionId -eq $ExpectedSession -and $p.StartTime.ToUniversalTime().ToFileTimeUtc().ToString() -ceq $current.created.ToString())}
  if($hosts.Count -eq 1){$owner=Invoke-CimMethod -InputObject $hosts[0] -MethodName GetOwnerSid;$ownerMatches=($owner.Sid -ceq $ExpectedSid)}
  $inventory.markerProcessBirthMatched=$birthMatches;$inventory.ownerSidMatched=$ownerMatches
  $script:result.hostInventories+=@($inventory);Save
  Check ($label+'-single-owned-host-and-task') ($single -and $birthMatches -and $ownerMatches -and $hosts[0].ProcessId -eq $current.pid -and $hosts[0].SessionId -eq $ExpectedSession -and $current.runtime -ceq $runtime -and $current.completion -ceq 'Running' -and $current.sid -ceq $ExpectedSid -and $current.helper -ceq $script:helper -and $current.installation -ceq $script:installation)
  Check ($label+'-ordinary-host-owner') $ownerMatches
 }finally{foreach($candidate in $retained){$candidate.Dispose()}}
}
function Restart-Proof([string]$label,[string]$previousRuntime,[string]$hostId){
 $null=Invoke-ProductCli @('service','restart')
 $a=Begin-Cli @('status','--json');$b=Begin-Cli @('status','--json')
 $one=(End-Cli $a)|ConvertFrom-Json;$two=(End-Cli $b)|ConvertFrom-Json
 $first=$one.result.Ok.value;$second=$two.result.Ok.value
 Check ($label+'-new-runtime-same-host-two-clients') ($one.result.Ok.type -ceq 'status' -and $two.result.Ok.type -ceq 'status' -and $first.runtimeId -and $first.runtimeId -cne $previousRuntime -and $first.runtimeId -ceq $second.runtimeId -and $first.hostId -ceq $hostId -and $second.hostId -ceq $hostId -and $first.sharing -ceq 'disabled' -and $second.sharing -ceq 'disabled')
 Assert-Single-Host $label $first.runtimeId
 $current=Get-Content -LiteralPath (Join-Path $script:registration 'managed-run.json') -Raw|ConvertFrom-Json
 @{runtime=$first.runtimeId;run=$current.run}
}
Save
try {
 $exe=Join-Path $root 'lomiremote.exe';$helper=Join-Path $root 'lomiremote-host.exe';$profile=Join-Path $root 'host-profile';$registration=$profile+'-service-windows-login'
 foreach($item in @(@('lomiremote.exe',$CliHash,3),@('lomiremote-host.exe',$HelperHash,2))){
  $source=Join-Path $Stage $item[0];Check ('staged-hash-'+$item[0]) ((Hash $source) -ceq $item[1])
  $destination=Join-Path $root $item[0];Copy-Item -LiteralPath $source -Destination $destination
  $bytes=[IO.File]::ReadAllBytes($destination);$offset=[BitConverter]::ToInt32($bytes,60)
  Check ('owned-binary-'+$item[0]) ((Hash $destination) -ceq $item[1] -and (Private-Acl (Get-Acl -LiteralPath $destination).Sddl) -and [BitConverter]::ToUInt16($bytes,$offset+92) -eq $item[2])
 }
 $null=Invoke-ProductCli @('service','install','--mode','login','--account',$identity.Name)
 $record=Get-Content -LiteralPath (Join-Path $registration 'registration.json') -Raw|ConvertFrom-Json
 $installation=[Guid]::Parse($record.installation).ToString('D');$folderName="\LomiRemote-$installation"
 $result.installation=$installation;$result.taskPath=$folderName+'\Host';Save
 $scheduler=New-Object -ComObject 'Schedule.Service';$scheduler.Connect();$folder=$scheduler.GetFolder($folderName);$task=$folder.GetTask('Host');$definition=$task.Definition
 $registrationArgument=if($registration -match '\s'){'"'+$registration+'"'}else{$registration}
 $expectedArguments='--managed-logon '+$registrationArgument+' '+$installation
 Check 'exact-current-user-task-action-and-logon-trigger' ($record.sid -ceq $ExpectedSid -and $record.profile -ceq $profile -and $record.helper -ceq $helper -and $record.phase -ceq 'Registered' -and $definition.Data -ceq $installation -and (Resolve-Sid $definition.Principal.UserId) -ceq $ExpectedSid -and $definition.Principal.LogonType -eq 3 -and $definition.Principal.RunLevel -eq 0 -and $definition.Actions.Count -eq 1 -and $definition.Actions.Item(1).Path -ceq $helper -and $definition.Actions.Item(1).Arguments -ceq $expectedArguments -and $definition.Triggers.Count -eq 1 -and $definition.Triggers.Item(1).Type -eq 9 -and (Resolve-Sid $definition.Triggers.Item(1).UserId) -ceq $ExpectedSid)
 $result.taskSddl=$task.GetSecurityDescriptor(7);$result.folderSddl=$folder.GetSecurityDescriptor(7)
 Check 'private-owned-task-folder-and-profile-acls' ((Private-Acl $result.taskSddl) -and (Private-Acl $result.folderSddl) -and (Private-Acl (Get-Acl -LiteralPath $profile).Sddl))
 Check 'install-does-not-start-host' ((No-Owned-Host) -and $task.GetInstances(0).Count -eq 0)
 Check 'installed-status-stopped' ((Invoke-ProductCli @('service','status')).Trim() -ceq 'Login host stopped.')
 $null=Invoke-ProductCli @('service','start')
 $a=Begin-Cli @('status','--json');$b=Begin-Cli @('status','--json')
 $one=(End-Cli $a)|ConvertFrom-Json;$two=(End-Cli $b)|ConvertFrom-Json
 $first=$one.result.Ok.value;$second=$two.result.Ok.value
 Check 'two-real-ipc-clients-same-runtime-sharing-disabled' ($one.result.Ok.type -ceq 'status' -and $two.result.Ok.type -ceq 'status' -and $first.runtimeId -and $first.runtimeId -ceq $second.runtimeId -and $first.hostId -ceq $second.hostId -and $first.sharing -ceq 'disabled' -and $second.sharing -ceq 'disabled')
 $result.firstRuntime=$first.runtimeId
 $marker=Get-Content -LiteralPath (Join-Path $registration 'managed-run.json') -Raw|ConvertFrom-Json
 $hostProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$($marker.pid)";$owner=Invoke-CimMethod -InputObject $hostProcess -MethodName GetOwnerSid
 Check 'actual-managed-helper-ordinary-interactive-session' ($owner.Sid -ceq $ExpectedSid -and $hostProcess.SessionId -eq $ExpectedSession -and $hostProcess.ExecutablePath -ceq $helper -and $marker.runtime -ceq $first.runtimeId)
 Assert-Single-Host 'initial' $first.runtimeId
 $null=Invoke-ProductCli @('service','status');$null=Invoke-ProductCli @('service','stop')
 Check 'graceful-stop-zero-owned-hosts' (No-Owned-Host)
 $clean=Get-Content -LiteralPath (Join-Path $registration 'managed-run.json') -Raw|ConvertFrom-Json
 Check 'stopped-task-idle-original-generation-clean' ($task.GetInstances(0).Count -eq 0 -and $task.State -eq 3 -and $task.LastTaskResult -eq 0 -and $clean.run -ceq $marker.run -and $clean.completion -ceq 'Clean')
 $stoppedRuntime=Restart-Proof 'stopped-restart' $first.runtimeId $first.hostId
 $runningRuntime=Restart-Proof 'running-restart' $stoppedRuntime.runtime $first.hostId
 $result.restartRuntimes=@($first.runtimeId,$stoppedRuntime.runtime,$runningRuntime.runtime)
 $result.restartRuns=@($marker.run,$stoppedRuntime.run,$runningRuntime.run)
 Check 'three-distinct-runtime-generations' (@($result.restartRuntimes|Select-Object -Unique).Count -eq 3)
 Check 'three-distinct-managed-run-generations' (@($result.restartRuns|Select-Object -Unique).Count -eq 3)
 $null=Invoke-ProductCli @('service','stop');$db=Join-Path $profile 'host.sqlite3';$before=Hash $db
 $null=Invoke-ProductCli @('service','uninstall')
 $absent=$false;try{$null=$scheduler.GetFolder($folderName)}catch{if(($_.Exception.HResult -band 0xffffffffL) -in @(0x80070002L,0x80070003L)){$absent=$true}else{throw}}
 Check 'uninstall-exact-folder-absent-data-preserved-no-hosts' ($absent -and !(Test-Path -LiteralPath (Join-Path $registration 'registration.json')) -and (Hash $db) -ceq $before -and (No-Owned-Host))
 $result.productTaskAbsent=$true;$result.ownedHostsRemaining=0;$result.dataPreserved=$true
 $result.ordinaryInteractiveLifecycleQualified=$true;$result.complete=$true;$result.passed=$true
 # Evidence and own stopped files deliberately remain. Unknown files are never deleted.
 $result.cleanupComplete=$false;$result.filesRetained=$true;Save
} catch {
 $result.errorType=$_.Exception.GetType().Name;$result.errorId=$_.FullyQualifiedErrorId;$result.errorLine=$_.InvocationInfo.ScriptLineNumber;Save
 exit 1
}
