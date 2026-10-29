param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Source)
. "$PSScriptRoot\..\services-windows\Common.ps1"
Assert-Administrator
if([Guid]::Parse($RunId).ToString('D') -cne $RunId){throw 'UUID required'}
if([Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0){throw 'Session0 required'}
$root=Join-Path 'C:\ProgramData\LomiWindowsFixture' $RunId
$name="LomiProductService-$RunId";$probeName="LomiProductServiceProbe-$RunId";$foreignName="LomiProductServiceForeign-$RunId"
$registration=Join-Path $env:USERPROFILE ".lomi-service-manager-$RunId"
if((Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $registration) -or (Get-Service -Name $name -ErrorAction SilentlyContinue)){throw 'Fresh UUID resources required'}
$parent=Split-Path $root
if(!(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent,(Get-ParentSecurity))}
Assert-FixtureChain
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;BA)')
$null=[IO.Directory]::CreateDirectory($root,$acl)
[IO.File]::WriteAllText((Join-Path $root 'fixture.marker'),"lomi-product-service-v1:$RunId`n",[Text.UTF8Encoding]::new($false))
$exe=Join-Path $root 'lomiremote.exe';$controller=Join-Path $root 'windows-service-proof.exe'
Copy-Item -LiteralPath (Join-Path $Source 'target\debug\lomiremote.exe') -Destination $exe
Copy-Item -LiteralPath (Join-Path $Source 'target\debug\examples\windows-service-proof.exe') -Destination $controller
$record=Join-Path $registration 'registration.json'
$checks=@()
function Check([string]$label,[bool]$value){if(!$value){throw $label};$script:checks+=@{name=$label;passed=$true};if(Test-Path -LiteralPath $root){@{checks=$script:checks}|ConvertTo-Json -Depth 5 -Compress|Set-Content -LiteralPath (Join-Path $root 'manager-progress.json')}}
function Invoke-Manager([string]$operation,[string]$error=''){
    $value=(& $controller $RunId $operation)|ConvertFrom-Json
    if($LASTEXITCODE -ne 0){throw 'Controller failed'}
    if($error){if($value.ok -ne $false -or $value.error -cne $error){$actual=if($value.ok){'unexpected-success'}else{$value.error};throw "Unexpected manager rejection: $operation ($actual)"}}elseif($value.ok -ne $true){throw "Manager operation failed: $operation ($($value.error))"}
    $value
}
function Service([string]$serviceName=$name){Get-CimInstance Win32_Service -Filter "Name='$serviceName'"}
function Wait-State([string]$serviceName,[string]$state){$deadline=[DateTime]::UtcNow.AddSeconds(20);do{$s=Service $serviceName;if($s -and $s.State -eq $state){return $s};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $deadline);throw 'Service state deadline'}
function Wait-Gone([uint32]$ownedId,[datetime]$created){$deadline=[DateTime]::UtcNow.AddSeconds(15);do{$p=Get-CimInstance Win32_Process -Filter "ProcessId=$ownedId";if(!$p -or $p.CreationDate -ne $created){return};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $deadline);throw 'Owned process remains'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LomiOwnedKernel {
 [DllImport("kernel32.dll",SetLastError=true)]
 [return:MarshalAs(UnmanagedType.Bool)] public static extern bool TerminateProcess(IntPtr process,uint code);
}
'@
function Crash-Owned {
    $s=Service;$p=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)"
    if($s.State -ne 'Running' -or !$p.ExecutablePath.Equals($exe,[StringComparison]::OrdinalIgnoreCase)){throw 'Crash owner identity mismatch'}
    $owned=[Diagnostics.Process]::GetProcessById($s.ProcessId);$handle=$owned.Handle
    $current=Service;$again=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)"
    if($current.State -ne 'Running' -or $current.ProcessId -ne $s.ProcessId -or $again.CreationDate -ne $p.CreationDate -or $owned.HasExited){throw 'Crash process handle binding lost'}
    if(![LomiOwnedKernel]::TerminateProcess($handle,1) -or !$owned.WaitForExit(10000) -or $owned.ExitCode -ne 1){throw 'Owned crash exit unconfirmed'}
    $owned.Dispose();$null=Wait-State $name 'Stopped';Wait-Gone $s.ProcessId $p.CreationDate
}
function Change-Config($arguments){$s=Service;$result=Invoke-CimMethod -InputObject $s -MethodName Change -Arguments $arguments;if($result.ReturnValue -ne 0){throw 'Owned stopped service change failed'}}
function Record-Bytes{[IO.File]::ReadAllBytes($record)}
function Write-Record($value){[IO.File]::WriteAllText($record,($value|ConvertTo-Json -Depth 8 -Compress),[Text.UTF8Encoding]::new($false))}
function Create-Manual([string]$serviceName,[string]$command){
    if(Service $serviceName){throw 'Foreign existing fixture service'}
    $r=Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{Name=$serviceName;DisplayName=$serviceName;PathName=$command;ServiceType=[byte]16;ErrorControl=[byte]1;StartMode='Manual';DesktopInteract=$false;StartName='NT AUTHORITY\LocalService'}
    if($r.ReturnValue -ne 0){throw 'Manual fixture create failed'}
}
function Delete-Owned([string]$serviceName,[string]$command){$s=Service $serviceName;if(!$s -or $s.PathName -cne $command -or $s.StartName -ne 'NT AUTHORITY\LocalService' -or $s.StartMode -ne 'Manual' -or $s.ProcessId -ne 0 -or $s.State -ne 'Stopped'){throw 'Owned delete identity mismatch'};& sc.exe delete $serviceName|Out-Null;if($LASTEXITCODE -ne 0){throw 'Owned fixture delete failed'};if(Service $serviceName){throw 'Owned fixture deletion pending'}}
function Observe-Database([string]$phase){
    $command='"'+$controller+'" '+$RunId+' probe-'+$phase
    Create-Manual $probeName $command
    $r=Invoke-CimMethod -InputObject (Service $probeName) -MethodName StartService
    if($r.ReturnValue -ne 0){throw 'Probe start failed'}
    $path=Join-Path $root $(if($phase -eq 'cleanup'){'profile-cleanup.json'}else{'db-'+$phase+'.json'});$deadline=[DateTime]::UtcNow.AddSeconds(20)
    do{if(Test-Path -LiteralPath $path){break};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $deadline)
    if(!(Test-Path -LiteralPath $path)){throw 'Read-only observer missing'}
    $s=Wait-State $probeName 'Stopped';if($s.ExitCode -ne 0){throw 'Read-only observer failed'}
    $processDeadline=[DateTime]::UtcNow.AddSeconds(15);do{$active=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.Equals($controller,[StringComparison]::OrdinalIgnoreCase)});if($active.Count -eq 0){break};Start-Sleep -Milliseconds 50}while([DateTime]::UtcNow -lt $processDeadline);if($active.Count -ne 0){throw 'Probe process remains'}
    $value=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    if($value.localService -ne $true -or ($phase -ne 'cleanup' -and ($value.exists -ne $true -or $value.readOnlyObserver -ne $true)) -or ($phase -eq 'cleanup' -and ($value.cleanupComplete -ne $true -or $value.fixtureCleanup -ne $true))){throw 'Observer identity mismatch'}
    Delete-Owned $probeName $command
    $value
}
# An explicit write-data ACE without DELETE must not authorize executable bytes.
$originalAcl=Get-Acl -LiteralPath $exe
$modified=Get-Acl -LiteralPath $exe
$modified.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-1-0'),[Security.AccessControl.FileSystemRights]2,[Security.AccessControl.AccessControlType]::Allow))
Set-Acl -LiteralPath $exe -AclObject $modified
$null=Invoke-Manager install 'SERVICE_OWNERSHIP_CONFLICT'
Check 'foreign-write-data-ace-rejected-before-intent' (!(Test-Path -LiteralPath $record) -and !(Service))
Set-Acl -LiteralPath $exe -AclObject $originalAcl
$null=Invoke-Manager install-intent-fault 'SERVICE_OPERATION_UNCERTAIN'
Check 'intent-durable-before-create' ((Test-Path -LiteralPath $record) -and !(Service) -and (Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).phase -eq 'Intent')
$intent=Get-Content -LiteralPath $record -Raw|ConvertFrom-Json
$badCommand=$intent.command+' --foreign'
Create-Manual $name $badCommand
$null=Invoke-Manager install 'SERVICE_OWNERSHIP_CONFLICT'
Check 'foreign-existing-service-not-adopted' ((Service).PathName -ceq $badCommand -and (Service).ProcessId -eq 0)
Delete-Owned $name $badCommand
$null=Invoke-Manager install-create-fault 'SERVICE_OPERATION_UNCERTAIN'
Check 'created-service-recovered-from-intent' ((Service).State -eq 'Stopped' -and (Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).phase -eq 'Intent')
$null=Invoke-Manager install
Check 'install-never-starts-manual-fixture' ((Service).State -eq 'Stopped' -and (Service).ProcessId -eq 0 -and (Service).StartMode -eq 'Manual')
# Failed startup remains observable; uninstall can remove an already-dead owner.
[IO.File]::WriteAllText((Join-Path $root 'host-profile'),'synthetic-invalid-profile')
$null=Invoke-Manager start 'SERVICE_NOT_READY'
$null=Invoke-Manager stop 'SERVICE_NOT_READY'
$uninstalled=Invoke-Manager uninstall
Check 'failed-start-uninstall-preserves-target-data' ($uninstalled.state.Contains('previous service failure') -and !(Service) -and [IO.File]::ReadAllText((Join-Path $root 'host-profile')) -ceq 'synthetic-invalid-profile')
Remove-Item -LiteralPath (Join-Path $root 'host-profile')
$null=Invoke-Manager install-logon-fault 'SERVICE_OS_CREDENTIALS_OR_LOGON_RIGHT_REQUIRED'
$null=Invoke-Manager status 'SERVICE_OS_CREDENTIALS_OR_LOGON_RIGHT_REQUIRED'
Check 'injected-os-setup-required-state-durable' (!(Service) -and (Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).phase -eq 'CredentialsRequired')
$null=Invoke-Manager install
Check 'setup-required-install-retry-recovers' ((Service).State -eq 'Stopped' -and (Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).phase -eq 'Registered')
$original=Service;$originalCommand=$original.PathName
Change-Config @{PathName=$originalCommand+' extra'}
$null=Invoke-Manager start 'SERVICE_OWNERSHIP_CONFLICT'
Check 'altered-full-command-refused' ((Service).ProcessId -eq 0)
Change-Config @{PathName=$originalCommand}
Change-Config @{PathName=$originalCommand.Replace('host-profile','other-profile')}
$null=Invoke-Manager uninstall 'SERVICE_OWNERSHIP_CONFLICT'
Check 'altered-profile-argument-refused' ((Service).ProcessId -eq 0 -and (Test-Path -LiteralPath $record))
Change-Config @{PathName=$originalCommand}
Change-Config @{StartName='NT AUTHORITY\NetworkService'}
$null=Invoke-Manager start 'SERVICE_OWNERSHIP_CONFLICT'
Check 'altered-account-refused' ((Service).ProcessId -eq 0)
Change-Config @{StartName='NT AUTHORITY\LocalService'}
$saved=Record-Bytes;$tampered=Get-Content -LiteralPath $record -Raw|ConvertFrom-Json;$tampered.operator_sid='S-1-5-18';Write-Record $tampered
$null=Invoke-Manager start 'SERVICE_OWNERSHIP_CONFLICT'
Check 'altered-registration-refused' ((Service).ProcessId -eq 0)
[IO.File]::WriteAllBytes($record,$saved)
# A different exact SCM host owns this target profile. Manager must never send
# an unbound profile-wide DaemonStop or signal that owner by its numeric PID.
$foreignCommand='"'+$exe+'" --internal-scm '+$foreignName+' "'+(Join-Path $root 'host-profile')+'"'
Create-Manual $foreignName $foreignCommand
$null=Invoke-CimMethod -InputObject (Service $foreignName) -MethodName StartService
$foreign=Wait-State $foreignName 'Running';$foreignId=$foreign.ProcessId
$null=Invoke-Manager start 'SERVICE_NOT_READY'
$null=Invoke-Manager stop 'SERVICE_NOT_READY'
Check 'existing-profile-owner-preserved' ((Service $foreignName).State -eq 'Running' -and (Service $foreignName).ProcessId -eq $foreignId)
$foreignProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$foreignId"
$null=Invoke-CimMethod -InputObject (Service $foreignName) -MethodName StopService
$null=Wait-State $foreignName 'Stopped';Wait-Gone $foreignId $foreignProcess.CreationDate
Delete-Owned $foreignName $foreignCommand
$restart=Invoke-Manager restart
Check 'failed-start-restart-recovered' ($restart.state.Contains('previous service failure') -and (Service).State -eq 'Running')
$actual=Service;$actualProcess=Get-CimInstance Win32_Process -Filter "ProcessId=$($actual.ProcessId)"
$actualSid=Invoke-CimMethod -InputObject $actualProcess -MethodName GetOwnerSid
Check 'actual-default-host-is-localservice-session0' ($actualSid.Sid -ceq 'S-1-5-19' -and $actualProcess.SessionId -eq 0)
$null=Invoke-Manager status
$firstId=(Service).ProcessId
$null=Invoke-Manager restart
Check 'controlled-restart-replaces-owner' ((Service).State -eq 'Running' -and (Service).ProcessId -ne $firstId)
Crash-Owned
$null=Invoke-Manager status 'SERVICE_NOT_READY'
$restarted=Invoke-Manager restart
Check 'crashed-owner-restart-recovered' ($restarted.state.Contains('previous service failure') -and (Service).State -eq 'Running')
Crash-Owned
$uninstalled=Invoke-Manager uninstall
Check 'crashed-owner-uninstall-recovered' ($uninstalled.state.Contains('previous service failure') -and !(Service) -and !(Test-Path -LiteralPath $record))
# A final clean host stop checkpoints SQLite before both preservation probes.
$null=Invoke-Manager install;$null=Invoke-Manager start;$null=Invoke-Manager stop
$before=Observe-Database before
$workspace=Join-Path $root 'workspace';$null=New-Item -ItemType Directory -Path $workspace
$synthetic=Join-Path $workspace 'keep.db';[IO.File]::WriteAllText($synthetic,'synthetic-workspace-db-v1')
$keepHash=(Get-FileHash -LiteralPath $synthetic -Algorithm SHA256).Hash
$held=[ServiceProcess.ServiceController]::new($name);$heldHandle=$held.ServiceHandle;$null=$heldHandle.DangerousGetHandle()
$null=Invoke-Manager uninstall-delete-fault 'SERVICE_OPERATION_UNCERTAIN'
Check 'deleting-intent-retained-after-delete' ((Get-Content -LiteralPath $record -Raw|ConvertFrom-Json).phase -eq 'Deleting')
$null=Invoke-Manager uninstall 'SERVICE_OPERATION_UNCERTAIN'
Check 'delete-pending-retains-registration' (Test-Path -LiteralPath $record)
$heldHandle.Dispose();$held.Close();$held.Dispose();Start-Sleep -Milliseconds 150
$null=Invoke-Manager uninstall
Check 'delete-pending-retry-confirms-absence' (!(Service) -and !(Test-Path -LiteralPath $record))
$after=Observe-Database after
Check 'actual-host-db-and-workspace-preserved' ($before.sha256 -ceq $after.sha256 -and $before.bytes -eq $after.bytes -and (Get-FileHash -LiteralPath $synthetic -Algorithm SHA256).Hash -ceq $keepHash)
# Public default CLI has no fixture path and rejects elevated/builtin policy.
$old=$ErrorActionPreference;$ErrorActionPreference='Continue'
$output=(& $exe --profile-dir (Join-Path $root 'forbidden-profile') service install --mode boot --account 'NT AUTHORITY\LocalService' 2>$null)|Out-String
$exit=$LASTEXITCODE;$ErrorActionPreference=$old
Check 'public-privileged-policy-rejected-before-profile' ($exit -eq 3 -and !(Test-Path -LiteralPath (Join-Path $root 'forbidden-profile')))
$cleaned=Observe-Database cleanup
Check 'same-account-fixture-profile-cleanup' ($cleaned.cleanupComplete -eq $true -and !(Test-Path -LiteralPath (Join-Path $root 'host-profile')))
# Only recognized fixture data, after all product/probe services and owners end.
Check 'all-fixture-services-absent' (!(Service) -and !(Service $probeName) -and !(Service $foreignName))
$active=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)})
Check 'all-owned-processes-gone' ($active.Count -eq 0)
$allowed=@('fixture.marker','manager-progress.json','lomiremote.exe','windows-service-proof.exe','host-profile','workspace','db-before.json','db-after.json','profile-cleanup.json')
foreach($item in Get-ChildItem -LiteralPath $root -Force){if($item.Name -notin $allowed -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unknown UUID content; preserve'}}
foreach($item in Get-ChildItem -LiteralPath $registration -Force){if($item.Name -ne 'owner.lock' -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unknown registration content; preserve'}}
foreach($item in Get-ChildItem -LiteralPath $workspace -Force){if($item.Name -ne 'keep.db' -or $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unknown workspace content; preserve'}}
$null=Invoke-Manager audit
Check 'native-openservice-confirms-three-absences' $true
Remove-Item -LiteralPath $root -Recurse -Force
Remove-Item -LiteralPath $registration -Recurse -Force
$rootAbsent=!(Test-Path -LiteralPath $root);$registrationAbsent=!(Test-Path -LiteralPath $registration)
Check 'fixture-and-registration-roots-absent' ($rootAbsent -and $registrationAbsent)
@{passed=($rootAbsent -and $registrationAbsent);qualified=$false;checks=$checks;actualHostDbDigestPreserved=$true;workspacePreserved=$true;managerService=$name;observerService=$probeName;foreignFixtureService=$foreignName;manualLocalServiceOnly=$true;publicBootCredentialsQualified=$false;servicesAbsent=$true;ownedProcessesRemaining=0;rootAbsent=$rootAbsent;registrationAbsent=$registrationAbsent;observerReadOnlyProbes=2;sameAccountCleanup=$true}|ConvertTo-Json -Depth 8 -Compress
