param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Source)
. "$PSScriptRoot\..\services-windows\Common.ps1"
Assert-Administrator
if ([Guid]::Parse($RunId).ToString('D') -cne $RunId) { throw 'UUID required' }
if ([Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0) { throw 'Session 0 required' }
$operator=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$root=Join-Path 'C:\ProgramData\LomiWindowsFixture' $RunId
$name="LomiProductScm-$RunId"
if ((Test-Path -LiteralPath $root) -or (Get-Service -Name $name -ErrorAction SilentlyContinue)) { throw 'Fresh resources required' }
$parent=Split-Path $root
if (!(Test-Path -LiteralPath $parent)) { $null=[IO.Directory]::CreateDirectory($parent,(Get-ParentSecurity)) }
Assert-FixtureChain
$acl=[Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;BA)")
$null=[IO.Directory]::CreateDirectory($root,$acl)
[IO.File]::WriteAllText((Join-Path $root 'fixture.marker'),"lomi-product-scm-v1:$RunId`n")
Copy-Item -LiteralPath (Join-Path $Source 'target\debug\lomiremote.exe') -Destination (Join-Path $root 'lomiremote.exe')
Copy-Item -LiteralPath (Join-Path $Source 'target\debug\examples\windows-scm-proof.exe') -Destination (Join-Path $root 'windows-scm-proof.exe')
$expected='"'+(Join-Path $root 'windows-scm-proof.exe')+'" '+$name+' "'+$root+'"'
$created=Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{Name=$name;DisplayName=$name;PathName=$expected;ServiceType=[byte]16;ErrorControl=[byte]1;StartMode='Manual';DesktopInteract=$false;StartName='NT AUTHORITY\LocalService'}
if ($created.ReturnValue -ne 0) { throw 'Service creation failed; preserve UUID' }
function Owned-Service {
    $s=Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($s.PathName -cne $script:expected -or $s.StartName -ne 'NT AUTHORITY\LocalService' -or $s.StartMode -ne 'Manual') { throw 'Service identity changed' }
    $s
}
function Wait-State([string]$state) {
    $deadline=[DateTime]::UtcNow.AddSeconds(45)
    do { $s=Owned-Service; if ($s.State -eq $state) { return $s }; Start-Sleep -Milliseconds 100 } while ([DateTime]::UtcNow -lt $deadline)
    throw 'SCM state deadline; preserve resources'
}
function Wait-Receipt([string]$file) {
    $path=Join-Path $root $file
    $deadline=[DateTime]::UtcNow.AddSeconds(60)
    do {
        if (Test-Path -LiteralPath (Join-Path $root 'observer-failed.json')) { throw 'Observer failed; preserve metadata' }
        if (Test-Path -LiteralPath $path) { $r=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json; if ($r.passed -ne $true) { throw 'Receipt failed' }; return $r }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Observer receipt deadline'
}
function Descendants([uint32]$owner) {
    $all=@(Get-CimInstance Win32_Process);$ids=@($owner);$found=@()
    do { $next=@($all|Where-Object { $_.ParentProcessId -in $ids -and $_.ProcessId -notin $ids });if($next.Count -gt 0){$ids+=@($next.ProcessId);$found+=$next} } while ($next.Count -gt 0)
    @($found|ForEach-Object { @{pid=$_.ProcessId;created=$_.CreationDate;name=$_.Name} })
}
function Assert-Gone($identities) {
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    do {
        $active=@(foreach($id in $identities) { $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($id.pid)"; if ($p -and $p.CreationDate -eq $id.created) { $p } })
        if ($active.Count -eq 0) { return }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Owned process remains; preserve resources'
}
function Owner-Identity($s) {
    $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($s.ProcessId)"
    if ($p.SessionId -ne 0) { throw 'Owner outside Session 0' }
    $sid=Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
    if ($sid.Sid -cne 'S-1-5-19') { throw 'Owner must remain LocalService' }
    @{pid=$p.ProcessId;created=$p.CreationDate;name=$p.Name}
}
$sentinel=Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList ('/d /c "title LomiScmSentinel-'+$RunId+' & ping -n 180 127.0.0.1 >nul"') -WindowStyle Hidden -PassThru
$sentinelId=$sentinel.Id
@{pid=$sentinelId;runId=$RunId}|ConvertTo-Json -Compress|Set-Content -LiteralPath (Join-Path $root 'sentinel-id.json')
Start-Sleep -Milliseconds 200
$sentinelTree=@(Descendants $sentinelId)
Start-Service -Name $name
$running=Wait-State 'Running';$owner=Owner-Identity $running
$first=Wait-Receipt 'observer-proof.json'
$tree=@(Descendants $running.ProcessId)
if (@($tree|Where-Object { $_.name -eq 'cmd.exe' }).Count -lt 1) { throw 'Ordinary live shell missing' }
# Foreign-account operator remains unable to use product IPC.
$oldPreference=$ErrorActionPreference;$ErrorActionPreference='Continue'
$denied=(& (Join-Path $root 'lomiremote.exe') --profile-dir (Join-Path $root 'profile') status --json 2>$null)|Out-String
$foreignExit=$LASTEXITCODE;$ErrorActionPreference=$oldPreference
if ($foreignExit -ne 5) { throw 'Foreign account IPC must remain denied' }
Stop-Service -Name $name
$stopped=Wait-State 'Stopped';Assert-Gone (@($owner)+$tree)
if ($stopped.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $root 'profile\discovery.json'))) { throw 'Controlled cleanup unconfirmed' }
Remove-Item -LiteralPath (Join-Path $root 'observer-proof.json')
[IO.File]::WriteAllText((Join-Path $root 'arm-timeout'),'fixture-only')
Start-Service -Name $name
$running=Wait-State 'Running';$owner=Owner-Identity $running
$second=Wait-Receipt 'observer-proof.json'
if ($second.runtimeId -eq $first.runtimeId) { throw 'Restart reused runtime' }
$tree=@(Descendants $running.ProcessId)
if (@($tree|Where-Object { $_.name -eq 'cmd.exe' }).Count -lt 1) { throw 'Restarted shell missing' }
# Retain an actual process handle before triggering the production deadline.
$timeoutProcess=[Diagnostics.Process]::GetProcessById($running.ProcessId)
$null=$timeoutProcess.Handle
[IO.File]::WriteAllText((Join-Path $root 'trigger-timeout'),'fixture-only')
$null=Wait-Receipt 'timeout-armed.json'
$stopResult=Invoke-CimMethod -InputObject (Owned-Service) -MethodName StopService
if ($stopResult.ReturnValue -notin @(0,6)) { throw 'SCM timeout STOP rejected' }
if (!$timeoutProcess.WaitForExit(15000)) { throw 'Timeout process exit unconfirmed' }
$timeoutExit=$timeoutProcess.ExitCode
$timeoutProcess.Dispose()
$crashed=Wait-State 'Stopped';Assert-Gone (@($owner)+$tree)
if ($timeoutExit -ne 1 -or $crashed.ExitCode -eq 0) { throw 'Production incomplete path must exit1 and fail SCM' }
Start-Sleep -Milliseconds 700
if ((Owned-Service).State -ne 'Stopped') { throw 'Unexpected automatic restart' }
Start-Service -Name $name
$running=Wait-State 'Running';$owner=Owner-Identity $running
$lost=Wait-Receipt 'restart-proof.json'
if ($lost.oldSessionLost -ne $true -or $lost.automaticShell -ne $false -or $lost.runtimeId -eq $second.runtimeId) { throw 'Crash restart projection failed' }
if (@(Descendants $running.ProcessId|Where-Object { $_.name -eq 'cmd.exe' }).Count -ne 0) { throw 'Automatic shell created' }
Stop-Service -Name $name
$stopped=Wait-State 'Stopped';Assert-Gone @($owner)
if ($stopped.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $root 'profile\discovery.json'))) { throw 'Projection stop failed' }
# Independently test the default actual CLI hidden entry, with no observer.
$original=Owned-Service
$expected='"'+(Join-Path $root 'lomiremote.exe')+'" --internal-scm '+$name+' "'+(Join-Path $root 'cli-profile')+'"'
$changed=Invoke-CimMethod -InputObject $original -MethodName Change -Arguments @{PathName=$expected}
if ($changed.ReturnValue -ne 0) { throw 'Exact stopped service binary switch failed' }
$null=Owned-Service
Start-Service -Name $name
$cliRunning=Wait-State 'Running';$cliOwner=Owner-Identity $cliRunning
Stop-Service -Name $name
$cliStopped=Wait-State 'Stopped';Assert-Gone @($cliOwner)
if ($cliStopped.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $root 'cli-profile\discovery.json'))) { throw 'Actual CLI controlled stop failed' }
Start-Service -Name $name
$cliRunning=Wait-State 'Running';$cliOwner=Owner-Identity $cliRunning
Stop-Process -Id $cliRunning.ProcessId -Force
$cliCrash=Wait-State 'Stopped';Assert-Gone @($cliOwner)
if ($cliCrash.ExitCode -eq 0) { throw 'Actual CLI crash must be nonzero' }
Start-Service -Name $name
$cliRunning=Wait-State 'Running';$cliOwner=Owner-Identity $cliRunning
Stop-Service -Name $name
$cliStopped=Wait-State 'Stopped';Assert-Gone @($cliOwner)
if ($cliStopped.ExitCode -ne 0 -or (Test-Path -LiteralPath (Join-Path $root 'cli-profile\discovery.json'))) { throw 'Actual CLI restart cleanup failed' }
if (!(Get-Process -Id $sentinelId -ErrorAction SilentlyContinue)) { throw 'Unrelated sentinel terminated' }
# Exact UUID content inventory: preserve all unknown entries and reparse points.
$allowed=@('fixture.marker','arm-timeout','trigger-timeout','timeout-armed.json','sentinel-id.json','lomiremote.exe','windows-scm-proof.exe','observer-proof.json','restart-proof.json','profile','cli-profile','dpapi-profile','workspace')
foreach($item in Get-ChildItem -LiteralPath $root -Force) { if ($item.Name -notin $allowed -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unknown UUID content; preserve' } }
foreach($dir in @('profile','cli-profile','dpapi-profile','workspace')) {
    $allowedFiles=if($dir -eq 'workspace'){@()}elseif($dir -eq 'dpapi-profile'){@('owner.lock','host-secrets.lock','host-secrets.dpapi')}else{@('host-public.toml','owner.lock','host.sqlite3','host.sqlite3-wal','host.sqlite3-shm')}
    foreach($item in Get-ChildItem -LiteralPath (Join-Path $root $dir) -Force) { if($item.PSIsContainer -or $item.Name -notin $allowedFiles -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'Unknown profile content; preserve'} }
}
$active=@(Get-CimInstance Win32_Process|Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase) })
if($active.Count -ne 0){throw 'UUID executable remains'}
$null=Owned-Service
& sc.exe delete $name|Out-Null
if($LASTEXITCODE -ne 0){throw 'Exact service deletion failed'}
Remove-Item -LiteralPath $root -Recurse -Force
# Sentinel is stopped only after its independent survival was verified.
Stop-Process -Id $sentinelId -Force
foreach($id in $sentinelTree) { $p=Get-CimInstance Win32_Process -Filter "ProcessId=$($id.pid)"; if ($p -and $p.CreationDate -eq $id.created) { Stop-Process -Id $id.pid -Force } }
Assert-Gone $sentinelTree
$serviceAbsent=($null -eq (Get-Service -Name $name -ErrorAction SilentlyContinue))
$profileRootAbsent=(!(Test-Path -LiteralPath $root))
if (!$serviceAbsent -or !$profileRootAbsent) { throw 'Final service/profile absence unconfirmed' }
@{passed=($serviceAbsent -and $profileRootAbsent);qualified=$false;productionTimeout=@{processExitCode=$timeoutExit;scmFailed=($crashed.ExitCode -ne 0);ownedTreeGone=$true;realScmStop=$true};localServiceOnly=$true;sessionId=0;observerExample=$first;restart=$lost;actualCliEntry=@{running=$true;controlledStop=$true;crashNonzero=$true;restart=$true};foreignAccountRejected=$true;controlledJobTreeGone=$true;crashedJobTreeGone=$true;sentinelPreserved=$true;serviceAbsent=$serviceAbsent;profileRootAbsent=$profileRootAbsent;ownedProcessesRemaining=0}|ConvertTo-Json -Depth 8 -Compress
