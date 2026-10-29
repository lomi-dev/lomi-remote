[CmdletBinding()]
param([Parameter(Mandatory)][switch]$DisposableSyntheticResources,
      [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$OperatorSid,
      [Parameter(Mandatory)][string]$Evidence, [switch]$FaultInjection)
. "$PSScriptRoot\Common.ps1"
if (-not $DisposableSyntheticResources) { throw 'Explicit synthetic resource flag required' }
Assert-Administrator
$context = Get-FixtureContext $RunId $OperatorSid
Assert-FixtureRoot $context
$null = Get-OwnedService $context
$report = [ordered]@{ kind='native-windows-service-synthetic'; runId=$RunId; qualified=$false; complete=$false; passed=$false; cleanupVerified=$false; checks=@(); not_run=@('headless boot','SSH disconnect across independent logins','multi-hour soak','other Windows builds/architectures') }
function Save-Evidence { $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Evidence -Encoding UTF8 }
function Record-Check([string]$Name,[scriptblock]$Action) {
    $row = [ordered]@{ name=$Name; passed=$false }
    $report.checks += $row
    Save-Evidence
    & $Action
    $row.passed = $true
    Save-Evidence
}
Save-Evidence
$exitCode = 1
try {
    Record-Check 'SCM-start-LocalService-session0' {
        Start-OwnedFixture $context
        $script:first = Wait-Fixture $context { param($s) $s.localService -and $s.sessionId -eq 0 -and $s.dpapiDecrypted }
        if ($first.qualified -ne $false -or $first.inputReplayed) { throw 'Invalid fixture scope' }
    }
    Record-Check 'second-owner-lock-denied' { $probe = Invoke-Fixture $context 'owner-probe'; if (-not $probe.secondOwnerRejected) { throw 'Owner lock proof missing' } }
    Record-Check 'two-independent-clients-no-input-replay' {
        $a = Invoke-Fixture $context; $b = Invoke-Fixture $context
        if ($a.ownerEpoch -ne $b.ownerEpoch -or $a.observation.inputWrites -ne 0 -or $b.observation.inputWrites -ne 0) { throw 'Client attach changed owner/input' }
    }
    Record-Check 'ConPTY-fixed-child-and-job-worker' {
        $null = Invoke-Fixture $context 'client' 'start'
        $script:started = Wait-Fixture $context { param($s) $s.observation.ready -and $s.observation.syntheticWorkerPid -gt 0 -and $s.jobActiveProcesses -eq 2 -and $s.observation.modelNonemptyCells -gt 0 }
    }
    Record-Check 'ConPTY-resize37x101' {
        $null = Invoke-Fixture $context 'client' 'resize'
        $null = Wait-Fixture $context { param($s) $s.observation.resized -and $s.observation.modelRows -eq 37 -and $s.observation.modelCols -eq 101 }
    }
    Record-Check 'after-detach-fixed-input-and-owner-survives' {
        # Each Invoke-Fixture is a separate native client process; no persistent
        # connection keeps the owner alive between these calls.
        Start-Sleep -Milliseconds 500
        $null = Invoke-Fixture $context 'client' 'after-detach'
        $s = Wait-Fixture $context { param($s) $s.observation.afterDetach }
        if ($s.ownerEpoch -ne $started.ownerEpoch -or $s.childPid -ne $started.childPid) { throw 'Owner/child changed after detach' }
    }
    Record-Check 'explicit-child-exit-job-empty' {
        $null = Invoke-Fixture $context 'client' 'exit'
        $null = Wait-Fixture $context { param($s) $s.jobActiveProcesses -eq 0 }
    }
    Record-Check 'SCM-stop-verified-cleanup-no-auto-respawn' {
        $null = Stop-OwnedFixture $context
        Start-Sleep -Milliseconds 500
        if ((Get-Service $context.Name).Status -ne 'Stopped') { throw 'Unexpected restart after stop' }
    }
    Record-Check 'restart-DPAPI-user-scope-and-old-epoch-lost' {
        Start-OwnedFixture $context
        $s = Wait-Fixture $context { param($s) $s.dpapiReopened -and $s.dpapiDecrypted -and $s.oldSessionLost -and $null -eq $s.sessionEpoch }
        if ($s.previousEpoch -ne $started.sessionEpoch -or $s.ownerEpoch -eq $started.ownerEpoch -or $s.observation.inputWrites -ne 0) { throw 'Restart adopted state or replayed input' }
    }
    Record-Check 'operator-can-read-ciphertext-cannot-decrypt' {
        $negative = Invoke-Fixture $context 'decrypt-negative'
        if (-not $negative.ciphertextReadable -or -not $negative.crossAccountDecryptRejected) { throw 'DPAPI negative proof incomplete' }
    }
    Record-Check 'fresh-explicit-epoch-and-CtrlC' {
        $null = Invoke-Fixture $context 'client' 'start'
        $s = Wait-Fixture $context { param($s) $s.observation.ready -and $s.jobActiveProcesses -eq 2 }
        if ($s.sessionEpoch -eq $started.sessionEpoch) { throw 'Fresh start reused epoch' }
        $null = Invoke-Fixture $context 'client' 'ctrl-c'
        $null = Wait-Fixture $context { param($s) $s.observation.ctrlC }
    }
    Record-Check 'SCM-ControlStop-kills-live-child-and-worker' { $null = Stop-OwnedFixture $context }
    if ($FaultInjection) {
        Record-Check 'squatted-server-SQOS-operator-impersonation-denied' {
            $probe = Invoke-Fixture $context 'security-probe'
            if (-not $probe.squattedServerRejected -or -not $probe.tokenAtMostIdentification) { throw 'SQOS isolation proof missing' }
        }
        Record-Check 'post-acquisition-close-spawn-failure-retains-and-releases-ConPTY' {
            Start-OwnedFixture $context
            $null = Wait-Fixture $context { param($s) $s.dpapiDecrypted }
            $null = Invoke-Fixture $context 'client' 'start'
            $null = Wait-Fixture $context { param($s) $s.observation.ready -and $s.jobActiveProcesses -eq 2 }
            $probe = Invoke-Fixture $context 'fault-close-probe'
            if (-not $probe.observation.conptyCloseFaultRetained -or -not $probe.observation.conptyCloseRetryComplete -or $probe.jobActiveProcesses -ne 0) { throw 'Close ownership proof incomplete' }
            $null = Stop-OwnedFixture $context
        }
        Record-Check 'delayed-response-reader-consumption-acknowledged' {
            Start-OwnedFixture $context
            $s = Wait-Fixture $context { param($s) $s.dpapiDecrypted }
            $delayed = Invoke-Fixture $context 'delayed-client' 'status'
            if ($delayed.ownerEpoch -ne $s.ownerEpoch) { throw 'Delayed client response corrupted' }
        }
        Record-Check 'ControlStop-cancels-unread-response-ack-wait' {
            $expected = Invoke-Fixture $context
            $info = [Diagnostics.ProcessStartInfo]::new()
            $info.FileName = $context.Exe
            $info.Arguments = "hold-client $RunId $OperatorSid status"
            $info.UseShellExecute = $false
            $info.CreateNoWindow = $true
            $info.RedirectStandardOutput = $true
            $held = [Diagnostics.Process]::Start($info)
            try {
                $ready = $held.StandardOutput.ReadLineAsync()
                if (-not $ready.Wait(3000) -or -not (($ready.Result | ConvertFrom-Json).requestWritten)) { throw 'Holding client not connected' }
                $clock = [Diagnostics.Stopwatch]::StartNew()
                $null = Stop-OwnedFixture $context $expected
                if ($clock.Elapsed.TotalSeconds -gt 8) { throw 'Stop exceeded cancellation budget' }
                if (-not $held.WaitForExit(3000)) { throw 'Holding client did not exit' }
            } finally {
                if (-not $held.HasExited) { $held.Kill(); $null = $held.WaitForExit(3000) }
                $held.Dispose()
            }
        }
    } else { $report.not_run += 'native fault/SQOS/delayed-reader regressions (requires fixture-test-hooks build and -FaultInjection)' }
    $exitCode = 0
} catch {
    # Class only: no PTY data, config dump, credentials or arbitrary exception text.
    $report.errorClass = $_.Exception.GetType().Name
    $report.errorId = $_.FullyQualifiedErrorId
    $report.errorLine = $_.InvocationInfo.ScriptLineNumber
} finally {
    try {
        $report.cleanupVerified = Confirm-OwnedFixtureCleanup $context
    } catch { $report.cleanupVerified = $false; $report.cleanupErrorClass = $_.Exception.GetType().Name; $exitCode = 1 }
    $report.complete = $exitCode -eq 0
    $report.passed = $exitCode -eq 0
    $report.exitCode = $exitCode
    Save-Evidence
}
exit $exitCode
