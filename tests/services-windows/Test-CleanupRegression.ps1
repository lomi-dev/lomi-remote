[CmdletBinding()]
param()
# Pure in-memory proof checks. No services, files, consoles, or native clients
# are started, stopped, read, or removed by these tests.
. "$PSScriptRoot\Common.ps1"
$run = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
$owner = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
$state = [pscustomobject]@{ Stops=0; Reads=0; LastStop=$null }
function Get-OwnedService { param($Context) [pscustomobject]@{ State='Stopped' } }
function Stop-OwnedFixture { param($Context) $state.Stops++; throw 'Unexpected service operation in pure proof test' }
function Invoke-Fixture { param($Context,$Mode,$Command) $state.Reads++; $state.LastStop }
function New-TestContext {
    $c = Get-FixtureContext $run 'S-1-5-21-1-2-3-1000'
    $c.CleanupState.OwnerEpoch = $owner
    $c
}
function Valid-Stop {
    [pscustomobject]@{ ownerEpoch=$owner; stopReceived=$true; cleanupComplete=$true; jobEmpty=$true }
}
$checks = @()
$c = New-TestContext
$state.LastStop = Valid-Stop
$state.LastStop.cleanupComplete = $false
$failed = $false
try { Assert-CurrentStopProof $c $state.LastStop } catch { $failed=$true }
if (-not $failed -or -not $c.CleanupState.FailedProof) { throw 'Invalid last-stop proof was not latched' }
# Even a subsequent Stopped state and repaired-looking file cannot erase a
# previously failed proof for this owner epoch.
$state.LastStop = Valid-Stop
$rejected = $false
try { $null = Confirm-OwnedFixtureCleanup $c } catch { $rejected=$true }
if (-not $rejected -or $null -ne $c.CleanupState.ProvenEpoch) { throw 'Stopped state replaced failed owner proof' }
$checks += 'failed-last-stop-proof-remains-unverified-after-SCM-Stopped'
$c = New-TestContext
$c.CleanupState.OwnerEpoch = $null
$rejected = $false
try { $null = Confirm-OwnedFixtureCleanup $c } catch { $rejected=$true }
if (-not $rejected) { throw 'Stopped state with unknown owner accepted' }
$checks += 'stopped-with-unknown-owner-rejected'
$c = New-TestContext
$state.LastStop = Valid-Stop
$state.LastStop.ownerEpoch = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc'
$rejected = $false
try { $null = Confirm-OwnedFixtureCleanup $c } catch { $rejected=$true }
if (-not $rejected) { throw 'Stale owner stop record accepted' }
$checks += 'stale-owner-stop-proof-rejected'
$c = New-TestContext
$state.LastStop = Valid-Stop
$state.LastStop.jobEmpty = 'true'
$rejected = $false
try { $null = Confirm-OwnedFixtureCleanup $c } catch { $rejected=$true }
if (-not $rejected) { throw 'Nonboolean cleanup evidence accepted' }
$checks += 'nonboolean-stop-proof-rejected'
$c = New-TestContext
$state.LastStop = Valid-Stop
$verified = Confirm-OwnedFixtureCleanup $c
if ($verified -isnot [bool] -or $verified -ne $true -or $c.CleanupState.ProvenEpoch -cne $owner) { throw 'Current-owner positive proof rejected' }
if ($state.Stops -ne 0) { throw 'Pure regression attempted a service operation' }
$checks += 'explicit-current-owner-stop-proof-accepted'
[pscustomobject]@{ passed=$true; checks=$checks; serviceOperations=0; qualified=$false } | ConvertTo-Json -Depth 4 -Compress
