[CmdletBinding()]
param([Parameter(Mandatory)][switch]$DisposableSyntheticResources,
      [Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$OperatorSid)
. "$PSScriptRoot\Common.ps1"
if (-not $DisposableSyntheticResources) { throw 'Explicit synthetic resource flag required' }
Assert-Administrator
$context = Get-FixtureContext $RunId $OperatorSid
Assert-FixtureRoot $context
# Validate before any SCM change. If a previous removal stopped after deleting
# the service, exact absent service is safe and the private UUID files remain retryable.
$items = @(Assert-FixtureContents $context)
$service = Get-OwnedService $context -AllowAbsent
if ($null -ne $service) {
    if ($service.State -ne 'Stopped') { $null = Stop-OwnedFixture $context }
    Assert-FixtureRoot $context
    $null = Assert-FixtureContents $context
    & sc.exe delete $context.Name | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Exact service deletion failed' }
    $deadline = [DateTime]::UtcNow.AddSeconds(8)
    do {
        $exists = Get-CimInstance Win32_Service -Filter "Name='$($context.Name)'"
        if ($null -eq $exists) { break }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($null -ne $exists) { throw 'Fixture deletion pending; private directory preserved' }
}
Assert-FixtureRoot $context
$items = @(Assert-FixtureContents $context)
# Keep the identity marker until every other file is gone, so an interrupted
# post-SCM removal remains verifiable and retryable.
foreach ($item in $items | Where-Object { $_.Name -ne 'fixture.marker' }) { Remove-Item -LiteralPath $item.FullName -Force }
Remove-Item -LiteralPath (Join-Path $context.Root 'fixture.marker') -Force
Remove-Item -LiteralPath $context.Root -Force
[pscustomobject]@{ removed=$true; qualified=$false; runId=$RunId } | ConvertTo-Json -Compress
