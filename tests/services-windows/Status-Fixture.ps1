[CmdletBinding()]
param([Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$OperatorSid)
. "$PSScriptRoot\Common.ps1"
$context = Get-FixtureContext $RunId $OperatorSid
Assert-FixtureRoot $context
$service = Get-OwnedService $context
$result = [ordered]@{ serviceExists=$true; state=$service.State; manualStart=$service.StartMode -eq 'Manual'; qualified=$false; runId=$RunId }
if ($service.State -eq 'Running') { $result.observation = Invoke-Fixture $context }
$result | ConvertTo-Json -Depth 8 -Compress
