[CmdletBinding()]
param([Parameter(Mandatory)][switch]$DisposableSyntheticResources,
      [Parameter(Mandatory)][string]$Binary,
      [Parameter(Mandatory)][string]$WorkDirectory)
# Prepared native regression. It creates only fresh synthetic UUID directories;
# SCM Create is intercepted and forced to fail, so it installs no service.
. "$PSScriptRoot\Common.ps1"
if (-not $DisposableSyntheticResources) { throw 'Explicit synthetic resource flag required' }
Assert-Administrator
$operator = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$probe = Join-Path $WorkDirectory ('parent-policy-' + [Guid]::NewGuid().ToString('D'))
$null = New-Item -ItemType Directory -Path $probe
$checks = @()
try {
    $bad = [Security.AccessControl.DirectorySecurity]::new()
    $bad.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;WD)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $probe -AclObject $bad
    $rejected = $false
    try { Assert-TrustedParentPath $probe } catch { $rejected = $true }
    if (-not $rejected) { throw 'Broadly writable precreated parent accepted' }
    $checks += 'broadly-writable-precreated-parent-rejected'
} finally {
    # This exact empty directory was created by this invocation; no recursion.
    Remove-Item -LiteralPath $probe -Force
}
$run = [Guid]::NewGuid().ToString('D')
$context = Get-FixtureContext $run $operator
$probeState = [pscustomobject]@{ createIntercepted=$false; queries=0 }
function Invoke-CimMethod {
    param($ClassName,$MethodName,$Arguments)
    if ($ClassName -ne 'Win32_Service' -or $MethodName -ne 'Create' -or $Arguments.Name -cne $context.Name) { throw 'Unexpected native operation in policy probe' }
    $probeState.createIntercepted = $true
    [pscustomobject]@{ ReturnValue=5 }
}
try {
    $failed = $false
    try { & "$PSScriptRoot\Install-Fixture.ps1" -DisposableSyntheticResources -RunId $run -OperatorSid $operator -Binary $Binary } catch { $failed = $true }
    if (-not $failed -or -not $probeState.createIntercepted) { throw 'Synthetic SCM create failure not exercised' }
    if ($null -ne (CimCmdlets\Get-CimInstance Win32_Service -Filter "Name='$($context.Name)'")) { throw 'Policy regression must never create an SCM service' }
    Assert-FixtureRoot $context
    $checks += 'failed-create-preserves-owned-retryable-files-with-no-service'
    # Unknown files must fail before any SCM query/deletion. This also proves a
    # failed preflight leaves both the files and the service decision untouched.
    $unknown = Join-Path $context.Root 'unexpected.synthetic'
    [IO.File]::WriteAllText($unknown,'synthetic only')
    $probeState.queries = 0
    function Get-CimInstance {
        param($ClassName,$Filter)
        $probeState.queries++
        CimCmdlets\Get-CimInstance -ClassName $ClassName -Filter $Filter
    }
    $rejected = $false
    try { & "$PSScriptRoot\Remove-Fixture.ps1" -DisposableSyntheticResources -RunId $run -OperatorSid $operator } catch { $rejected = $true }
    if (-not $rejected -or $probeState.queries -ne 0 -or -not (Test-Path -LiteralPath $unknown)) { throw 'Unknown contents changed SCM or files' }
    $checks += 'unknown-files-rejected-before-SCM-or-file-deletion'
    Remove-Item -LiteralPath $unknown -Force
    # Simulate interruption after service deletion and one file deletion. No
    # actual SCM operation is needed: absent service is established above.
    Remove-Item -LiteralPath (Join-Path $context.Root 'bootstrap.pending') -Force
    $null = & "$PSScriptRoot\Remove-Fixture.ps1" -DisposableSyntheticResources -RunId $run -OperatorSid $operator
    if (Test-Path -LiteralPath $context.Root) { throw 'Absent-service cleanup could not resume' }
    $checks += 'interrupted-removal-with-absent-service-resumes-private-UUID-cleanup'
} finally {
    Remove-Item Function:\Invoke-CimMethod -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-CimInstance -ErrorAction SilentlyContinue
    # Cleanup only if the exact protected marker/root is still verifiable.
    if (Test-Path -LiteralPath $context.Root) {
        $null = & "$PSScriptRoot\Remove-Fixture.ps1" -DisposableSyntheticResources -RunId $run -OperatorSid $operator
    }
}
[pscustomobject]@{ passed=$true; checks=$checks; scmServiceCreated=$false; qualified=$false } | ConvertTo-Json -Depth 4 -Compress
