Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.ServiceProcess
function Get-FixtureContext {
    param([Parameter(Mandatory)][string]$RunId, [Parameter(Mandatory)][string]$OperatorSid)
    $parsed = [Guid]::Empty
    if (-not [Guid]::TryParseExact($RunId, 'D', [ref]$parsed) -or $parsed.ToString('D') -cne $RunId) { throw 'Invalid fixture UUID' }
    if ($OperatorSid -notmatch '^S-1-5-21-(\d+-){3}\d+$') { throw 'Expected an explicit operator account SID' }
    $root = Join-Path 'C:\ProgramData\LomiWindowsFixture' $RunId
    [pscustomobject]@{ RunId=$RunId; OperatorSid=$OperatorSid; Root=$root; Name="LomiFixture-$RunId"; Exe=(Join-Path $root 'lomi-windows-service-fixture.exe'); CleanupState=[pscustomobject]@{ OwnerEpoch=$null; ProvenEpoch=$null; FailedProof=$false } }
}
function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Requires elevated administrator for only the fresh fixture resources' }
}
function Assert-PlainDirectory {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Untrusted directory chain' }
}
function Get-ParentSecurity {
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;;0x1200a9;;;LS)(A;OICI;FA;;;BA)')
    $security
}
function Assert-TrustedParentPath {
    param([string]$Path)
    Assert-PlainDirectory $Path
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -cne 'S-1-5-32-544') { throw 'Untrusted fixture parent owner' }
    $expected = Get-ParentSecurity
    $section = [Security.AccessControl.AccessControlSections]::Access
    if ($acl.GetSecurityDescriptorSddlForm($section) -cne $expected.GetSecurityDescriptorSddlForm($section)) { throw 'Untrusted fixture parent DACL' }
}
function Assert-FixtureChain {
    Assert-PlainDirectory 'C:\'
    Assert-PlainDirectory 'C:\ProgramData'
    $baseAcl = Get-Acl -LiteralPath 'C:\ProgramData'
    $trusted = @('S-1-5-18','S-1-5-32-544')
    if ($baseAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted ProgramData owner' }
    foreach ($ace in $baseAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -ne 'Allow' -or ($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly)) { continue }
        if (([uint32]$ace.FileSystemRights -band 0xD0040) -ne 0 -and $ace.IdentityReference.Value -notin $trusted) { throw 'Untrusted ProgramData replacement rights' }
    }
    Assert-TrustedParentPath 'C:\ProgramData\LomiWindowsFixture'
}
function Assert-FixtureContents {
    param($Context)
    $allowed = @('lomi-windows-service-fixture.exe','fixture.marker','bootstrap.pending','initialized','owner.lock','dpapi.bin','session.json','last-stop.json','startup-status.json')
    $items = @(Get-ChildItem -LiteralPath $Context.Root -Force)
    foreach ($item in $items) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -notin $allowed) { throw 'Unexpected fixture content; preserving resources' }
    }
    $items
}
function Assert-FixtureRoot {
    param($Context)
    Assert-FixtureChain
    $item = Get-Item -LiteralPath $Context.Root -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Invalid fixture root' }
    $acl = Get-Acl -LiteralPath $Context.Root
    $expected = [Security.AccessControl.DirectorySecurity]::new()
    $expected.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;$($Context.OperatorSid))")
    $section = [Security.AccessControl.AccessControlSections]::Access
    if ($acl.GetSecurityDescriptorSddlForm($section) -cne $expected.GetSecurityDescriptorSddlForm($section)) { throw 'Untrusted UUID directory DACL' }
    $marker = Get-Item -LiteralPath (Join-Path $Context.Root 'fixture.marker') -Force
    if ($marker.PSIsContainer -or ($marker.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $marker.Length -gt 128) { throw 'Invalid fixture marker file' }
    if ((Get-Content -LiteralPath (Join-Path $Context.Root 'fixture.marker') -Raw) -cne "lomi-windows-synthetic-v1:$($Context.RunId)`n") { throw 'Fixture marker mismatch' }
}
function Get-OwnedService {
    param($Context, [switch]$AllowAbsent)
    Assert-FixtureRoot $Context
    $service = Get-CimInstance Win32_Service -Filter "Name='$($Context.Name)'"
    if ($null -eq $service) { if ($AllowAbsent) { return $null }; throw 'Exact fixture service missing' }
    $expected = '"' + $Context.Exe + '" service ' + $Context.RunId + ' ' + $Context.OperatorSid
    if ($service.PathName -cne $expected -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Fixture service identity mismatch' }
    $service
}
function Invoke-Fixture {
    param($Context, [string]$Mode='client', [string]$Command='status')
    $arguments = @($Mode,$Context.RunId,$Context.OperatorSid)
    if ($Mode -in @('client','delayed-client','hold-client')) { $arguments += $Command }
    $lines = & $Context.Exe @arguments
    if ($LASTEXITCODE -ne 0) {
        $tag = ''
        try {
            $failure = ($lines -join "`n") | ConvertFrom-Json
            if ($null -ne $failure.PSObject.Properties['faultStage']) { $tag = ':' + $failure.faultStage }
        } catch { }
        throw "Synthetic fixture operation failed: $Mode/$Command$tag"
    }
    ($lines -join "`n") | ConvertFrom-Json
}
function Wait-Fixture {
    param($Context, [scriptblock]$Condition, [int]$Seconds=8)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        try { $status = Invoke-Fixture $Context; if (& $Condition $status) { return $status } } catch { }
        Start-Sleep -Milliseconds 100
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Fixture observation deadline'
}
function Assert-CurrentStopProof {
    param($Context, $Stopped)
    try {
        $epoch = [Guid]::Empty
        if ($Context.CleanupState.FailedProof -or [string]::IsNullOrEmpty($Context.CleanupState.OwnerEpoch) -or
            -not [Guid]::TryParseExact($Context.CleanupState.OwnerEpoch,'D',[ref]$epoch)) { throw 'Current owner proof unknown or previously failed' }
        if ($Stopped.ownerEpoch -cne $Context.CleanupState.OwnerEpoch -or
            $Stopped.stopReceived -isnot [bool] -or $Stopped.stopReceived -ne $true -or
            $Stopped.cleanupComplete -isnot [bool] -or $Stopped.cleanupComplete -ne $true -or
            $Stopped.jobEmpty -isnot [bool] -or $Stopped.jobEmpty -ne $true) { throw 'Current owner stop proof invalid' }
        $Context.CleanupState.ProvenEpoch = $Stopped.ownerEpoch
    } catch {
        $Context.CleanupState.FailedProof = $true
        $Context.CleanupState.ProvenEpoch = $null
        throw
    }
}
function Stop-OwnedFixture {
    param($Context, $ExpectedOwner=$null)
    $null = Get-OwnedService $Context
    try {
        $expected = $ExpectedOwner
        if ($null -eq $expected) { try { $expected = Invoke-Fixture $Context } catch { } }
        if ($null -eq $Context.CleanupState.OwnerEpoch -and $null -ne $expected) { $Context.CleanupState.OwnerEpoch = $expected.ownerEpoch }
        $Context.CleanupState.ProvenEpoch = $null
        # Stop even when IPC could not establish proof. Such a stop must remain
        # unverified; a later SCM Stopped observation cannot erase the failure.
        $controller = [ServiceProcess.ServiceController]::new($Context.Name)
        try { $controller.Stop(); $controller.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(8)) } finally { $controller.Dispose() }
        $stopped = Invoke-Fixture $Context 'read-stop'
        if ($null -eq $expected -or $expected.ownerEpoch -cne $Context.CleanupState.OwnerEpoch) { throw 'Current owner epoch not established' }
        Assert-CurrentStopProof $Context $stopped
        $stopped
    } catch {
        $Context.CleanupState.FailedProof = $true
        $Context.CleanupState.ProvenEpoch = $null
        throw
    }
}
function Confirm-OwnedFixtureCleanup {
    param($Context)
    $service = Get-OwnedService $Context
    if ($service.State -ne 'Stopped') { $null = Stop-OwnedFixture $Context }
    # Always reread the last-stop record and bind it to the observed current
    # owner epoch. Service state alone proves neither cleanup nor ownership.
    Assert-CurrentStopProof $Context (Invoke-Fixture $Context 'read-stop')
    $true
}
function Start-OwnedFixture {
    param($Context)
    $null = Get-OwnedService $Context
    $Context.CleanupState.OwnerEpoch = $null
    $Context.CleanupState.ProvenEpoch = $null
    $Context.CleanupState.FailedProof = $false
    $controller = [ServiceProcess.ServiceController]::new($Context.Name)
    try { $controller.Start(); $controller.WaitForStatus('Running',[TimeSpan]::FromSeconds(8)) } finally { $controller.Dispose() }
    $owner = Wait-Fixture $Context { param($s) -not [string]::IsNullOrEmpty($s.ownerEpoch) }
    $epoch = [Guid]::Empty
    if (-not [Guid]::TryParseExact($owner.ownerEpoch,'D',[ref]$epoch)) { throw 'Invalid current owner epoch' }
    $Context.CleanupState.OwnerEpoch = $owner.ownerEpoch
}
