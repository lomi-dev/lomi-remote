[CmdletBinding()]
param(
    [Parameter(Mandatory)][switch]$DisposableSyntheticResources,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$OperatorSid,
    [Parameter(Mandatory)][string]$Binary
)
. "$PSScriptRoot\Common.ps1"
if (-not $DisposableSyntheticResources) { throw 'Explicit synthetic resource flag required' }
Assert-Administrator
if ([Environment]::GetFolderPath('CommonApplicationData') -cne 'C:\ProgramData') { throw 'Fixture currently requires C:\ProgramData; refusing another root' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $OperatorSid) { throw 'Operator SID must be the current elevated installer account' }
$context = Get-FixtureContext $RunId $OperatorSid
if (Test-Path -LiteralPath $context.Root) { throw 'Fresh UUID directory already exists; refusing reuse' }
if ($null -ne (Get-Service -Name $context.Name -ErrorAction SilentlyContinue)) { throw 'Fresh UUID service already exists' }
$source = Get-Item -LiteralPath $Binary
if ($source.PSIsContainer -or ($source.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Expected regular compiled fixture binary' }
$parent = Split-Path $context.Root
if (-not (Test-Path -LiteralPath $parent)) {
    # Security is assigned atomically at creation; never repair/take ownership
    # of an existing parent that another account might have precreated.
    $null = [IO.Directory]::CreateDirectory($parent, (Get-ParentSecurity))
}
Assert-FixtureChain
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;$OperatorSid)")
$null = [IO.Directory]::CreateDirectory($context.Root, $acl)
Assert-FixtureChain
[IO.File]::WriteAllText((Join-Path $context.Root 'fixture.marker'), "lomi-windows-synthetic-v1:$RunId`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText((Join-Path $context.Root 'bootstrap.pending'), "synthetic-bootstrap-v1`n", [Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $source.FullName -Destination $context.Exe
$binaryPath = '"' + $context.Exe + '" service ' + $RunId + ' ' + $OperatorSid
# No credentials, shell profiles, remote endpoints, auto-start, recovery action,
# real user key store, or reboot changes. LocalService has a distinct DPAPI scope.
Assert-FixtureRoot $context
$null = Assert-FixtureContents $context
$created = Invoke-CimMethod -ClassName Win32_Service -MethodName Create -Arguments @{
    Name=$context.Name; DisplayName=$context.Name; PathName=$binaryPath;
    ServiceType=[byte]16; ErrorControl=[byte]1; StartMode='Manual'; DesktopInteract=$false;
    StartName='NT AUTHORITY\LocalService'
}
if ($created.ReturnValue -ne 0) { throw 'Exact synthetic LocalService creation failed' }
$null = Get-OwnedService $context
[pscustomobject]@{ installed=$true; started=$false; qualified=$false; runId=$RunId; service=$context.Name } | ConvertTo-Json -Compress
