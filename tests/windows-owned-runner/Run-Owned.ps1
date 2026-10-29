[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string] $Executable,
    [string[]] $Arguments = @(),
    [Parameter(Mandatory = $true)][string] $WorkingDirectory,
    [Parameter(Mandatory = $true)][System.Collections.IDictionary] $Environment,
    [ValidateRange(1, 86400000)][int] $TimeoutMilliseconds = 60000,
    [ValidateRange(1, 60000)][int] $CleanupMilliseconds = 10000,
    [ValidateRange(0, 16777216)][int] $CaptureBytesPerStream = 1048576
)

$ErrorActionPreference = 'Stop'
if (-not ('Lomi.WindowsOwnedRunner' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'OwnedProcess.cs')
}
# No native output is sent through a PowerShell text pipeline.
[Lomi.WindowsOwnedRunner]::Run($Executable, $Arguments, $WorkingDirectory,
    $Environment, $TimeoutMilliseconds, $CleanupMilliseconds, $CaptureBytesPerStream)
