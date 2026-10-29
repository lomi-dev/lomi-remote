# PREPARED_NOT_EXECUTED. Input is RAM-only; never pipe this invocation to logging.
[CmdletBinding()]
param(
 [Parameter(Mandatory)][string]$Executable,
 [string[]]$Arguments=@(),
 [Parameter(Mandatory)][string]$WorkingDirectory,
 [Parameter(Mandatory)][Collections.IDictionary]$Environment,
 [Parameter(Mandatory)][string]$OwnedRoot,
 [Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$PrivateStdin,
 [ValidateRange(1,360000)][int]$TimeoutMilliseconds=60000,
 [ValidateRange(1,10000)][int]$CleanupMilliseconds=10000,
 [ValidateRange(0,65536)][int]$MaxOutputBytesPerStream=65536
)
$ErrorActionPreference='Stop'
if(-not ('Lomi.RestrictedPostgresTests.RestrictedOwnedRunner' -as [type])){
 Add-Type -Path (Join-Path $PSScriptRoot 'RestrictedOwnedProcess.cs') -ReferencedAssemblies System.Core
}
# The strict helper also performs this check; caller-side proof precedes Run.
if(-not [Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::ElevenStringPrefix($Environment)){throw 'PREFIX_REJECTED'}
[Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::Run($Executable,$Arguments,$WorkingDirectory,
 $Environment,$OwnedRoot,$PrivateStdin,$TimeoutMilliseconds,$CleanupMilliseconds,$MaxOutputBytesPerStream)
