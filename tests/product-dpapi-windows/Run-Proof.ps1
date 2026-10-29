param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Source)
. "$PSScriptRoot\..\services-windows\Common.ps1"
Assert-Administrator
if([Guid]::Parse($RunId).ToString('D') -cne $RunId -or [Diagnostics.Process]::GetCurrentProcess().SessionId -ne 0){throw 'UUID Session0 required'}
$root=Join-Path 'C:\ProgramData\LomiWindowsFixture' $RunId
$controller=Join-Path $Source 'target\debug\examples\windows-service-proof.exe'
$copied=Join-Path $root 'windows-service-proof.exe'
if(Test-Path -LiteralPath $root){throw 'Fresh UUID required'}
$parent=Split-Path $root
if(!(Test-Path -LiteralPath $parent)){$null=[IO.Directory]::CreateDirectory($parent,(Get-ParentSecurity))}
Assert-FixtureChain
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;BA)')
$null=[IO.Directory]::CreateDirectory($root,$acl)
[IO.File]::WriteAllText((Join-Path $root 'fixture.marker'),"lomi-product-service-v1:$RunId`n",[Text.UTF8Encoding]::new($false))
Copy-Item -LiteralPath $controller -Destination $copied
$hash=(Get-FileHash -LiteralPath $controller -Algorithm SHA256).Hash.ToLowerInvariant()
if((Get-FileHash -LiteralPath $copied -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash){throw 'Copied binary digest mismatch'}
function Invoke-Proof([string]$operation){
    $value=(& $controller $RunId ('dpapi-'+$operation))|ConvertFrom-Json
    if($LASTEXITCODE -ne 0 -or $value.ok -ne $true){throw "Synthetic DPAPI operation failed: $operation ($($value.error))"}
    $value.value
}
$export=Invoke-Proof export
$created=Invoke-Proof create
$run=Invoke-Proof run
$finish=Invoke-Proof finish
$deleted=Invoke-Proof delete
$audit=(& $controller $RunId audit)|ConvertFrom-Json
if($LASTEXITCODE -ne 0 -or $audit.ok -ne $true){throw 'Native exact-service absence audit failed'}
$active=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)})
if($active.Count -ne 0 -or !$deleted.serviceAbsent -or $deleted.nativeAbsenceError -ne 1060 -or !$finish.operatorProfileAbsent -or !$run.localServiceProfileAbsent -or $run.processExitCode -ne 0 -or !$run.processHandleRetained){throw 'Cleanup authority incomplete'}
Assert-PlainDirectory $root
$allowed=@('fixture.marker','windows-service-proof.exe','operator-ciphertext.bin','dpapi-intent.json','dpapi-go','dpapi-clean','dpapi-proof.json','dpapi-cleanup.json')
foreach($item in Get-ChildItem -LiteralPath $root -Force){if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -notin $allowed){throw 'Unknown UUID contents; preserve'}}
if((Get-FileHash -LiteralPath $copied -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash -or [IO.File]::ReadAllText((Join-Path $root 'fixture.marker')) -cne "lomi-product-service-v1:$RunId`n"){throw 'Changed fixture identity; preserve'}
Get-ChildItem -LiteralPath $root -Force|Remove-Item -Force
Remove-Item -LiteralPath $root -Force
@{runId=$RunId;passed=$true;export=$export;created=$created;run=$run;finish=$finish;deleted=$deleted;binarySha256=$hash;fixtureRootAbsent=(!(Test-Path -LiteralPath $root));ownedProcessesRemaining=$active.Count;taskSchedulerMutations=0;syntheticPayloadOnly=$true;accountChanges=0}|ConvertTo-Json -Depth 10 -Compress
