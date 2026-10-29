$ErrorActionPreference='Stop'
# Locked ring 0.17.14 compiles C through cc even with shipped x64 Windows
# assembly objects. Bundled SQLite also needs C; Rust-only platform checks do
# not prove this toolchain. Discovery is read-only and emits closed booleans.
$compiler=$false;$linker=$false;$sdk=$false
$candidates=@()
$command=Get-Command cl.exe -ErrorAction SilentlyContinue
if($command){$candidates+=Split-Path -Parent $command.Source}
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if(Test-Path -LiteralPath $vswhere){
 $installations=@(& $vswhere -all -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
 if($LASTEXITCODE -ne 0){throw 'MSVC_DISCOVERY_UNAVAILABLE'}
 foreach($installation in $installations){
  $tools=Join-Path $installation 'VC\Tools\MSVC'
  if(Test-Path -LiteralPath $tools){foreach($version in Get-ChildItem -LiteralPath $tools -Directory){$candidates+=Join-Path $version.FullName 'bin\Hostx64\x64'}}
 }
}
foreach($candidate in $candidates){
 if(Test-Path -LiteralPath (Join-Path $candidate 'cl.exe')){$compiler=$true}
 if(Test-Path -LiteralPath (Join-Path $candidate 'link.exe')){$linker=$true}
}
$kit=Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10'
$includes=Join-Path $kit 'Include'
if(Test-Path -LiteralPath $includes){foreach($version in Get-ChildItem -LiteralPath $includes -Directory){
 $libraries=Join-Path $kit ('Lib\'+$version.Name)
 if((Test-Path -LiteralPath (Join-Path $version.FullName 'um\Windows.h')) -and (Test-Path -LiteralPath (Join-Path $version.FullName 'ucrt\stdio.h')) -and (Test-Path -LiteralPath (Join-Path $libraries 'um\x64\kernel32.lib')) -and (Test-Path -LiteralPath (Join-Path $libraries 'ucrt\x64\ucrt.lib'))){$sdk=$true}
}}
@{msvcCompilerDiscovered=$compiler;msvcLinkerDiscovered=$linker;windowsSdkDiscovered=$sdk;nativeCBuildRequired=$true;compilerExecuted=$false}|ConvertTo-Json -Compress
