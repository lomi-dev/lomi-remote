param([Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$Archive)
$ErrorActionPreference='Stop'
if([Guid]::Parse($RunId).ToString('D') -cne $RunId -or [IO.Path]::GetFileName($Source) -cne "lomi-product-dpapi-$RunId"){throw 'Exact UUID required'}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class LomiDpapiAbsence {
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
 [DllImport("advapi32.dll")] static extern bool CloseServiceHandle(IntPtr handle);
 public static int Error(string name) {var m=OpenSCManager(null,null,1);if(m==IntPtr.Zero)throw new Exception("SCM query denied");try {var s=OpenService(m,name,4);if(s!=IntPtr.Zero){CloseServiceHandle(s);return 0;}return Marshal.GetLastWin32Error();}finally{CloseServiceHandle(m);}}
}
'@
$services=@{}
foreach($prefix in @('LomiProductService-','LomiProductServiceProbe-','LomiProductServiceForeign-')){$absenceCode=[LomiDpapiAbsence]::Error($prefix+$RunId);if($absenceCode -ne 1060){throw 'Exact native service absence unconfirmed'};$services[$prefix+$RunId]=$absenceCode}
$root=Join-Path 'C:\ProgramData\LomiWindowsFixture' $RunId
$active=@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and ($_.ExecutablePath.StartsWith($Source+'\',[StringComparison]::OrdinalIgnoreCase) -or $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase))})
if($active.Count -ne 0 -or (Test-Path -LiteralPath $root) -or (Test-Path -LiteralPath $Source) -or (Test-Path -LiteralPath $Archive)){throw 'Owned resources remain'}
@{serviceAbsence=$services;fixtureRootAbsent=$true;ownedSourceAbsent=$true;ownedArchiveAbsent=$true;ownedProcessesRemaining=0;operatorProfileAbsent=$true;localServiceProfileAbsent=$true}|ConvertTo-Json -Compress
