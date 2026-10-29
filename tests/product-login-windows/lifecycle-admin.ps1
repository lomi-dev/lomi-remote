param([Parameter(Mandatory)][ValidateSet('stage','launch','poll','collect','inventory','delete-helper','delete-root','delete-stage')][string]$Phase,[Parameter(Mandatory)][string]$RunId,[Parameter(Mandatory)][string]$Source,[Parameter(Mandatory)][string]$ExpectedSid,[Parameter(Mandatory)][int]$ExpectedSession,[Parameter(Mandatory)][string]$CliHash,[Parameter(Mandatory)][string]$HelperHash,[Parameter(Mandatory)][string]$ScriptHash,[Parameter(Mandatory)][string]$IdentityHash,[string]$InventoryHash='',[string]$ResultHash='',[switch]$FixtureDiagnostics)
$ErrorActionPreference='Stop'
if([Guid]::Parse($RunId).ToString('D') -cne $RunId -or $ExpectedSession -le 0 -or $ExpectedSid -cne 'S-1-5-21-1379812509-1041957290-335626797-1005'){throw 'Fixed identity/UUID/session required'}
$stage=Join-Path 'C:\ProgramData' "LomiLoginProof-$RunId";$taskName="LomiLoginProof-$RunId"
$program=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments="-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$stage\lifecycle.ps1`" -RunId $RunId -Stage `"$stage`" -ExpectedSid $ExpectedSid -ExpectedSession $ExpectedSession -CliHash $CliHash -HelperHash $HelperHash"
if($FixtureDiagnostics){$arguments+=' -FixtureDiagnostics'}
$expected=@{'lomiremote.exe'=$CliHash;'lomiremote-host.exe'=$HelperHash;'lifecycle.ps1'=$ScriptHash;'lifecycle-identity.ps1'=$IdentityHash}
function Hash-Text([string]$text){$sha=[Security.Cryptography.SHA256]::Create();try{([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Hash-File([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function No-Reparse([string]$path){if((Get-Item -LiteralPath $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse point; preserve'}}
function Ordinary-Root {
 $profiles=@(Get-CimInstance Win32_UserProfile|Where-Object{$_.SID -ceq $ExpectedSid})
 if($profiles.Count -ne 1){throw 'Exact user profile required'}
 $profile=$profiles[0].LocalPath
 foreach($path in @($profile,(Join-Path $profile 'AppData'),(Join-Path $profile 'AppData\Local'))){No-Reparse $path}
 Join-Path $profile "AppData\Local\LomiLoginProof-$RunId"
}
function Assert-Stage {
 No-Reparse $stage
 $acl=Get-Acl -LiteralPath $stage
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl)
 if($raw.Owner.Value -ne 'S-1-5-32-544'){throw 'Stage owner changed'}
 foreach($ace in $raw.DiscretionaryAcl){if($ace.AceQualifier -ne 'AccessAllowed' -or $ace.SecurityIdentifier.Value -notin @('S-1-5-32-544','S-1-5-18',$ExpectedSid)){throw 'Stage ACL changed'};if($ace.SecurityIdentifier.Value -eq $ExpectedSid -and ($ace.AccessMask -band 0x500D0116)){throw 'Ordinary stage write allowed'}}
 foreach($name in $expected.Keys){$path=Join-Path $stage $name;No-Reparse $path;if((Hash-File $path) -cne $expected[$name]){throw 'Stage bytes changed'}}
}
function Scheduler { $s=New-Object -ComObject 'Schedule.Service';$s.Connect();$s }
function Resolve-Sid([string]$value){if($value.StartsWith('S-1-')){[Security.Principal.SecurityIdentifier]::new($value).Value}else{[Security.Principal.NTAccount]::new($value).Translate([Security.Principal.SecurityIdentifier]).Value}}
function Assert-Task($task,[switch]$Pinned) {
 $d=$task.Definition
 if($task.Path -cne ('\'+$taskName) -or $d.Data -cne $RunId -or (Resolve-Sid $d.Principal.UserId) -cne $ExpectedSid -or $d.Principal.LogonType -ne 3 -or $d.Principal.RunLevel -ne 0 -or $d.Actions.Count -ne 1 -or $d.Actions.Item(1).Type -ne 0 -or $d.Actions.Item(1).Path -cne $program -or $d.Actions.Item(1).Arguments -cne $arguments -or $d.Actions.Item(1).WorkingDirectory -cne $stage -or $d.Triggers.Count -ne 0 -or $d.Settings.ExecutionTimeLimit -cne 'PT0S' -or $d.Settings.AllowHardTerminate -ne $false){throw 'Helper definition changed'}
 $sddl=$task.GetSecurityDescriptor(7);$raw=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
 if($raw.Owner.Value -cne 'S-1-5-32-544' -or !$raw.DiscretionaryAcl){throw 'Helper owner changed'}
 foreach($ace in $raw.DiscretionaryAcl){if($ace.AceQualifier -ne 'AccessAllowed' -or $ace.SecurityIdentifier.Value -notin @('S-1-5-32-544','S-1-5-18',$ExpectedSid)){throw 'Helper ACL changed'};if($ace.SecurityIdentifier.Value -eq $ExpectedSid -and ($ace.AccessMask -band 0x500D0116)){throw 'Ordinary helper write allowed'}}
 $pin=@{runId=$RunId;xmlSha256=(Hash-Text $task.Xml);sddlSha256=(Hash-Text $sddl)}
 if($Pinned){$file=Join-Path $stage 'helper-identity.json';No-Reparse $file;$saved=Get-Content -LiteralPath $file -Raw|ConvertFrom-Json;if($saved.runId -cne $RunId -or $saved.xmlSha256 -cne $pin.xmlSha256 -or $saved.sddlSha256 -cne $pin.sddlSha256){throw 'Pinned helper changed'}}
 $pin
}
function Last-Run($task){$task.LastRunTime.ToString('o',[Globalization.CultureInfo]::InvariantCulture)}
function Assert-Completed($task,[string]$beforeLastRunTime){
 if(!$beforeLastRunTime -or $task.State -ne 3 -or $task.GetInstances(0).Count -ne 0 -or $task.LastTaskResult -in @(0x41301,0x41303) -or $task.LastRunTime.Year -lt 2000 -or $task.LastRunTime -le [datetime]::Parse($beforeLastRunTime,[Globalization.CultureInfo]::InvariantCulture)){throw 'Helper completion unknown; preserve'}
}
function Assert-Stopped($task,[string]$beforeLastRunTime){Assert-Completed $task $beforeLastRunTime;if($task.LastTaskResult -ne 0){throw 'Helper not successfully stopped'}}
function Assert-Absent($scheduler){try{$null=$scheduler.GetFolder('\').GetTask($taskName);throw 'Helper remains'}catch{if(($_.Exception.HResult -band 0xffffffffL) -notin @(0x80070002L,0x80070003L)){throw}}}
function Inventory {
 $root=Ordinary-Root;No-Reparse $root;$rootIdentity=[LomiLoginFileIdentity]::Read($root)
 if(@(Get-CimInstance Win32_Process|Where-Object{$_.ExecutablePath -and $_.ExecutablePath.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)}).Count -ne 0){throw 'Owned process remains'}
 $allowed=@{'lomiremote.exe'=$false;'lomiremote-host.exe'=$false;'lifecycle-result.json'=$false;'host-profile'=$true;'host-profile/owner.lock'=$false;'host-profile/host.sqlite3'=$false;'host-profile/host.sqlite3-wal'=$false;'host-profile/host.sqlite3-shm'=$false;'host-profile-service-windows-login'=$true;'host-profile-service-windows-login/owner.lock'=$false;'host-profile-service-windows-control'=$true;'host-profile-service-windows-control/owner.lock'=$false}
 $inventory=@();$pending=[Collections.Generic.Queue[string]]::new();$pending.Enqueue($root)
 while($pending.Count){$directory=$pending.Dequeue();No-Reparse $directory
  foreach($item in Get-ChildItem -LiteralPath $directory -Force){
   No-Reparse $item.FullName;$relative=$item.FullName.Substring($root.Length+1).Replace('\','/')
   if(!$allowed.ContainsKey($relative) -or $item.PSIsContainer -ne $allowed[$relative]){throw 'Unknown UUID content; preserve'}
   $acl=Get-Acl -LiteralPath $item.FullName;$owner=[Security.AccessControl.RawSecurityDescriptor]::new($acl.Sddl).Owner.Value
   if($owner -cne $ExpectedSid){throw 'Ordinary UUID file owner changed'}
   $entry=@{path=$relative;directory=[bool]$item.PSIsContainer;owner=$owner;sddlSha256=(Hash-Text $acl.Sddl);identity=[LomiLoginFileIdentity]::Read($item.FullName)}
   if($item.PSIsContainer){$pending.Enqueue($item.FullName)}else{$entry.sha256=Hash-File $item.FullName;$entry.bytes=$item.Length}
   $inventory+= $entry
  }
 }
 $rootAcl=Get-Acl -LiteralPath $root
 if([Security.AccessControl.RawSecurityDescriptor]::new($rootAcl.Sddl).Owner.Value -cne $ExpectedSid){throw 'Ordinary root owner changed'}
 foreach($name in @('lomiremote.exe','lomiremote-host.exe')){if((Hash-File (Join-Path $root $name)) -cne $expected[$name]){throw 'Owned binary changed'}}
 $receiptPath=Join-Path $root 'lifecycle-result.json'
 if((Hash-File $receiptPath) -cne $ResultHash){throw 'Collected ordinary receipt changed'}
 $receipt=Get-Content -LiteralPath $receiptPath -Raw|ConvertFrom-Json
 if($receipt.runId -cne $RunId -or $receipt.root -cne $root -or $receipt.sid -cne $ExpectedSid -or $receipt.session -ne $ExpectedSession -or $receipt.passed -ne $true -or $receipt.productTaskAbsent -ne $true){throw 'Ordinary receipt changed'}
 foreach($key in @('volume','fileId','finalPath','links')){if($receipt.rootIdentity.$key -cne $rootIdentity.$key){throw 'Original UUID root identity changed'}}
 $s=Scheduler;try{$null=$s.GetFolder("\LomiRemote-$($receipt.installation)");throw 'Product folder remains'}catch{if(($_.Exception.HResult -band 0xffffffffL) -notin @(0x80070002L,0x80070003L)){throw}}
 @{runId=$RunId;root=$root;rootIdentity=$rootIdentity;rootSddlSha256=(Hash-Text $rootAcl.Sddl);files=@($inventory|Sort-Object -Property path)}
}
if($Phase -eq 'stage'){
 if(Test-Path -LiteralPath $stage){throw 'Fresh UUID stage required'}
 $acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;GRGX;;;$ExpectedSid)")
 $null=[IO.Directory]::CreateDirectory($stage,$acl)
 foreach($name in @('lomiremote.exe','lomiremote-host.exe')){Copy-Item -LiteralPath (Join-Path $Source ('target\debug\'+$name)) -Destination (Join-Path $stage $name)}
 foreach($name in @('lifecycle.ps1','lifecycle-identity.ps1')){Copy-Item -LiteralPath (Join-Path $Source ('tests\product-login-windows\'+$name)) -Destination (Join-Path $stage $name)}
 Assert-Stage;@{stage=$stage;scriptHash=$ScriptHash}|ConvertTo-Json -Compress;return
}
Assert-Stage
. (Join-Path $stage 'lifecycle-identity.ps1')
$scheduler=Scheduler;$schedulerRoot=$scheduler.GetFolder('\')
if($Phase -eq 'launch'){
 Assert-Absent $scheduler
 $d=$scheduler.NewTask(0);$d.Data=$RunId;$d.Principal.UserId=$ExpectedSid;$d.Principal.LogonType=3;$d.Principal.RunLevel=0
 $d.Settings.ExecutionTimeLimit='PT0S';$d.Settings.AllowHardTerminate=$false;$d.Settings.DisallowStartIfOnBatteries=$false;$d.Settings.StopIfGoingOnBatteries=$false
 $a=$d.Actions.Create(0);$a.Path=$program;$a.Arguments=$arguments;$a.WorkingDirectory=$stage
 # TASK_CREATE | TASK_DONT_ADD_PRINCIPAL_ACE preserves the explicit read/run ACL.
 $task=$schedulerRoot.RegisterTaskDefinition($taskName,$d,18,$ExpectedSid,$null,3,"O:BAD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;$ExpectedSid)")
 $pin=Assert-Task $task
 $pin.beforeLastRunTime=Last-Run $task
 [IO.File]::WriteAllText((Join-Path $stage 'helper-identity.json'),($pin|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))
 $null=Assert-Task $task -Pinned;$null=$task.Run($null);@{launched=$true;identity=$pin}|ConvertTo-Json -Depth 4 -Compress;return
}
if($Phase -in @('poll','collect','inventory','delete-helper')){
 $task=$schedulerRoot.GetTask($taskName);$null=Assert-Task $task -Pinned
 $pin=Get-Content -LiteralPath (Join-Path $stage 'helper-identity.json') -Raw|ConvertFrom-Json
 if($Phase -eq 'poll'){@{state=[int]$task.State;instances=[int]$task.GetInstances(0).Count;last=[int]$task.LastTaskResult;lastRunTime=(Last-Run $task)}|ConvertTo-Json -Compress;return}
 # A failed but completed helper may expose its closed diagnostic receipt.
 # Successful completion remains mandatory for inventory/deletion below.
 if($Phase -eq 'collect'){Assert-Completed $task $pin.beforeLastRunTime;Get-Content -LiteralPath (Join-Path (Ordinary-Root) 'lifecycle-result.json') -Raw;return}
 Assert-Stopped $task $pin.beforeLastRunTime
 if($Phase -eq 'inventory'){Inventory|ConvertTo-Json -Depth 8 -Compress;return}
 if($Phase -eq 'delete-helper'){$schedulerRoot.DeleteTask($taskName,0);Assert-Absent $scheduler;@{helperTaskAbsent=$true}|ConvertTo-Json -Compress;return}
}
Assert-Absent $scheduler
if($Phase -eq 'delete-root'){
 $manifest=Join-Path $stage 'ordinary-inventory.json';No-Reparse $manifest
 if((Hash-File $manifest) -cne $InventoryHash){throw 'Pinned cleanup manifest changed'}
 $before=Get-Content -LiteralPath $manifest -Raw|ConvertFrom-Json;$current=Inventory
 if($before.runId -cne $RunId -or $before.root -cne $current.root -or $before.rootSddlSha256 -cne $current.rootSddlSha256 -or $before.files.Count -ne $current.files.Count){throw 'Ordinary inventory changed'}
 foreach($key in @('volume','fileId','finalPath','links')){if($before.rootIdentity.$key -cne $current.rootIdentity.$key){throw 'Root native identity changed'}}
 for($index=0;$index -lt $current.files.Count;$index++){$a=$before.files[$index];$b=$current.files[$index];foreach($key in @('path','directory','owner','sddlSha256','sha256','bytes')){if($a.$key -cne $b[$key]){throw 'Ordinary file identity changed'}};foreach($key in @('volume','fileId','finalPath','links')){if($a.identity.$key -cne $b.identity.$key){throw 'Native file identity changed'}}}
 # Keep ancestry/root/entries pinned without delete sharing throughout cleanup.
 # Leaf pins additionally deny writes; no path-based recursive removal occurs.
 $pins=@{};$ancestorPins=@()
 try {
  $parent=[IO.Directory]::GetParent($current.root)
  while($parent){$ancestorPins+= [LomiLoginFileIdentity]::Hold($parent.FullName,$false,$false);$parent=$parent.Parent}
  $pins['']=[LomiLoginFileIdentity]::Hold($current.root,$true,$false)
  foreach($key in @('volume','fileId','finalPath','links')){if($pins[''].Identity.$key -cne $before.rootIdentity.$key){throw 'Pinned root identity changed'}}
  foreach($entry in @($before.files|Sort-Object {($_.path.Split('/')).Count})){ $path=Join-Path $current.root $entry.path
   $pin=[LomiLoginFileIdentity]::Hold($path,$true,(!$entry.directory));$pins[$entry.path]=$pin
   foreach($key in @('volume','fileId','finalPath','links')){if($pin.Identity.$key -cne $entry.identity.$key){throw 'Pinned entry changed'}}
   if(!$entry.directory -and $pin.Sha256() -cne $entry.sha256){throw 'Pinned content changed'}
   if((Hash-Text (Get-Acl -LiteralPath $path).Sddl) -cne $entry.sddlSha256){throw 'Pinned ACL changed'}
  }
  # Reject extras after every expected object is held. An entry added later is
  # preserved: only exact pinned leaves are deleted; nonempty dirs fail closed.
  foreach($directory in @('')+@($before.files|Where-Object{$_.directory}|ForEach-Object{$_.path})){
   $path=if($directory){Join-Path $current.root $directory}else{$current.root}
   foreach($item in Get-ChildItem -LiteralPath $path -Force){$relative=$item.FullName.Substring($current.root.Length+1).Replace('\','/');if(!$pins.ContainsKey($relative)){throw 'New unknown child; preserve'}}
  }
  foreach($entry in @($before.files|Where-Object{!$_.directory})){$pins[$entry.path].Delete()}
  foreach($entry in @($before.files|Where-Object{$_.directory}|Sort-Object {($_.path.Split('/')).Count} -Descending)){
   if(@(Get-ChildItem -LiteralPath (Join-Path $current.root $entry.path) -Force).Count){throw 'Unknown child in pinned directory'}
   $pins[$entry.path].Delete()
  }
  if(@(Get-ChildItem -LiteralPath $current.root -Force).Count){throw 'Unknown child in pinned root'}
  $pins[''].Delete()
 } finally {foreach($pin in $pins.Values){$pin.Dispose()};foreach($pin in $ancestorPins){$pin.Dispose()}}
 @{ordinaryRootAbsent=(!(Test-Path -LiteralPath $current.root))}|ConvertTo-Json -Compress;return
}
if($Phase -eq 'delete-stage'){
 $expected['ordinary-inventory.json']=$InventoryHash
 $pinFile=Join-Path $stage 'helper-identity.json';No-Reparse $pinFile;$pin=Get-Content -LiteralPath $pinFile -Raw|ConvertFrom-Json
 if($pin.runId -cne $RunId){throw 'Helper pin changed'};$expected['helper-identity.json']=Hash-File $pinFile
 $items=@(Get-ChildItem -LiteralPath $stage -Force);if($items.Count -ne $expected.Count){throw 'Stage inventory changed'}
 foreach($item in $items){No-Reparse $item.FullName;if($item.PSIsContainer -or !$expected.ContainsKey($item.Name) -or (Hash-File $item.FullName) -cne $expected[$item.Name]){throw 'Unknown stage content; preserve'}}
 $pins=@{};$rootPin=[LomiLoginFileIdentity]::Hold($stage,$true,$false)
 try{foreach($item in $items){$pin=[LomiLoginFileIdentity]::Hold($item.FullName,$true,$true);$pins[$item.Name]=$pin;if($pin.Sha256() -cne $expected[$item.Name]){throw 'Pinned stage changed'}};foreach($pin in $pins.Values){$pin.Delete()};if(@(Get-ChildItem -LiteralPath $stage -Force).Count){throw 'Unknown stage child'};$rootPin.Delete()}finally{foreach($pin in $pins.Values){$pin.Dispose()};$rootPin.Dispose()}
 @{stageAbsent=(!(Test-Path -LiteralPath $stage))}|ConvertTo-Json -Compress
}
