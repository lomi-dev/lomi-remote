# PREPARED_NOT_EXECUTED. Exactly one nonsecret mode; Windows owner admission only.
[CmdletBinding()]
param([Parameter(Mandatory)][ValidateSet('Input','Empty','Token','BlockedWriter','EarlyClose','HandleInheritance','Overflow','StdoutOverflow','StderrOverflow','PreResumeFault','PreResumeDeadline','TimeoutDescendant','InputRejected','CallbackAclRejected')][string]$Mode,
 [Parameter(Mandatory)][string]$OwnedRoot)
$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';$stage='root-validation';$result=$null;$passed=$false;$sentinel=$null
function AssertRawRootAcl($acl,$sid){
 $raw=[Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(),0)
 if(!$sid.Equals($raw.Owner) -or ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or
  $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 1){throw 'RAW_ROOT_DACL'}
 $ace=$raw.DiscretionaryAcl[0]
 if($ace -isnot [Security.AccessControl.CommonAce] -or $ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
  $ace.IsCallback -or $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
  !$sid.Equals($ace.SecurityIdentifier) -or $ace.AccessMask -ne 2032127 -or [int]$ace.AceFlags -ne 3){throw 'RAW_ROOT_DACL'}
}
try{
 $g=[Guid]::Empty
 if(-not [IO.Path]::IsPathRooted($OwnedRoot) -or $OwnedRoot.StartsWith('\\') -or $OwnedRoot -cne [IO.Path]::GetFullPath($OwnedRoot) -or
  -not [Guid]::TryParseExact([IO.Path]::GetFileName($OwnedRoot),'D',[ref]$g) -or $g -eq [Guid]::Empty){throw 'UUID_ROOT'}
 for($part=[IO.DirectoryInfo]::new($OwnedRoot);$null -ne $part;$part=$part.Parent){if($part.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'REPARSE'}}
 $acl=[IO.Directory]::GetAccessControl($OwnedRoot);$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 try{
  $sid=$identity.User;$rules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
  if($identity.ImpersonationLevel -ne [Security.Principal.TokenImpersonationLevel]::None -or $null -eq $sid -or
   !$sid.Equals($acl.GetOwner([Security.Principal.SecurityIdentifier])) -or !$acl.AreAccessRulesProtected -or $rules.Count -ne 1){throw 'ROOT_OWNER_ACL'}
  $rule=$rules[0]
  if($rule.IsInherited -or !$sid.Equals($rule.IdentityReference) -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or
   $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or $rule.PropagationFlags -ne 'None'){throw 'ROOT_EXACT_ACE'}
  AssertRawRootAcl $acl $sid
 }finally{$identity.Dispose()}
 if([IO.Directory]::GetFileSystemEntries($OwnedRoot).Length -ne 0){throw 'FRESH_EMPTY_ROOT'}
 $stage='bootstrap-outside-helper-job';$temp=Join-Path $OwnedRoot '.bootstrap';$null=[IO.Directory]::CreateDirectory($temp)
 $public=@{SystemRoot='C:\Windows';WINDIR='C:\Windows';ComSpec='C:\Windows\System32\cmd.exe';PATH='C:\Windows\System32;C:\Windows;C:\Windows\System32\WindowsPowerShell\v1.0';HOME=$OwnedRoot;USERPROFILE=$OwnedRoot;TEMP=$temp;TMP=$temp;APPDATA=(Join-Path $OwnedRoot 'AppData\Roaming');LOCALAPPDATA=(Join-Path $OwnedRoot 'AppData\Local');PSModulePath='C:\Windows\System32\WindowsPowerShell\v1.0\Modules'}
 $environment=[Collections.Generic.Dictionary[string,string]]::new([StringComparer]::Ordinal)
 foreach($key in $public.Keys){$environment.Add([string]$key,[string]$public[$key]);[Environment]::SetEnvironmentVariable($key,[string]$public[$key],[EnvironmentVariableTarget]::Process)}
 if('Lomi.RestrictedPostgresTests.RestrictedOwnedRunner' -as [type]){throw 'FRESH_OWNER_PROCESS_REQUIRED'}
 Add-Type -Path (Join-Path $PSScriptRoot 'RestrictedOwnedProcess.cs') -ReferencedAssemblies System.Core
 $exe=Join-Path $OwnedRoot 'ProbeChild.exe'
 Add-Type -Path (Join-Path $PSScriptRoot 'ProbeChild.cs') -ReferencedAssemblies System.Core -OutputAssembly $exe -OutputType ConsoleApplication
 $null=[Reflection.Assembly]::LoadFrom($exe)
 $stage='environment-prefix';$prefix=[Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::ElevenStringPrefix($environment)
 if(!$prefix){throw 'RAW_PREFIX'}
 $privateBytes=[byte[]]::new(0);$childMode=$Mode;$arguments=@();$timeout=15000;$cap=65536;$delay=0;$attempts=0
 $fault=[Lomi.RestrictedPostgresTests.ProbeFault]::None;$marker=Join-Path $OwnedRoot 'witness.bin'
 if($Mode -in @('Input','BlockedWriter','EarlyClose','Overflow','StdoutOverflow','StderrOverflow')){
  $privateBytes=[byte[]]::new(65536);for($i=0;$i -lt $privateBytes.Length;$i++){$privateBytes[$i]=[byte](($i*37+11) -band 255)}
 }
 switch($Mode){
  'Token'{
   $witnesses=@()
   foreach($group in @('S-1-5-32-544','S-1-5-32-547')){
    $p=Join-Path $OwnedRoot ('group-'+$group+'.bin');[IO.File]::WriteAllBytes($p,[byte[]]::new(0))
    $d=[Security.AccessControl.FileSecurity]::new();$d.SetOwner($sid);$d.SetAccessRuleProtection($true,$false)
    $d.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($group),[Security.AccessControl.FileSystemRights]::FullControl,[Security.AccessControl.AccessControlType]::Allow))
    [IO.File]::SetAccessControl($p,$d);$witnesses+=,$p
   }
   # Positive BA-only control under the unchanged owner. Failure is unsupported,
   # never a false denial pass. PU fixture is also checked by its exact DACL.
   $control=[IO.File]::Open($witnesses[0],'Open','Write','ReadWrite');$control.Dispose()
   for($n=0;$n -lt $witnesses.Count;$n++){
    $d=[IO.File]::GetAccessControl($witnesses[$n]);$r=$d.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
    $expectedGroup=@('S-1-5-32-544','S-1-5-32-547')[$n]
    if(!$d.AreAccessRulesProtected -or $r.Count -ne 1 -or $r[0].IsInherited -or $r[0].IdentityReference.Value -cne $expectedGroup -or
     $r[0].AccessControlType -ne 'Allow' -or $r[0].FileSystemRights -ne 'FullControl'){throw 'SYNTHETIC_GROUP_WITNESS_ACL'}
   }
   $arguments=@('Token',$marker)+$witnesses
  }
  'BlockedWriter'{$childMode='Blocked';$timeout=3000}
  'HandleInheritance'{
   $sentinelPath=Join-Path $OwnedRoot 'sentinel.bin';$sentinel=[IO.File]::Open($sentinelPath,'CreateNew','ReadWrite','ReadWrite')
   $number=$sentinel.SafeFileHandle.DangerousGetHandle().ToInt64()
   if(![Lomi.RestrictedPostgresTests.ProbeChild]::MarkInheritable($number) -or ![Lomi.RestrictedPostgresTests.ProbeChild]::PointsToFile($number,$sentinelPath)){throw 'SENTINEL_CONTROL'}
   $arguments=@('Handle',$marker,$number.ToString([Globalization.CultureInfo]::InvariantCulture),$sentinelPath)
  }
  'Overflow'{$cap=1024}
  'StdoutOverflow'{$cap=1024}
  'StderrOverflow'{$cap=1024}
  'PreResumeFault'{$childMode='Marker';$fault=[Lomi.RestrictedPostgresTests.ProbeFault]::RejectBeforeResume}
  'PreResumeDeadline'{$childMode='Marker';$timeout=50;$delay=100}
  'TimeoutDescendant'{$childMode='Tree';$timeout=5000}
 }
 if($arguments.Count -eq 0){$arguments=@($childMode,$marker)}
 $stage='restricted-native-run'
 if($Mode -ceq 'CallbackAclRejected'){
  $stage='callback-fixture-construction-unverified'
  # This fixture changes only this already validated disposable UUID root.
  # Native construction/readback failure is a failed qualification, never a pass.
  [Lomi.RestrictedPostgresTests.ProbeChild]::InstallCallbackAclFixture($OwnedRoot)
  $fixtureAcl=[IO.Directory]::GetAccessControl($OwnedRoot)
  $fixtureRaw=[Security.AccessControl.RawSecurityDescriptor]::new($fixtureAcl.GetSecurityDescriptorBinaryForm(),0)
  if(!$sid.Equals($fixtureRaw.Owner) -or ($fixtureRaw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or
   $null -eq $fixtureRaw.DiscretionaryAcl -or $fixtureRaw.DiscretionaryAcl.Count -ne 2){throw 'CALLBACK_FIXTURE_READBACK'}
  $ownAce=$fixtureRaw.DiscretionaryAcl[0];$extraAce=$fixtureRaw.DiscretionaryAcl[1]
  if($ownAce -isnot [Security.AccessControl.CommonAce] -or $ownAce.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or
   $ownAce.IsCallback -or !$sid.Equals($ownAce.SecurityIdentifier) -or $ownAce.AccessMask -ne 2032127 -or [int]$ownAce.AceFlags -ne 3 -or
   $extraAce -isnot [Security.AccessControl.CommonAce] -or $extraAce.AceType -ne [Security.AccessControl.AceType]::AccessAllowedCallback -or
   !$extraAce.IsCallback -or $extraAce.SecurityIdentifier.Value -cne 'S-1-5-32-544' -or $extraAce.SecurityIdentifier.Equals($sid) -or
   $extraAce.AccessMask -ne 2032127 -or [int]$extraAce.AceFlags -ne 3){throw 'CALLBACK_FIXTURE_READBACK'}
  $psRejected=$false;$nativeRejected=$false
  try{AssertRawRootAcl $fixtureAcl $sid}catch{if($_.Exception.Message -cne 'RAW_ROOT_DACL'){throw};$psRejected=$true}
  $stage='callback-fixture-native-root-rejection'
  try{$result=[Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::RunForProbe($exe,@('Marker',$marker),$OwnedRoot,$environment,$OwnedRoot,$privateBytes,1000,1000,1024,$fault,0,[ref]$attempts)}
  catch{if($_.Exception.InnerException -isnot [InvalidOperationException]){throw};$nativeRejected=$true}
  if(!$psRejected -or !$nativeRejected -or $attempts -ne 0 -or $null -ne $result -or [IO.File]::Exists($marker)){throw 'CALLBACK_ROOT_REJECTION'}
  $callbackFixture=@{rawAceCount=2;extraCallbackAnotherSid=$true;powerShellRejected=$psRejected;helperRejectedBeforeCreation=$nativeRejected}
  $passed=$true
 }elseif($Mode -ceq 'InputRejected'){
  $rejections=0
  foreach($candidate in @(@{bytes=$null},@{bytes=[byte[]]::new(65537)})){
   try{$null=[Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::RunForProbe($exe,@('Marker',$marker),$OwnedRoot,$environment,$OwnedRoot,$candidate.bytes,1000,1000,1024,$fault,0,[ref]$attempts)}
   catch{if($_.Exception.InnerException -isnot [ArgumentOutOfRangeException]){throw};$rejections++}
  }
  if($rejections -ne 2 -or $attempts -ne 0 -or [IO.File]::Exists($marker)){throw 'INPUT_REJECTION'}
  $passed=$true
 }else{
  try{$result=[Lomi.RestrictedPostgresTests.RestrictedOwnedRunner]::RunForProbe($exe,[string[]]$arguments,$OwnedRoot,$environment,$OwnedRoot,$privateBytes,$timeout,10000,$cap,$fault,$delay,[ref]$attempts)}
  finally{[Array]::Clear($privateBytes,0,$privateBytes.Length)}
  # Preserve the returned closed nonsecret result in final evidence before any
  # assertions; no exception path discards the actual failure envelope.
  $stage='assert-returned-result'
  if(!$result.completionKnown -or !$result.JobEmpty -or $null -eq $result.exitCode -or !$result.callerTokenUnchanged){throw 'POSITIVE_CLEANUP_REQUIRED'}
  if($Mode -cne 'PreResumeFault' -and (!$result.tokenVerifiedBeforeResume -or !$result.defaultDaclVerifiedBeforeResume)){throw 'ACTUAL_TOKEN_PROOF'}
  switch($Mode){
   {$_ -in @('Input','Empty','Token','HandleInheritance')}{
    if($result.exitCode -ne 0 -or $result.timeout -or $result.overflow -or !$result.stdinComplete -or !$result.stdinEofSent -or
     $result.failureCategory -ne 'None' -or $result.stdoutBytesObserved -ne 0 -or $result.stderrBytesObserved -ne 0 -or ![IO.File]::Exists($marker)){throw 'POSITIVE_PROBE'}
    if($Mode -ceq 'Input' -and $result.stdinBytesWritten -ne 65536){throw 'EXACT_INPUT_COUNT'}
   }
   'BlockedWriter'{if(!$result.timeout -or $result.stdinComplete -or $result.stdinBytesWritten -ge 65536 -or ![IO.File]::Exists($marker)){throw 'BLOCKED_WRITER'}}
   'EarlyClose'{if($result.timeout -or $result.overflow -or $result.failureCategory -ne 'InputIncomplete' -or
    $result.stdinComplete -or $result.stdinBytesWritten -ge 65536 -or ![IO.File]::Exists($marker)){throw 'EARLY_CLOSE'}}
   'Overflow'{if(!$result.overflow){throw 'OUTPUT_OVERFLOW'}}
   'StdoutOverflow'{if(!$result.overflow -or $result.stdoutBytesObserved -le $cap -or $result.stderrBytesObserved -ne 0){throw 'STDOUT_OVERFLOW'}}
   'StderrOverflow'{if(!$result.overflow -or $result.stderrBytesObserved -le $cap -or $result.stdoutBytesObserved -ne 0){throw 'STDERR_OVERFLOW'}}
   'PreResumeFault'{if($attempts -ne 0 -or $result.tokenVerifiedBeforeResume -or $result.failureCategory -ne 'ProbeFault' -or [IO.File]::Exists($marker)){throw 'ZERO_RESUME_FAULT'}}
   'PreResumeDeadline'{if(!$result.timeout -or $attempts -ne 0 -or [IO.File]::Exists($marker)){throw 'ZERO_RESUME_DEADLINE'}}
   'TimeoutDescendant'{
    if(!$result.timeout -or ![IO.File]::Exists($marker)){throw 'DESCENDANT_DID_NOT_START'}
    $released=[IO.File]::Open($marker,'Open','ReadWrite','None');$released.Dispose()
   }
  }
  $passed=$true
 }
}catch{
 $failure=@{stage=$stage;category=$_.Exception.GetType().Name;line=[int]$_.InvocationInfo.ScriptLineNumber;hresult=[int]$_.Exception.HResult}
}finally{
 if($null -ne $sentinel){$sentinel.Dispose()}
}
$evidence=@{mode=$Mode;passed=$passed;result=$result;resumeAttempts=$attempts;prefixPassed=$prefix;callbackFixture=$callbackFixture;failure=$failure;sourceStatus='PREPARED_NOT_EXECUTED_UNTIL_SEPARATE_ADMISSION'}
[Console]::Out.Write(($evidence|ConvertTo-Json -Depth 8 -Compress))
if(!$passed){exit 1}
