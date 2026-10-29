param([Parameter(Mandatory)][string]$Source)
$ErrorActionPreference='Stop'
$ExpectedSid='S-1-5-21-1379812509-1041957290-335626797-1005';$RunId='00000000-0000-4000-8000-000000000001'
$stage='C:\ProgramData\LomiLoginProof-'+$RunId;$taskName='LomiLoginProof-'+$RunId
$program=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe';$arguments='fixed-test-arguments'
$admin=Join-Path $Source 'lifecycle-admin.ps1';$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($admin,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Admin parser failed'}
# Import function definitions only. No top-level administrator action executes.
foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([ScriptBlock]::Create($node.Extent.Text))}
function Fake-Task {
 $actions=[pscustomobject]@{Count=1;Action=[pscustomobject]@{Type=0;Path=$program;Arguments=$arguments;WorkingDirectory=$stage}}
 $actions|Add-Member -MemberType ScriptMethod -Name Item -Value {param($index)$this.Action}
 $task=[pscustomobject]@{Path=('\'+$taskName);Xml='<Task/>';State=3;LastTaskResult=0;LastRunTime=[datetime]'2026-10-19T12:00:00';Instances=0;Sddl="O:BAD:P(A;;GA;;;BA)(A;;GA;;;SY)(A;;GRGX;;;$ExpectedSid)";Definition=[pscustomobject]@{Data=$RunId;Principal=[pscustomobject]@{UserId=$ExpectedSid;LogonType=3;RunLevel=0};Actions=$actions;Triggers=[pscustomobject]@{Count=0};Settings=[pscustomobject]@{ExecutionTimeLimit='PT0S';AllowHardTerminate=$false}}}
 $task|Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptor -Value {param($flags)$this.Sddl}
 $task|Add-Member -MemberType ScriptMethod -Name GetInstances -Value {param($flags)[pscustomobject]@{Count=$this.Instances}}
 $task
}
$beforeLastRunTime='1999-11-30T00:00:00.0000000'
$task=Fake-Task;$null=Assert-Task $task;Assert-Stopped $task $beforeLastRunTime
$task.LastTaskResult=1;Assert-Completed $task $beforeLastRunTime
$task=Fake-Task
$task.LastRunTime=[datetime]::Parse($beforeLastRunTime,[Globalization.CultureInfo]::InvariantCulture)
$rejected=$false;try{Assert-Completed $task $beforeLastRunTime}catch{$rejected=$true};if(!$rejected){throw 'Never-run READY task accepted as completed'}
$task=Fake-Task
$checks=@()
$ordinary=[Management.Automation.Language.Parser]::ParseFile((Join-Path $Source 'lifecycle.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Ordinary parser failed'}
foreach($node in $ordinary.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([ScriptBlock]::Create($node.Extent.Text))}
foreach($instances in @(0,1)){
 if(!(Single-Inventory 1 1 0 1 0 $instances)){throw 'Authenticated native/CIM singleton rejected'}
 $checks+=@{name=('native-cim-singleton-scheduler-instances-'+$instances);passed=$true}
}
foreach($case in @(
 @{name='missing-cim-host';values=@(0,1,0,1,0,0)},
 @{name='duplicate-cim-host';values=@(2,1,0,1,0,0)},
 @{name='missing-native-host';values=@(1,0,0,1,0,0)},
 @{name='duplicate-native-host';values=@(1,2,0,1,0,0)},
 @{name='unreadable-live-native-host';values=@(1,1,1,1,0,0)},
 @{name='missing-product-task';values=@(1,1,0,0,0,0)},
 @{name='duplicate-product-task';values=@(1,1,0,2,0,0)},
 @{name='unexpected-task-subfolder';values=@(1,1,0,1,1,0)},
 @{name='duplicate-scheduler-instance';values=@(1,1,0,1,0,2)},
 @{name='invalid-scheduler-instance-count';values=@(1,1,0,1,0,-1)}
)){
 $v=$case.values
 if(Single-Inventory $v[0] $v[1] $v[2] $v[3] $v[4] $v[5]){throw ('Invalid singleton accepted: '+$case.name)}
 $checks+=@{name=$case.name;passed=$true}
}
$command=Get-Command Invoke-ProductCli
if($command.CommandType -ne 'Function' -or $command.Name -cne 'Invoke-ProductCli'){throw 'Product CLI function shadowed'}
$checks+=@{name='product-cli-command-resolves-function-without-alias';passed=$true}
$diagnostic=Closed-CliError "LOGIN_FIXTURE_LAUNCH stage=Admission category=LOGIN_HOST_NOT_READY`nLOGIN_HOST_NOT_READY`n"
if($diagnostic.unrecognized -or $diagnostic.diagnostics.Count -ne 1 -or $diagnostic.diagnostics[0].stage -cne 'Admission' -or $diagnostic.codes[0] -cne 'LOGIN_HOST_NOT_READY'){throw 'Closed admission diagnostic missing'}
$checks+=@{name='closed-admission-stage-retains-canonical-error';passed=$true}
foreach($text in @('LOGIN_FIXTURE_LAUNCH stage=Environment category=LOGIN_HOST_NOT_READY','LOGIN_FIXTURE_LAUNCH stage=Readiness category=LOGIN_HOST_NOT_READY private=sentinel','OPERATOR_PRIVATE_SENTINEL')){
 $diagnostic=Closed-CliError $text
 if(!$diagnostic.unrecognized -or $diagnostic.diagnostics.Count -ne 0 -or $diagnostic.codes.Count -ne 0){throw 'Unrecognized diagnostic entered evidence'}
}
$checks+=@{name='closed-diagnostics-reject-private-or-unknown-payload';passed=$true}
$task=Fake-Task;$task.Definition.Principal.UserId='test-user';$null=Assert-Task $task;$checks+=@{name='scheduler-canonical-local-name-resolves-exact-sid';passed=$true}
foreach($case in @(
 @{name='foreign-task-path';change={param($t)$t.Path='\foreign'}},
 @{name='foreign-uuid';change={param($t)$t.Definition.Data='foreign'}},
 @{name='foreign-account';change={param($t)$t.Definition.Principal.UserId='S-1-5-18'}},
 @{name='password-logon';change={param($t)$t.Definition.Principal.LogonType=1}},
 @{name='elevated-run-level';change={param($t)$t.Definition.Principal.RunLevel=1}},
 @{name='extra-action';change={param($t)$t.Definition.Actions.Count=2}},
 @{name='foreign-executable';change={param($t)$t.Definition.Actions.Action.Path='C:\foreign.exe'}},
 @{name='foreign-arguments';change={param($t)$t.Definition.Actions.Action.Arguments='foreign'}},
 @{name='foreign-working-directory';change={param($t)$t.Definition.Actions.Action.WorkingDirectory='C:\foreign'}},
 @{name='unexpected-trigger';change={param($t)$t.Definition.Triggers.Count=1}},
 @{name='forced-termination';change={param($t)$t.Definition.Settings.AllowHardTerminate=$true}},
 @{name='time-limit';change={param($t)$t.Definition.Settings.ExecutionTimeLimit='PT1M'}},
 @{name='foreign-acl';change={param($t)$t.Sddl='O:BAD:P(A;;GA;;;WD)'}},
 @{name='ordinary-task-generic-write';change={param($t)$t.Sddl="O:BAD:P(A;;GA;;;BA)(A;;GW;;;$ExpectedSid)"}},
 @{name='ordinary-task-write';change={param($t)$t.Sddl="O:BAD:P(A;;GA;;;BA)(A;;GA;;;$ExpectedSid)"}}
)){
 $task=Fake-Task;& $case.change $task;$rejected=$false
 try{$null=Assert-Task $task}catch{$rejected=$true}
 if(!$rejected){throw ('Task substitution accepted: '+$case.name)}
 $checks+=@{name=$case.name;passed=$true}
}
foreach($case in @(@{name='helper-failed';change={param($t)$t.LastTaskResult=1}},@{name='helper-running';change={param($t)$t.State=4}},@{name='helper-live-instance';change={param($t)$t.Instances=1}})){
 $task=Fake-Task;& $case.change $task;$rejected=$false;try{Assert-Stopped $task $beforeLastRunTime}catch{$rejected=$true};if(!$rejected){throw ('Helper completion accepted: '+$case.name)};$checks+=@{name=$case.name;passed=$true}
}
. (Join-Path $Source 'lifecycle-identity.ps1')
$proof=Join-Path $Source ('identity-'+[Guid]::NewGuid().ToString('D'));$null=New-Item -ItemType Directory -Path $proof
$file=Join-Path $proof 'leaf.txt';$unknown=Join-Path $proof 'unknown.txt';[IO.File]::WriteAllText($file,'synthetic-leaf');[IO.File]::WriteAllText($unknown,'synthetic-unknown')
$rootPin=$null;$leafPin=$null
try {
 $rootPin=[LomiLoginFileIdentity]::Hold($proof,$true,$false);$leafPin=[LomiLoginFileIdentity]::Hold($file,$true,$true)
 $rejected=$false;try{[IO.File]::Move($file,($file+'.foreign'))}catch{$rejected=$true};if(!$rejected){throw 'Pinned leaf rename allowed'};$checks+=@{name='retained-leaf-denies-rename';passed=$true}
 $rejected=$false;try{[IO.File]::WriteAllText($file,'foreign')}catch{$rejected=$true};if(!$rejected){throw 'Pinned leaf write allowed'};$checks+=@{name='retained-leaf-denies-write';passed=$true}
 $rejected=$false;try{[IO.Directory]::Move($proof,($proof+'.foreign'))}catch{$rejected=$true};if(!$rejected){throw 'Pinned root rename allowed'};$checks+=@{name='retained-root-denies-rename';passed=$true}
 $leafPin.Delete();if(Test-Path -LiteralPath $file){throw 'Exact handle leaf deletion failed'}
 $rejected=$false;try{$rootPin.Delete()}catch{$rejected=$true};if(!$rejected -or [IO.File]::ReadAllText($unknown) -cne 'synthetic-unknown'){throw 'Unknown child removed'};$checks+=@{name='nonempty-root-preserves-unknown-child';passed=$true}
 $unknownPin=[LomiLoginFileIdentity]::Hold($unknown,$true,$true);try{$unknownPin.Delete()}finally{$unknownPin.Dispose()};$rootPin.Delete()
 if(Test-Path -LiteralPath $proof){throw 'Exact identity fixture cleanup failed'};$checks+=@{name='exact-handles-cleanup-owned-fixture';passed=$true}
}finally{if($leafPin){$leafPin.Dispose()};if($rootPin){$rootPin.Dispose()}}
@{passed=$true;negativeChecks=$checks;count=$checks.Count;taskSchedulerMutations=0}|ConvertTo-Json -Depth 5 -Compress
