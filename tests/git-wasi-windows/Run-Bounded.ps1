param([Parameter(Mandatory)][string]$Executable,[string[]]$ArgumentList=@(),[Parameter(Mandatory)][string]$Directory,[int]$TimeoutSeconds=90,[switch]$Canary)
$ErrorActionPreference='Stop'
# Only our exact child PID is ever terminated. Captured streams have independent
# hard byte limits; background drains keep reading until termination/EOF.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
public static class LomiBounded {
 public sealed class Drain {
  public MemoryStream Data=new MemoryStream(); public volatile bool Overflow;
  public async Task Read(Stream input) {
   byte[] buffer=new byte[4096]; int count;
   while((count=await input.ReadAsync(buffer,0,buffer.Length))>0) {
    int remaining=131072-(int)Data.Length;
    if(count>remaining) Overflow=true;
    if(remaining>0) Data.Write(buffer,0,Math.Min(remaining,count));
   }
  }
 }
 static void KillTree(Process process) {
  using(var killer=Process.Start(new ProcessStartInfo("taskkill.exe","/PID "+process.Id+" /T /F") {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true})) {
   var a=killer.StandardOutput.ReadToEndAsync();var b=killer.StandardError.ReadToEndAsync();
   if(!killer.WaitForExit(3000)) {killer.Kill();throw new Exception("owned tree termination uncertain");}
   if(killer.ExitCode!=0) throw new Exception("owned tree termination rejected");
   if(!Task.WaitAll(new Task[]{a,b},1000)) throw new Exception("tree terminator drain uncertain");
  }
  if(!process.WaitForExit(3000)) throw new Exception("owned child termination uncertain");
 }
 public static object Run(string exe,string args,string cwd,int seconds,bool canary) {
  var info=new ProcessStartInfo(exe,args) { WorkingDirectory=cwd,UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,RedirectStandardInput=true };
  if(canary) info.EnvironmentVariables["LOMI_PRIVATE_CANARY"]="synthetic-host-only";
  using(var process=new Process {StartInfo=info}) {
   process.Start();
   try {
   process.StandardInput.Close();
   var output=new Drain();var error=new Drain();
   var outTask=output.Read(process.StandardOutput.BaseStream);var errTask=error.Read(process.StandardError.BaseStream);
   var clock=Stopwatch.StartNew();bool expired=false;
   while(!process.WaitForExit(50)) {
    if(clock.Elapsed.TotalSeconds>seconds||output.Overflow||error.Overflow) {
     expired=true;
     KillTree(process);
     break;
    }
   }
   if(!Task.WaitAll(new Task[]{outTask,errTask},3000)) throw new Exception("owned output drain uncertain");
   return new {exitCode=process.ExitCode,timedOut=expired,outputOverflow=output.Overflow||error.Overflow,stdoutBase64=Convert.ToBase64String(output.Data.ToArray()),stderrBase64=Convert.ToBase64String(error.Data.ToArray()),durationMilliseconds=clock.ElapsedMilliseconds,completionKnown=true};
   } finally {if(!process.HasExited) KillTree(process);}
  }
 }
}
'@
$quoted=@($ArgumentList|ForEach-Object {if($_ -match '["\r\n]' -or $_.EndsWith('\')){throw 'Unsupported fixed argument'};'"'+$_+'"'}) -join ' '
try {
 [LomiBounded]::Run($Executable,$quoted,$Directory,$TimeoutSeconds,$Canary.IsPresent)|ConvertTo-Json -Compress
} catch {
 @{completionKnown=$false;errorClass='OwnedWorkerUncertain'}|ConvertTo-Json -Compress
 exit 1
}
