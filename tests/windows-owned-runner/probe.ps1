[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Normal', 'PreResumeDeadline', 'Overflow', 'Arguments', 'Environment', 'HandleInheritance', 'TimeoutGrandchild', 'AbruptOwner',
        'ChildNormal', 'ChildMarker', 'ChildOverflow', 'ChildArguments', 'ChildEnvironment', 'ChildHandle', 'ChildTree', 'ChildHold', 'Owner')]
    [string] $Mode,
    [Parameter(Mandatory = $true)][string] $PowerShellExecutable,
    [Parameter(Mandatory = $true)][string] $WorkingDirectory,
    [Parameter(Mandatory = $true)][string] $EnvironmentJsonPath,
    [Parameter(Mandatory = $true)][string] $MarkerPath,
    [Parameter(ValueFromRemainingArguments = $true)][AllowEmptyString()][string[]] $ProbeArguments
)

# Source only. No invocation is performed when this file is added to the repository.
$ErrorActionPreference = 'Stop'
$scriptPath = $PSCommandPath
$runnerPath = Join-Path $PSScriptRoot 'Run-Owned.ps1'
foreach ($path in @($PowerShellExecutable, $WorkingDirectory, $EnvironmentJsonPath, $MarkerPath)) {
    if (-not [IO.Path]::IsPathRooted($path) -or [IO.Path]::GetFullPath($path) -ne $path) {
        throw 'All probe paths must be normalized absolute paths.'
    }
}
$environment = @{}
$parsedEnvironment = Get-Content -LiteralPath $EnvironmentJsonPath -Raw | ConvertFrom-Json
foreach ($property in $parsedEnvironment.PSObject.Properties) {
    if ($property.Value -isnot [string]) { throw 'Environment values must be strings.' }
    $environment.Add($property.Name, $property.Value)
}

function Get-ChildArguments([string] $ChildMode) {
    @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $scriptPath,
        '-Mode', $ChildMode, '-PowerShellExecutable', $PowerShellExecutable,
        '-WorkingDirectory', $WorkingDirectory, '-EnvironmentJsonPath', $EnvironmentJsonPath,
        '-MarkerPath', $MarkerPath)
}

function Assert-MarkerReleased {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    do {
        try {
            $stream = [IO.File]::Open($MarkerPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $stream.Dispose()
            return
        } catch [IO.IOException] { Start-Sleep -Milliseconds 20 }
    } while ($watch.ElapsedMilliseconds -lt 5000)
    throw 'Descendant marker is still held; cleanup is uncertain.'
}

function Assert-CleanResult($Result) {
    if (-not $Result.completionKnown -or -not $Result.JobEmpty -or $Result.timeout -or $Result.overflow -or $Result.exitCode -ne 0) {
        throw 'Probe did not complete cleanly.'
    }
}

function Import-HandleProbe {
    if ('Lomi.OwnedHandleProbe' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Lomi {
    public static class OwnedHandleProbe {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint size, uint flags);
        public static bool PointsToFile(long value, string expected) {
            StringBuilder path = new StringBuilder(32768);
            uint size = GetFinalPathNameByHandleW(new IntPtr(value), path, (uint)path.Capacity, 0);
            if (size == 0 || size >= path.Capacity) return false;
            string actual = path.ToString();
            if (actual.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) actual = @"\\" + actual.Substring(8);
            else if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            return String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
        }
    }
}
'@
}

switch ($Mode) {
    'ChildMarker' {
        [IO.File]::WriteAllText($MarkerPath, 'child executed')
        exit 0
    }
    'ChildOverflow' {
        $output = [Console]::OpenStandardOutput()
        $bytes = New-Object byte[] 8192
        while ($true) { $output.Write($bytes, 0, $bytes.Length) }
    }
    'ChildArguments' {
        $all = [Environment]::GetCommandLineArgs()
        $tail = @($all[($all.Length - 3)..($all.Length - 1)])
        $encoded = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $tail -Compress))
        [Console]::OpenStandardOutput().Write($encoded, 0, $encoded.Length)
        exit 0
    }
    'ChildEnvironment' {
        if ([Environment]::GetEnvironmentVariable('LOMI_OWNED_OPERATOR_ONLY') -ne $null -or
            [Environment]::GetEnvironmentVariable('LOMI_OWNED_EXPLICIT') -ne 'explicit-value-42') { exit 9 }
        exit 0
    }
    'ChildHandle' {
        Import-HandleProbe
        $number = [long]::Parse([Environment]::GetEnvironmentVariable('LOMI_OWNED_SENTINEL_HANDLE'), [Globalization.CultureInfo]::InvariantCulture)
        if ([Lomi.OwnedHandleProbe]::PointsToFile($number, $MarkerPath)) { exit 9 }
        exit 0
    }
    'ChildNormal' {
        $bytes = [byte[]](0, 1, 10, 13, 127, 128, 255)
        [Console]::OpenStandardOutput().Write($bytes, 0, $bytes.Length)
        [Console]::OpenStandardError().Write($bytes, 0, $bytes.Length)
        exit 7
    }
    'ChildHold' {
        $stream = [IO.File]::Open($MarkerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { Start-Sleep -Seconds 120 } finally { $stream.Dispose() }
        exit 0
    }
    'ChildTree' {
        # This process was already assigned to the runner Job; the descendant
        # inherits that membership. Start-Process does not request breakaway.
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $PowerShellExecutable
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        # Get-ChildArguments values are constrained to ordinary absolute fixture
        # paths below. The production runner owns full CRT quoting separately.
        $arguments = Get-ChildArguments 'ChildHold'
        foreach ($argument in $arguments) {
            if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Probe fixture paths cannot contain quotes or end with backslash.' }
        }
        $info.Arguments = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $info.WorkingDirectory = $WorkingDirectory
        $child = [Diagnostics.Process]::Start($info)
        try { $child.WaitForExit() } finally { $child.Dispose() }
        exit 0
    }
    'Owner' {
        & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildTree') `
            -WorkingDirectory $WorkingDirectory -Environment $environment -TimeoutMilliseconds 60000 | Out-Null
        exit 0
    }
    'Normal' {
        $result = & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildNormal') `
            -WorkingDirectory $WorkingDirectory -Environment $environment
        if (-not $result.completionKnown -or -not $result.JobEmpty -or $result.timeout -or $result.overflow -or
            $result.exitCode -ne 7 -or $result.stdoutBase64 -cne 'AAEKDX+A/w==' -or $result.stderrBase64 -cne 'AAEKDX+A/w==') {
            throw 'Normal probe failed.'
        }
        $result
    }
    'Overflow' {
        $result = & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildOverflow') `
            -WorkingDirectory $WorkingDirectory -Environment $environment -TimeoutMilliseconds 10000 -CaptureBytesPerStream 256
        if (-not $result.overflow -or $result.timeout -or -not $result.completionKnown -or -not $result.JobEmpty -or
            [Convert]::FromBase64String($result.stdoutBase64).Length -ne 256) { throw 'Overflow probe failed.' }
        $result
    }
    'PreResumeDeadline' {
        if (Test-Path -LiteralPath $MarkerPath) { throw 'Use a fresh marker path.' }
        if (-not ('Lomi.WindowsOwnedRunner' -as [type])) {
            Add-Type -Path (Join-Path $PSScriptRoot 'OwnedProcess.cs')
        }
        # The explicit 100 ms test-only delay exceeds the 50 ms execution budget.
        # Atomic ownership is established, but no instruction in ChildMarker runs.
        $resumeAttempts = 0
        $result = [Lomi.WindowsOwnedRunner]::RunWithPreResumeDelayForProbe(
            $PowerShellExecutable, [string[]](Get-ChildArguments 'ChildMarker'), $WorkingDirectory,
            $environment, 50, 10000, 1024, 100, [ref] $resumeAttempts)
        if (-not $result.timeout -or -not $result.completionKnown -or -not $result.JobEmpty -or
            $null -eq $result.exitCode -or $result.overflow -or $resumeAttempts -ne 0 -or
            (Test-Path -LiteralPath $MarkerPath)) {
            throw 'Pre-resume deadline probe failed.'
        }
        $result
    }
    'Arguments' {
        $expected = [string[]]@('', 'before\"after', 'trailing\')
        $arguments = @(Get-ChildArguments 'ChildArguments') + $expected
        $result = & $runnerPath -Executable $PowerShellExecutable -Arguments $arguments `
            -WorkingDirectory $WorkingDirectory -Environment $environment
        Assert-CleanResult $result
        $actual = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.stdoutBase64)) | ConvertFrom-Json
        if ($actual.Count -ne $expected.Count) { throw 'Argument count mismatch.' }
        for ($index = 0; $index -lt $expected.Count; $index++) {
            if ($actual[$index] -cne $expected[$index]) { throw 'Argument quoting probe failed.' }
        }
        $result
    }
    'Environment' {
        $previous = [Environment]::GetEnvironmentVariable('LOMI_OWNED_OPERATOR_ONLY')
        try {
            [Environment]::SetEnvironmentVariable('LOMI_OWNED_OPERATOR_ONLY', 'must-not-be-inherited')
            $childEnvironment = $environment.Clone()
            $childEnvironment.Remove('LOMI_OWNED_OPERATOR_ONLY')
            $childEnvironment['LOMI_OWNED_EXPLICIT'] = 'explicit-value-42'
            $result = & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildEnvironment') `
                -WorkingDirectory $WorkingDirectory -Environment $childEnvironment
            Assert-CleanResult $result
            $result
        } finally { [Environment]::SetEnvironmentVariable('LOMI_OWNED_OPERATOR_ONLY', $previous) }
    }
    'HandleInheritance' {
        if (Test-Path -LiteralPath $MarkerPath) { throw 'Use a fresh, local marker path without reparse points.' }
        Import-HandleProbe
        $sentinel = [IO.File]::Open($MarkerPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
        try {
            $handle = $sentinel.SafeFileHandle.DangerousGetHandle()
            if (-not [Lomi.OwnedHandleProbe]::SetHandleInformation($handle, 1, 1)) { throw 'Could not mark sentinel handle inheritable.' }
            # Confirm the witness identifies this file in the owner before testing
            # the same numeric value in the child. It is never used as a signal.
            if (-not [Lomi.OwnedHandleProbe]::PointsToFile($handle.ToInt64(), $MarkerPath)) { throw 'Sentinel file witness could not be established.' }
            $childEnvironment = $environment.Clone()
            $childEnvironment['LOMI_OWNED_SENTINEL_HANDLE'] = $handle.ToInt64().ToString([Globalization.CultureInfo]::InvariantCulture)
            $result = & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildHandle') `
                -WorkingDirectory $WorkingDirectory -Environment $childEnvironment
            Assert-CleanResult $result
            $result
        } finally { $sentinel.Dispose() }
    }
    'TimeoutGrandchild' {
        if (Test-Path -LiteralPath $MarkerPath) { throw 'Use a fresh marker path.' }
        $result = & $runnerPath -Executable $PowerShellExecutable -Arguments (Get-ChildArguments 'ChildTree') `
            -WorkingDirectory $WorkingDirectory -Environment $environment -TimeoutMilliseconds 10000
        if (-not (Test-Path -LiteralPath $MarkerPath)) { throw 'Grandchild did not acquire the marker.' }
        Assert-MarkerReleased
        if (-not $result.timeout -or -not $result.completionKnown -or -not $result.JobEmpty) { throw 'Timeout probe failed.' }
        $result
    }
    'AbruptOwner' {
        if (Test-Path -LiteralPath $MarkerPath) { throw 'Use a fresh marker path.' }
        $info = New-Object Diagnostics.ProcessStartInfo
        $info.FileName = $PowerShellExecutable
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.WorkingDirectory = $WorkingDirectory
        $info.EnvironmentVariables.Clear()
        foreach ($name in $environment.Keys) { $info.EnvironmentVariables.Add($name, $environment[$name]) }
        $arguments = Get-ChildArguments 'Owner'
        foreach ($argument in $arguments) {
            if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Probe fixture paths cannot contain quotes or end with backslash.' }
        }
        $info.Arguments = ($arguments | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $owner = [Diagnostics.Process]::Start($info)
        try {
            $watch = [Diagnostics.Stopwatch]::StartNew()
            while (-not (Test-Path -LiteralPath $MarkerPath)) {
                if ($owner.HasExited -or $watch.ElapsedMilliseconds -ge 20000) { throw 'Owner did not establish the descendant marker.' }
                Start-Sleep -Milliseconds 20
            }
            # Process.Start retains the native handle. Never reopen or signal a numeric PID.
            $owner.Kill()
            if (-not $owner.WaitForExit(5000)) { throw 'Owner exit was not observed.' }
            Assert-MarkerReleased
            'Abrupt-owner marker released after retained-handle owner termination.'
        } finally {
            if (-not $owner.HasExited) { $owner.Kill(); [void]$owner.WaitForExit(5000) }
            $owner.Dispose()
        }
    }
}
