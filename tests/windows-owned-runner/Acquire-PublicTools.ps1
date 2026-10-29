# PREPARED_NOT_EXECUTED. Invoke only through the reviewed native Run-Owned parent.
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string] $OwnedRoot)

$ErrorActionPreference = 'Stop'
# Validate before Add-Type can write compiler temporary files. This process is
# disposable; TEMP/TMP are set explicitly, never copied from the operator.
if (-not [IO.Path]::IsPathRooted($OwnedRoot) -or $OwnedRoot.StartsWith('\\') -or
    $OwnedRoot -cne [IO.Path]::GetFullPath($OwnedRoot) -or $OwnedRoot.EndsWith('\')) {
    throw 'A normalized absolute local UUID root is required.'
}
$rootId = [Guid]::Empty
if (-not [Guid]::TryParseExact([IO.Path]::GetFileName($OwnedRoot), 'D', [ref]$rootId) -or
    $rootId -eq [Guid]::Empty) { throw 'A nonzero UUID root is required.' }
for ($part = [IO.DirectoryInfo]::new($OwnedRoot); $null -ne $part; $part = $part.Parent) {
    if (($part.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse path rejected.' }
}
$rootAcl = [IO.Directory]::GetAccessControl($OwnedRoot,
    ([Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner))
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $sid = $identity.User
    $rules = $rootAcl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
    if ($null -eq $sid -or -not $sid.Equals($rootAcl.GetOwner([Security.Principal.SecurityIdentifier])) -or
        -not $rootAcl.AreAccessRulesProtected -or $rules.Count -ne 1 -or
        $identity.ImpersonationLevel -eq [Security.Principal.TokenImpersonationLevel]::Impersonation -or
        $identity.ImpersonationLevel -eq [Security.Principal.TokenImpersonationLevel]::Delegation) {
        throw 'Private current-token root required.'
    }
    $rule = $rules[0]
    if ($rule.IsInherited -or -not $sid.Equals($rule.IdentityReference) -or
        $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
        $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
        $rule.InheritanceFlags -ne ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit) -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw 'Exact private root ACL required.'
    }
    # GetAccessRules can omit callback ACEs; the entire raw DACL must match.
    $raw = [Security.AccessControl.RawSecurityDescriptor]::new($rootAcl.GetSecurityDescriptorBinaryForm(), 0)
    if (-not $sid.Equals($raw.Owner) -or
        ($raw.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) -eq 0 -or
        $null -eq $raw.DiscretionaryAcl -or $raw.DiscretionaryAcl.Count -ne 1) {
        throw 'Exact raw private root DACL required.'
    }
    $ace = $raw.DiscretionaryAcl[0]
    if ($ace -isnot [Security.AccessControl.CommonAce] -or
        $ace.AceType -ne [Security.AccessControl.AceType]::AccessAllowed -or $ace.IsCallback -or
        $ace.AceQualifier -ne [Security.AccessControl.AceQualifier]::AccessAllowed -or
        -not $sid.Equals($ace.SecurityIdentifier) -or $ace.AccessMask -ne 2032127 -or [int]$ace.AceFlags -ne 3) {
        throw 'One ordinary noncallback private root ACE required.'
    }
} finally { $identity.Dispose() }
if ([IO.Directory]::GetFileSystemEntries($OwnedRoot).Length -ne 0) { throw 'Empty root required.' }
$compileRoot = [IO.Path]::Combine($OwnedRoot, '.compile')
[void][IO.Directory]::CreateDirectory($compileRoot)
[Environment]::SetEnvironmentVariable('TEMP', $compileRoot, [EnvironmentVariableTarget]::Process)
[Environment]::SetEnvironmentVariable('TMP', $compileRoot, [EnvironmentVariableTarget]::Process)
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.IO.Compression
if ('Lomi.PublicToolAcquisition' -as [type]) { throw 'Acquisition type already loaded; use a fresh owned process.' }
Add-Type -ReferencedAssemblies System.Core,System.Net.Http,System.IO.Compression -TypeDefinition @'
using System;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Lomi {
public static class PublicToolAcquisition {
    [DllImport("kernel32.dll", SetLastError=true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool IsProcessInJob(IntPtr process, IntPtr job,
        [MarshalAs(UnmanagedType.Bool)] out bool result);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    sealed class Pin {
        internal string Name, Url, Hash, Member, Host, BinaryHash;
        internal long Cap, BinaryCap, Bytes, BinaryBytes;
        internal bool Verified;
    }
    static void Require(bool ok) { if (!ok) throw new InvalidOperationException("Policy check failed."); }
    static void Deadline(Stopwatch clock) { Require(clock.ElapsedMilliseconds < 300000); }
    static string Hex(byte[] bytes) { return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(); }
    static FileStream NewFile(string path) {
        return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536);
    }
    static void CheckRoot(string root) {
        Require(Path.IsPathRooted(root) && !root.StartsWith(@"\\", StringComparison.Ordinal));
        Require(String.Equals(root, Path.GetFullPath(root), StringComparison.Ordinal));
        Require(root.Length > 3 && root[root.Length - 1] != Path.DirectorySeparatorChar);
        Guid id;
        Require(Guid.TryParseExact(Path.GetFileName(root), "D", out id) && id != Guid.Empty);
        // Inspect every path component to reject an ancestor junction/symlink as well.
        for (DirectoryInfo d = new DirectoryInfo(root); d != null; d = d.Parent)
            Require((d.Attributes & FileAttributes.ReparsePoint) == 0);
        DirectorySecurity acl = Directory.GetAccessControl(root,
            AccessControlSections.Access | AccessControlSections.Owner);
        using (WindowsIdentity token = WindowsIdentity.GetCurrent()) {
            Require(token.ImpersonationLevel != TokenImpersonationLevel.Impersonation &&
                token.ImpersonationLevel != TokenImpersonationLevel.Delegation);
            SecurityIdentifier sid = token.User;
            Require(sid != null && sid.Equals(acl.GetOwner(typeof(SecurityIdentifier))));
            Require(acl.AreAccessRulesProtected);
            AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
            Require(rules.Count == 1);
            FileSystemAccessRule rule = (FileSystemAccessRule)rules[0];
            Require(!rule.IsInherited && sid.Equals(rule.IdentityReference) &&
                rule.AccessControlType == AccessControlType.Allow &&
                rule.FileSystemRights == FileSystemRights.FullControl &&
                rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
                rule.PropagationFlags == PropagationFlags.None);
            RawSecurityDescriptor raw = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
            Require(sid.Equals(raw.Owner) &&
                (raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 &&
                raw.DiscretionaryAcl != null && raw.DiscretionaryAcl.Count == 1);
            CommonAce ace = raw.DiscretionaryAcl[0] as CommonAce;
            Require(ace != null && ace.AceType == AceType.AccessAllowed && !ace.IsCallback &&
                ace.AceQualifier == AceQualifier.AccessAllowed && sid.Equals(ace.SecurityIdentifier) &&
                ace.AccessMask == 2032127 && (int)ace.AceFlags == 3);
        }
        string[] contents = Directory.GetFileSystemEntries(root);
        Require(contents.Length == 1 && contents[0] == Path.Combine(root, ".compile"));
        Require(Directory.Exists(contents[0]) &&
            (File.GetAttributes(contents[0]) & FileAttributes.ReparsePoint) == 0);
        bool inJob;
        Require(IsProcessInJob(GetCurrentProcess(), IntPtr.Zero, out inJob) && inJob);
    }
    static void CheckUri(Uri uri, bool node) {
        Require(uri.IsAbsoluteUri && uri.Scheme == "https" && uri.Port == 443 &&
            uri.UserInfo.Length == 0 && uri.Fragment.Length == 0);
        string host = uri.DnsSafeHost.ToLowerInvariant();
        Require(node ? host == "nodejs.org" :
            host == "github.com" || host == "release-assets.githubusercontent.com" ||
            host == "objects.githubusercontent.com" || host == "github-releases.githubusercontent.com");
    }
    static void Download(Pin pin, string root, HttpClient client, CancellationToken cancel, Stopwatch clock) {
        Uri uri = new Uri(pin.Url);
        for (int redirects = 0; ; redirects++) {
            Deadline(clock); CheckUri(uri, pin.Name == "node");
            using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri))
            using (HttpResponseMessage response = client.SendAsync(request,
                HttpCompletionOption.ResponseHeadersRead, cancel).GetAwaiter().GetResult()) {
                int status = (int)response.StatusCode;
                if (status == 301 || status == 302 || status == 303 || status == 307 || status == 308) {
                    Require(redirects < 5 && response.Headers.Location != null);
                    uri = new Uri(uri, response.Headers.Location);
                    CheckUri(uri, pin.Name == "node");
                    continue;
                }
                Require(status == 200 && response.Content.Headers.ContentEncoding.Count == 0);
                long? expected = response.Content.Headers.ContentLength;
                Require(!expected.HasValue || (expected.Value > 0 && expected.Value <= pin.Cap));
                pin.Host = uri.DnsSafeHost.ToLowerInvariant();
                using (Stream input = response.Content.ReadAsStreamAsync().GetAwaiter().GetResult())
                using (FileStream output = NewFile(Path.Combine(root, pin.Name + ".zip")))
                using (SHA256 sha = SHA256.Create()) {
                    byte[] buffer = new byte[65536];
                    Stopwatch transfer = Stopwatch.StartNew();
                    while (true) {
                        Deadline(clock); cancel.ThrowIfCancellationRequested();
                        // ReadAsync may return a short TLS record. Charge only
                        // actual bytes, rounded up; no credit carries to a later read.
                        long started = transfer.ElapsedMilliseconds;
                        int n = input.ReadAsync(buffer, 0, buffer.Length, cancel).GetAwaiter().GetResult();
                        if (n == 0) break;
                        Require(pin.Bytes <= pin.Cap - n);
                        output.Write(buffer, 0, n); sha.TransformBlock(buffer, 0, n, buffer, 0);
                        pin.Bytes += n;
                        long next = started + ((n * 1000L + 1048575L) / 1048576L);
                        int delay = (int)Math.Max(0, next - transfer.ElapsedMilliseconds);
                        if (delay != 0 && cancel.WaitHandle.WaitOne(delay)) cancel.ThrowIfCancellationRequested();
                    }
                    sha.TransformFinalBlock(new byte[0], 0, 0);
                    Require(pin.Bytes > 0 && (!expected.HasValue || expected.Value == pin.Bytes));
                    Require(Hex(sha.Hash) == pin.Hash);
                    pin.Verified = true;
                }
                return;
            }
        }
    }
    static void CheckEntry(ZipArchiveEntry entry) {
        string name = entry.FullName;
        Require(name.Length > 0 && name.Length <= 512 && name[0] != '/' &&
            name.IndexOf('\\') < 0 && name.IndexOf(':') < 0 && name.IndexOf('\0') < 0);
        string[] parts = name.Split('/');
        for (int i = 0; i < parts.Length; i++)
            Require(parts[i] != "." && parts[i] != ".." &&
                (parts[i].Length > 0 || i == parts.Length - 1));
        uint attributes = unchecked((uint)entry.ExternalAttributes);
        uint unixType = (attributes >> 16) & 0xf000;
        Require(unixType == 0 || unixType == 0x8000 || unixType == 0x4000);
        Require((attributes & (uint)FileAttributes.ReparsePoint) == 0);
        Require(entry.Length >= 0 && entry.CompressedLength >= 0);
    }
    static void Extract(Pin pin, string root, Stopwatch clock) {
        Require(pin.Verified); Deadline(clock);
        using (FileStream source = new FileStream(Path.Combine(root, pin.Name + ".zip"),
            FileMode.Open, FileAccess.Read, FileShare.None))
        using (ZipArchive zip = new ZipArchive(source, ZipArchiveMode.Read, false)) {
            Require(zip.Entries.Count > 0 && zip.Entries.Count <= 20000);
            var names = new System.Collections.Generic.HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ZipArchiveEntry chosen = null;
            foreach (ZipArchiveEntry entry in zip.Entries) {
                Deadline(clock); CheckEntry(entry); Require(names.Add(entry.FullName));
                if (entry.FullName == pin.Member) chosen = entry;
            }
            Require(chosen != null && chosen.Length > 0 && chosen.Length <= pin.BinaryCap);
            using (Stream input = chosen.Open())
            using (FileStream output = NewFile(Path.Combine(root, pin.Name + ".exe")))
            using (SHA256 sha = SHA256.Create()) {
                byte[] buffer = new byte[65536];
                while (true) {
                    Deadline(clock);
                    int n = input.Read(buffer, 0, buffer.Length);
                    if (n == 0) break;
                    Require(pin.BinaryBytes <= chosen.Length - n);
                    output.Write(buffer, 0, n); sha.TransformBlock(buffer, 0, n, buffer, 0);
                    pin.BinaryBytes += n;
                }
                Require(pin.BinaryBytes == chosen.Length);
                sha.TransformFinalBlock(new byte[0], 0, 0); pin.BinaryHash = Hex(sha.Hash);
            }
        }
        // Static executable format check only; never execute the acquired program.
        using (BinaryReader reader = new BinaryReader(File.OpenRead(Path.Combine(root, pin.Name + ".exe")))) {
            Require(reader.BaseStream.Length >= 64 && reader.ReadUInt16() == 0x5a4d);
            reader.BaseStream.Position = 0x3c;
            uint offset = reader.ReadUInt32();
            Require(offset >= 64 && offset <= reader.BaseStream.Length - 6);
            reader.BaseStream.Position = offset;
            Require(reader.ReadUInt32() == 0x4550 && reader.ReadUInt16() == 0x8664);
        }
    }
    static void Receipt(string root, Pin[] pins, bool success, string stage) {
        StringBuilder json = new StringBuilder();
        json.Append("{\"schema\":1,\"status\":\"").Append(success ? "ACQUIRED_NOT_EXECUTED" : "FAILED_UNCERTAIN")
            .Append("\",\"completionKnown\":").Append(success ? "true" : "false")
            .Append(",\"cleanupKnown\":").Append(success ? "true" : "false")
            .Append(",\"cleanupMeaning\":\"managed handles disposed; files retained; no deletion attempted\"")
            .Append(",\"stage\":\"").Append(stage).Append("\",\"artifacts\":[");
        for (int i = 0; i < pins.Length; i++) {
            Pin pin = pins[i]; if (i != 0) json.Append(',');
            json.Append("{\"name\":\"").Append(pin.Name).Append("\",\"archiveSha256\":\"")
                .Append(pin.Verified ? pin.Hash : "").Append("\",\"archiveVerified\":")
                .Append(pin.Verified ? "true" : "false").Append(",\"archiveBytes\":").Append(pin.Bytes)
                .Append(",\"binarySha256\":\"").Append(pin.BinaryHash ?? "")
                .Append("\",\"binaryBytes\":").Append(pin.BinaryBytes)
                .Append(",\"finalHttpsHost\":\"").Append(pin.Host ?? "").Append("\"}");
        }
        json.Append("]}"); Require(json.Length <= 8192);
        using (FileStream file = NewFile(Path.Combine(root, "acquisition-receipt.json"))) {
            byte[] bytes = new UTF8Encoding(false).GetBytes(json.ToString()); file.Write(bytes, 0, bytes.Length);
        }
    }
    public static void Run(string root) {
        Stopwatch clock = Stopwatch.StartNew();
        // Root validation failures create no receipt or other file.
        CheckRoot(root);
        Pin[] pins = {
            new Pin { Name="node", Url="https://nodejs.org/download/release/v22.22.3/node-v22.22.3-win-x64.zip",
                Hash="6c8d54f635feff4df76c2ca80f45332eb2ff57d25226edce36592e51a177ee33",
                Member="node-v22.22.3-win-x64/node.exe", Cap=60L*1024*1024, BinaryCap=100L*1024*1024 },
            new Pin { Name="bun", Url="https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-windows-x64-baseline.zip",
                Hash="78c221c2376f79731ccf4e4af0b3bb46d81fefa3296c5abee09ad8a1b21e68c6",
                Member="bun-windows-x64-baseline/bun.exe", Cap=100L*1024*1024, BinaryCap=200L*1024*1024 }
        };
        string stage = "download";
        try {
            using (CancellationTokenSource cancel = new CancellationTokenSource())
            using (HttpClientHandler handler = new HttpClientHandler()) {
                cancel.CancelAfter((int)Math.Max(1, 300000 - clock.ElapsedMilliseconds));
                handler.AllowAutoRedirect = false; handler.UseCookies = false; handler.UseProxy = false;
                handler.UseDefaultCredentials = false; handler.AutomaticDecompression = DecompressionMethods.None;
                handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;
                using (HttpClient client = new HttpClient(handler)) {
                    client.Timeout = Timeout.InfiniteTimeSpan;
                    foreach (Pin pin in pins) {
                        stage = pin.Name + "-download"; Download(pin, root, client, cancel.Token, clock);
                        stage = pin.Name + "-extract"; Extract(pin, root, clock);
                    }
                }
            }
            stage = "receipt"; Deadline(clock); Receipt(root, pins, true, "complete");
        } catch {
            // Never delete evidence or recurse through an uncertain directory tree.
            try { Receipt(root, pins, false, stage); } catch { }
            throw new InvalidOperationException("Acquisition failed or uncertain; preserve the owned root and stop.");
        }
    }
}
}
'@
[Lomi.PublicToolAcquisition]::Run($OwnedRoot)
