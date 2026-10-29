// PREPARED_NOT_EXECUTED. Additive test helper; no dependency on normal RunCore.
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace Lomi.RestrictedPostgresTests
{
    public enum FailureStage { None, Token, Setup, Verify, Resume, Input, Observe, Cleanup }
    public enum FailureCategory { None, Native, Policy, ProbeFault, InputIncomplete, Timeout, Overflow, Worker, Cleanup }
    public enum ProbeFault { None, RejectBeforeResume }
    public sealed class RestrictedResult
    {
        public int? exitCode { get; internal set; }
        public bool timeout { get; internal set; }
        public bool overflow { get; internal set; }
        public bool completionKnown { get; internal set; }
        public bool JobEmpty { get; internal set; }
        public bool tokenVerifiedBeforeResume { get; internal set; }
        public bool defaultDaclVerifiedBeforeResume { get; internal set; }
        public bool callerTokenUnchanged { get; internal set; }
        public bool stdinComplete { get; internal set; }
        public bool stdinEofSent { get; internal set; }
        public long stdinBytesWritten { get; internal set; }
        public long stdoutBytesObserved { get; internal set; }
        public long stderrBytesObserved { get; internal set; }
        public FailureStage failureStage { get; internal set; }
        public FailureCategory failureCategory { get; internal set; }
        public int nativeError { get; internal set; }
    }

    public static class RestrictedOwnedRunner
    {
        const uint Infinite = 0xffffffff, Query = 8, Duplicate = 2, AssignPrimary = 1, AdjustDefault = 0x80;
        const string Administrators = "S-1-5-32-544", PowerUsers = "S-1-5-32-547";
        static void Need(bool value) { if (!value) throw new InvalidOperationException("Policy"); }
        static void Check(bool value) { if (!value) throw new Win32Exception(Marshal.GetLastWin32Error()); }
        static bool Close(ref IntPtr handle)
        {
            IntPtr old = handle; handle = IntPtr.Zero;
            return old == IntPtr.Zero || CloseHandle(old);
        }
        static int Remaining(Stopwatch watch, int budget) { return (int)Math.Max(0L, budget - watch.ElapsedMilliseconds); }
        static void Absolute(string path)
        {
            if (String.IsNullOrEmpty(path) || path.IndexOf('\0') >= 0 || path.StartsWith(@"\\", StringComparison.Ordinal) ||
                !Path.IsPathRooted(path) || !String.Equals(path, Path.GetFullPath(path), StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("Normalized local absolute path required.");
        }
        static void NoReparse(string directory)
        {
            for (DirectoryInfo d = new DirectoryInfo(directory); d != null; d = d.Parent)
                Need((d.Attributes & FileAttributes.ReparsePoint) == 0);
        }
        static void Root(string root, string workingDirectory)
        {
            Absolute(root); Absolute(workingDirectory); Guid id;
            Need(Guid.TryParseExact(Path.GetFileName(root), "D", out id) && id != Guid.Empty);
            Need(String.Equals(root, workingDirectory, StringComparison.OrdinalIgnoreCase) ||
                workingDirectory.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
            NoReparse(root); NoReparse(workingDirectory);
            DirectorySecurity acl = Directory.GetAccessControl(root, AccessControlSections.Owner | AccessControlSections.Access);
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                Need(identity.ImpersonationLevel == TokenImpersonationLevel.None);
                Need(identity.User != null && identity.User.Equals(acl.GetOwner(typeof(SecurityIdentifier))) && acl.AreAccessRulesProtected);
                AuthorizationRuleCollection rules = acl.GetAccessRules(true, true, typeof(SecurityIdentifier));
                Need(rules.Count == 1); FileSystemAccessRule rule = (FileSystemAccessRule)rules[0];
                Need(!rule.IsInherited && identity.User.Equals(rule.IdentityReference) &&
                    rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights == FileSystemRights.FullControl &&
                    rule.InheritanceFlags == (InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit) &&
                    rule.PropagationFlags == PropagationFlags.None);
                // Managed rule projection can omit callback ACEs. Inspect the
                // complete raw DACL and require one ordinary ACE, not one rule.
                RawSecurityDescriptor raw = new RawSecurityDescriptor(acl.GetSecurityDescriptorBinaryForm(), 0);
                Need(identity.User.Equals(raw.Owner) &&
                    (raw.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0 &&
                    raw.DiscretionaryAcl != null && raw.DiscretionaryAcl.Count == 1);
                CommonAce ace = raw.DiscretionaryAcl[0] as CommonAce;
                Need(ace != null && ace.AceType == AceType.AccessAllowed && !ace.IsCallback &&
                    ace.AceQualifier == AceQualifier.AccessAllowed && identity.User.Equals(ace.SecurityIdentifier) &&
                    ace.AccessMask == 2032127 && (int)ace.AceFlags == 3);
            }
        }
        static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid argument.");
            StringBuilder b = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) { if (c == '\\') { slashes++; continue; } b.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; b.Append(c); }
            return b.Append('\\', slashes * 2).Append('"').ToString();
        }
        static string EnvironmentBlock(IDictionary source)
        {
            if (source == null) throw new ArgumentNullException("environment");
            var entries = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry e in source)
            {
                string key = e.Key as string, value = e.Value as string;
                if (String.IsNullOrEmpty(key) || key.IndexOfAny(new char[] { '=', '\0' }) >= 0 || value == null ||
                    value.IndexOf('\0') >= 0 || entries.ContainsKey(key)) throw new ArgumentException("Invalid environment.");
                entries.Add(key, value);
            }
            StringBuilder b = new StringBuilder(); foreach (var e in entries) b.Append(e.Key).Append('=').Append(e.Value).Append('\0');
            if (entries.Count == 0) b.Append('\0'); return b.Append('\0').ToString();
        }
        // Pure prefix check on the actual IDictionary; never enters native launch.
        public static bool ElevenStringPrefix(IDictionary map)
        {
            string[] keys = { "SystemRoot", "WINDIR", "ComSpec", "PATH", "HOME", "USERPROFILE", "TEMP", "TMP", "APPDATA", "LOCALAPPDATA", "PSModulePath" };
            Need(map != null && map.Count == keys.Length);
            foreach (DictionaryEntry e in map)
            {
                Need(e.Key is string && e.Value is string); bool found = false;
                foreach (string key in keys) if (String.Equals(key, (string)e.Key, StringComparison.Ordinal)) { found = true; break; }
                Need(found);
            }
            EnvironmentBlock(map); return true;
        }

        sealed class TokenState
        {
            internal string User, Primary; internal int Session, Type;
            internal Dictionary<string, uint> Groups = new Dictionary<string, uint>(StringComparer.Ordinal);
            internal List<LUID_AND_ATTRIBUTES> Privileges = new List<LUID_AND_ATTRIBUTES>();
            internal byte[] Dacl; internal int RestrictingCount;
        }
        static IntPtr Information(IntPtr token, int kind, out int size)
        {
            size = 0; bool first = GetTokenInformation(token, kind, IntPtr.Zero, 0, out size);
            Need(!first && Marshal.GetLastWin32Error() == 122 && size > 0 && size <= 1048576);
            IntPtr memory = Marshal.AllocHGlobal(size);
            try { int written; Check(GetTokenInformation(token, kind, memory, size, out written)); Need(written > 0 && written <= size); return memory; }
            catch { Marshal.FreeHGlobal(memory); throw; }
        }
        static byte[] DefaultDacl(IntPtr token)
        {
            int size; IntPtr memory = Information(token, 6, out size);
            try
            {
                Need(size >= IntPtr.Size); IntPtr acl = Marshal.ReadIntPtr(memory);
                if (acl == IntPtr.Zero) return null;
                long offset = acl.ToInt64() - memory.ToInt64(); Need(offset >= 0 && offset <= size - 8);
                int length = (ushort)Marshal.ReadInt16(acl, 2); Need(length >= 8 && length <= size - offset);
                byte[] bytes = new byte[length]; Marshal.Copy(acl, bytes, 0, length); new RawAcl(bytes, 0); return bytes;
            }
            finally { Marshal.FreeHGlobal(memory); }
        }
        static int Integer(IntPtr token, int kind)
        {
            int size; IntPtr memory = Information(token, kind, out size);
            try { Need(size >= 4); return Marshal.ReadInt32(memory); } finally { Marshal.FreeHGlobal(memory); }
        }
        static TokenState Snapshot(IntPtr token)
        {
            TokenState s = new TokenState(); int size; IntPtr memory = Information(token, 1, out size);
            try { Need(size >= Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES))); s.User = new SecurityIdentifier(Marshal.ReadIntPtr(memory)).Value; }
            finally { Marshal.FreeHGlobal(memory); }
            memory = Information(token, 5, out size);
            try { Need(size >= IntPtr.Size); s.Primary = new SecurityIdentifier(Marshal.ReadIntPtr(memory)).Value; }
            finally { Marshal.FreeHGlobal(memory); }
            memory = Information(token, 2, out size);
            try
            {
                int count = Marshal.ReadInt32(memory), offset = (int)Marshal.OffsetOf(typeof(TOKEN_GROUPS_ONE), "First");
                int stride = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES)); Need(count >= 0 && count <= 4096 && offset + (long)stride * count <= size);
                for (int i = 0; i < count; i++) { var g = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(IntPtr.Add(memory, offset + i * stride), typeof(SID_AND_ATTRIBUTES)); s.Groups.Add(new SecurityIdentifier(g.Sid).Value, g.Attributes); }
            }
            finally { Marshal.FreeHGlobal(memory); }
            memory = Information(token, 3, out size);
            try
            {
                int count = Marshal.ReadInt32(memory), offset = (int)Marshal.OffsetOf(typeof(TOKEN_PRIVILEGES_ONE), "First");
                int stride = Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)); Need(count >= 0 && count <= 4096 && offset + (long)stride * count <= size);
                for (int i = 0; i < count; i++) s.Privileges.Add((LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(IntPtr.Add(memory, offset + i * stride), typeof(LUID_AND_ATTRIBUTES)));
            }
            finally { Marshal.FreeHGlobal(memory); }
            memory = Information(token, 11, out size);
            try { Need(size >= 4); s.RestrictingCount = Marshal.ReadInt32(memory); } finally { Marshal.FreeHGlobal(memory); }
            s.Type = Integer(token, 8); s.Session = Integer(token, 12); s.Dacl = DefaultDacl(token); return s;
        }
        static bool EqualBytes(byte[] a, byte[] b)
        {
            if (a == null || b == null) return a == b; if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false; return true;
        }
        static void RestrictedPolicy(TokenState current, TokenState original, byte[] expectedDacl)
        {
            Need(current.Type == 1 && current.User == original.User && current.Primary == original.Primary &&
                current.Session == original.Session && current.RestrictingCount == 0 && current.Groups.Count == original.Groups.Count);
            foreach (var group in original.Groups)
            {
                uint flags; Need(current.Groups.TryGetValue(group.Key, out flags));
                if (group.Key == Administrators || group.Key == PowerUsers) Need((flags & 0x10) != 0 && (flags & 3) == 0);
                else Need(flags == group.Value);
            }
            LUID change; Check(LookupPrivilegeValueW(null, "SeChangeNotifyPrivilege", out change));
            foreach (var privilege in current.Privileges) Need(privilege.Luid.Low == change.Low && privilege.Luid.High == change.High);
            Need(current.Privileges.Count <= 1 && EqualBytes(current.Dacl, expectedDacl));
            RawAcl acl = new RawAcl(current.Dacl, 0); bool userGrant = false;
            foreach (GenericAce ace in acl)
            {
                CommonAce common = ace as CommonAce;
                if (common != null && common.SecurityIdentifier.Value == original.User && common.AceQualifier == AceQualifier.AccessAllowed &&
                    (common.AccessMask & 0x10000000) != 0 && (common.AceFlags & AceFlags.InheritOnly) == 0) userGrant = true;
            }
            Need(userGrant);
        }
        static byte[] AddUserDefaultDacl(IntPtr restricted, TokenState original)
        {
            RawAcl old = original.Dacl == null ? null : new RawAcl(original.Dacl, 0);
            RawAcl acl = new RawAcl(old == null ? (byte)2 : old.Revision, (old == null ? 0 : old.Count) + 1);
            if (old != null) foreach (GenericAce ace in old) acl.InsertAce(acl.Count, ace);
            // New restricted token only: retain existing ACEs; append the PG user grant.
            acl.InsertAce(acl.Count, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed, 0x10000000,
                new SecurityIdentifier(original.User), false, null));
            byte[] bytes = new byte[acl.BinaryLength]; acl.GetBinaryForm(bytes, 0);
            IntPtr memory = Marshal.AllocHGlobal(IntPtr.Size + bytes.Length);
            try
            {
                IntPtr pointer = IntPtr.Add(memory, IntPtr.Size); Marshal.Copy(bytes, 0, pointer, bytes.Length); Marshal.WriteIntPtr(memory, pointer);
                Check(SetTokenInformation(restricted, 6, memory, IntPtr.Size));
            }
            finally { Marshal.FreeHGlobal(memory); }
            return bytes;
        }
        static IntPtr Sid(string value)
        {
            SecurityIdentifier sid = new SecurityIdentifier(value); byte[] bytes = new byte[sid.BinaryLength]; sid.GetBinaryForm(bytes, 0);
            IntPtr memory = Marshal.AllocHGlobal(bytes.Length); Marshal.Copy(bytes, 0, memory, bytes.Length); return memory;
        }

        sealed class Worker
        {
            readonly object gate = new object(); readonly bool writing; readonly int cap; readonly byte[] input;
            IntPtr pipe, threadHandle; bool stopping;
            internal readonly Thread Thread; internal bool Started;
            internal bool Eof, Overflow, Failed, InputComplete, EofSent, HandlesClosed; internal long Bytes;
            internal Worker(IntPtr pipe, int cap, byte[] input, bool writing)
            { this.pipe = pipe; this.cap = cap; this.input = input; this.writing = writing; Thread = new Thread(Work); Thread.IsBackground = true; }
            internal void Start()
            {
                try { Thread.Start(); Started = true; }
                catch { lock (gate) { Failed = true; Close(ref pipe); if (input != null) Array.Clear(input, 0, input.Length); } throw; }
            }
            internal bool IsOverflow { get { lock (gate) return Overflow; } }
            internal bool IsFailed { get { lock (gate) return Failed; } }
            void Work()
            {
                GCHandle pinned = new GCHandle(); byte[] readBuffer = null;
                try
                {
                    lock (gate) Check(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), out threadHandle, 0, false, 2));
                    if (writing) pinned = GCHandle.Alloc(input, GCHandleType.Pinned); else readBuffer = new byte[4096];
                    int position = 0;
                    while (true)
                    {
                        lock (gate) if (stopping) return;
                        uint count;
                        if (writing)
                        {
                            if (position == input.Length) { lock (gate) InputComplete = true; return; }
                            int length = Math.Min(4096, input.Length - position);
                            if (!WriteFile(pipe, IntPtr.Add(pinned.AddrOfPinnedObject(), position), (uint)length, out count, IntPtr.Zero))
                            { lock (gate) Failed = true; return; }
                            Need(count > 0 && count <= length); position += (int)count;
                        }
                        else
                        {
                            if (!ReadFile(pipe, readBuffer, (uint)readBuffer.Length, out count, IntPtr.Zero))
                            { lock (gate) { if (Marshal.GetLastWin32Error() == 109) Eof = true; else Failed = true; } return; }
                            if (count == 0) { lock (gate) Eof = true; return; }
                        }
                        lock (gate) { Bytes = Math.Min(Int64.MaxValue - count, Bytes) + count; if (!writing && Bytes > cap) Overflow = true; }
                    }
                }
                catch { lock (gate) Failed = true; }
                finally
                {
                    if (pinned.IsAllocated) pinned.Free();
                    if (input != null) Array.Clear(input, 0, input.Length);
                    if (readBuffer != null) Array.Clear(readBuffer, 0, readBuffer.Length);
                    lock (gate) { bool closed = Close(ref pipe); if (!closed) Failed = true; if (writing) EofSent = closed; HandlesClosed = Close(ref threadHandle) && closed; if (!HandlesClosed) Failed = true; }
                }
            }
            internal void Cancel()
            {
                lock (gate) { stopping = true; if (threadHandle != IntPtr.Zero) CancelSynchronousIo(threadHandle); }
            }
            internal void Copy(RestrictedResult result, int which)
            {
                lock (gate)
                {
                    if (which == 0) { result.stdinBytesWritten = Bytes; result.stdinComplete = InputComplete && EofSent && !Failed; result.stdinEofSent = EofSent; }
                    if (which == 1) result.stdoutBytesObserved = Bytes;
                    if (which == 2) result.stderrBytesObserved = Bytes;
                    result.overflow |= Overflow;
                }
            }
            internal bool Stopped { get { return Started && !Thread.IsAlive; } }
            internal bool WriterCollected { get { lock (gate) return Stopped && HandlesClosed; } }
            internal bool ReaderComplete { get { lock (gate) return Stopped && Eof && !Failed; } }
        }
        static bool Empty(IntPtr job)
        {
            ACCOUNTING info; Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(ACCOUNTING)), IntPtr.Zero));
            return info.ActiveProcesses == 0;
        }
        public static RestrictedResult Run(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, string ownedRoot, byte[] privateStdin, int timeoutMilliseconds,
            int cleanupMilliseconds, int maxOutputBytesPerStream)
        {
            int ignored; return Core(executable, arguments, workingDirectory, environment, ownedRoot, privateStdin,
                timeoutMilliseconds, cleanupMilliseconds, maxOutputBytesPerStream, ProbeFault.None, 0, out ignored);
        }
        // Explicit deterministic test seam; normal Run cannot enable it via environment.
        public static RestrictedResult RunForProbe(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, string ownedRoot, byte[] privateStdin, int timeoutMilliseconds,
            int cleanupMilliseconds, int maxOutputBytesPerStream, ProbeFault fault, int preResumeDelayMilliseconds, out int resumeAttempts)
        {
            if (!Enum.IsDefined(typeof(ProbeFault), fault) || preResumeDelayMilliseconds < 0 || preResumeDelayMilliseconds > 1000) throw new ArgumentOutOfRangeException();
            return Core(executable, arguments, workingDirectory, environment, ownedRoot, privateStdin,
                timeoutMilliseconds, cleanupMilliseconds, maxOutputBytesPerStream, fault, preResumeDelayMilliseconds, out resumeAttempts);
        }
        static RestrictedResult Core(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, string ownedRoot, byte[] privateStdin, int timeoutMilliseconds,
            int cleanupMilliseconds, int maxOutputBytesPerStream, ProbeFault fault, int delay, out int resumeAttempts)
        {
            resumeAttempts = 0;
            if (privateStdin == null || privateStdin.Length > 65536 || timeoutMilliseconds < 1 || timeoutMilliseconds > 360000 ||
                cleanupMilliseconds < 1 || cleanupMilliseconds > 10000 || maxOutputBytesPerStream < 0 || maxOutputBytesPerStream > 65536)
                throw new ArgumentOutOfRangeException();
            Absolute(executable); Root(ownedRoot, workingDirectory); NoReparse(Path.GetDirectoryName(executable));
            Need((File.GetAttributes(executable) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) == 0);
            string block = EnvironmentBlock(environment); ElevenStringPrefix(environment);
            StringBuilder command = new StringBuilder(Quote(executable)); if (arguments != null) foreach (string arg in arguments) command.Append(' ').Append(Quote(arg));
            if (command.Length >= 32767) throw new ArgumentException("Command line too long.");
            byte[] inputCopy = (byte[])privateStdin.Clone(); RestrictedResult result = new RestrictedResult();
            IntPtr caller = IntPtr.Zero, restricted = IntPtr.Zero, actual = IntPtr.Zero, ba = IntPtr.Zero, pu = IntPtr.Zero;
            IntPtr job = IntPtr.Zero, inputRead = IntPtr.Zero, inputWrite = IntPtr.Zero, outputRead = IntPtr.Zero, outputWrite = IntPtr.Zero, errorRead = IntPtr.Zero, errorWrite = IntPtr.Zero;
            IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero, jobs = IntPtr.Zero, env = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION(); Worker writer = null, stdout = null, stderr = null;
            TokenState original = null; bool assigned = false, exited = false, cleanupOk = true, initialized = false; FileStream executableGuard = null;
            FailureStage stage = FailureStage.Token; Stopwatch execution = Stopwatch.StartNew();
            try
            {
                executableGuard = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
                Check(OpenProcessToken(GetCurrentProcess(), Query | Duplicate | AssignPrimary | AdjustDefault, out caller));
                original = Snapshot(caller); Need(original.Type == 1 && original.RestrictingCount == 0);
                ba = Sid(Administrators); pu = Sid(PowerUsers);
                SID_AND_ATTRIBUTES[] disabled = { new SID_AND_ATTRIBUTES { Sid = ba }, new SID_AND_ATTRIBUTES { Sid = pu } };
                Check(CreateRestrictedToken(caller, 1, 2, disabled, 0, IntPtr.Zero, 0, IntPtr.Zero, out restricted));
                byte[] expectedDacl = AddUserDefaultDacl(restricted, original);
                RestrictedPolicy(Snapshot(restricted), original, expectedDacl);
                stage = FailureStage.Setup; job = CreateJobObjectW(IntPtr.Zero, null); Check(job != IntPtr.Zero);
                JOB_LIMITS limits = new JOB_LIMITS(); limits.Basic.LimitFlags = 0x2000;
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(JOB_LIMITS))));
                SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES { Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), Inherit = true };
                Check(CreatePipe(out inputRead, out inputWrite, ref security, 4096)); Check(SetHandleInformation(inputWrite, 1, 0));
                Check(CreatePipe(out outputRead, out outputWrite, ref security, 4096)); Check(SetHandleInformation(outputRead, 1, 0));
                Check(CreatePipe(out errorRead, out errorWrite, ref security, 4096)); Check(SetHandleInformation(errorRead, 1, 0));
                IntPtr size = IntPtr.Zero; InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size); Need(size != IntPtr.Zero);
                attributes = Marshal.AllocHGlobal(size); Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size)); initialized = true;
                handles = Marshal.AllocHGlobal(3 * IntPtr.Size); Marshal.WriteIntPtr(handles, inputRead); Marshal.WriteIntPtr(handles, IntPtr.Size, outputWrite); Marshal.WriteIntPtr(handles, 2 * IntPtr.Size, errorWrite);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handles, new IntPtr(3 * IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
                jobs = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobs, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000d), jobs, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
                STARTUPINFOEX startup = new STARTUPINFOEX(); startup.StartupInfo.Size = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startup.StartupInfo.Flags = 0x100; startup.StartupInfo.Input = inputRead; startup.StartupInfo.Output = outputWrite; startup.StartupInfo.Error = errorWrite; startup.Attributes = attributes;
                env = Marshal.StringToHGlobalUni(block);
                Check(CreateProcessAsUserW(restricted, executable, command, IntPtr.Zero, IntPtr.Zero, true, 4 | 0x08000000 | 0x80000 | 0x400, env, workingDirectory, ref startup, out process));
                assigned = true;
                Check(Close(ref inputRead)); Check(Close(ref outputWrite)); Check(Close(ref errorWrite));
                stage = FailureStage.Verify;
                bool member; Check(IsProcessInJob(process.Process, job, out member)); Need(member);
                Check(OpenProcessToken(process.Process, Query, out actual)); RestrictedPolicy(Snapshot(actual), original, expectedDacl);
                result.tokenVerifiedBeforeResume = result.defaultDaclVerifiedBeforeResume = true;
                if (fault == ProbeFault.RejectBeforeResume) { result.tokenVerifiedBeforeResume = false; result.failureCategory = FailureCategory.ProbeFault; throw new InvalidOperationException("Probe"); }
                stdout = new Worker(outputRead, maxOutputBytesPerStream, null, false); outputRead = IntPtr.Zero; stdout.Start();
                stderr = new Worker(errorRead, maxOutputBytesPerStream, null, false); errorRead = IntPtr.Zero; stderr.Start();
                if (delay != 0) Thread.Sleep(delay);
                if (Remaining(execution, timeoutMilliseconds) == 0) result.timeout = true;
                else
                {
                    stage = FailureStage.Resume; resumeAttempts++; uint previousSuspendCount = ResumeThread(process.Thread);
                    Check(previousSuspendCount != Infinite); Need(previousSuspendCount == 1);
                    writer = new Worker(inputWrite, 0, inputCopy, true); inputWrite = IntPtr.Zero; writer.Start();
                    stage = FailureStage.Observe;
                    while (true)
                    {
                        if (Remaining(execution, timeoutMilliseconds) == 0) { result.timeout = true; break; }
                        if (stdout.IsOverflow || stderr.IsOverflow || stdout.IsFailed || stderr.IsFailed || writer.IsFailed) break;
                        uint wait = WaitForSingleObject(process.Process, 0); Check(wait != Infinite); exited = wait == 0;
                        if (exited && Empty(job)) { if (Remaining(execution, timeoutMilliseconds) == 0) result.timeout = true; break; }
                        Thread.Sleep(Math.Min(10, Remaining(execution, timeoutMilliseconds)));
                    }
                }
            }
            catch (Exception error)
            {
                result.failureStage = stage;
                Win32Exception native = error as Win32Exception;
                if (native != null) { result.failureCategory = FailureCategory.Native; result.nativeError = native.NativeErrorCode; }
                else if (result.failureCategory == FailureCategory.None) result.failureCategory = FailureCategory.Policy;
            }
            finally
            {
                Stopwatch cleanup = Stopwatch.StartNew();
                if (process.Process != IntPtr.Zero)
                {
                    try
                    {
                        if (assigned) { if (!Empty(job)) Check(TerminateJobObject(job, 1)); }
                        else Check(TerminateProcess(process.Process, 1));
                        exited = WaitForSingleObject(process.Process, (uint)Remaining(cleanup, cleanupMilliseconds)) == 0;
                        if (exited) { uint code; Check(GetExitCodeProcess(process.Process, out code)); result.exitCode = unchecked((int)code); }
                        if (assigned) do { result.JobEmpty = Empty(job); if (result.JobEmpty) break; Thread.Sleep(Math.Min(10, Remaining(cleanup, cleanupMilliseconds))); } while (Remaining(cleanup, cleanupMilliseconds) > 0);
                    }
                    catch { cleanupOk = false; }
                }
                // If verification failed before drainers owned the pipes, create them
                // after termination to prove EOF; never run an unverified child.
                try
                {
                    if (assigned && stdout == null && outputRead != IntPtr.Zero) { stdout = new Worker(outputRead, maxOutputBytesPerStream, null, false); outputRead = IntPtr.Zero; stdout.Start(); }
                    if (assigned && stderr == null && errorRead != IntPtr.Zero) { stderr = new Worker(errorRead, maxOutputBytesPerStream, null, false); errorRead = IntPtr.Zero; stderr.Start(); }
                }
                catch { cleanupOk = false; }
                Worker[] workers = { writer, stdout, stderr };
                foreach (Worker w in workers) if (w != null && w.Started) w.Thread.Join(Remaining(cleanup, cleanupMilliseconds) / 2);
                foreach (Worker w in workers) if (w != null && w.Started && w.Thread.IsAlive) w.Cancel();
                foreach (Worker w in workers) if (w != null && w.Started) w.Thread.Join(Remaining(cleanup, cleanupMilliseconds));
                if (writer == null || !writer.Started) Array.Clear(inputCopy, 0, inputCopy.Length);
                if (writer != null) writer.Copy(result, 0); if (stdout != null) stdout.Copy(result, 1); if (stderr != null) stderr.Copy(result, 2);
                try
                {
                    if (caller != IntPtr.Zero && original != null)
                    {
                        TokenState after = Snapshot(caller);
                        Need(after.Type == original.Type && after.RestrictingCount == original.RestrictingCount &&
                            after.User == original.User && after.Primary == original.Primary && after.Session == original.Session &&
                            after.Groups.Count == original.Groups.Count && after.Privileges.Count == original.Privileges.Count && EqualBytes(after.Dacl, original.Dacl));
                        foreach (var g in original.Groups) Need(after.Groups.ContainsKey(g.Key) && after.Groups[g.Key] == g.Value);
                        for (int i = 0; i < after.Privileges.Count; i++) Need(after.Privileges[i].Luid.Low == original.Privileges[i].Luid.Low &&
                            after.Privileges[i].Luid.High == original.Privileges[i].Luid.High && after.Privileges[i].Attributes == original.Privileges[i].Attributes);
                        result.callerTokenUnchanged = true;
                    }
                }
                catch { cleanupOk = false; }
                cleanupOk &= Close(ref job); cleanupOk &= Close(ref process.Thread); cleanupOk &= Close(ref process.Process);
                cleanupOk &= Close(ref inputRead); cleanupOk &= Close(ref inputWrite); cleanupOk &= Close(ref outputRead); cleanupOk &= Close(ref outputWrite); cleanupOk &= Close(ref errorRead); cleanupOk &= Close(ref errorWrite);
                cleanupOk &= Close(ref actual); cleanupOk &= Close(ref restricted); cleanupOk &= Close(ref caller);
                if (ba != IntPtr.Zero) Marshal.FreeHGlobal(ba); if (pu != IntPtr.Zero) Marshal.FreeHGlobal(pu);
                if (attributes != IntPtr.Zero) { if (initialized) DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles); if (jobs != IntPtr.Zero) Marshal.FreeHGlobal(jobs); if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
                if (executableGuard != null) try { executableGuard.Dispose(); } catch { cleanupOk = false; }
                bool writerStopped = writer == null || writer.WriterCollected;
                result.completionKnown = cleanupOk && assigned && exited && result.JobEmpty && stdout != null && stdout.ReaderComplete &&
                    stderr != null && stderr.ReaderComplete && writerStopped && result.callerTokenUnchanged;
                if (!cleanupOk && result.failureCategory == FailureCategory.None) { result.failureStage = FailureStage.Cleanup; result.failureCategory = FailureCategory.Cleanup; }
            }
            if (result.failureCategory == FailureCategory.None)
            {
                if (result.timeout) result.failureCategory = FailureCategory.Timeout;
                else if (result.overflow) result.failureCategory = FailureCategory.Overflow;
                else if (!result.stdinComplete) result.failureCategory = FailureCategory.InputIncomplete;
                else if (!result.completionKnown) result.failureCategory = FailureCategory.Worker;
                if (result.failureCategory != FailureCategory.None) result.failureStage = FailureStage.Observe;
            }
            return result;
        }

        [StructLayout(LayoutKind.Sequential)] struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_GROUPS_ONE { public uint Count; public SID_AND_ATTRIBUTES First; }
        [StructLayout(LayoutKind.Sequential)] struct LUID { public uint Low; public int High; }
        [StructLayout(LayoutKind.Sequential)] struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct TOKEN_PRIVILEGES_ONE { public uint Count; public LUID_AND_ATTRIBUTES First; }
        [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
        [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO { public int Size; public IntPtr Reserved, Desktop, Title; public uint X,Y,XSize,YSize,XChars,YChars,Fill,Flags; public short Show,ReservedSize; public IntPtr ReservedBytes,Input,Output,Error; }
        [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr Process,Thread; public uint ProcessId,ThreadId; }
        [StructLayout(LayoutKind.Sequential)] struct BASIC_LIMITS { public long ProcessTime,JobTime; public uint LimitFlags; public UIntPtr MinWorkingSet,MaxWorkingSet; public uint ActiveLimit; public UIntPtr Affinity; public uint Priority,Scheduling; }
        [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong ReadOps,WriteOps,OtherOps,ReadBytes,WriteBytes,OtherBytes; }
        [StructLayout(LayoutKind.Sequential)] struct JOB_LIMITS { public BASIC_LIMITS Basic; public IO_COUNTERS Io; public UIntPtr ProcessMemory,JobMemory,PeakProcessMemory,PeakJobMemory; }
        [StructLayout(LayoutKind.Sequential)] struct ACCOUNTING { public long User,Kernel,PeriodUser,PeriodKernel; public uint Faults,Processes,ActiveProcesses,Terminated; }
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr data,int length,out int needed);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool SetTokenInformation(IntPtr token,int kind,IntPtr data,int length);
        [DllImport("advapi32.dll", SetLastError=true)] static extern bool CreateRestrictedToken(IntPtr token,uint flags,uint disabledCount,[In] SID_AND_ATTRIBUTES[] disabled,uint deletedCount,IntPtr deleted,uint restrictingCount,IntPtr restricting,out IntPtr result);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValueW(string system,string name,out LUID luid);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessAsUserW(IntPtr token,string executable,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,bool inherit,uint flags,IntPtr environment,string directory,ref STARTUPINFOEX startup,out PROCESS_INFORMATION process);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool DuplicateHandle(IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,uint access,bool inherit,uint options);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SECURITY_ATTRIBUTES security,uint size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool ReadFile(IntPtr file,byte[] data,uint length,out uint read,IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool WriteFile(IntPtr file,IntPtr data,uint length,out uint written,IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool CancelSynchronousIo(IntPtr thread);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr security,string name);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job,int kind,ref JOB_LIMITS limits,uint length);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job,int kind,out ACCOUNTING result,uint length,IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsProcessInJob(IntPtr process,IntPtr job,[MarshalAs(UnmanagedType.Bool)] out bool result);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process,uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list,int count,uint flags,ref IntPtr size);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list,uint flags,IntPtr kind,IntPtr value,IntPtr size,IntPtr previous,IntPtr returned);
    }
}
