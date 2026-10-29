using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Lomi
{
    public sealed class OwnedResult
    {
        public int? exitCode { get; internal set; }
        public bool timeout { get; internal set; }
        public bool overflow { get; internal set; }
        public bool completionKnown { get; internal set; }
        public bool JobEmpty { get; internal set; }
        public string stdoutBase64 { get; internal set; }
        public string stderrBase64 { get; internal set; }
    }

    public static class WindowsOwnedRunner
    {
        const uint INFINITE = 0xffffffff, WAIT_OBJECT_0 = 0;
        const uint CREATE_SUSPENDED = 4, CREATE_NO_WINDOW = 0x08000000;
        const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000, CREATE_UNICODE_ENVIRONMENT = 0x400;
        const uint STARTF_USESTDHANDLES = 0x100, KILL_ON_JOB_CLOSE = 0x2000;
        static readonly IntPtr Invalid = new IntPtr(-1);

        static void Check(bool ok) { if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()); }
        static void Close(ref IntPtr h) { if (h != IntPtr.Zero && h != Invalid) CloseHandle(h); h = IntPtr.Zero; }
        static void Absolute(string path)
        {
            if (String.IsNullOrEmpty(path) || path.IndexOf('\0') >= 0 ||
                !Path.IsPathRooted(path) || !String.Equals(Path.GetFullPath(path), path, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("A normalized absolute path is required.");
        }
        // CommandLineToArgvW / CRT quoting, including empty arguments and trailing backslashes.
        static string Quote(string value)
        {
            if (value == null || value.IndexOf('\0') >= 0) throw new ArgumentException("Invalid argument.");
            StringBuilder s = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value)
            {
                if (c == '\\') { slashes++; continue; }
                s.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); slashes = 0; s.Append(c);
            }
            s.Append('\\', slashes * 2); return s.Append('"').ToString();
        }
        static string EnvironmentBlock(IDictionary source)
        {
            if (source == null) throw new ArgumentNullException("environment");
            SortedDictionary<string, string> entries = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (DictionaryEntry entry in source)
            {
                string key = entry.Key as string, value = entry.Value as string;
                if (String.IsNullOrEmpty(key) || key.IndexOfAny(new char[] { '=', '\0' }) >= 0 ||
                    value == null || value.IndexOf('\0') >= 0 || entries.ContainsKey(key))
                    throw new ArgumentException("Invalid or duplicate environment entry.");
                entries.Add(key, value);
            }
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> entry in entries) block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
            if (entries.Count == 0) block.Append('\0');
            return block.Append('\0').ToString();
        }

        // Each reader owns its pipe until its background thread has stopped. CancelSynchronousIo
        // uses a retained duplicate of that thread's handle, never a thread/process ID lookup.
        sealed class Capture
        {
            readonly object gate = new object(); readonly MemoryStream bytes = new MemoryStream();
            readonly int limit; IntPtr pipe, threadHandle; bool stopping;
            internal bool Eof, Overflow; internal readonly Thread Thread; internal bool Started;
            internal bool HasOverflow { get { lock (gate) return Overflow; } }
            internal Capture(IntPtr handle, int max)
            { pipe = handle; limit = max; Thread = new Thread(Read); Thread.IsBackground = true; }
            internal void Start()
            {
                try { Thread.Start(); Started = true; }
                catch { lock (gate) Close(ref pipe); throw; }
            }
            void Read()
            {
                try
                {
                    lock (gate)
                    {
                        Check(DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), out threadHandle, 0, false, 2));
                    }
                    byte[] buffer = new byte[8192];
                    while (true)
                    {
                        lock (gate) { if (stopping) return; }
                        uint count;
                        bool ok = ReadFile(pipe, buffer, (uint)buffer.Length, out count, IntPtr.Zero);
                        if (!ok)
                        {
                            if (Marshal.GetLastWin32Error() == 109) { lock (gate) Eof = true; }
                            return;
                        }
                        if (count == 0) { lock (gate) Eof = true; return; }
                        lock (gate)
                        {
                            int keep = Math.Min((int)count, limit - (int)bytes.Length);
                            bytes.Write(buffer, 0, keep);
                            if (keep != count) Overflow = true; // Continue draining and discard the excess.
                        }
                    }
                }
                catch { /* A failed reader prevents completionKnown. */ }
                finally { lock (gate) { Close(ref pipe); Close(ref threadHandle); } }
            }
            internal void Cancel()
            {
                lock (gate)
                {
                    stopping = true;
                    if (threadHandle != IntPtr.Zero) CancelSynchronousIo(threadHandle);
                    // A read can begin just after cancellation. The owner also closes the Job;
                    // if EOF cannot be confirmed within the deadline the result stays uncertain.
                }
            }
            internal void Snapshot(out string encoded, out bool overflow, out bool eof)
            { lock (gate) { encoded = Convert.ToBase64String(bytes.ToArray()); overflow = Overflow; eof = Eof; } }
        }

        static int Remaining(Stopwatch clock, int duration)
        { return (int)Math.Max(0L, duration - clock.ElapsedMilliseconds); }
        static bool Empty(IntPtr job)
        {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
            Check(QueryInformationJobObject(job, 1, out info, (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero));
            return info.ActiveProcesses == 0;
        }

        public static OwnedResult Run(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, int timeoutMilliseconds, int cleanupMilliseconds, int captureBytesPerStream)
        {
            int ignoredResumeAttempts;
            return RunCore(executable, arguments, workingDirectory, environment, timeoutMilliseconds,
                cleanupMilliseconds, captureBytesPerStream, 0, out ignoredResumeAttempts);
        }

        // Explicit test-only entry point. Production Run always supplies zero delay;
        // no environment variable or operator configuration can enable this seam.
        public static OwnedResult RunWithPreResumeDelayForProbe(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, int timeoutMilliseconds, int cleanupMilliseconds, int captureBytesPerStream, int delayMilliseconds,
            out int resumeAttempts)
        {
            if (delayMilliseconds < 0 || delayMilliseconds > 1000) throw new ArgumentOutOfRangeException("delayMilliseconds");
            return RunCore(executable, arguments, workingDirectory, environment, timeoutMilliseconds,
                cleanupMilliseconds, captureBytesPerStream, delayMilliseconds, out resumeAttempts);
        }

        static OwnedResult RunCore(string executable, string[] arguments, string workingDirectory,
            IDictionary environment, int timeoutMilliseconds, int cleanupMilliseconds, int captureBytesPerStream, int preResumeDelayMilliseconds,
            out int resumeAttempts)
        {
            resumeAttempts = 0;
            Absolute(executable); Absolute(workingDirectory);
            if (timeoutMilliseconds < 1 || timeoutMilliseconds > 86400000 || cleanupMilliseconds < 1 || cleanupMilliseconds > 60000 ||
                captureBytesPerStream < 0 || captureBytesPerStream > 16777216) throw new ArgumentOutOfRangeException();
            StringBuilder command = new StringBuilder(Quote(executable));
            if (arguments != null) foreach (string argument in arguments) command.Append(' ').Append(Quote(argument));
            if (command.Length >= 32767) throw new ArgumentException("Command line is too long.");
            string block = EnvironmentBlock(environment);
            OwnedResult result = new OwnedResult { stdoutBase64 = "", stderrBase64 = "" };
            IntPtr job = IntPtr.Zero, outputRead = IntPtr.Zero, outputWrite = IntPtr.Zero;
            IntPtr errorRead = IntPtr.Zero, errorWrite = IntPtr.Zero, input = IntPtr.Zero;
            IntPtr attributes = IntPtr.Zero, handles = IntPtr.Zero, jobList = IntPtr.Zero, env = IntPtr.Zero;
            PROCESS_INFORMATION process = new PROCESS_INFORMATION(); Capture stdout = null, stderr = null;
            bool assigned = false, exited = false, clean = true, attributesInitialized = false;
            Stopwatch execution = Stopwatch.StartNew();
            try
            {
                job = CreateJobObjectW(IntPtr.Zero, null); Check(job != IntPtr.Zero);
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
                limits.BasicLimitInformation.LimitFlags = KILL_ON_JOB_CLOSE;
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))));
                SECURITY_ATTRIBUTES security = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)), bInheritHandle = true };
                Check(CreatePipe(out outputRead, out outputWrite, ref security, 0));
                Check(SetHandleInformation(outputRead, 1, 0));
                Check(CreatePipe(out errorRead, out errorWrite, ref security, 0));
                Check(SetHandleInformation(errorRead, 1, 0));
                input = CreateFileW("NUL", 0x80000000, 3, ref security, 3, 0, IntPtr.Zero); Check(input != Invalid);
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                attributes = Marshal.AllocHGlobal(size);
                Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size));
                attributesInitialized = true;
                handles = Marshal.AllocHGlobal(IntPtr.Size * 3);
                Marshal.WriteIntPtr(handles, 0, input); Marshal.WriteIntPtr(handles, IntPtr.Size, outputWrite); Marshal.WriteIntPtr(handles, IntPtr.Size * 2, errorWrite);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x00020002), handles, new IntPtr(IntPtr.Size * 3), IntPtr.Zero, IntPtr.Zero));
                // PROC_THREAD_ATTRIBUTE_JOB_LIST makes membership atomic with creation.
                // Unsupported platforms fail here; there is no post-creation fallback.
                jobList = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(jobList, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x0002000d), jobList, new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero));
                STARTUPINFOEX startup = new STARTUPINFOEX(); startup.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                startup.StartupInfo.hStdInput = input; startup.StartupInfo.hStdOutput = outputWrite; startup.StartupInfo.hStdError = errorWrite;
                startup.lpAttributeList = attributes; env = Marshal.StringToHGlobalUni(block);
                Check(CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                    env, workingDirectory, ref startup, out process));
                assigned = true; // Successful native creation applied the required Job list.
                Close(ref input); Close(ref outputWrite); Close(ref errorWrite);
                bool inOwnedJob;
                Check(IsProcessInJob(process.hProcess, job, out inOwnedJob));
                Check(inOwnedJob); // Exact retained Job handle, before any child instruction runs.
                stdout = new Capture(outputRead, captureBytesPerStream); outputRead = IntPtr.Zero; stdout.Start();
                stderr = new Capture(errorRead, captureBytesPerStream); errorRead = IntPtr.Zero; stderr.Start();
                if (preResumeDelayMilliseconds != 0) Thread.Sleep(preResumeDelayMilliseconds);
                if (Remaining(execution, timeoutMilliseconds) == 0)
                {
                    result.timeout = true; // Keep the owned primary thread suspended.
                }
                else
                {
                    resumeAttempts++; // Count the actual native attempt, including a failed call.
                    Check(ResumeThread(process.hThread) != INFINITE);
                    while (true)
                    {
                        if (Remaining(execution, timeoutMilliseconds) == 0) { result.timeout = true; break; }
                        if (stdout.HasOverflow || stderr.HasOverflow) break;
                        uint wait = WaitForSingleObject(process.hProcess, 0); Check(wait != INFINITE);
                        exited = wait == WAIT_OBJECT_0;
                        if (exited && Empty(job))
                        {
                            // Native wait/query calls may themselves cross the deadline.
                            if (Remaining(execution, timeoutMilliseconds) == 0) result.timeout = true;
                            break;
                        }
                        Thread.Sleep(Math.Min(10, Remaining(execution, timeoutMilliseconds)));
                    }
                }
            }
            catch { clean = false; }
            finally
            {
                // A child is never resumed until its atomic Job membership was verified.
                // Retained-handle fallback is only for an unsuccessful native creation that
                // nevertheless returned a process handle; no numeric process IDs are used.
                if (process.hProcess != IntPtr.Zero)
                {
                    if (assigned)
                    {
                        try { if (!Empty(job)) Check(TerminateJobObject(job, 1)); } catch { clean = false; }
                    }
                    else { if (!TerminateProcess(process.hProcess, 1)) clean = false; }
                    Stopwatch cleanup = Stopwatch.StartNew();
                    exited = WaitForSingleObject(process.hProcess, (uint)Remaining(cleanup, cleanupMilliseconds)) == WAIT_OBJECT_0;
                    if (exited) { uint code; if (GetExitCodeProcess(process.hProcess, out code)) result.exitCode = unchecked((int)code); else clean = false; }
                    if (assigned)
                    {
                        try
                        {
                            do { result.JobEmpty = Empty(job); if (result.JobEmpty) break; Thread.Sleep(Math.Min(10, Remaining(cleanup, cleanupMilliseconds))); }
                            while (Remaining(cleanup, cleanupMilliseconds) > 0);
                        }
                        catch { clean = false; }
                    }
                    if (stdout != null && stdout.Started) stdout.Thread.Join(Remaining(cleanup, cleanupMilliseconds));
                    if (stderr != null && stderr.Started) stderr.Thread.Join(Remaining(cleanup, cleanupMilliseconds));
                }
                // Closing our last Job handle kills any remaining members, but does not prove
                // their termination. JobEmpty above records only a positive native query.
                Close(ref job);
                if (stdout != null) stdout.Cancel(); if (stderr != null) stderr.Cancel();
                Close(ref process.hThread); Close(ref process.hProcess);
                Close(ref input); Close(ref outputRead); Close(ref outputWrite); Close(ref errorRead); Close(ref errorWrite);
                if (attributes != IntPtr.Zero) { if (attributesInitialized) DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
                if (handles != IntPtr.Zero) Marshal.FreeHGlobal(handles);
                if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
                if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
            }
            bool outOverflow = false, errOverflow = false, outEof = false, errEof = false; string outText = "", errText = "";
            if (stdout != null) stdout.Snapshot(out outText, out outOverflow, out outEof);
            if (stderr != null) stderr.Snapshot(out errText, out errOverflow, out errEof);
            result.stdoutBase64 = outText; result.stderrBase64 = errText; result.overflow = outOverflow || errOverflow;
            result.completionKnown = clean && assigned && exited && result.JobEmpty && outEof && errEof &&
                stdout != null && stderr != null && stdout.Started && stderr.Started && !stdout.Thread.IsAlive && !stderr.Thread.IsAlive;
            return result;
        }

        [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle; }
        [StructLayout(LayoutKind.Sequential)] struct STARTUPINFO { public int cb; public IntPtr lpReserved, lpDesktop, lpTitle; public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags; public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError; }
        [StructLayout(LayoutKind.Sequential)] struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
        [StructLayout(LayoutKind.Sequential)] struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public uint dwProcessId, dwThreadId; }
        [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_BASIC_LIMIT_INFORMATION { public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags; public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit; public UIntPtr Affinity; public uint PriorityClass, SchedulingClass; }
        [StructLayout(LayoutKind.Sequential)] struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }
        [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION { public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation; public IO_COUNTERS IoInfo; public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed; }
        [StructLayout(LayoutKind.Sequential)] struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION { public long TotalUserTime, TotalKernelTime, ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime; public uint TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses; }
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentThread();
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CancelSynchronousIo(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadFile(IntPtr file, byte[] buffer, uint size, out uint read, IntPtr overlapped);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CreatePipe(out IntPtr read, out IntPtr write, ref SECURITY_ATTRIBUTES attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(string name, uint access, uint sharing, ref SECURITY_ATTRIBUTES attributes, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint size);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool IsProcessInJob(IntPtr process, IntPtr job, [MarshalAs(UnmanagedType.Bool)] out bool inJob);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool CreateProcessW(string executable, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment, string directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION process);
    }
}
