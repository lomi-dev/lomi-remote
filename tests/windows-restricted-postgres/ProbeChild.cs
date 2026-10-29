// PREPARED_NOT_EXECUTED. Nonsecret fixed probes, no PostgreSQL or shell launch.
using System;
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
    public static class ProbeChild
    {
        static void Need(bool value) { if (!value) throw new InvalidOperationException("Probe"); }
        [StructLayout(LayoutKind.Sequential)] struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct GROUPS { public uint Count; public SID_AND_ATTRIBUTES First; }
        [StructLayout(LayoutKind.Sequential)] struct SECURITY_ATTRIBUTES { public int Length; public IntPtr Descriptor; [MarshalAs(UnmanagedType.Bool)] public bool Inherit; }
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out IntPtr token);
        [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr token,int kind,IntPtr memory,int size,out int needed);
        [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool SetFileSecurityW(string path,uint information,byte[] descriptor);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder value,uint length,uint flags);
        [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref SECURITY_ATTRIBUTES security,uint size);
        [DllImport("kernel32.dll")] static extern IntPtr GetStdHandle(int kind);
        public static bool MarkInheritable(long handle) { return SetHandleInformation(new IntPtr(handle),1,1); }
        public static bool PointsToFile(long handle,string path)
        {
            StringBuilder b=new StringBuilder(32768);uint length=GetFinalPathNameByHandleW(new IntPtr(handle),b,(uint)b.Capacity,0);
            if(length==0 || length>=b.Capacity)return false;
            string actual=b.ToString();if(actual.StartsWith(@"\\?\",StringComparison.Ordinal))actual=actual.Substring(4);
            return String.Equals(Path.GetFullPath(actual),Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase);
        }
        // Source-only negative fixture; native acceptance remains unqualified.
        // Never repair/restore this root after adding the deliberately extra ACE.
        public static void InstallCallbackAclFixture(string root)
        {
            Guid id;
            Need(!String.IsNullOrEmpty(root) && Path.IsPathRooted(root) && !root.StartsWith(@"\\",StringComparison.Ordinal) &&
                String.Equals(root,Path.GetFullPath(root),StringComparison.Ordinal) &&
                Guid.TryParseExact(Path.GetFileName(root),"D",out id) && id!=Guid.Empty);
            for(DirectoryInfo d=new DirectoryInfo(root);d!=null;d=d.Parent)Need((d.Attributes&FileAttributes.ReparsePoint)==0);
            DirectorySecurity security=Directory.GetAccessControl(root,AccessControlSections.Owner|AccessControlSections.Access);
            RawSecurityDescriptor raw=new RawSecurityDescriptor(security.GetSecurityDescriptorBinaryForm(),0);
            using(WindowsIdentity identity=WindowsIdentity.GetCurrent())
            {
                Need(identity.ImpersonationLevel==TokenImpersonationLevel.None && identity.User!=null && identity.User.Equals(raw.Owner) &&
                    (raw.ControlFlags&ControlFlags.DiscretionaryAclProtected)!=0 && raw.DiscretionaryAcl!=null && raw.DiscretionaryAcl.Count==1);
                CommonAce own=raw.DiscretionaryAcl[0] as CommonAce;
                Need(own!=null && own.AceType==AceType.AccessAllowed && !own.IsCallback &&
                    identity.User.Equals(own.SecurityIdentifier) && own.AccessMask==2032127 && (int)own.AceFlags==3);
                SecurityIdentifier other=new SecurityIdentifier("S-1-5-32-544");Need(!other.Equals(identity.User));
                RawAcl changed=new RawAcl(raw.DiscretionaryAcl.Revision,2);changed.InsertAce(0,own);
                changed.InsertAce(1,new CommonAce(AceFlags.ObjectInherit|AceFlags.ContainerInherit,
                    AceQualifier.AccessAllowed,2032127,other,true,new byte[0]));
                raw.DiscretionaryAcl=changed;
                byte[] bytes=new byte[raw.BinaryLength];raw.GetBinaryForm(bytes,0);
                if(!SetFileSecurityW(root,0x80000004,bytes))throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        static void TokenCheck()
        {
            IntPtr token;Need(OpenProcessToken(GetCurrentProcess(),8,out token));
            try
            {
                int needed;Need(!GetTokenInformation(token,2,IntPtr.Zero,0,out needed) && Marshal.GetLastWin32Error()==122 && needed>0 && needed<1048576);
                IntPtr memory=Marshal.AllocHGlobal(needed);
                try
                {
                    Need(GetTokenInformation(token,2,memory,needed,out needed));
                    int count=Marshal.ReadInt32(memory),offset=(int)Marshal.OffsetOf(typeof(GROUPS),"First"),stride=Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
                    Need(count>=0 && count<=4096 && offset+(long)count*stride<=needed);
                    for(int i=0;i<count;i++)
                    {
                        var g=(SID_AND_ATTRIBUTES)Marshal.PtrToStructure(IntPtr.Add(memory,offset+i*stride),typeof(SID_AND_ATTRIBUTES));
                        string sid=new SecurityIdentifier(g.Sid).Value;
                        if(sid=="S-1-5-32-544" || sid=="S-1-5-32-547")Need((g.Attributes&0x10)!=0 && (g.Attributes&3)==0);
                    }
                }
                finally{Marshal.FreeHGlobal(memory);}
            }
            finally{Need(CloseHandle(token));}
            // Exercise object creation with this token's new user default-DACL ACE.
            SECURITY_ATTRIBUTES security=new SECURITY_ATTRIBUTES{Length=Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)),Inherit=false};
            IntPtr read,write;Need(CreatePipe(out read,out write,ref security,4096));
            try{Need(read!=IntPtr.Zero && write!=IntPtr.Zero);}finally{Need(CloseHandle(read));Need(CloseHandle(write));}
        }
        static void Marker(string path){using(FileStream f=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){f.WriteByte(1);}}
        static void Pattern(bool empty)
        {
            using(Stream input=Console.OpenStandardInput())
            {
                byte[] buffer=new byte[997];int index=0;
                while(true)
                {
                    int n=input.Read(buffer,0,buffer.Length);if(n==0)break;
                    for(int j=0;j<n;j++){Need(!empty && index<65536 && buffer[j]==(byte)((index*37+11)&255));index++;}
                }
                Need(index==(empty?0:65536));Array.Clear(buffer,0,buffer.Length);
            }
        }
        static string Quote(string value)
        {
            Need(value.IndexOf('"')<0 && !value.EndsWith("\\",StringComparison.Ordinal));return "\""+value+"\"";
        }
        static void Denied(string path)
        {
            bool denied=false;
            try{using(FileStream f=new FileStream(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite)){} }
            catch(UnauthorizedAccessException){denied=true;}
            Need(denied);
        }
        static void Flood(Stream stream)
        {
            byte[] bytes=new byte[4096];for(int i=0;i<64;i++)stream.Write(bytes,0,bytes.Length);stream.Flush();
        }
        public static int Main(string[] args)
        {
            // No exception messages or stack traces: output is discarded, but keep
            // child diagnostics closed even if an owner later changes capture policy.
            try
            {
                Need(args.Length>=2);string mode=args[0],marker=args[1];TokenCheck();
                switch(mode)
                {
                    case "Input":Pattern(false);Marker(marker);break;
                    case "Empty":Pattern(true);Marker(marker);break;
                    case "Token":Pattern(true);Denied(args[2]);Denied(args[3]);Marker(marker);break;
                    case "Blocked":Marker(marker);Thread.Sleep(300000);break;
                    case "EarlyClose":Marker(marker);Need(CloseHandle(GetStdHandle(-10)));Thread.Sleep(300000);break;
                    case "Marker":Marker(marker);break;
                    case "Handle":
                        Need(args.Length==4 && !PointsToFile(Int64.Parse(args[2],System.Globalization.CultureInfo.InvariantCulture),args[3]));
                        Pattern(true);Marker(marker);break;
                    case "Overflow":
                        Thread output=new Thread(delegate(){try{Flood(Console.OpenStandardOutput());}catch{}});
                        Thread error=new Thread(delegate(){try{Flood(Console.OpenStandardError());}catch{}});
                        output.IsBackground=error.IsBackground=true;output.Start();error.Start();Pattern(false);output.Join();error.Join();break;
                    case "StdoutOverflow":Pattern(false);Flood(Console.OpenStandardOutput());break;
                    case "StderrOverflow":Pattern(false);Flood(Console.OpenStandardError());break;
                    case "Tree":
                        ProcessStartInfo info=new ProcessStartInfo();info.FileName=System.Reflection.Assembly.GetExecutingAssembly().Location;
                        info.Arguments=Quote("Hold")+" "+Quote(marker);info.UseShellExecute=false;info.CreateNoWindow=true;info.WorkingDirectory=Path.GetDirectoryName(marker);
                        using(Process descendant=Process.Start(info)){Need(descendant!=null);descendant.WaitForExit();}break;
                    case "Hold":
                        using(FileStream held=new FileStream(marker,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)){Thread.Sleep(300000);}break;
                    default:return 3;
                }
                return 0;
            }
            catch(Exception error)
            {
                // Fixed numeric category only. No args, paths, token or input data.
                Console.Error.Write(error is Win32Exception?"PROBE_NATIVE_FAILURE":"PROBE_CHECK_FAILURE");return 4;
            }
        }
    }
}
