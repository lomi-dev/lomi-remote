# Read-only snapshots and retained no-delete-share handles for exact cleanup.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class LomiLoginFileIdentity {
 [StructLayout(LayoutKind.Sequential)] struct Info {
  public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
  public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
 }
 [StructLayout(LayoutKind.Sequential)] struct Disposition { public uint DeleteFile; }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
 static extern SafeFileHandle CreateFileW(string path,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle file,out Info info);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle file,StringBuilder path,uint count,uint flags);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle file,int kind,ref Disposition value,uint size);
 public sealed class Identity { public string volume, fileId, finalPath; public uint links; }
 static Identity Identify(SafeFileHandle file,string path) {
  Info info;if(!GetFileInformationByHandle(file,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
  if((info.Attributes&0x400)!=0||info.Links!=1) throw new Exception("reparse or hardlinked identity");
  var final=new StringBuilder(32768);uint length=GetFinalPathNameByHandleW(file,final,32768,0);
  if(length==0||length>=32768) throw new Win32Exception(Marshal.GetLastWin32Error());
  string value=final.ToString();if(value.StartsWith(@"\\?\")) value=value.Substring(4);
  if(!String.Equals(Path.GetFullPath(path),value,StringComparison.OrdinalIgnoreCase)) throw new Exception("redirected file ancestry");
  return new Identity{volume=info.Volume.ToString(),fileId=(((ulong)info.IndexHigh<<32)|info.IndexLow).ToString(),finalPath=value,links=info.Links};
 }
 public sealed class Pin : IDisposable {
  readonly SafeFileHandle handle;readonly string path;readonly bool canDelete;
  public Identity Identity { get { return Identify(handle,path); } }
  public Pin(string value,bool deletion,bool leaf) {
   path=value;canDelete=deletion;
   // Directory handles deny rename/delete; leaves also deny concurrent writes.
   uint access=0x80U|(deletion?0x10000U:0U)|(leaf?0x80000000U:0U);
   handle=CreateFileW(path,access,leaf?1U:3U,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
   if(handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
   try{Identify(handle,path);}catch{handle.Dispose();throw;}
  }
  public string Sha256() {
   // Non-owning wrapper: closing the stream keeps the authoritative pin open.
   using(var wrapper=new SafeFileHandle(handle.DangerousGetHandle(),false))
   using(var stream=new FileStream(wrapper,FileAccess.Read))
   using(var hash=SHA256.Create()) {stream.Position=0;return BitConverter.ToString(hash.ComputeHash(stream)).Replace("-","").ToLowerInvariant();}
  }
  public void Delete() {
   if(!canDelete) throw new Exception("non-deleting ancestor pin");
   Identify(handle,path);var disposition=new Disposition{DeleteFile=1};
   if(!SetFileInformationByHandle(handle,4,ref disposition,4)) throw new Win32Exception(Marshal.GetLastWin32Error());
   Dispose();
  }
  public void Dispose(){handle.Dispose();}
 }
 public static Identity Read(string path){using(var pin=new Pin(path,false,false)){return pin.Identity;}}
 public static Pin Hold(string path,bool deletion,bool leaf){return new Pin(path,deletion,leaf);}
}
'@
