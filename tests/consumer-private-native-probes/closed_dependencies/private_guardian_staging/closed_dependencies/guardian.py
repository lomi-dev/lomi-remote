"""In-process foreground PostgreSQL guardian. Import creates no native processes.

One standalone main thread owns all children and SIGCHLD; no other code may reap
these handles or replace its signal dispositions. Work is always retained here.
An UNKNOWN result never authorizes reuse, deletion, or numeric-PID recovery.
Standalone runners MUST use the context manager or call finish_owner() in their
outermost finally before returning/exiting; cleanup() is a diagnostic snapshot.
finish_owner() retains this process if owned resource cleanup remains unproven.

Raw command files are ONLY for public/schema fixtures. Do not use this raw-log
adapter for positive credential fixtures. Those need a separately admitted
private parser-worker and closed-pipe seam before integration.

Optional log_policy installs its source-admitted inherited file cap before any
child and reserves complete output pairs. No kernel log cap is claimed when
log_policy is omitted. Verified ordinary log retirement is explicitly caller-
requested after compact recording; foreground logs remain charged.
"""
from dataclasses import dataclass
from pathlib import Path
import ctypes
from contextlib import ExitStack
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import time
import uuid

DATABASES=('postgres','lomi_derivative_fixture','lomi_derivative_reference_old','lomi_derivative_reference_new')
CANCEL_SIGNALS=(signal.SIGALRM,signal.SIGINT,signal.SIGTERM,signal.SIGHUP)
class Cancelled(RuntimeError):pass
class BudgetExpired(RuntimeError):pass
class IdentityUnknown(RuntimeError):pass

class Cancellation:
    def __init__(self):self.signals=[]
    def handle(self,signum,frame=None):
        # Never raise here: Popen may have created a child without returning its
        # handle yet, and cleanup must survive repeated cancellation requests.
        if signum not in self.signals:self.signals.append(signum)
    @property
    def requested(self):return bool(self.signals)

@dataclass(frozen=True)
class Executable:
    path:Path
    sha256:str

@dataclass
class Child:
    handle:object
    name:str
    argv:tuple
    stdout:Path
    stderr:Path
    reaped:bool=False
    exit_code:object=None
    group_quiet:bool=False
    forced:bool=False
    foreground:bool=False
    evidence_fallback:bool=False
    log_token:object=None
    stdout_identity:object=None
    stderr_identity:object=None
    retired:bool=False

@dataclass(frozen=True)
class Result:
    argv:tuple
    pid:int
    returncode:object
    stdout:str
    stderr:str
    evidenceComplete:bool
    stdoutSha256:object=None
    stderrSha256:object=None

def darwin_group_inventory(raw,count,capacity,anchor_pid):
    """Pure inventory admission. libproc zero is ambiguous, never absence proof."""
    width=ctypes.sizeof(ctypes.c_int)
    if count<=0 or count>=capacity or count>len(raw) or count%width:raise IdentityUnknown('group enumeration incomplete/ambiguous')
    pids=list((ctypes.c_int*(count//width)).from_buffer_copy(raw[:count]))
    if anchor_pid not in pids or len(set(pids))!=len(pids) or any(pid<=0 for pid in pids):raise IdentityUnknown('retained anchor missing from complete group inventory')
    return pids

def signal_retained_group(backend,handle,signum,sender):
    """Only an unreaped anchor authorizes signaling; EPERM needs zombie proof."""
    backend.peek(handle)
    try:sender(handle.pid,signum)
    except ProcessLookupError:pass
    except PermissionError:
        # Darwin may reject a group signal when every member is a zombie. An
        # alive anchor, live member, lost identity or ambiguous inventory cannot
        # authorize suppression. No numeric-PID existence inference is used.
        if backend.peek(handle) is None or backend.other_live_group_members(handle):raise
        backend.peek(handle)

class Native:
    """No implicit command helpers. Group inspection uses libproc or procfs."""
    def __init__(self):self.owner=None
    def initialize(self):
        if os.name!='posix' or not hasattr(os,'WNOWAIT'):raise OSError('POSIX WNOWAIT required')
        signal.signal(signal.SIGCHLD,signal.SIG_DFL)
        self.owner=os.getpid()
    def require_owner(self):
        if self.owner!=os.getpid() or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL:raise IdentityUnknown('SIGCHLD ownership changed')
    def spawn(self,argv,*,cwd,env,stdout,stderr):
        self.require_owner()
        return subprocess.Popen(argv,cwd=cwd,env=env,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,start_new_session=True)
    def peek(self,handle):
        self.require_owner()
        if handle.returncode is not None:raise IdentityUnknown('handle already reaped')
        try:status=os.waitid(os.P_PID,handle.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
        except ChildProcessError as exc:raise IdentityUnknown('retained child ownership lost') from exc
        if status is None:return None
        if status.si_pid!=handle.pid:raise IdentityUnknown('waitid child mismatch')
        return status.si_status if status.si_code==os.CLD_EXITED else -status.si_status
    def signal_group(self,handle,signum):
        signal_retained_group(self,handle,signum,os.killpg)
    def other_live_group_members(self,handle):
        self.peek(handle)
        if sys.platform=='darwin':
            lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
            lib.proc_listpids.argtypes=(ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_int)
            lib.proc_listpids.restype=ctypes.c_int
            lib.proc_pidinfo.argtypes=(ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int)
            lib.proc_pidinfo.restype=ctypes.c_int
            size=lib.proc_listpids(2,handle.pid,None,0)
            if size<=0:raise IdentityUnknown('group size query failed/ambiguous zero')
            # Spare capacity avoids declaring a truncated membership list empty.
            capacity=max(4096,size+4096);buffer=ctypes.create_string_buffer(capacity)
            count=lib.proc_listpids(2,handle.pid,buffer,capacity)
            # A retained anchor must appear even in an otherwise zombie-only
            # group. Missing/zero inventory remains UNKNOWN until native proof.
            pids=darwin_group_inventory(buffer.raw,count,capacity,handle.pid);live=[]
            for pid in pids:
                if pid<=0 or pid==handle.pid:continue
                info=ctypes.create_string_buffer(4096);amount=lib.proc_pidinfo(pid,3,0,info,len(info))
                if amount<20:raise IdentityUnknown('group member state unproven')
                fields=(ctypes.c_uint32*5).from_buffer_copy(info.raw[:20])
                if fields[3]!=pid:raise IdentityUnknown('group member identity changed')
                if fields[1]!=5:live.append(pid) # SZOMB=5; no worker is signaled individually.
        elif sys.platform.startswith('linux'):
            live=[]
            for path in Path('/proc').iterdir():
                if not path.name.isdecimal() or int(path.name)==handle.pid:continue
                try:raw=(path/'stat').read_text()
                except FileNotFoundError:continue
                fields=raw[raw.rindex(')')+2:].split()
                if len(fields)<3:raise IdentityUnknown('group member state incomplete')
                if int(fields[2])==handle.pid and fields[0]!='Z':live.append(int(path.name))
        else:raise IdentityUnknown('no in-process group inspection on this platform')
        self.peek(handle)
        return live
    def reap(self,handle,timeout):return handle.wait(timeout=timeout)

class Guardian:
    def __init__(self,work,tools,*,started,backend=None,clock=time.monotonic,sleep=time.sleep,signals=signal,run_id=None,terminal_observer=None,_test_terminal_hook=None,log_policy=None):
        self.clock=clock;self.sleep=sleep;self.signals=signals;self.started=started
        if type(started) not in (int,float) or not started<=clock():raise ValueError('original monotonic start required')
        self.backend=backend if backend is not None else Native();self.tools=tools;self.log_policy=log_policy
        if _test_terminal_hook is not None and (isinstance(self.backend,Native) or not getattr(self.backend,'test_only',False)):raise ValueError('terminal test escape requires injected non-Native fake backend')
        self.terminal_observer=terminal_observer;self._test_terminal_hook=_test_terminal_hook
        self.qualification_expired=False;self.unqualified=False;self.evidence_errors=[];self.terminal_retention=False
        self.qualification_deadline=started+900;self.emergency_deadline=started+960
        self.cancel=Cancellation();self.children=[];self.postgres=None;self.startup_confirmed=False
        self.previous_handlers={};self.handlers_installed=False;self.cleanup_result=None;self.cleanup_started=False
        self.work=Path(work);self.run_id=run_id or str(uuid.uuid4())
        if not self.work.is_absolute() or self.work.resolve()!=self.work:raise ValueError('resolved absolute private work required')
        info=self.work.stat()
        if not self.work.is_dir() or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():raise ValueError('private owned0700 work required')
        if list(self.work.iterdir()):raise ValueError('new empty work required')
        for name in ('home','tmp','socket','logs'):(self.work/name).mkdir(mode=0o700)
        self.marker={'runId':self.run_id,'work':str(self.work),'data':str(self.work/'data'),'socket':str(self.work/'socket')}
        self.marker_path=self.work/'guardian-owned.json';self.marker_bytes=(json.dumps(self.marker,sort_keys=True)+'\n').encode()
        fd=os.open(self.marker_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'wb') as out:out.write(self.marker_bytes)
        # Registration is complete before the first spawn can be called.
        self.registered=True
        self.env=dict(PATH='/usr/bin:/bin',HOME=str(self.work/'home'),TMPDIR=str(self.work/'tmp'),LANG='C',LC_ALL='C',TZ='UTC')
        # Reserve a disk-bounded discarded sink before ANY child. Cleanup must
        # not depend on fresh evidence-file creation when disk/log writes fail.
        fd=os.open(os.devnull,os.O_WRONLY)
        if not stat.S_ISCHR(os.fstat(fd).st_mode):os.close(fd);raise ValueError('discard sink is not a character device')
        self._emergency_sink=os.fdopen(fd,'wb',buffering=0)
        if self.log_policy is not None:
            try:self.log_policy.prepare(self.work)
            except BaseException:self._emergency_sink.close();raise
    def verify_work(self):
        if not self.registered or self.marker_path.is_symlink() or self.marker_path.read_bytes()!=self.marker_bytes:raise IdentityUnknown('owned work marker changed')
        for path in (self.work,self.work/'home',self.work/'tmp',self.work/'socket',self.work/'logs'):
            info=path.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o700 or info.st_uid!=os.getuid():raise IdentityUnknown('owned private directory changed')
    def verify_pg_identity(self):
        self.verify_work()
        if self.postgres is None or self.postgres.reaped:raise IdentityUnknown('no unreaped foreground PG identity')
        self.backend.peek(self.postgres.handle)
        data=self.work/'data';pidfile=data/'postmaster.pid'
        if data.resolve()!=data or not data.is_dir() or pidfile.is_symlink():raise IdentityUnknown('owned PG data path changed')
        lines=pidfile.read_text().splitlines()
        if len(lines)<6 or lines[0]!=str(self.postgres.handle.pid) or lines[1]!=str(data) or lines[3]!='55439' or lines[4]!=str(self.work/'socket') or lines[5]!='':raise IdentityUnknown('PG PID/data/socket does not match retained foreground handle')
        return True
    def cleanup_startup_identity_grace(self):
        """At most5s for the same foreground child to publish its PID identity.

        Cancellation is ignored only for cleanup; original emergency deadline
        stays fixed. Missing, partial or wrong PID files never authorize pg_ctl.
        Even a naturally exited child plus absent PID is not a shutdown proof.
        """
        end=min(self.clock()+5,self.emergency_deadline);last='identity not published'
        while True:
            self.verify_work();self.remaining(cleanup=True)
            if self.postgres is None or self.postgres.reaped:raise IdentityUnknown('no retained startup child')
            if self.backend.peek(self.postgres.handle) is not None:raise IdentityUnknown('postmaster exited before startup cleanup identity proved')
            try:return self.verify_pg_identity()
            except (OSError,ValueError,IdentityUnknown) as exc:last=type(exc).__name__+': '+str(exc)
            if self.clock()>=end:raise IdentityUnknown('startup cleanup identity grace exhausted: '+last)
            self.sleep(min(.025,end-self.clock()))
    def install(self):
        if self.handlers_installed or self.cleanup_started:raise RuntimeError('guardian already installed or cleanup started')
        # Optional fixed policy installs inherited file limits BEFORE all children.
        if self.log_policy is not None:
            try:self.log_policy.install()
            except BaseException as exc:
                self.unqualified=True;self.evidence_errors.append(type(exc).__name__+': '+str(exc));raise
        # Standalone startup only: do not call after another owner starts children.
        self.backend.initialize()
        for sig in CANCEL_SIGNALS:
            self.previous_handlers[sig]=self.signals.getsignal(sig);self.signals.signal(sig,self.cancel.handle)
        self.handlers_installed=True
        self.signals.setitimer(self.signals.ITIMER_REAL,max(.001,self.qualification_deadline-self.clock()))
        return self
    def __enter__(self):return self.install()
    def __exit__(self,kind,value,traceback):
        self.finish_owner()
        return False
    def restore_handlers(self):
        if not self.cleanup_result or not self.cleanup_result['completed']:raise IdentityUnknown('cannot restore before proven cleanup')
        self.signals.setitimer(self.signals.ITIMER_REAL,0)
        for sig,handler in self.previous_handlers.items():self.signals.signal(sig,handler)
        self.handlers_installed=False
    def observe_qualification(self):
        if self.clock()>=self.qualification_deadline:self.qualification_expired=True
        if self.qualification_expired or self.cancel.requested or self.evidence_errors:self.unqualified=True
        return not self.unqualified
    def remaining(self,*,cleanup=False):
        self.observe_qualification()
        remaining=(self.emergency_deadline if cleanup else self.started+840)-self.clock()
        if remaining<=0:
            self.unqualified=True
            raise BudgetExpired('fixed emergency cleanup deadline exhausted' if cleanup else 'original work840 budget exhausted')
        return remaining
    def checkpoint(self,*,cleanup=False):
        value=self.remaining(cleanup=cleanup)
        if not cleanup and self.cancel.requested:raise Cancelled('cancellation latched')
        return value
    def executable(self,name):
        item=self.tools[name];path=Path(item.path)
        if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('pinned executable path')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=item.sha256:raise ValueError('executable identity changed: '+name)
        return str(path)
    def _launch(self,name,args,*,cleanup=False,foreground=False):
        if self.cleanup_started and not cleanup:raise RuntimeError('no work launch after cleanup started')
        self.checkpoint(cleanup=cleanup);self.verify_work()
        if not self.handlers_installed:raise RuntimeError('install nonraising handlers before launch')
        args=tuple(str(x) for x in args)
        if foreground and (name!='postgres' or args!=self._postgres_args()):raise ValueError('exact foreground postgres argv required')
        if name=='postgres' and not foreground and args!=('--version',):raise ValueError('postgres work requires foreground role')
        argv=(self.executable(name),*args);index=len(self.children)+1
        stdout=self.work/'logs'/('child-'+str(index)+'.stdout');stderr=self.work/'logs'/('child-'+str(index)+'.stderr')
        handle=None;record=None;stack=ExitStack();close_error=None;fallback=False;log_token=None
        stdout_identity=None;stderr_identity=None
        # Reserve the complete peak log pair before spawning. Budget/evidence
        # failure stops work, but cleanup still uses the preopened discard sink.
        try:
            if self.log_policy is not None:
                try:log_token=self.log_policy.reserve(name,stdout,stderr,cleanup=cleanup)
                except BaseException as exc:
                    self.evidence_errors.append(type(exc).__name__+': '+str(exc));self.unqualified=True
                    if not cleanup:raise
                    fallback=True
            if not fallback:
                try:
                    out=stack.enter_context(stdout.open('xb'));os.fchmod(out.fileno(),0o600)
                    info=os.fstat(out.fileno());stdout_identity=(info.st_dev,info.st_ino)
                    err=stack.enter_context(stderr.open('xb'));os.fchmod(err.fileno(),0o600)
                    info=os.fstat(err.fileno());stderr_identity=(info.st_dev,info.st_ino)
                except BaseException as exc:
                    self.evidence_errors.append(type(exc).__name__+': '+str(exc));self.unqualified=True
                    try:stack.close()
                    except BaseException as close:self.evidence_errors.append(type(close).__name__+': '+str(close))
                    if not cleanup:raise
                    fallback=True
            if fallback:out=err=self._emergency_sink
            self.checkpoint(cleanup=cleanup)
            handle=self.backend.spawn(argv,cwd=str(self.work),env=self.env.copy(),stdout=out,stderr=err)
            record=Child(handle,name,tuple(argv),stdout,stderr,foreground=foreground,evidence_fallback=fallback,
                log_token=log_token,stdout_identity=stdout_identity,stderr_identity=stderr_identity)
            self.children.append(record)
            if foreground:self.postgres=record
        finally:
            if handle is not None and record is None:
                record=Child(handle,name,tuple(argv),stdout,stderr,foreground=foreground,evidence_fallback=fallback,
                    log_token=log_token,stdout_identity=stdout_identity,stderr_identity=stderr_identity)
                self.children.append(record)
                if foreground:self.postgres=record
            try:stack.close()
            except BaseException as exc:
                close_error=exc;self.evidence_errors.append(type(exc).__name__+': '+str(exc));self.unqualified=True
        if close_error is not None and not cleanup:raise close_error
        return record
    def _signal(self,record,sig):
        if not any(record is child for child in self.children) or record.reaped:raise IdentityUnknown('cannot signal reaped/unowned handle')
        self.backend.signal_group(record.handle,sig)
    def _finish(self,record):
        if not any(record is child for child in self.children) or record.reaped:raise IdentityUnknown('unowned handle/double reap')
        self.remaining(cleanup=True)
        if self.backend.peek(record.handle) is None:raise IdentityUnknown('child still live')
        if self.backend.other_live_group_members(record.handle):raise IdentityUnknown('live group member remains')
        record.group_quiet=True
        record.exit_code=self.backend.reap(record.handle,min(2,self.remaining(cleanup=True)));record.reaped=True
    def _stop(self,record):
        if not any(record is child for child in self.children):raise IdentityUnknown('unowned handle')
        if record.reaped:return
        self.remaining(cleanup=True)
        # Keep the anchor unreaped throughout TERM grace and KILL escalation.
        self._signal(record,signal.SIGTERM);end=min(self.clock()+.25,self.emergency_deadline)
        while self.clock()<end:
            self.sleep(min(.025,end-self.clock()))
        self.remaining(cleanup=True);self._signal(record,signal.SIGKILL);record.forced=True
        end=min(self.clock()+2,self.emergency_deadline)
        while True:
            if self.backend.peek(record.handle) is not None and not self.backend.other_live_group_members(record.handle):break
            if self.clock()>=end:raise IdentityUnknown('owned group did not stop within bound')
            self.sleep(min(.025,end-self.clock()))
        self._finish(record)
    def _command(self,name,args,*,cleanup=False,expected=(0,),timeout=60):
        record=self._launch(name,args,cleanup=cleanup)
        end=min(self.clock()+min(60,timeout),(self.emergency_deadline if cleanup else self.started+840))
        try:
            while True:
                self.checkpoint(cleanup=cleanup)
                if self.backend.peek(record.handle) is not None:
                    if self.backend.other_live_group_members(record.handle):self._stop(record)
                    else:self._finish(record)
                    break
                if self.clock()>=end:raise BudgetExpired('owned child60s bound')
                self.sleep(min(.025,end-self.clock()))
            if record.exit_code not in expected:raise RuntimeError('unexpected child exit: '+name)
            return record
        except BaseException:
            self.unqualified=True
            if not record.reaped:
                try:self._stop(record)
                except BaseException:pass # Retained record remains UNKNOWN for cleanup.
            raise
    def initialize(self):
        return self._command('initdb',['-D',self.work/'data','-U','e2_owner','--auth=trust','--no-locale','-E','UTF8'])
    def run_node(self,script,*args):return self._command('node',[script,*args])
    def psql(self,database,sql_path,*,expected=(0,)):
        if database not in DATABASES:raise ValueError('fixture database allowlist')
        path=Path(sql_path)
        if path.resolve()!=path or self.work not in path.parents or not path.is_file():raise ValueError('owned SQL file required')
        return self._command('psql',['-X','--no-password','-qAt','-h',self.work/'socket','-p','55439','-U','e2_owner','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-d',database,'-f',path],expected=expected)
    def tool_version(self,name):
        if name not in ('postgres','pg_ctl','initdb','psql','node'):raise ValueError('version tool allowlist')
        return self._command(name,['--version'])
    def _verified_log(self,path,identity):
        if path.parent!=self.work/'logs' or path.is_symlink() or path.resolve()!=path:raise IdentityUnknown('owned result path changed')
        info=path.lstat()
        if not stat.S_ISREG(info.st_mode) or (info.st_dev,info.st_ino)!=identity or info.st_nlink!=1:raise IdentityUnknown('original log inode changed')
        return info
    def result(self,record,*,max_bytes=32*1024**2):
        """Bounded UTF-8/universal-newline text, ONLY public/schema fixture logs."""
        if not any(record is child for child in self.children):raise IdentityUnknown('unknown result record')
        if record.retired:raise IdentityUnknown('result logs already retired')
        if not record.foreground and not record.reaped:raise IdentityUnknown('ordinary result child not reaped')
        if type(max_bytes) is not int or not 0<=max_bytes<=32*1024**2:raise ValueError('result byte bound')
        if record.evidence_fallback:return Result(record.argv,record.handle.pid,record.exit_code,'','',False)
        def read(path,identity):
            info=self._verified_log(path,identity)
            if info.st_size>max_bytes:raise ValueError('result exceeds byte bound')
            with path.open('rb') as stream:
                opened=os.fstat(stream.fileno())
                if (opened.st_dev,opened.st_ino)!=identity:raise IdentityUnknown('log inode changed before read')
                raw=stream.read(max_bytes+1)
            if len(raw)>max_bytes:raise ValueError('result grew past byte bound')
            return raw.decode('utf-8',errors='strict').replace('\r\n','\n').replace('\r','\n'),hashlib.sha256(raw).hexdigest()
        try:stdout,stdout_sha=read(record.stdout,record.stdout_identity);stderr,stderr_sha=read(record.stderr,record.stderr_identity)
        except BaseException as exc:
            self.evidence_errors.append(type(exc).__name__+': '+str(exc));self.unqualified=True;raise
        return Result(record.argv,record.handle.pid,record.exit_code,stdout,stderr,True,stdout_sha,stderr_sha)
    def retire_result(self,record,*,stdout_sha256,stderr_sha256):
        """Caller MUST first commit exact compact recording/consume returned data.

        Verify both original ordinary-child log inodes and raw hashes before any
        unlink. No raw text is cached here. A failed release never admits work.
        Foreground PG logs stay charged through the complete shutdown lifecycle.
        """
        try:
            if not any(record is child for child in self.children):raise IdentityUnknown('unknown retirement record')
            if not record.reaped or record.foreground or record.evidence_fallback or record.retired:raise IdentityUnknown('ordinary complete unretired result required')
            items=((record.stdout,record.stdout_identity,stdout_sha256),(record.stderr,record.stderr_identity,stderr_sha256))
            for path,identity,expected in items:
                if type(expected) is not str or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):raise ValueError('raw log SHA256 required')
                info=self._verified_log(path,identity)
                if info.st_size>32*1024**2:raise ValueError('retirement log exceeds fixed32MiB bound')
                digest=hashlib.sha256();total=0
                with path.open('rb') as stream:
                    opened=os.fstat(stream.fileno())
                    if (opened.st_dev,opened.st_ino)!=identity:raise IdentityUnknown('log inode changed before hashing')
                    while True:
                        block=stream.read(65536)
                        if not block:break
                        total+=len(block)
                        if total>32*1024**2:raise ValueError('retirement log grew past fixed bound')
                        digest.update(block)
                after=self._verified_log(path,identity)
                if total!=info.st_size or (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):raise IdentityUnknown('log changed during retirement hash')
                if digest.hexdigest()!=expected:raise IdentityUnknown('raw log hash differs from recorded result')
            for path,identity,_ in items:self._verified_log(path,identity)
            for path,_,_ in items:path.unlink()
            record.retired=True
            if self.log_policy is not None and record.log_token is not None:self.log_policy.release(record.log_token)
            return True
        except BaseException as exc:
            self.unqualified=True;self.evidence_errors.append(type(exc).__name__+': '+str(exc));raise
    def _postgres_args(self):
        return tuple(str(x) for x in ['-D',self.work/'data','-h','','-k',self.work/'socket','-p','55439','-c','max_connections=2','-c','superuser_reserved_connections=0','-c','reserved_connections=0','-c','unix_socket_permissions=0700','-c','statement_timeout=55000','-c','lock_timeout=10000','-c','idle_in_transaction_session_timeout=55000'])
    def start_postgres(self):
        if self.postgres is not None:raise RuntimeError('only one foreground postgres')
        record=self._launch('postgres',self._postgres_args(),foreground=True)
        self.postgres=record # No cancellation check before this PG registration.
        self.checkpoint()
        return record
    def wait_startup(self):
        if self.postgres is None:raise RuntimeError('foreground postgres not launched')
        end=min(self.clock()+60,self.started+840)
        while True:
            self.checkpoint()
            if self.backend.peek(self.postgres.handle) is not None:raise RuntimeError('postgres exited during startup')
            if (self.work/'data/postmaster.pid').is_file() and list((self.work/'socket').iterdir()):
                self.verify_pg_identity()
                self._command('pg_ctl',['-D',self.work/'data','status'],expected=(0,),timeout=min(5,self.checkpoint()))
                self.checkpoint()
                if self.backend.peek(self.postgres.handle) is not None:raise RuntimeError('postgres exited before readiness')
                self.startup_confirmed=True;return
            if self.clock()>=end:raise BudgetExpired('postgres startup60s bound')
            self.sleep(min(.025,end-self.clock()))
    def cleanup(self):
        if self.cleanup_result and self.cleanup_result['completed']:
            try:
                self.verify_work();self.observe_qualification()
                if (self.work/'data/postmaster.pid').exists() or list((self.work/'socket').iterdir()):raise IdentityUnknown('cleanup proof changed')
            except BaseException as exc:
                self.unqualified=True
                self.cleanup_result={**self.cleanup_result,'status':'UNKNOWN','completed':False,'errors':[type(exc).__name__+': '+str(exc)]}
            self.cleanup_result.update(qualificationEligible=self.cleanup_result['completed'] and self.observe_qualification(),qualificationDeadlineExpired=self.qualification_expired,evidenceErrors=list(self.evidence_errors))
            return self.cleanup_result
        self.cleanup_started=True
        errors=[];pg_stopped=False;status_absent=False
        try:self.verify_work()
        except BaseException as exc:errors.append(type(exc).__name__+': '+str(exc))
        # Stop retained ordinary clients before requesting marked PG shutdown.
        for record in list(self.children):
            if record is self.postgres or record.reaped:continue
            try:self._stop(record)
            except BaseException as exc:errors.append(type(exc).__name__+': '+str(exc))
        if self.postgres is not None and self.postgres.reaped:
            pg_stopped=bool(self.cleanup_result and self.cleanup_result.get('postmasterNormalExit'))
            status_absent=bool(self.cleanup_result and self.cleanup_result.get('pgCtlStatusAbsent'))
        elif self.postgres is not None:
            try:
                self.cleanup_startup_identity_grace();self.checkpoint(cleanup=True)
                # pg_ctl is only a stop/status client, never a detached starter.
                self._command('pg_ctl',['-D',self.work/'data','-m','immediate','-w','-t','20','stop'],cleanup=True,timeout=25)
                status=self._command('pg_ctl',['-D',self.work/'data','status'],cleanup=True,expected=(3,),timeout=5)
                status_absent=status.exit_code==3
                end=min(self.clock()+2,self.emergency_deadline)
                while self.backend.peek(self.postgres.handle) is None:
                    if self.clock()>=end:raise IdentityUnknown('postmaster still live after stop')
                    self.sleep(min(.025,end-self.clock()))
                if self.backend.peek(self.postgres.handle)!=0:raise IdentityUnknown('postmaster did not exit normally')
                self._finish(self.postgres);pg_stopped=True
            except BaseException as exc:
                errors.append(type(exc).__name__+': '+str(exc))
                try:self._stop(self.postgres)
                except BaseException as stop:errors.append(type(stop).__name__+': '+str(stop))
        # Include cleanup-client launches in the final retained-handle audit.
        for record in self.children:
            if not record.reaped:
                try:self._stop(record)
                except BaseException as exc:errors.append(type(exc).__name__+': '+str(exc))
        try:
            self.verify_work();self.observe_qualification()
            absent=not (self.work/'data/postmaster.pid').exists();socket_empty=not list((self.work/'socket').iterdir())
        except BaseException as exc:
            errors.append(type(exc).__name__+': '+str(exc));absent=False;socket_empty=False
        pg_proven=self.postgres is None or (pg_stopped and status_absent and not self.postgres.forced and absent and socket_empty)
        complete=not errors and pg_proven and absent and socket_empty and all(r.reaped and r.group_quiet for r in self.children)
        self.observe_qualification()
        if not complete:self.unqualified=True
        self.cleanup_result=dict(status='CLEANUP_PROVEN' if complete else 'UNKNOWN',completed=complete,privateWorkRetained=True,
            foregroundPostgresRegistered=self.postgres is not None,startupConfirmed=self.startup_confirmed,postmasterNormalExit=pg_stopped,
            pgCtlStatusAbsent=status_absent,postmasterPidAbsent=absent,socketDirectoryEmpty=socket_empty,
            allRetainedChildrenReaped=all(r.reaped for r in self.children),ownershipUnresolved=not pg_proven or any(not r.reaped for r in self.children),
            qualificationEligible=complete and self.observe_qualification(),qualificationDeadlineExpired=self.qualification_expired,
            originalQualificationDeadline=self.qualification_deadline,emergencyCleanupDeadline=self.emergency_deadline,
            evidenceErrors=list(self.evidence_errors),errors=errors,cancellationSignals=list(self.cancel.signals))
        return self.cleanup_result

    def finish_owner(self):
        """Mandatory standalone exit guard; unresolved ownership cannot return.

        Terminal observer is advisory and may fail. The private fake-backend
        escape exists solely for pure tests and is rejected for native owners.
        This method never creates a renewed deadline or another owner process.
        """
        result=self.cleanup()
        if result['ownershipUnresolved']:
            self.unqualified=True;self.terminal_retention=True
            while True:
                self.observe_qualification()
                self.cleanup_result.update(status='TERMINAL_OWNER_RETAINED_UNQUALIFIED',qualificationEligible=False,ownerRetained=True)
                if self.terminal_observer is not None:
                    try:self.terminal_observer(self.cleanup_result.copy())
                    except BaseException:pass # Failure reporting cannot drop ownership.
                if self._test_terminal_hook is not None:
                    if isinstance(self.backend,Native) or not getattr(self.backend,'test_only',False):
                        # Late attribute injection must not raise out of the
                        # terminal owner loop or invoke a Native escape hook.
                        self.cleanup_result['invalidTestHook']='native-or-unmarked-backend test hook ignored'
                    else:self._test_terminal_hook(self,self.cleanup_result.copy())
                # The fixed emergency deadline is never renewed. Past it the
                # owner holds handles/work/latches in memory without signaling.
                if self.clock()<self.emergency_deadline:
                    result=self.cleanup()
                    if not result['ownershipUnresolved']:break
                try:self.sleep(.25)
                except BaseException:pass
        result=self.cleanup_result
        if result['completed'] and self.handlers_installed:self.restore_handlers()
        self._emergency_sink.close()
        return result
