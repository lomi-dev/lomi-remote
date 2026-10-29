// Test-only true-exit observer. Reuse the exact product audit/membership guard;
// no production API or containment certificate is extended by this fixture.
#include "../../crates/lomi-terminal/src/supervisor/macos_coalition/capability.c"
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/file.h>
#include <time.h>

static double monotonic(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(71);
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.;
}
static bool number(const char *s, uint64_t max, uint64_t *value) {
    if (!*s) return false;
    uint64_t n=0;
    for (;*s;s++) { if (*s<'0'||*s>'9'||n>(max-(uint64_t)(*s-'0'))/10) return false; n=n*10+(uint64_t)(*s-'0'); }
    *value=n; return true;
}
static bool register_exit(int queue,struct lomi_coalition_identity *identity,
                          const char *executable,uintptr_t cookie) {
    path_api path=(path_api)dlsym(RTLD_DEFAULT,"proc_pidpath_audittoken");
    audit_token_t token;memcpy(&token,identity->audit,sizeof token);
    char before[PROC_PIDPATHINFO_MAXSIZE]={0},after[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(!path)return false;
    int pre=path(&token,before,sizeof before);
    if(pre<=0||pre>=(int)sizeof before||strcmp(before,executable))return false;
    struct lomi_coalition_identity current={0};
    if(membership(&token,identity->pid,&current)||!same(identity,&current))return false;
    struct kevent change,receipt;
    EV_SET(&change,(uintptr_t)identity->pid,EVFILT_PROC,EV_ADD|EV_RECEIPT|EV_ONESHOT,
        NOTE_EXIT,0,(void *)cookie);
    struct timespec zero={0};
    if(kevent(queue,&change,1,&receipt,1,&zero)!=1||!(receipt.flags&EV_ERROR)||receipt.data
        ||receipt.ident!=(uintptr_t)identity->pid||receipt.filter!=EVFILT_PROC||receipt.udata!=(void *)cookie)return false;
    int post=path(&token,after,sizeof after);
    if(post<=0||post>=(int)sizeof after||strcmp(before,after)
        ||membership(&token,identity->pid,&current)||!same(identity,&current))return false;
    return true;
}
static bool marker(int root,const char *name) {
    int fd=openat(root,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0)return false;
    bool ok=write(fd,"observer-authorized",19)==19&&fsync(fd)==0;
    if(close(fd))ok=false;
    return ok&&fsync(root)==0;
}
static bool proof(const char *path,const char *bytes) {
    if(strlen(path)>=PATH_MAX)return false;
    char buffer[PATH_MAX];strcpy(buffer,path);char *name=strrchr(buffer,'/');
    if(!name||!name[1])return false;*name++=0;
    int parent=open(buffer,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat metadata;
    if(parent<0||fstat(parent,&metadata)||metadata.st_uid!=geteuid()
        ||(metadata.st_mode&07777)!=0700||lomi_coalition_safe_acl(parent))return false;
    int fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){close(parent);return false;}
    size_t n=strlen(bytes);bool ok=write(fd,bytes,n)==(ssize_t)n&&fsync(fd)==0;
    if(close(fd)||fsync(parent))ok=false;
    close(parent);return ok;
}
int main(int argc,char **argv) {
    if(argc==2&&!strcmp(argv[1],"--preflight")) {
        if(lomi_coalition_available())return 3;
        int queue=kqueue();if(queue<0)return 3;close(queue);
        puts("SDK_PREFLIGHT_AVAILABLE");return 0;
    }
    if(argc!=28)return 2;
    // proof, controllerPID, workloadPID, eight audit words, two coalitionIDs,
    // generation nonce, exact frozen product executable. All are public metadata.
    uint64_t values[12];
    for(int i=0;i<12;i++)if(!number(argv[i+2],i<10?UINT32_MAX:UINT64_MAX,&values[i]))return 2;
    if(!values[0]||values[0]>INT32_MAX||!values[1]||values[1]>INT32_MAX)return 2;
    struct lomi_coalition_identity expected={.pid=(int32_t)values[0],.resource=values[10],.jetsam=values[11]};
    for(int i=0;i<8;i++)expected.audit[i]=(uint32_t)values[i+2];
    if(strlen(argv[14])!=36)return 2;
    for(const char *p=argv[14];*p;p++)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')||*p=='-'))return 2;
    struct lomi_coalition_identity controller={0},workload={0};
    uint64_t count=0;
    if(lomi_coalition_identity(expected.pid,&controller)||!same(&expected,&controller)
        ||lomi_coalition_identity((int32_t)values[1],&workload)||workload.pid==controller.pid
        ||workload.resource!=controller.resource||workload.jetsam!=controller.jetsam
        ||lomi_coalition_count(&controller,&count)||count!=2)return 3;
    uint64_t host_values[11];
    for(int i=0;i<11;i++)if(!number(argv[i+16],i<9?UINT32_MAX:UINT64_MAX,&host_values[i]))return 2;
    if(!host_values[0]||host_values[0]>INT32_MAX)return 2;
    struct lomi_coalition_identity host_expected={.pid=(int32_t)host_values[0],.resource=host_values[9],.jetsam=host_values[10]},host={0};
    for(int i=0;i<8;i++)host_expected.audit[i]=(uint32_t)host_values[i+1];
    if(host_expected.pid==controller.pid||host_expected.pid==workload.pid
        ||lomi_coalition_identity(host_expected.pid,&host)||!same(&host_expected,&host))return 3;
    int root=open(argv[27],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat root_stat;
    if(root<0||fstat(root,&root_stat)||root_stat.st_uid!=geteuid()
        ||(root_stat.st_mode&07777)!=0700||lomi_coalition_safe_acl(root))return 3;
    struct stat marker_state;
    if(fstatat(root,"fault.injected",&marker_state,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT
        ||fstatat(root,"operator.release",&marker_state,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return 3;
    // Retain task-name capabilities in addition to identity-bound knotes.
    mach_port_t ports[3]={MACH_PORT_NULL,MACH_PORT_NULL,MACH_PORT_NULL};
    if(task_name_for_pid(mach_task_self(),controller.pid,&ports[0])!=KERN_SUCCESS
        ||task_name_for_pid(mach_task_self(),workload.pid,&ports[1])!=KERN_SUCCESS
        ||task_name_for_pid(mach_task_self(),host.pid,&ports[2])!=KERN_SUCCESS)return 3;
    int queue=kqueue();
    if(queue<0||!register_exit(queue,&controller,argv[15],1)||!register_exit(queue,&workload,argv[15],2)||!register_exit(queue,&host,argv[15],3))return 3;
    puts("OBSERVER_READY");fflush(stdout);
    struct pollfd input={.fd=STDIN_FILENO,.events=POLLIN};char instruction=0;
    if(poll(&input,1,10000)!=1||read(STDIN_FILENO,&instruction,1)!=1||instruction!='K')return 4;
    // Recheck the same complete controller audit generation immediately before
    // delivering to that token; ESRCH/exec/reuse is Unknown, never another target.
    audit_token_t token;memcpy(&token,controller.audit,sizeof token);
    struct lomi_coalition_identity checked={0};
    signal_api deliver=(signal_api)dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");
    if(!deliver||membership(&token,controller.pid,&checked)||!same(&controller,&checked)
        ||lomi_coalition_count(&controller,&count)||count!=2)return 5;
    if(deliver(&token,SIGKILL))return 5;
    bool controller_exit=false,workload_exit=false,host_exit=false,orphan_live=false;double deadline=monotonic()+25;
    while(monotonic()<deadline&&(!controller_exit||!workload_exit)) {
        struct timespec budget={.tv_sec=1};struct kevent event;
        int n=kevent(queue,NULL,0,&event,1,&budget);
        if(n<0&&errno==EINTR)continue;
        if(n<0)return 6;
        if(!n)continue;
        if(event.filter!=EVFILT_PROC||!(event.fflags&NOTE_EXIT)||(event.flags&EV_ERROR))return 6;
        if(event.udata==(void *)1&&event.ident==(uintptr_t)controller.pid&&!controller_exit) {
            controller_exit=true;
            struct lomi_coalition_identity live={0};
            audit_token_t workload_token;memcpy(&workload_token,workload.audit,sizeof workload_token);
            orphan_live=!workload_exit && !membership(&workload_token,workload.pid,&live)
                &&same(&workload,&live)&&!lomi_coalition_identity(workload.pid,&live)&&same(&workload,&live);
            // Acceptance requires this positive live check; dequeue order alone
            // never establishes exit order. Still collect both true-exit events
            // for independent operator cleanup if acceptance remains Unknown.
            if(!marker(root,"fault.injected"))return 7;
            puts("CONTROLLER_EXIT_OBSERVED");fflush(stdout);
        }
        else if(event.udata==(void *)2&&event.ident==(uintptr_t)workload.pid&&!workload_exit)workload_exit=true;
        else if(event.udata==(void *)3&&event.ident==(uintptr_t)host.pid&&!host_exit)host_exit=true;
        else return 6;
    }
    if(!controller_exit||!workload_exit)return 6;
    char report[2048];int length=snprintf(report,sizeof report,
        "{\"schema\":1,\"nonce\":\"%s\",\"controllerPid\":%d,\"workloadPid\":%d,\"hostPid\":%d,\"initialLiveCount\":2,\"allRegistrationsAccepted\":true,\"sameControllerAuditSignal\":true,\"workloadLiveAfterControllerNoteExit\":%s,\"controllerNoteExit\":true,\"workloadNoteExit\":true,\"numericSignalsUsed\":false,\"fixtureGenerationProcessesGone\":true}\n",
        argv[14],controller.pid,workload.pid,host.pid,orphan_live?"true":"false");
    if(length<=0||length>=(int)sizeof report||!proof(argv[1],report))return 7;
    if(!marker(root,"operator.release"))return 7;
    puts("BOTH_EXIT_OBSERVED");fflush(stdout);
    deadline=monotonic()+20;
    while(monotonic()<deadline&&!host_exit) {
        struct timespec budget={.tv_sec=1};struct kevent event;
        int n=kevent(queue,NULL,0,&event,1,&budget);
        if(n<0&&errno==EINTR)continue;
        if(n<0)return 6;
        if(!n)continue;
        if(event.filter!=EVFILT_PROC||!(event.fflags&NOTE_EXIT)||(event.flags&EV_ERROR)
            ||event.udata!=(void *)3||event.ident!=(uintptr_t)host.pid)return 6;
        host_exit=true;
    }
    if(!host_exit)return 6;
    char final_path[PATH_MAX];length=snprintf(final_path,sizeof final_path,"%s.host.json",argv[1]);
    if(length<=0||length>=(int)sizeof final_path)return 7;
    length=snprintf(report,sizeof report,"{\"schema\":1,\"nonce\":\"%s\",\"hostPid\":%d,\"hostNoteExit\":true,\"fixtureAllThreeProcessesGone\":true}\n",argv[14],host.pid);
    if(length<=0||length>=(int)sizeof report||!proof(final_path,report))return 7;
    close(root);close(queue);for(int i=0;i<3;i++)mach_port_deallocate(mach_task_self(),ports[i]);
    puts("ALL_EXIT_OBSERVED");return 0;
}
