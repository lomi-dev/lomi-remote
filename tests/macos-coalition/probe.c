// Experimental private-ABI feasibility probe. Never enumerates/signals coalition members.
#include "coalition_abi.h"
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef int (*path_api)(audit_token_t *, void *, uint32_t);
static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }
static void expire(int sig) { (void)sig; _exit(91); }
static double now(void) { struct timespec value; if (clock_gettime(CLOCK_MONOTONIC, &value)) _exit(92); return value.tv_sec + value.tv_nsec / 1e9; }
struct sample { const char *outcome; const char *reason; pid_t pid, sid; int bytes; uint64_t resource, jetsam; };
static struct sample query(pid_t pid) {
    struct sample result = {.outcome="Unknown", .reason="audit-unavailable", .pid=pid, .sid=-1};
    path_api path_fn = (path_api)dlsym(RTLD_DEFAULT, "proc_pidpath_audittoken");
    if (!path_fn) { result.outcome="Unsupported"; result.reason="audit-api-absent"; return result; }
    mach_port_t task = MACH_PORT_NULL;
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_name_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS) return result;
    kern_return_t status = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    mach_port_deallocate(mach_task_self(), task);
    if (status != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT || audit_token_to_pid(token) != pid || audit_token_to_euid(token) != geteuid()) return result;
    char before[PROC_PIDPATHINFO_MAXSIZE] = {0}, after[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (path_fn(&token, before, sizeof before) <= 0) { result.reason="audit-precheck-failed"; return result; }
    result.sid = getsid(pid);
    struct lomi_private_proc_pidcoalitioninfo value = {0};
    result.bytes = proc_pidinfo(pid, LOMI_PRIVATE_PROC_PIDCOALITIONINFO, 0, &value, sizeof value);
    if (path_fn(&token, after, sizeof after) <= 0 || strcmp(before, after) || result.sid <= 0) { result.reason="audit-postcheck-failed"; return result; }
    if (result.bytes != sizeof value) { result.reason="private-query-size-mismatch"; return result; }
    if (value.reserved1 || value.reserved2 || value.reserved3) { result.reason="private-schema-reserved-nonzero"; return result; }
    result.resource=value.coalition_id[LOMI_PRIVATE_COALITION_RESOURCE];
    result.jetsam=value.coalition_id[LOMI_PRIVATE_COALITION_JETSAM];
    result.outcome="Observed"; result.reason="private-schema-and-audit-sandwich";
    return result;
}
static void print_sample(FILE *output, const struct sample *value) {
    fprintf(output,"{\"outcome\":\"%s\",\"reason\":\"%s\",\"pid\":%d,\"sid\":%d,\"bytes\":%d,\"resource\":%" PRIu64 ",\"jetsam\":%" PRIu64 "}",value->outcome,value->reason,value->pid,value->sid,value->bytes,value->resource,value->jetsam);
}
typedef int (*usage_api)(uint64_t,struct coalition_resource_usage *,size_t);
struct usage { const char *outcome,*reason; uint64_t started,exited; int error; };
static struct usage usage_for(uint64_t resource,bool absent) {
    struct usage result={.outcome="Unknown",.reason="resource-query-error"};
    usage_api function=(usage_api)dlsym(RTLD_DEFAULT,absent?"lomi_intentionally_absent_usage_api":"coalition_info_resource_usage");
    if(!function){result.outcome="Unsupported";result.reason="resource-api-absent";return result;}
    struct lomi_private_coalition_usage_prefix prefix={UINT64_MAX,UINT64_MAX};
    errno=0;
    int status=function(resource,(struct coalition_resource_usage *)&prefix,sizeof prefix);
    result.error=errno;
    if(!resource||resource==UINT64_MAX){result.reason=status?"invalid-id-rejected":"invalid-id-unexpected-success";return result;}
    if(status)return result;
    if(prefix.tasks_started==UINT64_MAX||prefix.tasks_exited==UINT64_MAX||prefix.tasks_started<prefix.tasks_exited){result.reason="resource-counter-shape-invalid";return result;}
    result.started=prefix.tasks_started;result.exited=prefix.tasks_exited;result.outcome="Observed";result.reason="resource-prefix16";return result;
}
static void print_usage(FILE *output,const struct usage *value) {
    fprintf(output,"{\"outcome\":\"%s\",\"reason\":\"%s\",\"errno\":%d,",value->outcome,value->reason,value->error);
    if(!strcmp(value->outcome,"Observed"))fprintf(output,"\"started\":%" PRIu64 ",\"exited\":%" PRIu64 ",\"active\":%" PRIu64 "}",value->started,value->exited,value->started-value->exited);
    else fprintf(output,"\"started\":null,\"exited\":null,\"active\":null}");
}
static int state(pid_t child) {
    siginfo_t info={0};
    if (waitid(P_PID,(id_t)child,&info,WEXITED|WNOHANG|WNOWAIT)) return -1;
    return info.si_pid==0 ? 0 : info.si_pid==child ? 1 : -1;
}
static bool await_stage(int fd,char expected) {
    struct pollfd item={.fd=fd,.events=POLLIN};
    if (poll(&item,1,800)!=1 || stopping) return false;
    char actual=0;
    return read(fd,&actual,1)==1 && actual==expected;
}
static bool instruction(int fd) { char value; ssize_t count; do { count=read(fd,&value,1); } while(count<0&&errno==EINTR); return count==1; }
static void child_alarm(void) { struct sigaction action={0};action.sa_handler=expire;sigemptyset(&action.sa_mask);if(sigaction(SIGALRM,&action,NULL))_exit(93); }
static bool same(const struct sample *a,const struct sample *b) { return !strcmp(a->outcome,"Observed")&&!strcmp(b->outcome,"Observed")&&a->resource==b->resource&&a->jetsam==b->jetsam; }
int main(int argc,char **argv) {
    if(argc==4&&!strcmp(argv[1],"--exec-child")) {
        // The original fork's alarm survives exec. Do not reset its deadline.
        child_alarm();
        int control=atoi(argv[2]),ready=atoi(argv[3]);
        if(write(ready,"E",1)!=1)_exit(94);
        (void)instruction(control);_exit(0);
    }
    bool job=argc==3&&!strcmp(argv[1],"--job");
    bool direct=argc==3&&!strcmp(argv[1],"--runner");
    if(!job&&!direct)return 2;
    // An exclusive lifetime lock stays held through process exit, including
    // the post-result manager-observation hold. The parent waits our child.
    int lifetime_fd=-1;
    if(job) {
        char path[4096];
        const char *slash=strrchr(argv[2],'/');
        if(!slash || (size_t)(slash-argv[2])+sizeof "/controller.lock">sizeof path)return 2;
        snprintf(path,sizeof path,"%.*s/controller.lock",(int)(slash-argv[2]),argv[2]);
        lifetime_fd=open(path,O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(lifetime_fd<0||flock(lifetime_fd,LOCK_EX|LOCK_NB)||fsync(lifetime_fd))return 2;
    }
    struct sigaction action={0};action.sa_handler=SIG_DFL;sigemptyset(&action.sa_mask);if(sigaction(SIGCHLD,&action,NULL))return 2;
    action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL))return 2;
    action.sa_handler=stop;if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL))return 2;
    struct sample owner=query(getpid()),runner={.outcome="Unrun",.reason="not-a-runner-child",.sid=-1};
    if(direct) {
        char *end=NULL;long expected=strtol(argv[2],&end,10);
        if(!end||*end||expected<=1||expected!=getppid())return 2;
        // This is our actual still-live Python parent, never arbitrary PID input.
        runner=query(getppid());
    }
    struct sample forked={.outcome="Unrun",.reason="no-child",.sid=-1},session=forked,executed=forked;
    struct usage counts_before={.outcome="Unrun",.reason="owner-unavailable"},counts_fork=counts_before,counts_sid=counts_before,counts_exec=counts_before,counts_after=counts_before;
    struct usage invalid=usage_for(UINT64_MAX,false),missing=usage_for(1,true);
    bool cleanup=false,retained=false;
    const char *outcome="Unknown",*reason="owner-query-unavailable";
    int control[2]={-1,-1},ready[2]={-1,-1},status=0;
    pid_t child=-1;
    if(strcmp(owner.outcome,"Observed")){outcome=owner.outcome;reason=owner.reason;goto done;}
    counts_before=usage_for(owner.resource,false);
    if(pipe(control)||pipe(ready)){reason="pipe-failed";goto done;}
    child=fork();
    if(child<0){reason="fork-failed";goto done;}
    if(child==0) {
        close(control[1]);close(ready[0]);child_alarm();alarm(4);
        if(write(ready[1],"F",1)!=1)_exit(94);
        if(!instruction(control[0]))_exit(0);
        if(setsid()<0)_exit(95);
        if(write(ready[1],"S",1)!=1)_exit(94);
        if(!instruction(control[0]))_exit(0);
        char cfd[32],rfd[32];snprintf(cfd,sizeof cfd,"%d",control[0]);snprintf(rfd,sizeof rfd,"%d",ready[1]);
        char *arguments[]={argv[0],"--exec-child",cfd,rfd,NULL};execv(argv[0],arguments);_exit(96);
    }
    close(control[0]);control[0]=-1;close(ready[1]);ready[1]=-1;
    if(!await_stage(ready[0],'F')){reason="fork-handshake-failed";goto done;}
    retained=state(child)==0;if(!retained){reason="child-not-retained-live";goto done;}
    forked=query(child);counts_fork=usage_for(owner.resource,false);
    if(write(control[1],"S",1)!=1||!await_stage(ready[0],'S')){reason="setsid-handshake-failed";goto done;}
    session=query(child);counts_sid=usage_for(owner.resource,false);
    if(write(control[1],"E",1)!=1||!await_stage(ready[0],'E')){reason="exec-handshake-failed";goto done;}
    executed=query(child);counts_exec=usage_for(owner.resource,false);
    if(!same(&owner,&forked)||!same(&forked,&session)||!same(&session,&executed)){reason="coalition-inheritance-unconfirmed";goto done;}
    if(forked.sid!=owner.sid||session.sid!=child||executed.sid!=child){reason="session-transition-unconfirmed";goto done;}
    outcome="Observed";reason="fork-setsid-exec-retain-coalitions";
done:
    for(size_t index=0;index<2;index++){if(control[index]>=0)close(control[index]);if(ready[index]>=0)close(ready[index]);}
    if(child>0) {
        double deadline=now()+5;
        while(now()<deadline&&state(child)==0)usleep(1000);
        if(state(child)==1&&waitpid(child,&status,WNOHANG)==child)cleanup=true;
        if(!cleanup||!WIFEXITED(status)||WEXITSTATUS(status)!=0){outcome="Unknown";reason="child-cleanup-or-exit-unconfirmed";}
    } else cleanup=true; // No child was created; never upgrades query outcome.
    if(!strcmp(owner.outcome,"Observed"))counts_after=usage_for(owner.resource,false);
    // No further fork occurs after this final resource-counter observation.
    FILE *output=stdout;int output_fd=-1;
    if(job) {
        output_fd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(output_fd<0)return 2;
        output=fdopen(output_fd,"w");if(!output){close(output_fd);return 2;}
    }
    fprintf(output,"{\"schema\":1,\"outcome\":\"%s\",\"reason\":\"%s\",\"cleanupConfirmed\":%s,\"retainedChild\":%s,\"numericSignalsUsed\":false,\"reparent\":\"Unrun\",\"privateAbiBytes\":%zu,\"self\":",outcome,reason,cleanup?"true":"false",retained?"true":"false",sizeof(struct lomi_private_proc_pidcoalitioninfo));
    print_sample(output,&owner);fprintf(output,",\"runner\":");print_sample(output,&runner);fprintf(output,",\"fork\":");print_sample(output,&forked);fprintf(output,",\"setsid\":");print_sample(output,&session);fprintf(output,",\"exec\":");print_sample(output,&executed);fprintf(output,",\"resourceUsage\":{\"before\":");print_usage(output,&counts_before);fprintf(output,",\"fork\":");print_usage(output,&counts_fork);fprintf(output,",\"setsid\":");print_usage(output,&counts_sid);fprintf(output,",\"exec\":");print_usage(output,&counts_exec);fprintf(output,",\"afterWait\":");print_usage(output,&counts_after);fprintf(output,",\"invalidId\":");print_usage(output,&invalid);fprintf(output,",\"missingSymbol\":");print_usage(output,&missing);fprintf(output,"}}\n");
    if(fflush(output)|| (job&&fsync(output_fd)))return 2;
    if(job) {
        if(fclose(output))return 2;
        // All children are reaped before this job advertises its result. Hold
        // briefly for simultaneous manager/PID comparisons, then self-expire.
        double deadline=now()+3;while(!stopping&&now()<deadline)usleep(10000);
    }
    return cleanup?0:2;
}
