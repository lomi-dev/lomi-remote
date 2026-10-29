// Synthetic retained middle + expiring leaf; never signals an orphan PID.
#define main lomi_baseline_main
#include "probe.c"
#undef main
#include <limits.h>
#include <sys/event.h>

static bool read_fixed(int fd,void *value,size_t size) {
    struct pollfd item={.fd=fd,.events=POLLIN};
    return poll(&item,1,600)==1&&read(fd,value,size)==(ssize_t)size;
}
static bool wait_owned(pid_t child,int *status) {
    double deadline=now()+5;
    while(now()<deadline&&state(child)==0)usleep(1000);
    return state(child)==1&&waitpid(child,status,WNOHANG)==child&&WIFEXITED(*status)&&WEXITSTATUS(*status)==0;
}
int main(int argc,char **argv) {
    if((argc==3&&!strcmp(argv[1],"--runner"))||(argc==4&&!strcmp(argv[1],"--exec-child")))return lomi_baseline_main(argc,argv);
    if(argc==4&&!strcmp(argv[1],"--reparent-leaf")) {
        child_alarm(); // The leaf's own pre-exec alarm deadline survives exec.
        int control=atoi(argv[2]),ready=atoi(argv[3]);
        if(write(ready,"E",1)!=1)_exit(94);
        (void)instruction(control);_exit(0);
    }
    if(argc!=3||strcmp(argv[1],"--job"))return 2;
    char path[4096];const char *slash=strrchr(argv[2],'/');
    if(!slash||(size_t)(slash-argv[2])+1>sizeof path)return 2;
    snprintf(path,sizeof path,"%.*s",(int)(slash-argv[2]),argv[2]);
    size_t length=strlen(path);bool rejected=length>=2&&!strcmp(path+length-2,"-b");
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(directory<0)return 2;
    int lifetime=openat(directory,"controller.lock",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lifetime<0||flock(lifetime,LOCK_EX|LOCK_NB)||fsync(lifetime)||fsync(directory))return 2;
    struct sigaction action={0};action.sa_handler=SIG_DFL;sigemptyset(&action.sa_mask);
    if(sigaction(SIGCHLD,&action,NULL))return 2;
    action.sa_handler=SIG_IGN;if(sigaction(SIGPIPE,&action,NULL))return 2;
    action.sa_handler=stop;if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL))return 2;
    struct sample owner=query(getpid()),middle_sample={.outcome="Unrun",.reason="not-created",.sid=-1},before=middle_sample,reparented=middle_sample,session=middle_sample,executed=middle_sample;
    struct usage initial=usage_for(owner.resource,false),together={.outcome="Unrun",.reason="not-created"},orphan=together,final=together;
    int mc[2]={-1,-1},mr[2]={-1,-1},lc[2]={-1,-1},lr[2]={-1,-1},queue=-1,status=0;
    pid_t middle=-1,leaf=-1;bool registration=false,event=false,middle_wait=false,leaf_wait=false,orphaned=false,audit_after_exec=false;
    pid_t observed_ppid=-1;const char *outcome="Unknown",*reason="setup-failed";
    audit_token_t token={{0}};path_api path_fn=(path_api)dlsym(RTLD_DEFAULT,"proc_pidpath_audittoken");
    uintptr_t cookie=0x52504152u;
    if(strcmp(owner.outcome,"Observed")||!path_fn||pipe(mc)||pipe(mr)||pipe(lc)||pipe(lr))goto cleanup;
    middle=fork();if(middle<0)goto cleanup;
    if(middle==0) {
        close(mc[1]);close(mr[0]);child_alarm();alarm(4);
        pid_t child=fork();
        if(child<0)_exit(96);
        if(child==0) {
            // alarm is NOT inherited through fork. Install our own immediately.
            child_alarm();alarm(3);
            close(mc[0]);close(mr[1]);close(lc[1]);close(lr[0]);
            if(write(lr[1],"L",1)!=1)_exit(94);
            if(!instruction(lc[0]))_exit(0);
            if(setsid()<0)_exit(95);
            if(write(lr[1],"S",1)!=1)_exit(94);
            if(!instruction(lc[0]))_exit(0);
            char cfd[32],rfd[32];snprintf(cfd,sizeof cfd,"%d",lc[0]);snprintf(rfd,sizeof rfd,"%d",lr[1]);
            char *args[]={argv[0],"--reparent-leaf",cfd,rfd,NULL};execv(argv[0],args);_exit(96);
        }
        close(lc[0]);close(lc[1]);close(lr[0]);close(lr[1]);
        if(write(mr[1],&child,sizeof child)!=sizeof child)_exit(94);
        char command=0;
        ssize_t count;do{count=read(mc[0],&command,1);}while(count<0&&errno==EINTR);
        if(count==1&&command=='R')_exit(0); // Only after accepted bound NOTE_EXIT.
        int child_status=0;
        if(!wait_owned(child,&child_status))_exit(97);
        if(write(mr[1],"W",1)!=1)_exit(94);
        _exit(0);
    }
    close(mc[0]);mc[0]=-1;close(mr[1]);mr[1]=-1;close(lc[0]);lc[0]=-1;close(lr[1]);lr[1]=-1;
    if(!read_fixed(mr[0],&leaf,sizeof leaf)||leaf<=1||!await_stage(lr[0],'L')||state(middle)!=0){reason="owned-handshake-failed";goto cleanup;}
    middle_sample=query(middle);before=query(leaf);together=usage_for(owner.resource,false);
    if(!same(&owner,&middle_sample)||!same(&middle_sample,&before)){reason="initial-coalition-mismatch";goto cleanup;}
    // Exec intentionally precedes token/knote acquisition: exec changes
    // pidversion and invalidates the earlier audit token even at the same UID.
    // The still-live middle retains the leaf PID throughout this transition.
    if(write(lc[1],"S",1)!=1||!await_stage(lr[0],'S')){reason="leaf-setsid-handshake-failed";goto cleanup;}
    session=query(leaf);
    if(write(lc[1],"E",1)!=1||!await_stage(lr[0],'E')){reason="leaf-exec-handshake-failed";goto cleanup;}
    executed=query(leaf);
    mach_port_t task=MACH_PORT_NULL;mach_msg_type_number_t token_count=TASK_AUDIT_TOKEN_COUNT;
    if(task_name_for_pid(mach_task_self(),leaf,&task)!=KERN_SUCCESS){reason="leaf-task-unavailable";goto cleanup;}
    kern_return_t token_status=task_info(task,TASK_AUDIT_TOKEN,(task_info_t)&token,&token_count);mach_port_deallocate(mach_task_self(),task);
    if(token_status!=KERN_SUCCESS||token_count!=TASK_AUDIT_TOKEN_COUNT||audit_token_to_pid(token)!=leaf||audit_token_to_euid(token)!=geteuid()){reason="leaf-audit-unavailable";goto cleanup;}
    char pre[PROC_PIDPATHINFO_MAXSIZE]={0},post[PROC_PIDPATHINFO_MAXSIZE]={0};
    if(path_fn(&token,pre,sizeof pre)<=0){reason="leaf-identity-precheck-failed";goto cleanup;}
    queue=kqueue();if(queue<0){reason="leaf-kqueue-unavailable";goto cleanup;}
    struct kevent change,receipt;struct timespec zero={0};
    EV_SET(&change,(uintptr_t)leaf,rejected?SHRT_MAX:EVFILT_PROC,EV_ADD|EV_RECEIPT|EV_ONESHOT,NOTE_EXIT,0,&cookie);
    int count=kevent(queue,&change,1,&receipt,1,&zero);
    registration=count==1&&(receipt.flags&EV_ERROR)&&receipt.data==0&&receipt.ident==(uintptr_t)leaf&&receipt.filter==EVFILT_PROC;
    if(!registration){reason="registration-not-accepted";goto cleanup;}
    if(path_fn(&token,post,sizeof post)<=0||strcmp(pre,post)||state(middle)!=0){reason="leaf-identity-postcheck-failed";goto cleanup;}
    if(write(mc[1],"R",1)!=1){reason="reparent-permission-failed";goto cleanup;}
    orphaned=true;
    middle_wait=wait_owned(middle,&status);if(!middle_wait){reason="middle-owned-wait-unconfirmed";goto cleanup;}
    if(path_fn(&token,pre,sizeof pre)<=0){reason="orphan-identity-precheck-failed";goto cleanup;}
    reparented=query(leaf);
    if(path_fn(&token,post,sizeof post)<=0||strcmp(pre,post)){reason="orphan-identity-postcheck-failed";goto cleanup;}
    orphan=usage_for(owner.resource,false);
    struct proc_bsdinfo bsd={0};
    bool ppid_pre=path_fn(&token,pre,sizeof pre)>0;
    int bytes=proc_pidinfo(leaf,PROC_PIDTBSDINFO,0,&bsd,sizeof bsd);
    bool ppid_post=path_fn(&token,post,sizeof post)>0&&!strcmp(pre,post);
    if(ppid_pre&&ppid_post&&bytes==sizeof bsd)observed_ppid=(pid_t)bsd.pbi_ppid;
    audit_after_exec=path_fn(&token,post,sizeof post)>0;
    if(!same(&before,&reparented)||!same(&reparented,&session)||!same(&session,&executed)||observed_ppid!=1||session.sid!=leaf||executed.sid!=leaf||!audit_after_exec){reason="orphan-identity-transition-unconfirmed";goto cleanup;}
    outcome="Observed";reason="bound-leaf-reparent-setsid-exec";
cleanup:
    if(lc[1]>=0){close(lc[1]);lc[1]=-1;}
    if(!orphaned&&mc[1]>=0){close(mc[1]);mc[1]=-1;}
    if(!orphaned&&middle>0){char ack=0;leaf_wait=read_fixed(mr[0],&ack,1)&&ack=='W';}
    if(middle>0&&!middle_wait)middle_wait=wait_owned(middle,&status);
    if(orphaned&&registration&&queue>=0) {
        struct kevent delivered;struct timespec budget={.tv_sec=3};
        int received=kevent(queue,NULL,0,&delivered,1,&budget);
        event=received==1&&delivered.filter==EVFILT_PROC&&delivered.ident==(uintptr_t)leaf&&(delivered.fflags&NOTE_EXIT)&&!(delivered.flags&EV_ERROR)&&delivered.udata==&cookie;
    }
    if(queue>=0)close(queue);
    for(size_t i=0;i<2;i++){if(mc[i]>=0)close(mc[i]);if(mr[i]>=0)close(mr[i]);if(lc[i]>=0)close(lc[i]);if(lr[i]>=0)close(lr[i]);}
    final=usage_for(owner.resource,false);
    bool cleanup=middle_wait&&(!orphaned?leaf_wait:event)&&!strcmp(final.outcome,"Observed")&&final.started-final.exited==1;
    if(!cleanup){outcome="Unknown";reason="cleanup-unconfirmed";}
    else if(rejected){outcome="Unrun";reason="registration-failure-middle-retained-and-waited-leaf";}
    int result=openat(directory,"result.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);if(result<0)return 2;
    FILE *output=fdopen(result,"w");if(!output)return 2;
    fprintf(output,"{\"schema\":\"reparent-v1\",\"outcome\":\"%s\",\"reason\":\"%s\",\"cleanupConfirmed\":%s,\"numericSignalsUsed\":false,\"execBeforeRegistration\":true,\"scenario\":\"%s\",\"registrationAccepted\":%s,\"orphaned\":%s,\"middleOwnedWait\":%s,\"leafWaitByMiddle\":%s,\"leafExitEvent\":%s,\"auditValidAfterExec\":%s,\"leafObservedPpid\":%d,\"self\":",outcome,reason,cleanup?"true":"false",rejected?"registration-failure":"normal",registration?"true":"false",orphaned?"true":"false",middle_wait?"true":"false",leaf_wait?"true":"false",event?"true":"false",audit_after_exec?"true":"false",observed_ppid);
    print_sample(output,&owner);fprintf(output,",\"middle\":");print_sample(output,&middle_sample);fprintf(output,",\"leafBefore\":");print_sample(output,&before);fprintf(output,",\"leafReparented\":");print_sample(output,&reparented);fprintf(output,",\"leafSetsid\":");print_sample(output,&session);fprintf(output,",\"leafExec\":");print_sample(output,&executed);fprintf(output,",\"usage\":{\"initial\":");print_usage(output,&initial);fprintf(output,",\"together\":");print_usage(output,&together);fprintf(output,",\"orphan\":");print_usage(output,&orphan);fprintf(output,",\"final\":");print_usage(output,&final);fprintf(output,"}}\n");
    if(fflush(output)||fsync(result)||fclose(output)||fsync(directory))return 2;
    double hold=now()+0.5;
    while(!stopping&&now()<hold)usleep(1000);
    return cleanup?0:2;
}
