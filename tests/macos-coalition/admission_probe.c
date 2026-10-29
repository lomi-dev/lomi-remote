// Experimental nonforking controller; every invocation records before gating.
#define main lomi_baseline_main
#include "probe.c"
#undef main

static int private_new(int directory,const char *name) {
    return openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
}
static bool finish_json(FILE *stream,int directory) {
    bool okay=fflush(stream)==0&&fsync(fileno(stream))==0;
    if(fclose(stream))okay=false;
    return okay&&fsync(directory)==0;
}
static bool write_sample(int directory,const char *name,const struct sample *owner) {
    int fd=private_new(directory,name);if(fd<0)return false;
    FILE *output=fdopen(fd,"w");if(!output){close(fd);return false;}
    struct usage counts=usage_for(owner->resource,false);
    fprintf(output,"{\"self\":");print_sample(output,owner);fprintf(output,",\"usage\":");print_usage(output,&counts);fprintf(output,"}\n");
    return finish_json(output,directory);
}
int main(int argc,char **argv) {
    if((argc==3&&!strcmp(argv[1],"--runner"))||(argc==4&&!strcmp(argv[1],"--exec-child")))return lomi_baseline_main(argc,argv);
    if(argc!=3||strcmp(argv[1],"--job"))return 2;
    // Each invocation has a finite lifetime even if the broker disappears.
    child_alarm();alarm(3);
    struct sigaction action={0};action.sa_handler=stop;sigemptyset(&action.sa_mask);
    if(sigaction(SIGTERM,&action,NULL)||sigaction(SIGINT,&action,NULL))return 2;
    char path[4096];const char *slash=strrchr(argv[2],'/');
    if(!slash||(size_t)(slash-argv[2])+1>sizeof path)return 2;
    snprintf(path,sizeof path,"%.*s",(int)(slash-argv[2]),argv[2]);
    int directory=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(directory<0)return 2;
    uint8_t random[16];arc4random_buf(random,sizeof random);char nonce[33];
    for(size_t i=0;i<sizeof random;i++)snprintf(nonce+2*i,3,"%02x",random[i]);
    char lock_name[80],record_name[80];snprintf(lock_name,sizeof lock_name,"invocation-%s.lock",nonce);snprintf(record_name,sizeof record_name,"start-%s.json",nonce);
    int invocation=private_new(directory,lock_name);
    if(invocation<0||flock(invocation,LOCK_EX|LOCK_NB)||fsync(invocation)||fsync(directory))return 2;
    struct sample owner=query(getpid());
    audit_token_t token={{0}};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
    if(task_info(mach_task_self(),TASK_AUDIT_TOKEN,(task_info_t)&token,&count)!=KERN_SUCCESS||count!=TASK_AUDIT_TOKEN_COUNT)return 2;
    int record=private_new(directory,record_name);if(record<0)return 2;
    FILE *output=fdopen(record,"w");if(!output)return 2;
    fprintf(output,"{\"schema\":1,\"nonce\":\"%s\",\"pid\":%d,\"auditPid\":%d,\"auditEuid\":%u,\"auditPidversion\":%d,\"auditToken\":[",nonce,getpid(),audit_token_to_pid(token),audit_token_to_euid(token),audit_token_to_pidversion(token));
    for(size_t i=0;i<8;i++)fprintf(output,"%s%u",i?",":"",token.val[i]);
    fprintf(output,"],\"self\":");print_sample(output,&owner);fprintf(output,",\"usage\":");struct usage initial=usage_for(owner.resource,false);print_usage(output,&initial);fprintf(output,"}\n");
    if(!finish_json(output,directory))return 2;
    // Deliberately AFTER the immutable start record: a refused workload still
    // proves an actual launchd invocation. Never mistake our gate for launchd.
    int controller=private_new(directory,"controller.lock");
    if(controller<0||flock(controller,LOCK_EX|LOCK_NB)||fsync(controller)||fsync(directory))return 2;
    int result=private_new(directory,"result.json");if(result<0)return 2;
    output=fdopen(result,"w");if(!output)return 2;
    fprintf(output,"{\"schema\":\"admission-v1\",\"cleanupConfirmed\":true,\"nonforking\":true,\"numericSignalsUsed\":false,\"nonce\":\"%s\",\"self\":",nonce);print_sample(output,&owner);fprintf(output,"}\n");
    if(!finish_json(output,directory))return 2;
    // No fork or exec occurs in this controller after entry. Samples are
    // requested only by fixed private files, never arbitrary IPC arguments.
    bool live=false,repeat=false;double deadline=now()+2;
    while(!stopping&&now()<deadline) {
        if(!live&&faccessat(directory,"sample.live.request",F_OK,AT_SYMLINK_NOFOLLOW)==0){live=write_sample(directory,"sample.live.json",&owner);if(!live)return 2;}
        if(!repeat&&faccessat(directory,"sample.repeat.request",F_OK,AT_SYMLINK_NOFOLLOW)==0){repeat=write_sample(directory,"sample.repeat.json",&owner);if(!repeat)return 2;}
        usleep(1000);
    }
    if(!write_sample(directory,"sample.final.json",&owner))return 2;
    return 0; // Both lifetime locks remain held until actual process exit.
}
