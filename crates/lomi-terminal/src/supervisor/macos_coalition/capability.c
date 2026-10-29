// Experimental macOS private coalition capability. See ADR-011/012 and abi.h.
// No PID signal: every signal uses a fresh SDK audit token after membership checks.
#include "abi.h"
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

typedef int (*path_api)(audit_token_t *,void *,uint32_t);
typedef int (*signal_api)(audit_token_t *,int);
typedef int (*usage_api)(uint64_t,struct coalition_resource_usage *,size_t);
struct lomi_coalition_identity { int32_t pid; uint32_t audit[8]; uint64_t resource,jetsam; };
_Static_assert(sizeof(audit_token_t)==32,"SDK audit token layout");
_Static_assert(sizeof(struct lomi_coalition_identity)==56,"Rust FFI identity layout");
static int membership(audit_token_t *token,int32_t pid,struct lomi_coalition_identity *result) {
    path_api path=(path_api)dlsym(RTLD_DEFAULT,"proc_pidpath_audittoken");
    if(!path||pid<=0||audit_token_to_pid(*token)!=pid||audit_token_to_euid(*token)!=geteuid())return -1;
    char before[PROC_PIDPATHINFO_MAXSIZE]={0},after[PROC_PIDPATHINFO_MAXSIZE]={0};
    int pre=path(token,before,sizeof before);
    if(pre<=0||pre>=(int)sizeof before)return -1;
    struct lomi_private_proc_pidcoalitioninfo value={0};
    int bytes=proc_pidinfo(pid,LOMI_PRIVATE_PROC_PIDCOALITIONINFO,0,&value,sizeof value);
    int post=path(token,after,sizeof after);
    if(post<=0||post>=(int)sizeof after||strcmp(before,after)||bytes!=sizeof value||value.reserved1||value.reserved2||value.reserved3||!value.coalition_id[0]||!value.coalition_id[1])return -1;
    result->pid=pid;memcpy(result->audit,token,sizeof *token);result->resource=value.coalition_id[0];result->jetsam=value.coalition_id[1];
    return 0;
}
int lomi_coalition_identity(int32_t pid,struct lomi_coalition_identity *result) {
    if(pid<=0||!result)return -1;
    mach_port_t task=MACH_PORT_NULL;
    if(task_name_for_pid(mach_task_self(),pid,&task)!=KERN_SUCCESS)return -1;
    audit_token_t token={{0}};mach_msg_type_number_t count=TASK_AUDIT_TOKEN_COUNT;
    kern_return_t status=task_info(task,TASK_AUDIT_TOKEN,(task_info_t)&token,&count);
    mach_port_deallocate(mach_task_self(),task);
    if(status!=KERN_SUCCESS||count!=TASK_AUDIT_TOKEN_COUNT)return -1;
    return membership(&token,pid,result);
}
static bool same(const struct lomi_coalition_identity *left,const struct lomi_coalition_identity *right);
int lomi_coalition_parent(const struct lomi_coalition_identity *child,const struct lomi_coalition_identity *parent) {
    if(!child||!parent||child->pid<=0||parent->pid<=0||child->pid==parent->pid)return -1;
    struct lomi_coalition_identity child_before={0},parent_before={0},child_after={0},parent_after={0};
    if(lomi_coalition_identity(child->pid,&child_before)||!same(child,&child_before)||
       lomi_coalition_identity(parent->pid,&parent_before)||!same(parent,&parent_before)||
       child->resource!=parent->resource||child->jetsam!=parent->jetsam)return -1;
    struct proc_bsdinfo info={0};
    int bytes=proc_pidinfo(child->pid,PROC_PIDTBSDINFO,0,&info,sizeof info);
    if(bytes!=sizeof info||info.pbi_ppid!=(uint32_t)parent->pid)return -1;
    // Bind the parent observation to the same two task incarnations sampled
    // around proc_pidinfo; a reused PID cannot satisfy both audit-token pins.
    if(lomi_coalition_identity(child->pid,&child_after)||!same(child,&child_after)||
       lomi_coalition_identity(parent->pid,&parent_after)||!same(parent,&parent_after))return -1;
    return 0;
}
static bool same(const struct lomi_coalition_identity *left,const struct lomi_coalition_identity *right) {
    return left->pid==right->pid&&left->resource==right->resource&&left->jetsam==right->jetsam&&!memcmp(left->audit,right->audit,sizeof left->audit);
}
int lomi_coalition_count(const struct lomi_coalition_identity *original,uint64_t *active) {
    if(!original||!active)return -1;
    usage_api usage=(usage_api)dlsym(RTLD_DEFAULT,"coalition_info_resource_usage");
    path_api path=(path_api)dlsym(RTLD_DEFAULT,"proc_pidpath_audittoken");
    if(!usage||!path)return -1;
    audit_token_t token;memcpy(&token,original->audit,sizeof token);
    struct lomi_coalition_identity current={0};
    if(membership(&token,original->pid,&current)||!same(original,&current))return -1;
    struct lomi_private_coalition_usage_prefix prefix={UINT64_MAX,UINT64_MAX};
    if(usage(original->resource,(struct coalition_resource_usage *)&prefix,sizeof prefix)||prefix.tasks_started==UINT64_MAX||prefix.tasks_exited==UINT64_MAX||prefix.tasks_started<=prefix.tasks_exited)return -1;
    // Bind the counter sample to the SAME original still-live controller.
    if(membership(&token,original->pid,&current)||!same(original,&current))return -1;
    *active=prefix.tasks_started-prefix.tasks_exited;return 0;
}
int lomi_coalition_available(void) {
    if(!dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken"))return -1;
    struct lomi_coalition_identity identity={0};uint64_t count=0;
    if(lomi_coalition_identity(getpid(),&identity)||lomi_coalition_count(&identity,&count)||!count)return -1;
    return 0;
}
static int signal_member(const struct lomi_coalition_identity *member,const struct lomi_coalition_identity *controller,int signal) {
    if(member->pid==controller->pid||member->resource!=controller->resource||member->jetsam!=controller->jetsam)return -1;
    signal_api deliver=(signal_api)dlsym(RTLD_DEFAULT,"proc_signal_with_audittoken");
    if(!deliver)return -1;
    audit_token_t token;memcpy(&token,member->audit,sizeof token);
    struct lomi_coalition_identity checked={0};
    if(membership(&token,member->pid,&checked)||!same(member,&checked))return -1;
    return deliver(&token,signal)==0?0:-1;
}
int lomi_coalition_drain(const struct lomi_coalition_identity *controller,int signal) {
    if(!controller||(signal!=SIGTERM&&signal!=SIGKILL))return -1;
    uint64_t active=0;if(lomi_coalition_count(controller,&active))return -1;
    if(active==1)return 0;
    int32_t pids[16384];
    int count=proc_listallpids(pids,sizeof pids);
    if(count<=0||count>=(int)(sizeof pids/sizeof pids[0]))return -1;
    for(int i=0;i<count;i++) {
        int32_t pid=pids[i];if(pid<=0||pid==controller->pid)continue;
        struct lomi_coalition_identity member={0};
        // Unreadable/racing candidates are never absence evidence. The independent
        // count remains >1 until every member actually leaves this coalition.
        if(lomi_coalition_identity(pid,&member))continue;
        if(member.resource==controller->resource&&member.jetsam==controller->jetsam)
            (void)signal_member(&member,controller,signal);
    }
    return 1; // A scan, including no matches, NEVER proves cleanup.
}

#include <sys/acl.h>
int lomi_coalition_safe_acl(int fd) {
    acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
    if(!acl)return errno==ENOENT?0:-1;
    acl_entry_t entry;int selector=ACL_FIRST_ENTRY,status=-1;
    while(acl_get_entry(acl,selector,&entry)==0) {
        acl_tag_t tag;
        if(acl_get_tag_type(entry,&tag)||tag!=ACL_EXTENDED_DENY)goto done;
        selector=ACL_NEXT_ENTRY;
    }
    if(errno==EINVAL)status=0;
done:acl_free(acl);return status;
}
