/* Trusted, root-side coalition identity and drain primitives. */
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
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define LOMI_PROC_PIDCOALITIONINFO 20
#define LOMI_COALITION_RESOURCE_PROBE_FLAGS 0x4u
#define LOMI_COALITION_JETSAM_PROBE_FLAGS 0x14u
#define LOMI_PROCESS_LIMIT 65536

struct lomi_private_proc_pidcoalitioninfo {
    uint64_t coalition_id[2];
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
};

struct lomi_private_coalition_usage_prefix {
    uint64_t tasks_started;
    uint64_t tasks_exited;
};

_Static_assert(sizeof(audit_token_t) == 32, "SDK audit-token layout");
_Static_assert(sizeof(struct lomi_private_proc_pidcoalitioninfo) == 40,
               "XNU coalition-info prefix layout");
_Static_assert(sizeof(struct lomi_private_coalition_usage_prefix) == 16,
               "XNU resource-usage prefix layout");

typedef int (*path_api)(audit_token_t *, void *, uint32_t);
typedef int (*signal_api)(audit_token_t *, int);
typedef int (*usage_api)(uint64_t, void *, size_t);
typedef int (*create_api)(uint64_t *, uint32_t);

/* XNU defines this from the kernel's DEVELOPMENT/DEBUG build configuration. */
static int production_kernel(void) {
    int development = -1;
    size_t length = sizeof(development);
    if (sysctlbyname("kern.development", &development, &length, NULL, 0) != 0 ||
        length != sizeof(development)) {
        return -1;
    }
    return development == 0 ? 1 : 0;
}

static path_api path_function(void) {
    return (path_api)dlsym(RTLD_DEFAULT, "proc_pidpath_audittoken");
}

static usage_api usage_function(void) {
    return (usage_api)dlsym(RTLD_DEFAULT, "coalition_info_resource_usage");
}

static signal_api signal_function(void) {
    return (signal_api)dlsym(RTLD_DEFAULT, "proc_signal_with_audittoken");
}

static create_api create_function(void) {
    return (create_api)dlsym(RTLD_DEFAULT, "coalition_create");
}

static bool same_identity(const struct lomi_privileged_cohort_identity *left,
                          const struct lomi_privileged_cohort_identity *right) {
    return left->pid == right->pid && left->pidversion == right->pidversion &&
           left->resource == right->resource && left->jetsam == right->jetsam &&
           memcmp(left->audit, right->audit, sizeof(left->audit)) == 0;
}

static bool same_cohorts(const struct lomi_privileged_cohort_identity *left,
                         const struct lomi_privileged_cohort_identity *right) {
    return left->resource == right->resource && left->jetsam == right->jetsam;
}

/*
 * Bind the supplied audit token to both process incarnation and coalition
 * membership. The two token-based path queries bracket proc_pidinfo so an
 * absent/reused PID or exec during the sample is never treated as membership.
 * No effective-UID filter is used: setuid descendants remain members.
 */
static int identity_from_token(const audit_token_t *token,
                               struct lomi_privileged_cohort_identity *result) {
    if (token == NULL || result == NULL) {
        return -1;
    }
    path_api path = path_function();
    int32_t pid = audit_token_to_pid(*token);
    uint32_t pidversion = token->val[7];
    if (path == NULL || pid <= 0 || pidversion == 0) {
        return -1;
    }

    char before[PROC_PIDPATHINFO_MAXSIZE] = {0};
    char after[PROC_PIDPATHINFO_MAXSIZE] = {0};
    int before_length = path((audit_token_t *)token, before, sizeof(before));
    if (before_length <= 0 || before_length >= (int)sizeof(before)) {
        return -1;
    }

    struct lomi_private_proc_pidcoalitioninfo info = {0};
    int bytes = proc_pidinfo(pid, LOMI_PROC_PIDCOALITIONINFO, 0, &info, sizeof(info));
    int after_length = path((audit_token_t *)token, after, sizeof(after));
    if (after_length <= 0 || after_length >= (int)sizeof(after) ||
        before_length != after_length || strcmp(before, after) != 0 ||
        bytes != (int)sizeof(info) || info.reserved1 != 0 || info.reserved2 != 0 ||
        info.reserved3 != 0 || info.coalition_id[0] == 0 || info.coalition_id[1] == 0) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->pid = pid;
    result->pidversion = pidversion;
    memcpy(result->audit, token, sizeof(result->audit));
    result->resource = info.coalition_id[0];
    result->jetsam = info.coalition_id[1];
    return 0;
}

static int audit_token_for_pid(int32_t pid, audit_token_t *token) {
    if (pid <= 0 || token == NULL) {
        return -1;
    }
    mach_port_t task = MACH_PORT_NULL;
    kern_return_t status = task_name_for_pid(mach_task_self(), pid, &task);
    if (status != KERN_SUCCESS || task == MACH_PORT_NULL) {
        if (task != MACH_PORT_NULL) {
            (void)mach_port_deallocate(mach_task_self(), task);
        }
        return -1;
    }

    memset(token, 0, sizeof(*token));
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    status = task_info(task, TASK_AUDIT_TOKEN, (task_info_t)token, &count);
    kern_return_t deallocated = mach_port_deallocate(mach_task_self(), task);
    if (status != KERN_SUCCESS || deallocated != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT || audit_token_to_pid(*token) != pid ||
        token->val[7] == 0) {
        return -1;
    }
    return 0;
}

static int identity_for_pid(int32_t pid,
                            struct lomi_privileged_cohort_identity *result) {
    audit_token_t token;
    if (audit_token_for_pid(pid, &token) != 0 || identity_from_token(&token, result) != 0) {
        return -1;
    }
    return 0;
}

int lomi_privileged_current_cohorts(struct lomi_privileged_cohort_identity *result) {
    if (result == NULL || production_kernel() != 1) {
        return -1;
    }
    audit_token_t token;
    memset(&token, 0, sizeof(token));
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)&token, &count) !=
            KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT || audit_token_to_pid(token) != getpid() ||
        audit_token_to_euid(token) != geteuid() || identity_from_token(&token, result) != 0) {
        return -1;
    }
    return 0;
}

int lomi_privileged_identity_from_audit_token(
    const uint32_t audit[8], struct lomi_privileged_cohort_identity *result) {
    if (audit == NULL || result == NULL || production_kernel() != 1) {
        return -1;
    }
    audit_token_t token;
    memcpy(&token, audit, sizeof(token));
    return identity_from_token(&token, result);
}

static int verified_controller(
    const struct lomi_privileged_cohort_identity *controller) {
    if (controller == NULL || controller->pid <= 0 || controller->pidversion == 0 ||
        controller->resource == 0 || controller->jetsam == 0 ||
        controller->pid != getpid()) {
        return -1;
    }
    struct lomi_privileged_cohort_identity current = {0};
    if (lomi_privileged_current_cohorts(&current) != 0 ||
        !same_identity(controller, &current)) {
        return -1;
    }
    return 0;
}

int lomi_privileged_count(const struct lomi_privileged_cohort_identity *controller,
                          uint64_t *members_excluding_controller) {
    if (geteuid() != 0 || members_excluding_controller == NULL || production_kernel() != 1 ||
        verified_controller(controller) != 0) {
        return -1;
    }
    usage_api usage = usage_function();
    path_api path = path_function();
    if (usage == NULL || path == NULL) {
        return -1;
    }

    struct lomi_private_coalition_usage_prefix counts = {UINT64_MAX, UINT64_MAX};
    if (usage(controller->resource, &counts, sizeof(counts)) != 0 ||
        counts.tasks_started == UINT64_MAX || counts.tasks_exited == UINT64_MAX ||
        counts.tasks_started <= counts.tasks_exited) {
        return -1;
    }
    uint64_t live = counts.tasks_started - counts.tasks_exited;
    if (live == 0) {
        return -1;
    }

    /* Sample again around the counter read; the controller is not a PID hint. */
    struct lomi_privileged_cohort_identity current = {0};
    audit_token_t controller_token;
    memcpy(&controller_token, controller->audit, sizeof(controller_token));
    if (identity_from_token(&controller_token, &current) != 0 ||
        !same_identity(controller, &current)) {
        return -1;
    }
    *members_excluding_controller = live - 1;
    return 0;
}

static int signal_member(
    const struct lomi_privileged_cohort_identity *member,
    const struct lomi_privileged_cohort_identity *controller, int signal_number) {
    if (member == NULL || controller == NULL || member->pid <= 0 ||
        member->pid == controller->pid || !same_cohorts(member, controller)) {
        return -1;
    }
    signal_api deliver = signal_function();
    if (deliver == NULL) {
        return -1;
    }
    struct lomi_privileged_cohort_identity current = {0};
    audit_token_t member_token;
    memcpy(&member_token, member->audit, sizeof(member_token));
    if (identity_from_token(&member_token, &current) != 0 ||
        !same_identity(member, &current) || !same_cohorts(&current, controller)) {
        return -1;
    }
    return deliver(&member_token, signal_number) == 0 ? 0 : -1;
}

int lomi_privileged_drain(const struct lomi_privileged_cohort_identity *controller,
                          int signal_number) {
    if ((signal_number != SIGTERM && signal_number != SIGKILL) ||
        geteuid() != 0 || production_kernel() != 1 || verified_controller(controller) != 0) {
        return -1;
    }
    uint64_t members = 0;
    if (lomi_privileged_count(controller, &members) != 0) {
        return -1;
    }
    if (members == 0) {
        return 0;
    }

    int32_t *pids = calloc(LOMI_PROCESS_LIMIT, sizeof(*pids));
    if (pids == NULL) {
        return -1;
    }
    int count = proc_listallpids(pids, (int)(LOMI_PROCESS_LIMIT * sizeof(*pids)));
    if (count <= 0 || count >= LOMI_PROCESS_LIMIT) {
        free(pids);
        return -1;
    }

    for (int index = 0; index < count; index++) {
        int32_t pid = pids[index];
        if (pid <= 0 || pid == controller->pid) {
            continue;
        }
        struct lomi_privileged_cohort_identity member = {0};
        /* An unreadable candidate cannot prove absence; the independent count
         * below remains authoritative and will keep this result pending. */
        if (identity_for_pid(pid, &member) != 0) {
            continue;
        }
        if (same_cohorts(&member, controller)) {
            (void)signal_member(&member, controller, signal_number);
        }
    }
    free(pids);

    if (lomi_privileged_count(controller, &members) != 0) {
        return -1;
    }
    return members == 0 ? 0 : 1;
}

int lomi_privileged_available(void) {
    if (geteuid() != 0 || production_kernel() != 1 || path_function() == NULL ||
        usage_function() == NULL ||
        signal_function() == NULL || create_function() == NULL) {
        return -1;
    }
    struct lomi_privileged_cohort_identity current = {0};
    uint64_t members = 0;
    if (lomi_privileged_current_cohorts(&current) != 0 ||
        lomi_privileged_count(&current, &members) != 0) {
        return -1;
    }
    return 0;
}

int lomi_privileged_probe(void) {
    if (production_kernel() != 1) {
        return -1;
    }
    create_api create = create_function();
    if (create == NULL) {
        return -1;
    }

    const uint32_t flags[2] = {
        LOMI_COALITION_RESOURCE_PROBE_FLAGS,
        LOMI_COALITION_JETSAM_PROBE_FLAGS,
    };
    int observed = -2;
    for (size_t index = 0; index < 2; index++) {
        uint64_t id = 0;
        errno = 0;
        int status = create(&id, flags[index]);
        int error = errno;
        int value = -1;
        if (status == -1 && error == EPERM) {
            value = 0;
        } else if (status == -1 && error == EINVAL) {
            value = 1;
        } else {
            return -1;
        }
        if (observed != -2 && observed != value) {
            return -1;
        }
        observed = value;
    }
    return observed == -2 ? -1 : observed;
}
