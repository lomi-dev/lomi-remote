// Self-owned child capability probe. No descendant discovery or containment claim.
#include <bsm/libbsm.h>
#include <dlfcn.h>
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach/task_info.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef int (*path_api)(audit_token_t *, void *, uint32_t);
typedef int (*signal_api)(audit_token_t *, int);
static const char hello[] = "lomi-owned-child-v1";
static void expire(int sig) { (void)sig; _exit(91); }
static double now(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) _exit(92);
    return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
// WNOWAIT establishes child ownership without releasing its PID identity.
static int child_state(pid_t child) {
    siginfo_t info = {0};
    if (waitid(P_PID, (id_t)child, &info, WEXITED | WNOHANG | WNOWAIT) != 0) return -1;
    return info.si_pid == 0 ? 0 : info.si_pid == child ? 1 : -1;
}
static bool wait_death(pid_t child, double deadline) {
    while (now() < deadline) {
        int state = child_state(child);
        if (state != 0) return state == 1;
        usleep(1000);
    }
    return false;
}
static bool read_hello(int fd) {
    struct pollfd p = {.fd = fd, .events = POLLIN};
    if (poll(&p, 1, 500) != 1) return false;
    char buffer[sizeof hello] = {0};
    ssize_t count = read(fd, buffer, sizeof buffer);
    return count == sizeof hello && memcmp(buffer, hello, sizeof hello) == 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *mode = argv[1];
    const char *modes[] = {"normal", "natural-before", "natural-during", "invalid-token", "registration-failure", "timeout", "truncated-list", "symbol-absent"};
    bool selected = false;
    for (size_t i = 0; i < sizeof modes / sizeof modes[0]; i++) if (!strcmp(mode, modes[i])) selected = true;
    if (!selected) return 2;
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGCHLD, &action, NULL) != 0) return 2;
    int control[2], ready[2];
    if (pipe(control) || pipe(ready)) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        close(control[1]); close(ready[0]);
        struct sigaction alarm_action = {0};
        alarm_action.sa_handler = expire;
        sigemptyset(&alarm_action.sa_mask);
        if (sigaction(SIGALRM, &alarm_action, NULL)) _exit(93);
        alarm(3); // Automatic self-expiry even if the fixture parent disappears.
        if (!strcmp(mode, "natural-before")) _exit(12);
        if (write(ready[1], hello, sizeof hello) != sizeof hello) _exit(94);
        close(ready[1]);
        char instruction;
        while (read(control[0], &instruction, 1) < 0 && errno == EINTR) {}
        _exit(0); // EOF/control byte is cooperative fixture cleanup, never a PID signal.
    }
    close(control[0]); close(ready[1]);
    const char *outcome = "Unknown", *reason = "handshake-unavailable";
    bool retained = false, audit = false, sid = false, pre = false, post = false;
    bool receipt = false, event = false, attempted = false, signaled = false;
    bool observed_wait = false, reaped = false;
    int status = 0, queue = -1;
    mach_port_t task = MACH_PORT_NULL;
    audit_token_t token = {{0}};
    path_api path_fn = (path_api)dlsym(RTLD_DEFAULT, "proc_pidpath_audittoken");
    signal_api signal_fn = (signal_api)dlsym(RTLD_DEFAULT,
        !strcmp(mode, "symbol-absent") ? "lomi_deliberately_absent_symbol" : "proc_signal_with_audittoken");
    if (!path_fn || !signal_fn) { outcome = "Unsupported"; reason = "audit-api-absent"; goto cleanup; }
    if (!read_hello(ready[0])) goto cleanup;
    retained = child_state(child) == 0;
    if (!retained) { reason = "child-not-live-before-token"; goto cleanup; }
    if (task_name_for_pid(mach_task_self(), child, &task) != KERN_SUCCESS) { reason = "task-name-unavailable"; goto cleanup; }
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&token, &count) != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) { reason = "task-audit-unavailable"; goto cleanup; }
    audit = audit_token_to_pid(token) == child && audit_token_to_euid(token) == geteuid();
    if (!audit) { reason = "audit-identity-mismatch"; goto cleanup; }
    char before[PROC_PIDPATHINFO_MAXSIZE] = {0}, after[PROC_PIDPATHINFO_MAXSIZE] = {0};
    if (!strcmp(mode, "invalid-token")) {
        audit_token_t invalid = {{0}};
        int invalid_result = path_fn(&invalid, before, sizeof before);
        reason = invalid_result <= 0 ? "invalid-token-rejected" : "invalid-token-unexpected-path";
        if (audit_token_to_pid(invalid) == child) reason = "invalid-token-unexpected-match";
        goto cleanup;
    }
    pre = path_fn(&token, before, sizeof before) > 0;
    if (!pre) { reason = "identity-precheck-failed"; goto cleanup; }
    sid = getsid(child) == getsid(0);
    if (!sid) { reason = "session-mismatch"; goto cleanup; }
    if (!strcmp(mode, "truncated-list")) {
        pid_t one[1];
        int bytes = proc_listpids(PROC_ALL_PIDS, 0, one, sizeof one);
        // A full buffer, malformed byte count or query error cannot establish
        // a complete candidate set. No empty-cleanup conclusion is permitted.
        reason = bytes >= (int)sizeof one ? "pid-list-truncated" : "pid-list-incomplete";
        goto cleanup;
    }
    queue = kqueue();
    if (queue < 0) { reason = "kqueue-unavailable"; goto cleanup; }
    uintptr_t cookie = 0x4c4f4d49u;
    struct kevent change, acknowledgement;
    EV_SET(&change, (uintptr_t)child, !strcmp(mode, "registration-failure") ? SHRT_MAX : EVFILT_PROC,
           EV_ADD | EV_RECEIPT | EV_ONESHOT, NOTE_EXIT, 0, &cookie);
    struct timespec zero = {0};
    int changed = kevent(queue, &change, 1, &acknowledgement, 1, &zero);
    receipt = changed == 1 && (acknowledgement.flags & EV_ERROR) && acknowledgement.data == 0
        && acknowledgement.ident == (uintptr_t)child && acknowledgement.filter == EVFILT_PROC;
    if (!receipt) { reason = "registration-not-accepted"; goto cleanup; }
    if (!strcmp(mode, "natural-during")) {
        if (write(control[1], "E", 1) != 1 || !wait_death(child, now() + 1)) { reason = "natural-exit-unconfirmed"; goto cleanup; }
    }
    post = path_fn(&token, after, sizeof after) > 0 && strcmp(before, after) == 0;
    if (!post || child_state(child) != 0) { reason = "identity-lost-during-handshake"; goto cleanup; }
    if (!strcmp(mode, "timeout")) {
        struct timespec budget = {.tv_nsec = 30000000};
        struct kevent ignored;
        int observed = kevent(queue, NULL, 0, &ignored, 1, &budget);
        reason = observed == 0 ? "exit-observation-timeout" : "unexpected-observation-in-timeout-case";
        goto cleanup;
    }
    // Only the verified fixture child is signaled. There is no numeric kill(),
    // no adopted descendant, no SID/UID scan and no mutation of a foreign task.
    attempted = true;
    signaled = signal_fn(&token, SIGKILL) == 0;
    if (!signaled) { reason = "audit-signal-failed"; goto cleanup; }
    struct timespec budget = {.tv_sec = 1};
    struct kevent delivered;
    int received = kevent(queue, NULL, 0, &delivered, 1, &budget);
    event = received == 1 && delivered.filter == EVFILT_PROC && delivered.ident == (uintptr_t)child
        && (delivered.fflags & NOTE_EXIT) && !(delivered.flags & EV_ERROR) && delivered.udata == &cookie;
    if (!event) { reason = "exit-event-unavailable"; goto cleanup; }
    observed_wait = wait_death(child, now() + 1);
    if (!observed_wait) { reason = "owned-child-death-unconfirmed"; goto cleanup; }
    outcome = "DeathObserved"; reason = "registered-child-exit-and-owned-wait";
cleanup:
    if (task != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), task);
    if (queue >= 0) close(queue);
    close(ready[0]); close(control[1]);
    bool cleanup_death = wait_death(child, now() + 4);
    if (cleanup_death) {
        pid_t result;
        do { result = waitpid(child, &status, WNOHANG); } while (result < 0 && errno == EINTR);
        reaped = result == child;
    }
    if (!reaped || (!strcmp(outcome, "DeathObserved") && (!WIFSIGNALED(status) || WTERMSIG(status) != SIGKILL))) {
        outcome = "Unknown"; reason = "owned-child-cleanup-unconfirmed";
    }
    printf("{\"scenario\":\"%s\",\"outcome\":\"%s\",\"reason\":\"%s\",\"childPid\":%d,\"retainedChildChecked\":%s,\"auditIdentityChecked\":%s,\"sessionChecked\":%s,\"identityPrecheck\":%s,\"identityPostcheck\":%s,\"registrationAccepted\":%s,\"exitEventObserved\":%s,\"signalAttempted\":%s,\"signalSucceeded\":%s,\"ownedWaitConfirmed\":%s,\"cleanupConfirmed\":%s,\"numericSignalsUsed\":false}\n",
        mode, outcome, reason, child, retained ? "true":"false", audit ? "true":"false", sid ? "true":"false", pre ? "true":"false", post ? "true":"false", receipt ? "true":"false", event ? "true":"false", attempted ? "true":"false", signaled ? "true":"false", observed_wait ? "true":"false", reaped ? "true":"false");
    return reaped ? 0 : 2;
}
