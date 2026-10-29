/* Public SDK layouts stay on the C side; Rust receives process metadata only. */
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#define LOMI_PROCESS_LIMIT 8192
struct lomi_process_identity {
    int32_t pid;
    int32_t state;
    int64_t seconds;
    int32_t micros;
    uint32_t uid;
    int32_t exiting;
    int32_t padding;
};
int lomi_macos_process_snapshot(struct lomi_process_identity *output,
                              size_t capacity, size_t *written) {
    if (capacity != LOMI_PROCESS_LIMIT) return EINVAL;
    struct kinfo_proc *processes = calloc(capacity, sizeof(*processes));
    if (processes == NULL) return ENOMEM;
    size_t bytes = capacity * sizeof(*processes);
    size_t length = bytes;
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    int error = 0;
    if (sysctl(mib, 4, processes, &length, NULL, 0) != 0) error = errno;
    else if (length == 0 || length >= bytes || length % sizeof(*processes) != 0)
        error = EOVERFLOW;
    if (error == 0) {
        *written = length / sizeof(*processes);
        for (size_t index = 0; index < *written; index++) {
            const struct extern_proc *process = &processes[index].kp_proc;
            output[index].pid = process->p_pid;
            output[index].state = process->p_stat;
            output[index].seconds = process->p_starttime.tv_sec;
            output[index].micros = process->p_starttime.tv_usec;
            output[index].uid = processes[index].kp_eproc.e_ucred.cr_uid;
            output[index].exiting = (process->p_flag & P_WEXIT) != 0;
            output[index].padding = 0;
        }
    }
    free(processes);
    return error;
}
