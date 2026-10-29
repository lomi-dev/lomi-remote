/* Compile/run only on the pinned native Ubuntu ARM64 runner. */
#include <linux/audit.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
_Static_assert(AUDIT_ARCH_AARCH64 == 0xc00000b7, "audit architecture");
_Static_assert(__NR_landlock_create_ruleset == 444, "Landlock create syscall");
_Static_assert(__NR_landlock_add_rule == 445, "Landlock rule syscall");
_Static_assert(__NR_landlock_restrict_self == 446, "Landlock restrict syscall");
_Static_assert(__NR_seccomp == 277 && __NR_execveat == 281, "bootstrap syscalls");
_Static_assert(__NR_close_range == 436, "close_range syscall");
_Static_assert(__NR_openat == 56 && __NR_read == 63 && __NR_write == 64, "I/O syscalls");
_Static_assert(__NR_socket == 198 && __NR_clone == 220 && __NR_execve == 221, "denied syscalls");
_Static_assert(SECCOMP_FILTER_FLAG_NEW_LISTENER == 8, "new listener flag");
_Static_assert(SECCOMP_USER_NOTIF_FLAG_CONTINUE == 1, "continue flag");
_Static_assert(SECCOMP_IOCTL_NOTIF_RECV == 0xc0502100, "receive ioctl");
_Static_assert(SECCOMP_IOCTL_NOTIF_SEND == 0xc0182101, "send ioctl");
_Static_assert(SECCOMP_IOCTL_NOTIF_ID_VALID == 0x40082102, "valid ioctl");
_Static_assert(sizeof(struct seccomp_notif) == 80, "notification size");
_Static_assert(sizeof(struct seccomp_notif_resp) == 24, "response size");
_Static_assert(sizeof(struct seccomp_data) == 64, "seccomp data size");
_Static_assert(sizeof(struct landlock_ruleset_attr) == 16, "ABI4 ruleset size");
_Static_assert(sizeof(struct landlock_path_beneath_attr) == 12, "packed rule size");
_Static_assert(LANDLOCK_ACCESS_FS_TRUNCATE == (1ULL << 14), "all ABI4 filesystem rights");
_Static_assert(LANDLOCK_ACCESS_NET_BIND_TCP == 1 && LANDLOCK_ACCESS_NET_CONNECT_TCP == 2, "network rights");
int main(void) {
    unsigned int action=SECCOMP_RET_USER_NOTIF;
    if (getuid()==0 || syscall(__NR_landlock_create_ruleset,0,0,LANDLOCK_CREATE_RULESET_VERSION)!=4 || syscall(__NR_seccomp,SECCOMP_GET_ACTION_AVAIL,0,&action)) return 1;
    puts("native headers and unprivileged Landlock ABI4/seccomp notification availability: passed");
    return 0;
}
