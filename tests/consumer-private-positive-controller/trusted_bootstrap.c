/*
 * macOS trusted entrypoint prototype. This file is not installed or admitted.
 * It verifies the fixed launcher bytes before Python can interpret them, then
 * gives the interpreter that same open descriptor through /dev/fd/N.
 */
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

#ifndef TRUSTED_ROOT
#define TRUSTED_ROOT "/Library/PrivilegedHelperTools/Lomi/private-positive-eleven"
#endif
#ifndef PINNED_PYTHON
#define PINNED_PYTHON "/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14"
#endif
#ifndef BOOTSTRAP_PATH
#define BOOTSTRAP_PATH "/Library/PrivilegedHelperTools/Lomi/private-positive-eleven/bootstrap"
#endif
#ifndef PYTHON_FRAMEWORK_PATH
#define PYTHON_FRAMEWORK_PATH "/Library/Frameworks/Python.framework/Versions/3.14"
#endif
#ifndef BOOTSTRAP_TESTING
#define TRUST_UID 0
#else
#define TRUST_UID getuid()
#endif

static const char *const kAdmission = "admission.json";
static const char *const kFreeze = "freeze.json";
static const char *const kController = "controller.py";
static const char *const kLauncher = "launcher.py";
#define MAX_ADMISSION 4096
#define MAX_FREEZE (1024 * 1024)
#define MAX_CONTROLLER (256 * 1024)
#define MAX_LAUNCHER 16384

static int failure_stage;
static void reject(void) {
#ifdef BOOTSTRAP_TESTING
    dprintf(STDERR_FILENO, "trusted bootstrap rejected at stage %d\n", failure_stage);
#endif
    _exit(126);
}

/* File mode bits do not represent macOS extended ACL grants. Reject any ACL. */
static bool has_no_extended_acl(int fd) {
    errno = 0;
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT;
    acl_free(acl);
    return false;
}

static bool valid_dir(int fd, uid_t uid) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || (st.st_mode & 0022) != 0 ||
        !has_no_extended_acl(fd)) return false;
#ifdef BOOTSTRAP_TESTING
    return st.st_uid == uid || st.st_uid == 0;
#else
    return st.st_uid == uid;
#endif
}

static bool valid_file(int fd, uid_t uid, struct stat *out) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != uid ||
        st.st_nlink != 1 || (st.st_mode & 0222) != 0 || st.st_size < 0 ||
        !has_no_extended_acl(fd)) return false;
    if (out) *out = st;
    return true;
}

/* Walk from / with O_NOFOLLOW at every component; no realpath/stat race. */
static int open_trusted_root(uid_t uid) {
    if (TRUSTED_ROOT[0] != '/' || TRUSTED_ROOT[1] == '\0') return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !valid_dir(fd, uid)) { if (fd >= 0) close(fd); return -1; }
    char path[PATH_MAX];
    size_t path_len = strlen(&TRUSTED_ROOT[1]);
    if (path_len >= sizeof(path)) { close(fd); return -1; }
    memcpy(path, &TRUSTED_ROOT[1], path_len + 1);
    char *save = NULL;
    for (char *part = strtok_r(path, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!*part || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) { close(fd); return -1; }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || !valid_dir(next, uid)) { if (next >= 0) close(next); close(fd); return -1; }
        close(fd);
        fd = next;
    }
    return fd;
}

static int open_trusted_file(int rootfd, const char *name, uid_t uid, size_t max, struct stat *st) {
    int fd = openat(rootfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    if (!valid_file(fd, uid, st) || (uint64_t)st->st_size > max) { close(fd); return -1; }
    return fd;
}

static bool read_all_stable(int fd, const struct stat *before, uint8_t *buf, size_t cap, size_t *len) {
    size_t used = 0;
    for (;;) {
        if (used == cap) {
            uint8_t extra;
            ssize_t n = read(fd, &extra, 1);
            if (n != 0) return false;
            break;
        }
        ssize_t n = read(fd, buf + used, cap - used);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) return false;
        if (n == 0) break;
        used += (size_t)n;
    }
    struct stat after;
    if (fstat(fd, &after) != 0 || before->st_dev != after.st_dev || before->st_ino != after.st_ino ||
        before->st_uid != after.st_uid || before->st_mode != after.st_mode ||
        before->st_nlink != after.st_nlink || before->st_size != after.st_size ||
        (uint64_t)used != (uint64_t)after.st_size) return false;
    *len = used;
    return true;
}

static void sha256_hex(const uint8_t *bytes, size_t len, char out[65]) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    static const char hex[] = "0123456789abcdef";
    CC_SHA256(bytes, (CC_LONG)len, digest);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[64] = '\0';
}

static bool is_lower_sha256(const char *value, char out[65]) {
    if (!value || strlen(value) != 64) return false;
    memcpy(out, value, 65);
    for (size_t i = 0; i < 64; ++i)
        if (!((out[i] >= '0' && out[i] <= '9') || (out[i] >= 'a' && out[i] <= 'f'))) return false;
    return out[64] == '\0';
}

typedef struct { const uint8_t *p; size_t n; size_t i; } Json;

static void json_ws(Json *j) {
    while (j->i < j->n && (j->p[j->i] == ' ' || j->p[j->i] == '\t' ||
           j->p[j->i] == '\r' || j->p[j->i] == '\n')) ++j->i;
}

/* The admission contract contains only ASCII strings, integer 1 and true. */
static bool json_string(Json *j, char *out, size_t cap) {
    json_ws(j);
    if (j->i >= j->n || j->p[j->i++] != '"') return false;
    size_t used = 0;
    while (j->i < j->n && j->p[j->i] != '"') {
        uint8_t c = j->p[j->i++];
        if (c < 0x20 || c > 0x7e || c == '\\' || used + 1 >= cap) return false;
        out[used++] = (char)c;
    }
    if (j->i >= j->n || j->p[j->i++] != '"') return false;
    out[used] = '\0';
    return true;
}

static bool token(Json *j, const char *value) {
    json_ws(j);
    size_t n = strlen(value);
    if (n > j->n - j->i || memcmp(j->p + j->i, value, n) != 0) return false;
    j->i += n;
    return true;
}

static bool json_skip_string(Json *j) {
    json_ws(j);
    if (j->i >= j->n || j->p[j->i++] != '"') return false;
    while (j->i < j->n) {
        uint8_t c = j->p[j->i++];
        if (c == '"') return true;
        if (c < 0x20) return false;
        if (c != '\\') continue;
        if (j->i >= j->n) return false;
        uint8_t escape = j->p[j->i++];
        if (escape == '"' || escape == '\\' || escape == '/' || escape == 'b' ||
            escape == 'f' || escape == 'n' || escape == 'r' || escape == 't') continue;
        if (escape != 'u' || j->n - j->i < 4) return false;
        for (size_t k = 0; k < 4; ++k) {
            uint8_t hex = j->p[j->i++];
            if (!((hex >= '0' && hex <= '9') || (hex >= 'a' && hex <= 'f') ||
                  (hex >= 'A' && hex <= 'F'))) return false;
        }
    }
    return false;
}

static bool json_number(Json *j) {
    json_ws(j);
    size_t start = j->i;
    if (j->i < j->n && j->p[j->i] == '-') ++j->i;
    if (j->i >= j->n) return false;
    if (j->p[j->i] == '0') ++j->i;
    else {
        if (j->p[j->i] < '1' || j->p[j->i] > '9') return false;
        while (j->i < j->n && j->p[j->i] >= '0' && j->p[j->i] <= '9') ++j->i;
    }
    if (j->i < j->n && j->p[j->i] == '.') {
        ++j->i;
        size_t fraction = j->i;
        while (j->i < j->n && j->p[j->i] >= '0' && j->p[j->i] <= '9') ++j->i;
        if (fraction == j->i) return false;
    }
    if (j->i < j->n && (j->p[j->i] == 'e' || j->p[j->i] == 'E')) {
        ++j->i;
        if (j->i < j->n && (j->p[j->i] == '+' || j->p[j->i] == '-')) ++j->i;
        size_t exponent = j->i;
        while (j->i < j->n && j->p[j->i] >= '0' && j->p[j->i] <= '9') ++j->i;
        if (exponent == j->i) return false;
    }
    return j->i > start;
}

static bool json_skip_value(Json *j, unsigned depth) {
    if (depth > 32) return false;
    json_ws(j);
    if (j->i >= j->n) return false;
    if (j->p[j->i] == '"') return json_skip_string(j);
    if (j->p[j->i] == '{') {
        ++j->i;
        json_ws(j);
        if (j->i < j->n && j->p[j->i] == '}') { ++j->i; return true; }
        for (;;) {
            if (!json_skip_string(j) || !token(j, ":") || !json_skip_value(j, depth + 1)) return false;
            json_ws(j);
            if (j->i < j->n && j->p[j->i] == ',') {
                ++j->i;
                json_ws(j);
                if (j->i >= j->n || j->p[j->i] == '}') return false;
                continue;
            }
            if (j->i < j->n && j->p[j->i] == '}') { ++j->i; return true; }
            return false;
        }
    }
    if (j->p[j->i] == '[') {
        ++j->i;
        json_ws(j);
        if (j->i < j->n && j->p[j->i] == ']') { ++j->i; return true; }
        for (;;) {
            if (!json_skip_value(j, depth + 1)) return false;
            json_ws(j);
            if (j->i < j->n && j->p[j->i] == ',') {
                ++j->i;
                json_ws(j);
                if (j->i >= j->n || j->p[j->i] == ']') return false;
                continue;
            }
            if (j->i < j->n && j->p[j->i] == ']') { ++j->i; return true; }
            return false;
        }
    }
    if (token(j, "true") || token(j, "false") || token(j, "null")) return true;
    return json_number(j);
}

static bool json_source_hash_map(Json *j, const char *expected_controller) {
    if (!token(j, "{")) return false;
    bool found_controller = false;
    json_ws(j);
    if (j->i < j->n && j->p[j->i] == '}') { ++j->i; return false; }
    for (;;) {
        char key[128], value[128];
        if (!json_string(j, key, sizeof(key)) || !token(j, ":")) return false;
        if (strcmp(key, "controller.py") == 0) {
            char digest[65];
            if (found_controller || !json_string(j, value, sizeof(value)) ||
                !is_lower_sha256(value, digest) || strcmp(digest, expected_controller) != 0) return false;
            found_controller = true;
        } else if (!json_skip_value(j, 0)) return false;
        json_ws(j);
        if (j->i < j->n && j->p[j->i] == ',') {
            ++j->i;
            json_ws(j);
            if (j->i >= j->n || j->p[j->i] == '}') return false;
            continue;
        }
        if (j->i < j->n && j->p[j->i] == '}') { ++j->i; break; }
        return false;
    }
    return found_controller;
}

static bool freeze_binds_controller(const uint8_t *raw, size_t len, const char *expected_controller) {
    Json j = {raw, len, 0};
    bool found_sources = false;
    if (!token(&j, "{")) return false;
    json_ws(&j);
    if (j.i < j.n && j.p[j.i] == '}') { ++j.i; return false; }
    for (;;) {
        char key[128];
        if (!json_string(&j, key, sizeof(key)) || !token(&j, ":")) return false;
        if (strcmp(key, "sourceSha256") == 0) {
            if (found_sources || !json_source_hash_map(&j, expected_controller)) return false;
            found_sources = true;
        } else if (!json_skip_value(&j, 0)) return false;
        json_ws(&j);
        if (j.i < j.n && j.p[j.i] == ',') {
            ++j.i;
            json_ws(&j);
            if (j.i >= j.n || j.p[j.i] == '}') return false;
            continue;
        }
        if (j.i < j.n && j.p[j.i] == '}') { ++j.i; break; }
        return false;
    }
    json_ws(&j);
    return found_sources && j.i == j.n;
}

static bool exact_admission(const uint8_t *raw, size_t len, char freeze_sha[65],
                            char controller_sha[65], char launcher_sha[65]) {
    Json j = {raw, len, 0};
    unsigned seen = 0;
    char got_freeze[65] = {0}, got_controller[65] = {0}, got_launcher[65] = {0};
    json_ws(&j);
    if (!token(&j, "{")) return false;
    for (;;) {
        char key[64], value[128];
        json_ws(&j);
        if (j.i < j.n && j.p[j.i] == '}') { ++j.i; break; }
        if (!json_string(&j, key, sizeof(key)) || !token(&j, ":")) return false;
        unsigned bit;
        if (strcmp(key, "schemaVersion") == 0) bit = 1u << 0;
        else if (strcmp(key, "scope") == 0) bit = 1u << 1;
        else if (strcmp(key, "freezeSha256") == 0) bit = 1u << 2;
        else if (strcmp(key, "rootReviewed") == 0) bit = 1u << 3;
        else if (strcmp(key, "controllerSha256") == 0) bit = 1u << 4;
        else if (strcmp(key, "launcherSha256") == 0) bit = 1u << 5;
        else return false;
        if (seen & bit) return false;
        seen |= bit;
        if (bit == (1u << 0)) {
            if (!token(&j, "1")) return false;
            json_ws(&j);
            if (j.i < j.n && (j.p[j.i] == '.' || j.p[j.i] == 'e' || j.p[j.i] == 'E' ||
                               (j.p[j.i] >= '0' && j.p[j.i] <= '9'))) return false;
        } else if (bit == (1u << 3)) {
            if (!token(&j, "true")) return false;
        } else {
            if (!json_string(&j, value, sizeof(value))) return false;
            if (bit == (1u << 1) && strcmp(value, "private-positive-auth-eleven-only") != 0) return false;
            if (bit == (1u << 2)) { if (!is_lower_sha256(value, got_freeze)) return false; }
            if (bit == (1u << 4) && !is_lower_sha256(value, got_controller)) return false;
            if (bit == (1u << 5) && !is_lower_sha256(value, got_launcher)) return false;
        }
        json_ws(&j);
        if (j.i < j.n && j.p[j.i] == ',') {
            ++j.i;
            json_ws(&j);
            if (j.i >= j.n || j.p[j.i] == '}') return false;
            continue;
        }
        if (j.i < j.n && j.p[j.i] == '}') { ++j.i; break; }
        return false;
    }
    json_ws(&j);
    if (j.i != j.n || seen != 0x3fu) return false;
    memcpy(freeze_sha, got_freeze, 65);
    memcpy(controller_sha, got_controller, 65);
    memcpy(launcher_sha, got_launcher, 65);
    return true;
}

static bool absolute_private_directory(const char *path, uid_t uid) {
    if (!path || path[0] != '/' || path[1] == '\0') return false;
    size_t path_len = strlen(path);
    if (path[path_len - 1] == '/' || strstr(path, "//") != NULL) return false;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 || !valid_dir(fd, uid)) { if (fd >= 0) close(fd); return false; }
    char copy[PATH_MAX];
    size_t n = strlen(path + 1);
    if (n >= sizeof(copy)) { close(fd); return false; }
    memcpy(copy, path + 1, n + 1);
    char *save = NULL;
    for (char *part = strtok_r(copy, "/", &save); part; part = strtok_r(NULL, "/", &save)) {
        if (!*part || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) { close(fd); return false; }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 || !valid_dir(next, uid)) { if (next >= 0) close(next); close(fd); return false; }
        close(fd);
        fd = next;
    }
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && st.st_uid == uid && (st.st_mode & 07777) == 0700;
    close(fd);
    return ok;
}

static bool pinned_interpreter_is_trusted(void) {
    const char *path = PINNED_PYTHON;
    if (!path || path[0] != '/' || path[1] == '\0') return false;
    int dirfd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dirfd < 0 || !valid_dir(dirfd, 0)) { if (dirfd >= 0) close(dirfd); return false; }
#ifdef BOOTSTRAP_TESTING
    const uid_t directory_owner = getuid();
#else
    const uid_t directory_owner = 0;
#endif
    char copy[PATH_MAX];
    size_t n = strlen(path + 1);
    if (n >= sizeof(copy)) { close(dirfd); return false; }
    memcpy(copy, path + 1, n + 1);
    char *save = NULL;
    char *part = strtok_r(copy, "/", &save);
    if (!part) { close(dirfd); return false; }
    for (;;) {
        char *next_part = strtok_r(NULL, "/", &save);
        if (!next_part) {
            int fd = openat(dirfd, part, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat st;
            bool trusted_owner = false;
            if (fd >= 0 && fstat(fd, &st) == 0) {
#ifdef BOOTSTRAP_TESTING
                trusted_owner = st.st_uid == 0 || st.st_uid == getuid();
#else
                trusted_owner = st.st_uid == 0;
#endif
            }
            bool ok = fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && trusted_owner &&
                      st.st_nlink == 1 && (st.st_mode & 0022) == 0 && has_no_extended_acl(fd);
            if (fd >= 0) close(fd);
            close(dirfd);
            return ok;
        }
        if (!*part || strcmp(part, ".") == 0 || strcmp(part, "..") == 0) { close(dirfd); return false; }
        int nextfd = openat(dirfd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nextfd < 0 || !valid_dir(nextfd, directory_owner)) { if (nextfd >= 0) close(nextfd); close(dirfd); return false; }
        close(dirfd);
        dirfd = nextfd;
        part = next_part;
    }
}

/* Verify the signed interpreter bundle, including sealed runtime resources. */
static bool pinned_python_bundle_is_trusted(void) {
    CFURLRef url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault,
        (const UInt8 *)PYTHON_FRAMEWORK_PATH, (CFIndex)strlen(PYTHON_FRAMEWORK_PATH), true);
    if (!url) return false;
    SecStaticCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    OSStatus status = SecRequirementCreateWithString(
        CFSTR("anchor apple generic and identifier \"org.python.python\" and certificate leaf[subject.OU] = \"BMM5U3QVKW\""),
        kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
#ifndef BOOTSTRAP_TESTING
    if (status == errSecSuccess) status = SecStaticCodeCheckValidity(code,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement);
#endif
    if (requirement) CFRelease(requirement);
    if (code) CFRelease(code);
    CFRelease(url);
    return status == errSecSuccess;
}

/* Validate the actual process image while POSIX_SPAWN_START_SUSPENDED holds it. */
static bool spawned_python_is_trusted(pid_t pid) {
#ifdef BOOTSTRAP_TESTING
    (void)pid;
#ifdef TEST_VALIDATION_REJECT
    return false;
#else
    struct stat marker_st;
    if (stat(TEST_CHILD_EFFECT_PATH, &marker_st) == 0 || errno != ENOENT) return false;
    int marker_fd = open(TEST_VALIDATION_MARKER_PATH,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (marker_fd < 0) return false;
    return close(marker_fd) == 0;
#endif
#else
    int raw_pid = (int)pid;
    CFNumberRef pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &raw_pid);
    if (!pid_number) return false;
    const void *keys[] = {kSecGuestAttributePid};
    const void *values[] = {pid_number};
    CFDictionaryRef attributes = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFRelease(pid_number);
    if (!attributes) return false;

    SecCodeRef guest = NULL;
    SecRequirementRef requirement = NULL;
    OSStatus status = SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags, &guest);
    CFRelease(attributes);
    if (status == errSecSuccess) status = SecRequirementCreateWithString(
        CFSTR("anchor apple generic and identifier \"org.python.python\" and certificate leaf[subject.OU] = \"BMM5U3QVKW\""),
        kSecCSDefaultFlags, &requirement);
    if (status == errSecSuccess) status = SecCodeCheckValidity(guest,
        kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement);
    if (requirement) CFRelease(requirement);
    if (guest) CFRelease(guest);
    return status == errSecSuccess;
#endif
}

typedef enum {
    CHILD_WAIT_STOPPED_UNREAPED,
    CHILD_WAIT_TERMINAL_REAPED,
    CHILD_WAIT_UNKNOWN
} ChildWaitOutcome;

static ChildWaitOutcome wait_for_stopped_child(pid_t pid) {
    int status;
    pid_t result;
    do { result = waitpid(pid, &status, WUNTRACED); } while (result < 0 && errno == EINTR);
    if (result != pid) return CHILD_WAIT_UNKNOWN;
    if (WIFSTOPPED(status)) return CHILD_WAIT_STOPPED_UNREAPED;
    if (WIFEXITED(status) || WIFSIGNALED(status)) return CHILD_WAIT_TERMINAL_REAPED;
    return CHILD_WAIT_UNKNOWN;
}

/* Only call after waitpid reported WIFSTOPPED: this unreaped child owns pid. */
static int kill_stopped_child(pid_t pid) {
#ifdef BOOTSTRAP_TESTING
#ifdef TEST_KILL_EINTR_ONCE
    static bool injected_eintr;
    if (!injected_eintr) {
        injected_eintr = true;
        int marker_fd = open(TEST_KILL_EINTR_MARKER_PATH,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (marker_fd >= 0) close(marker_fd);
        errno = EINTR;
        return -1;
    }
#endif
#endif
    return kill(pid, SIGKILL);
}

static bool kill_and_reap_stopped_child(pid_t pid, ChildWaitOutcome outcome) {
    if (pid <= 0 || outcome != CHILD_WAIT_STOPPED_UNREAPED) return false;
    int kill_result;
    do { kill_result = kill_stopped_child(pid); } while (kill_result != 0 && errno == EINTR);
    int status;
    pid_t result;
    if (kill_result != 0) {
        /* Do not block when we could not prove SIGKILL was delivered. */
        result = waitpid(pid, &status, WNOHANG);
        return result == pid && (WIFEXITED(status) || WIFSIGNALED(status));
    }
    do { result = waitpid(pid, &status, 0); } while (result < 0 && errno == EINTR);
    return result == pid && (WIFEXITED(status) || WIFSIGNALED(status));
}

static bool sigchld_allows_waitpid(void) {
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) != 0) return false;
    return action.sa_handler == SIG_DFL && (action.sa_flags & SA_NOCLDWAIT) == 0;
}

#ifdef BOOTSTRAP_TESTING
static bool write_test_pid(pid_t pid) {
    int fd = open(TEST_CHILD_PID_PATH, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    char value[32];
    int len = snprintf(value, sizeof(value), "%ld\n", (long)pid);
    bool ok = len > 0 && (size_t)len < sizeof(value) && write(fd, value, (size_t)len) == len;
    if (close(fd) != 0) ok = false;
    return ok;
}

static bool write_test_spawn_marker(void) {
    int fd = open(TEST_SPAWN_MARKER_PATH, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    return close(fd) == 0;
}

static void set_test_sigchld_disposition(void) {
#ifdef TEST_SIGCHLD_IGNORE
    (void)signal(SIGCHLD, SIG_IGN);
#endif
#ifdef TEST_SIGCHLD_NOCLDWAIT
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    action.sa_flags = SA_NOCLDWAIT;
    (void)sigaction(SIGCHLD, &action, NULL);
#endif
}
#endif

static bool valid_environment(uid_t uid) {
    static const char *const keys[] = {"HOME", "TMPDIR", "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "__CF_USER_TEXT_ENCODING"};
    const char *values[sizeof(keys) / sizeof(keys[0])] = {0};
    unsigned seen = 0;
    if (!environ) return false;
    for (char **p = environ; *p; ++p) {
        char *equals = strchr(*p, '=');
        if (!equals || equals == *p) return false;
        size_t keylen = (size_t)(equals - *p);
        size_t i;
        for (i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
            if (strlen(keys[i]) == keylen && memcmp(*p, keys[i], keylen) == 0) break;
        if (i == sizeof(keys) / sizeof(keys[0]) || (seen & (1u << i))) return false;
        seen |= 1u << i;
        values[i] = equals + 1;
    }
    if (!values[0] || !values[1] || !values[2] || !values[7] ||
        strcmp(values[2], "/usr/bin:/bin") != 0 ||
        !absolute_private_directory(values[0], uid) || !absolute_private_directory(values[1], uid)) return false;
    char expected_cf[64];
    if (snprintf(expected_cf, sizeof(expected_cf), "0x%X:0x0:0x0", (unsigned)uid) < 0 ||
        strcmp(values[7], expected_cf) != 0) return false;
    if (values[3] && strcmp(values[3], "C") != 0) return false;
    if (values[4] && strcmp(values[4], "C") != 0) return false;
    if (values[5] && strcmp(values[5], "C") != 0 && strcmp(values[5], "C.UTF-8") != 0 &&
        strcmp(values[5], "UTF-8") != 0) return false;
    if (values[6] && strcmp(values[6], "UTC") != 0) return false;
    return true;
}

int main(int argc, char **argv) {
#ifdef BOOTSTRAP_TESTING
    set_test_sigchld_disposition();
#endif
    failure_stage = 1;
    if (argc != 1 || !argv || !argv[0] || strcmp(argv[0], BOOTSTRAP_PATH) != 0) reject();
    uid_t uid = (uid_t)TRUST_UID;
    failure_stage = 2;
    if (!valid_environment(uid)) reject();
    failure_stage = 3;
    if (!pinned_interpreter_is_trusted() || !pinned_python_bundle_is_trusted()) reject();
    failure_stage = 4;
    int rootfd = open_trusted_root(uid);
    if (rootfd < 0) reject();

    struct stat admission_st, freeze_st, controller_st, launcher_st;
    failure_stage = 3;
    int afd = open_trusted_file(rootfd, kAdmission, uid, MAX_ADMISSION, &admission_st);
    int ffd = open_trusted_file(rootfd, kFreeze, uid, MAX_FREEZE, &freeze_st);
    int cfd = open_trusted_file(rootfd, kController, uid, MAX_CONTROLLER, &controller_st);
    int lfd = open_trusted_file(rootfd, kLauncher, uid, MAX_LAUNCHER, &launcher_st);
    close(rootfd);
    if (afd < 0 || ffd < 0 || cfd < 0 || lfd < 0) reject();

    static uint8_t admission_raw[MAX_ADMISSION], freeze_raw[MAX_FREEZE];
    static uint8_t controller_raw[MAX_CONTROLLER], launcher_raw[MAX_LAUNCHER];
    size_t admission_len = 0, freeze_len = 0, controller_len = 0, launcher_len = 0;
    failure_stage = 4;
    bool read_ok = read_all_stable(afd, &admission_st, admission_raw, sizeof(admission_raw), &admission_len) &&
                   read_all_stable(ffd, &freeze_st, freeze_raw, sizeof(freeze_raw), &freeze_len) &&
                   read_all_stable(cfd, &controller_st, controller_raw, sizeof(controller_raw), &controller_len) &&
                   read_all_stable(lfd, &launcher_st, launcher_raw, sizeof(launcher_raw), &launcher_len);
    close(afd); close(ffd); close(cfd);
    if (!read_ok) { close(lfd); reject(); }

    char expected_freeze[65], expected_controller[65], expected_launcher[65];
    char actual_freeze[65], actual_controller[65], actual_launcher[65];
    failure_stage = 5;
    if (!exact_admission(admission_raw, admission_len, expected_freeze, expected_controller, expected_launcher) ||
        !freeze_binds_controller(freeze_raw, freeze_len, expected_controller)) { close(lfd); reject(); }
    sha256_hex(freeze_raw, freeze_len, actual_freeze);
    sha256_hex(controller_raw, controller_len, actual_controller);
    sha256_hex(launcher_raw, launcher_len, actual_launcher);
    failure_stage = 6;
    if (strcmp(expected_freeze, actual_freeze) != 0 ||
        strcmp(expected_controller, actual_controller) != 0 ||
        strcmp(expected_launcher, actual_launcher) != 0) { close(lfd); reject(); }

    /* Rewind the already validated descriptor and intentionally preserve it across exec. */
    failure_stage = 7;
    if (lseek(lfd, 0, SEEK_SET) != 0 || fcntl(lfd, F_SETFD, 0) != 0) { close(lfd); reject(); }
    if (lfd != 3) {
        if (dup2(lfd, 3) != 3) { close(lfd); reject(); }
        close(lfd);
        lfd = 3;
    }
    char script_path[64];
    if (snprintf(script_path, sizeof(script_path), "/dev/fd/%d", lfd) < 0) { close(lfd); reject(); }
    char *const child_argv[] = {(char *)PINNED_PYTHON, "-I", "-S", "-B", script_path, NULL};
    char *const *child_env = environ;
    posix_spawnattr_t attributes;
    if (posix_spawnattr_init(&attributes) != 0) { close(lfd); reject(); }
    short spawn_flags = POSIX_SPAWN_START_SUSPENDED;
    int spawn_error = posix_spawnattr_setflags(&attributes, spawn_flags);
    pid_t child = -1;
    if (spawn_error == 0 && !sigchld_allows_waitpid()) spawn_error = ECHILD;
#ifdef BOOTSTRAP_TESTING
    if (spawn_error == 0 && !write_test_spawn_marker()) spawn_error = EIO;
#endif
    if (spawn_error == 0)
        spawn_error = posix_spawn(&child, PINNED_PYTHON, NULL, &attributes, child_argv, child_env);
    posix_spawnattr_destroy(&attributes);
    if (spawn_error != 0 || child <= 0) { close(lfd); reject(); }

    failure_stage = 8;
    /* START_SUSPENDED prevents user-space execution until this parent resumes it. */
    ChildWaitOutcome wait_outcome = wait_for_stopped_child(child);
    if (wait_outcome != CHILD_WAIT_STOPPED_UNREAPED) {
        close(lfd);
        reject();
    }
#ifdef BOOTSTRAP_TESTING
    if (!write_test_pid(child)) {
        if (!kill_and_reap_stopped_child(child, wait_outcome)) failure_stage = 11;
        close(lfd);
        reject();
    }
#endif
    if (!spawned_python_is_trusted(child)) {
        if (!kill_and_reap_stopped_child(child, wait_outcome)) failure_stage = 11;
        close(lfd);
        reject();
    }
    failure_stage = 9;
    if (kill(child, SIGCONT) != 0) {
        if (!kill_and_reap_stopped_child(child, wait_outcome)) failure_stage = 11;
        close(lfd);
        reject();
    }
    close(lfd);
    failure_stage = 10;
    int child_status;
    pid_t waited;
    do { waited = waitpid(child, &child_status, 0); } while (waited < 0 && errno == EINTR);
    if (waited != child || (!WIFEXITED(child_status) && !WIFSIGNALED(child_status))) {
        reject();
    }
    if (WIFEXITED(child_status)) _exit(WEXITSTATUS(child_status));
    if (WIFSIGNALED(child_status)) _exit(128 + WTERMSIG(child_status));
    reject();
}

