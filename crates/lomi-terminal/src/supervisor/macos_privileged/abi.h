/* Private ABI boundary for privileged per-PTY terminal primitives. */
#ifndef LOMI_MACOS_PRIVILEGED_ABI_H
#define LOMI_MACOS_PRIVILEGED_ABI_H

#include <stddef.h>
#include <stdint.h>

struct lomi_privileged_cohort_identity {
    int32_t pid;
    uint32_t pidversion;
    uint32_t audit[8];
    uint64_t resource;
    uint64_t jetsam;
};

_Static_assert(sizeof(struct lomi_privileged_cohort_identity) == 56,
               "Rust/C privileged identity size");
_Static_assert(offsetof(struct lomi_privileged_cohort_identity, pidversion) == 4,
               "Rust/C pidversion offset");
_Static_assert(offsetof(struct lomi_privileged_cohort_identity, audit) == 8,
               "Rust/C audit-token offset");
_Static_assert(offsetof(struct lomi_privileged_cohort_identity, resource) == 40,
               "Rust/C resource-cohort offset");
_Static_assert(offsetof(struct lomi_privileged_cohort_identity, jetsam) == 48,
               "Rust/C jetsam-cohort offset");

int lomi_privileged_current_cohorts(struct lomi_privileged_cohort_identity *result);
int lomi_privileged_identity_from_audit_token(
    const uint32_t audit[8], struct lomi_privileged_cohort_identity *result);
int lomi_privileged_count(const struct lomi_privileged_cohort_identity *controller,
                          uint64_t *members_excluding_controller);
/* 0 = only controller remains; 1 = members remain; -1 = unknown/fail-closed. */
int lomi_privileged_drain(const struct lomi_privileged_cohort_identity *controller,
                          int signal_number);
int lomi_privileged_available(void);
/* 0 = unprivileged, 1 = privileged, -1 = unknown. */
int lomi_privileged_probe(void);

#endif
