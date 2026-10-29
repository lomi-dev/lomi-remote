/*
 * Copyright (c) 2005-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

// Modified 2026-10-19: experimental product projection of pinned private XNU
// declarations. See tests/macos-coalition/upstream/manifest.json and APPLE_LICENSE.
// This is NOT an SDK-stable/public interface and is enabled only by the default-off experimental product feature.
#ifndef LOMI_EXPERIMENTAL_COALITION_ABI_H
#define LOMI_EXPERIMENTAL_COALITION_ABI_H
#include <stddef.h>
#include <stdint.h>
#define LOMI_PRIVATE_PROC_PIDCOALITIONINFO 20
#define LOMI_PRIVATE_COALITION_RESOURCE 0
#define LOMI_PRIVATE_COALITION_JETSAM 1
#define LOMI_PRIVATE_COALITION_NUM_TYPES 2
struct lomi_private_proc_pidcoalitioninfo {
    uint64_t coalition_id[LOMI_PRIVATE_COALITION_NUM_TYPES];
    uint64_t reserved1;
    uint64_t reserved2;
    uint64_t reserved3;
};
_Static_assert(sizeof(struct lomi_private_proc_pidcoalitioninfo) == 40, "pinned private ABI size");
_Static_assert(offsetof(struct lomi_private_proc_pidcoalitioninfo, reserved1) == 16, "pinned reserved1 offset");
_Static_assert(offsetof(struct lomi_private_proc_pidcoalitioninfo, reserved2) == 24, "pinned reserved2 offset");
_Static_assert(offsetof(struct lomi_private_proc_pidcoalitioninfo, reserved3) == 32, "pinned reserved3 offset");
// Only the source-supported resource-usage prefix is allocated and requested.
struct lomi_private_coalition_usage_prefix { uint64_t tasks_started; uint64_t tasks_exited; };
struct coalition_resource_usage; // Opaque complete private XNU type, not copied.
_Static_assert(sizeof(struct lomi_private_coalition_usage_prefix) == 16, "pinned resource counter prefix");
#endif
