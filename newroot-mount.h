/* Detached mount backend for supported layouts on modern kernels.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <stdint.h>

#include "bind-mount.h"

#ifdef HAVE_DETACHED_MOUNTS
/* The caller owns both descriptors and initializes them to -1. */
typedef struct
{
  int root_fd;
  int host_fd;
} SinglePivot;

/* Return an owned, empty root descriptor, or -1 if the kernel lacks support.
 * Permission errors and unexpected failures are fatal. Does not alter the
 * caller's mount tree; layout eligibility must be checked by the caller. */
int single_pivot_prepare (void);

int single_pivot_openat2 (int         root,
                          const char *path,
                          int         flags);
void single_pivot_bind (const SinglePivot *state,
                        bind_option_t      options,
                        int                source,
                        const char        *src_display,
                        int                target,
                        const char        *dest_display);
void single_pivot_mount_filesystem (const SinglePivot *state,
                                    const char        *type,
                                    unsigned           attrs,
                                    uint32_t           perms,
                                    size_t             size,
                                    int                target,
                                    const char        *dest_display);

/* Attach and enter the prepared root, detach the host root, and close both
 * owned descriptors. The host root must have been made recursively slave
 * before assembling bind mounts. */
void single_pivot_enter (SinglePivot *state,
                         const char  *base_path);
#endif /* HAVE_DETACHED_MOUNTS */
