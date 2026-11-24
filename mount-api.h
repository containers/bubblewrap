/* File-descriptor filesystem creation.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#pragma once

#include <stdint.h>
#include "utils.h"

/* Return an owned mount fd, or -1 with ENOSYS if an API is unavailable.
 * Other errors are fatal and identify the filesystem and destination. */
int create_detached_mount (const char *type, unsigned attrs, uint32_t perms,
                           size_t size, const char *dest_display);

/* Return false only if an API is unavailable, before attaching anything. */
bool mount_filesystem_fd (const char *type, unsigned attrs, uint32_t perms,
                          size_t size, int dest_fd, const char *dest_display);
