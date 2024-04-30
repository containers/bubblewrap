/* bubblewrap
 * Copyright (C) 2016 Alexander Larsson
 * SPDX-License-Identifier: LGPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#pragma once

#include "utils.h"

#include "parse-mountinfo.h"

/// --------------------------------------------------------------------------------------------------------------------
/// Type definitions

typedef enum {
    BIND_READONLY = (1 << 0),
    BIND_DEVICES = (1 << 2),
} bind_option_t;

typedef enum {
    BIND_MOUNT_SUCCESS = 0,
    BIND_MOUNT_ERROR_MOUNT,
    BIND_MOUNT_ERROR_REALPATH_DEST,
    BIND_MOUNT_ERROR_REOPEN_DEST,
    BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD,
    BIND_MOUNT_ERROR_FIND_DEST_MOUNT,
    BIND_MOUNT_ERROR_REMOUNT,
} bind_mount_result;

typedef struct _BindOp BindOp;

struct _BindOp {
    char *dest;
    bind_option_t options;
    BindOp *next;
};

/// --------------------------------------------------------------------------------------------------------------------
/// Functions

bind_mount_result
bind_mount_fixup (int proc_fd, BindOp *bind_ops, size_t bind_ops_quantity, char **failing_path);

void die_with_bind_result (bind_mount_result res,
                           int saved_errno,
                           const char *failing_path,
                           const char *format,
                           ...)
__attribute__((__noreturn__))
__attribute__((format (printf, 4, 5)));
