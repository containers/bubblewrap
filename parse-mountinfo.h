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
#include "sys/mount.h"

/// ---------------------------------------------------------------------------------------------------------------------
/// Types declarations

typedef struct MountInfo MountInfo;
struct MountInfo {
    char *mountpoint;
    unsigned long options;
};

typedef MountInfo *MountTab;

/// ---------------------------------------------------------------------------------------------------------------------
/// Safety

#define cleanup_mount_tab __attribute__((cleanup (cleanup_mount_tabp)))

void
cleanup_mount_tabp (void *p);

void
mount_tab_free (MountTab tab);

/// ---------------------------------------------------------------------------------------------------------------------
/// Public functions

MountTab
parse_mountinfo (int  proc_fd,
                 const char *root_mount);