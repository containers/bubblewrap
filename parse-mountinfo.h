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