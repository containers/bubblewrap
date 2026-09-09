/* File-descriptor filesystem creation.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#include "config.h"

#include <sys/mount.h>
#include "mount-api.h"

#ifdef HAVE_FILESYSTEM_MOUNTS
static bool
configure_filesystem (int context, unsigned command, const char *key,
                      const char *value, const char *type, const char *dest_display)
{
  if (fsconfig (context, command, key, value, 0) == 0)
    return true;
  if (errno == ENOSYS)
    return false;
  die_with_error ("fsconfig %s for %s on %s", key ? key : "create", type, dest_display);
}
#endif

int
create_detached_mount (const char *type, unsigned attrs, uint32_t perms,
                       size_t size, const char *dest_display)
{
#ifdef HAVE_FILESYSTEM_MOUNTS
  cleanup_fd int context = fsopen (type, FSOPEN_CLOEXEC);

  if (context < 0)
    {
      if (errno == ENOSYS)
        return -1;
      die_with_error ("fsopen %s for %s", type, dest_display);
    }
  if (strcmp (type, "tmpfs") == 0)
    {
      cleanup_free char *mode = xasprintf ("%#o", perms);
      if (!configure_filesystem (context, FSCONFIG_SET_STRING, "mode", mode, type, dest_display))
        return -1;
      if (size)
        {
          cleanup_free char *bytes = xasprintf ("%zu", size);
          if (!configure_filesystem (context, FSCONFIG_SET_STRING, "size", bytes, type, dest_display))
            return -1;
        }
    }
  if (!configure_filesystem (context, FSCONFIG_CMD_CREATE, NULL, NULL, type, dest_display))
    return -1;
  int tree = fsmount (context, FSMOUNT_CLOEXEC, attrs);
  if (tree < 0 && errno != ENOSYS)
    die_with_error ("fsmount %s on %s", type, dest_display);
  return tree;
#else
  (void) type;
  (void) attrs;
  (void) perms;
  (void) size;
  (void) dest_display;
  errno = ENOSYS;
  return -1;
#endif
}

bool
mount_filesystem_fd (const char *type, unsigned attrs, uint32_t perms,
                     size_t size, int dest_fd, const char *dest_display)
{
#ifdef HAVE_FILESYSTEM_MOUNTS
  cleanup_fd int tree = create_detached_mount (type, attrs, perms, size, dest_display);

  if (tree < 0)
    return false;
  if (move_mount (tree, "", dest_fd, "",
                  MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) == 0)
    return true;
  if (errno == ENOSYS)
    return false;
  die_with_error ("move_mount %s on %s", type, dest_display);
#else
  (void) type;
  (void) attrs;
  (void) perms;
  (void) size;
  (void) dest_fd;
  (void) dest_display;
  return false;
#endif
}
