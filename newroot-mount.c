/* Detached mount backend for supported layouts on modern kernels.
 * SPDX-License-Identifier: LGPL-2.0-or-later */
#include "config.h"

#include <sys/mount.h>

#include "newroot-mount.h"
#include "mount-api.h"

#ifdef HAVE_DETACHED_MOUNTS
#include <linux/openat2.h>
#include <sys/syscall.h>

/* No path-based fallback: detached trees have no usable visible path. */
int
single_pivot_openat2 (int root, const char *path, int flags)
{
  struct open_how how = {
    .flags = flags | O_CLOEXEC | ((flags & O_PATH) ? 0 : O_NOCTTY),
    .resolve = RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
  };
  int fd;

  do
    fd = syscall (SYS_openat2, root, path[0] ? path : ".", &how, sizeof how);
  while (fd < 0 && (errno == EINTR || errno == EAGAIN));
  return fd;
}

static void
single_pivot_check_target (const SinglePivot *state, int target,
                           const char *src_display, const char *dest_display)
{
  struct stat target_st, root_st;

  if (fstat (target, &target_st) < 0 || fstat (state->root_fd, &root_st) < 0)
    die_with_error ("single-pivot: stat mount target %s", dest_display);
  /* Covering the retained root descriptor would make later lookups use the
   * covered tree. Reject all aliases, including /., // and parent symlinks. */
  if (target_st.st_dev == root_st.st_dev && target_st.st_ino == root_st.st_ino)
    die ("single-pivot does not support mounting %s on / (destination %s)",
         src_display, dest_display);
}

void
single_pivot_mount_filesystem (const SinglePivot *state, const char *type, unsigned attrs,
                               uint32_t perms, size_t size, int target, const char *dest_display)
{
  single_pivot_check_target (state, target, type, dest_display);
  if (!mount_filesystem_fd (type, attrs, perms, size, target, dest_display))
    die_with_error ("single-pivot: mount API unavailable for %s on %s", type, dest_display);
}

void
single_pivot_bind (const SinglePivot *state, bind_option_t options,
                   int source, const char *src_display, int target, const char *dest_display)
{
  single_pivot_check_target (state, target, src_display, dest_display);
  bind_mount_result result = bind_mount_fd_new (source, target, options | BIND_RECURSIVE);
  if (result != BIND_MOUNT_SUCCESS)
    die_with_bind_result (result, errno, dest_display,
                          "single-pivot: Can't bind mount %s on %s", src_display, dest_display);
}

/* EBADF/EINVAL are expected for these deliberately invalid descriptors.
 * Probes must not change the host or sandbox mount tree. An absent syscall
 * selects the existing backend before setup starts. Denials and unexpected
 * errors are fatal: never retry a failed mount operation with weaker rules. */
static bool
single_pivot_probe (int result, const char *name)
{
  if (result < 0 && errno == ENOSYS)
    return false;
  if (result < 0 && (errno == EBADF || errno == EINVAL))
    return true;
  die_with_error ("single-pivot: probe %s", name);
}

int
single_pivot_prepare (void)
{
  cleanup_fd int host = open ("/", O_PATH | O_DIRECTORY | O_CLOEXEC);

  if (host < 0)
    die_with_error ("single-pivot: probe host root");
  cleanup_fd int lookup = single_pivot_openat2 (host, "/", O_PATH | O_DIRECTORY);
  if (lookup < 0)
    {
      if (errno == ENOSYS)
        return -1;
      die_with_error ("single-pivot: probe openat2");
    }
  cleanup_fd int tree = create_detached_mount ("tmpfs", MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
                                               0755, 0, "/");
  if (tree < 0)
    return -1;
  struct mount_attr attr = { .attr_set = MOUNT_ATTR_NOSUID };
  bool present =
    single_pivot_probe (open_tree (-1, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
                                   AT_EMPTY_PATH | AT_RECURSIVE), "open_tree") &&
    single_pivot_probe (mount_setattr_wrapper (-1, "", AT_EMPTY_PATH | AT_RECURSIVE,
                                       &attr, sizeof attr), "mount_setattr") &&
    single_pivot_probe (move_mount (-1, "", -1, "", MOVE_MOUNT_F_EMPTY_PATH |
                                    MOVE_MOUNT_T_EMPTY_PATH), "move_mount");
  if (!present)
    return -1;

  /* Syscall presence is insufficient: older kernels reject cloning detached
   * mounts and attaching a mount to a detached target. Test both operations
   * on disposable clones, retaining the untouched tmpfs as the real root.
   * No user setup has run, so unsupported semantics can still select legacy.
   * Only known unsupported errors from these valid probes allow fallback;
   * permission denials and all failures after selection remain fatal. */
  cleanup_fd int clone = open_tree (tree, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
                                    AT_EMPTY_PATH | AT_RECURSIVE);
  if (clone < 0)
    {
      if (errno == EINVAL || errno == ENOSYS)
        return -1;
      die_with_error ("single-pivot: functional probe open_tree");
    }
  cleanup_fd int target = open_tree (tree, "", OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC |
                                     AT_EMPTY_PATH | AT_RECURSIVE);
  if (target < 0)
    die_with_error ("single-pivot: functional probe target clone");
  if (move_mount (clone, "", target, "",
                  MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH) < 0)
    {
      if (errno == EINVAL || errno == ENOSYS)
        return -1;
      die_with_error ("single-pivot: functional probe move_mount");
    }
  int root_fd = tree;
  tree = -1;
  return root_fd;
}

void
single_pivot_enter (SinglePivot *state, const char *base_path)
{
  if (move_mount (state->root_fd, "", AT_FDCWD, base_path,
                  MOVE_MOUNT_F_EMPTY_PATH) < 0)
    die_with_error ("single-pivot: attach final root at %s", base_path);
  if (fchdir (state->root_fd) < 0)
    die_with_error ("single-pivot: enter final root");
  if (pivot_root (".", ".") < 0)
    die_with_error ("single-pivot: pivot_root");
  if (fchdir (state->host_fd) < 0)
    die_with_error ("single-pivot: enter old root");
  if (umount2 (".", MNT_DETACH) < 0)
    die_with_error ("single-pivot: detach old root");
  if (chdir ("/") < 0)
    die_with_error ("single-pivot: return to final root");
  close (state->host_fd);
  close (state->root_fd);
  state->host_fd = state->root_fd = -1;
}
#endif /* HAVE_DETACHED_MOUNTS */
