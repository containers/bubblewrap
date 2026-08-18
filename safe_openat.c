/*
 * This code was copied from:
 *
 * crun - OCI runtime written in C
 *
 * Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
 * crun is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * crun is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with crun.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "config.h"

#include "utils.h"
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#ifndef __set_errno
#define __set_errno(val) ((errno) = (val))
#endif

bool opt_force_openat_fallback = false;

#if ASSUMED_KERNEL < BWRAP_KERNEL_VERSION (5, 6, 0)
#  define USE_OPENAT_FALLBACK 1
#else
#  define USE_OPENAT_FALLBACK 0
#endif

#define cleanup_close cleanup_fd

#define LIKELY(x) __builtin_expect ((x), 1)
#define UNLIKELY(x) __builtin_expect ((x), 0)

/* Adapted from systemd.  Include space for the NUL byte.  */
#define DECIMAL_STR_MAX(type)                                        \
  ((size_t) 2U + (sizeof (type) <= 1 ? 3U : sizeof (type) <= 2 ? 5U  \
                                        : sizeof (type) <= 4   ? 10U \
                                        : sizeof (type) <= 8   ? 20U \
                                                               : sizeof (int[-2 * (sizeof (type) > 8)])))

#define _STRLEN(s) (sizeof (s) - 1)

/* openat2 resolve flags */
#ifndef RESOLVE_IN_ROOT
#  define RESOLVE_IN_ROOT 0x10
#endif
#ifndef RESOLVE_NO_MAGICLINKS
#  define RESOLVE_NO_MAGICLINKS 0x02
#endif

/* Structures for syscalls */
struct openat2_open_how
{
  uint64_t flags;
  uint64_t mode;
  uint64_t resolve;
};

static inline int
syscall_openat2 (int dirfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve)
{
#ifdef __NR_openat2
  struct openat2_open_how how = {
    .flags = flags,
    .mode = mode,
    .resolve = resolve,
  };
  return (int) syscall (__NR_openat2, dirfd, path, &how, sizeof (how), 0);
#else
  (void) dirfd;
  (void) path;
  (void) flags;
  (void) mode;
  (void) resolve;
  errno = ENOSYS;
  return -1;
#endif
}

#define consume_slashes(t) \
  ({                       \
    typeof (t) _s = (t);   \
    while (*_s == '/')     \
      _s++;                \
    _s;                    \
  })


/* _STRLEN("self") < DECIMAL_STR_MAX (pid_t), so we don't need to calculate the length of both.  */
#define PROC_PID_FD_STRLEN (_STRLEN ("/proc/") + DECIMAL_STR_MAX (pid_t) \
                            + _STRLEN ("/fd/") + DECIMAL_STR_MAX (int))

/* A buffer long enough to hold either /proc/self/fd/$FD or a /proc/$PID/fd/$FD path.  */
typedef char proc_fd_path_t[PROC_PID_FD_STRLEN];

static inline void
get_proc_fd_path (proc_fd_path_t path, pid_t pid, int fd)
{
  const size_t max_len = sizeof (proc_fd_path_t);
  size_t n;

  if (pid)
    n = snprintf (path, max_len, "/proc/%d/fd/%d", pid, fd);
  else
    n = snprintf (path, max_len, "/proc/self/fd/%d", fd);

  if (UNLIKELY (n >= max_len))
    abort ();
}

static inline void
get_proc_self_fd_path (proc_fd_path_t path, int fd)
{
  get_proc_fd_path (path, 0, fd);
}


static int
check_fd_is_path (const char *path, int fd, UNUSED const char *fdname)
{
  proc_fd_path_t fdpath;
  size_t path_len = strlen (path);
  char link[PATH_MAX];
  int ret;

  get_proc_self_fd_path (fdpath, fd);
  ret = TEMP_FAILURE_RETRY (readlink (fdpath, link, sizeof (link)));
  if (UNLIKELY (ret < 0))
    return -1;

  if (((size_t) ret) != path_len || memcmp (link, path, path_len))
    {
      // crun_make_error (err, 0, "target `%s` does not point to the directory `%s`", fdname, path);
      __set_errno(ENOTDIR);
      return -1;
    }

  return 0;
}

#if USE_OPENAT_FALLBACK
static int
check_fd_under_path (const char *rootfs, size_t rootfslen, int fd, UNUSED const char *fdname)
{
  proc_fd_path_t fdpath;
  char link[PATH_MAX];
  int ret;

  /* Every path is under "/", there is nothing to verify.  The check below
     would reject any path since it expects a '/' right after the rootfs.  */
  if (rootfslen == 0 || (rootfslen == 1 && rootfs[0] == '/'))
    return 0;

  get_proc_self_fd_path (fdpath, fd);
  ret = TEMP_FAILURE_RETRY (readlink (fdpath, link, sizeof (link)));
  if (UNLIKELY (ret < 0))
    return -1;

  if (((size_t) ret) <= rootfslen || memcmp (link, rootfs, rootfslen) != 0 || link[rootfslen] != '/')
    {
      // crun_make_error (err, 0, "target `%s` not under the directory `%s`", fdname, rootfs);
      __set_errno(ENOTDIR);
      return -1;
    }

  return 0;
}
#endif

/* DIRFD must be a file descriptor for ROOTFS itself: PATH is resolved
   against ROOTFS and the result is then opened relatively to DIRFD.  */
static int
safe_openat_fallback (int dirfd, const char *rootfs, const char *path, int flags,
                      int mode)
{
#if !USE_OPENAT_FALLBACK
  (void) dirfd;
  (void) rootfs;
  (void) path;
  (void) flags;
  (void) mode;
  errno = ENOSYS;
  return -1;
#else
  cleanup_free char *parent_path = NULL;
  const char *last_component = NULL;
  const char *orig_path = path;
  const char *path_in_chroot;
  cleanup_close int fd = -1;
  char resolved[PATH_MAX];
  char buffer[PATH_MAX];
  size_t rootfs_len = is_empty_string (rootfs) ? 0 : strlen (rootfs);
  int ret;

  /* chroot_realpath resolves the last component as well, so when O_NOFOLLOW
     is requested resolve only the parent directory and let openat(2) deal
     with the last component, otherwise a symlink would be followed even
     though the caller asked not to.  */
  if (flags & O_NOFOLLOW)
    {
      char *sep;

      parent_path = xstrdup (path);
      sep = strrchr (parent_path, '/');
      if (sep == NULL)
        {
          /* No parent directory, the entire path is the last component.  */
          last_component = path;
          parent_path[0] = '\0';
        }
      else if (sep[1] != '\0')
        {
          *sep = '\0';
          last_component = path + (sep - parent_path) + 1;
        }
      /* A trailing '/' forces the symlink to be resolved anyway, so in that
         case keep resolving the entire path.  */

      if (last_component)
        path = parent_path;
    }

  path_in_chroot = chroot_realpath (rootfs, path, buffer);
  if (path_in_chroot == NULL)
    return -1;

  /* When rootfs is "/" or not set, chroot_realpath returns the path
     unchanged, so drop the prefix only when it is really there.  */
  if (rootfs_len > 0 && strncmp (path_in_chroot, rootfs, rootfs_len) == 0)
    path_in_chroot += rootfs_len;
  path_in_chroot = consume_slashes (path_in_chroot);

  if (last_component)
    {
      ret = snprintf (resolved, sizeof (resolved), "%s%s%s", path_in_chroot,
                      path_in_chroot[0] == '\0' ? "" : "/", last_component);
      if (UNLIKELY (ret >= (int) sizeof (resolved)))
        {
          __set_errno (ENAMETOOLONG);
          return -1;
        }

      path_in_chroot = resolved;
    }

  /* If the path is empty we are at the root, dup the dirfd itself.  */
  if (path_in_chroot[0] == '\0')
    {
      ret = dup (dirfd);
      if (UNLIKELY (ret < 0))
        return -1;
      return ret;
    }

  ret = openat (dirfd, path_in_chroot, flags, mode);
  if (UNLIKELY (ret < 0))
    return -1;

  fd = ret;

  ret = check_fd_under_path (rootfs, rootfs_len, fd, orig_path);
  if (UNLIKELY (ret < 0))
    return ret;

  ret = fd;
  fd = -1;
  return ret;
#endif /* USE_OPENAT_FALLBACK */
}

int
safe_openat (int dirfd, const char *rootfs, const char *path, int flags, int mode)
{
  static bool openat2_supported = true;
  int ret;

  if (is_empty_string (path))
    {
      cleanup_close int fd = -1;

      fd = open (rootfs, flags, mode);
      if (UNLIKELY (fd < 0))
        return -1;

      /* Skip the readlink-based check when opening the root
         directory itself (rootfs="/", path="").  After pivot_root,
         "/" can only refer to the container root so the readlink
         verification is redundant, and after setns the /proc-based
         readlink may not be reachable by path yet.  */
      if (rootfs[0] != '/' || rootfs[1] != '\0')
        {
          ret = check_fd_is_path (rootfs, fd, path);
          if (UNLIKELY (ret < 0))
            return ret;
        }

      ret = fd;
      fd = -1;
      return ret;
    }

  if (openat2_supported && !opt_force_openat_fallback)
    {
    repeat:
      ret = syscall_openat2 (dirfd, path, flags, mode, RESOLVE_IN_ROOT|RESOLVE_NO_MAGICLINKS);
      if (UNLIKELY (ret < 0))
        {
          if (errno == EINTR || errno == EAGAIN)
            goto repeat;
          if (errno == ENOSYS)
            openat2_supported = false;
          if (errno == ENOSYS || errno == EINVAL || errno == EPERM)
            return safe_openat_fallback (dirfd, rootfs, path, flags, mode);

          return -1;
        }

      return ret;
    }

  return safe_openat_fallback (dirfd, rootfs, path, flags, mode);
}
