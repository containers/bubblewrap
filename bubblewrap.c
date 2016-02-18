/* bubblewrap
 * Copyright (C) 2016 Alexander Larsson
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "config.h"

#include <poll.h>
#include <sched.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include "utils.h"
#include "network.h"
#include "bind-mount.h"

/* Globals to avoid having to use getuid(), since the uid/gid changes during runtime */
static uid_t uid;
static gid_t gid;
static bool is_privileged;
static const char *argv0;
static const char *host_tty_dev;
static int proc_fd = -1;
struct passwd *pwuid;
struct group *grgid;

typedef enum {
  SETUP_BIND_MOUNT_DIR,
  SETUP_RO_BIND_MOUNT_DIR,
  SETUP_BIND_MOUNT,
  SETUP_RO_BIND_MOUNT,
  SETUP_DEV_BIND_MOUNT,
  SETUP_MOUNT_PROC,
  SETUP_MOUNT_DEV,
  SETUP_MAKE_DIR,
  SETUP_MAKE_FILE,
  SETUP_MAKE_SYMLINK,
  SETUP_MAKE_PASSWD,
  SETUP_MAKE_GROUP,
} SetupOpType;

typedef struct _SetupOp SetupOp;

struct _SetupOp {
  SetupOpType type;
  const char *source;
  const char *dest;
  int fd;
  SetupOp *next;
};

typedef struct _LockFile LockFile;

struct _LockFile {
  const char *path;
  LockFile *next;
};

static SetupOp *ops = NULL;
static SetupOp *last_op = NULL;
static LockFile *lock_files = NULL;
static LockFile *last_lock_file = NULL;

enum {
  PRIV_SEP_OP_DONE,
  PRIV_SEP_OP_BIND_MOUNT,
  PRIV_SEP_OP_PROC_MOUNT,
  PRIV_SEP_OP_TMPFS_MOUNT,
  PRIV_SEP_OP_DEVPTS_MOUNT,
};

typedef struct {
  uint32_t op;
  uint32_t flags;
  uint32_t arg1_offset;
  uint32_t arg2_offset;
} PrivSepOp;

static SetupOp *
setup_op_new (SetupOpType type)
{
  SetupOp *op = xcalloc (sizeof (SetupOp));

  op->type = type;
  op->fd = -1;
  if (last_op != NULL)
    last_op->next = op;
  else
    ops = op;

  last_op = op;
  return op;
}

static LockFile *
lock_file_new (const char *path)
{
  LockFile *lock = xcalloc (sizeof (LockFile));

  lock->path = path;
  if (last_lock_file != NULL)
    last_lock_file->next = lock;
  else
    lock_files = lock;

  last_lock_file = lock;
  return lock;
}


static void
usage ()
{
  fprintf (stderr, "usage: %s [OPTIONS...] COMMAND [ARGS...]\n\n", argv0);

  fprintf (stderr,
           "	--help			     Print this help\n"
           "	--version		     Print version\n"
           "	--unshare-ipc		     Create new ipc namespace\n"
           "	--unshare-pid		     Create new pid namespace\n"
           "	--unshare-net		     Create new network namespace\n"
           "	--unshare-uts		     Create new uts namespace\n"
           "	--chdir DIR		     Change directory to DIR\n"
           "	--mount-bind SRC DEST	     Bind mount the host path SRC on DEST\n"
           "	--mount-dev-bind SRC DEST    Bind mount the host path SRC on DEST, allowing device access\n"
           "	--mount-ro-bind SRC DEST     Bind mount the host path SRC readonly on DEST\n"
           "	--mount-bind-dir SRC DEST    Bind mount the files in host dir SRC into to DEST (unless target exists)\n"
           "	--mount-ro-bind-dir SRC DEST Bind mount the files in host dir SRC readonly into to DEST (unless target exists)\n"
           "	--mount-proc DEST	     Mount procfs on DEST\n"
           "	--mount-dev DEST	     Mount new dev on DEST\n"
           "	--make-dir DEST		     Create dir at DEST\n"
           "	--make-file FD DEST	     Copy from FD to dest DEST\n"
           "	--make-symlink SRC DEST	     Create symlink at DEST with target SRC\n"
           "	--make-passwd DEST	     Create trivial /etc/passwd file at DEST\n"
           "	--make-group DEST	     Create trivial /etc/group file at DEST\n"
           "	--lock-file DEST	     Take a lock on DEST while sandbox is running\n"
           "	--sync-fd FD		     Keep this fd open while sandbox is running\n"
           );
  exit (1);
}

static void
block_sigchild (void)
{
  sigset_t mask;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_BLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");
}

static void
unblock_sigchild (void)
{
  sigset_t mask;

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  if (sigprocmask (SIG_UNBLOCK, &mask, NULL) == -1)
    die_with_error ("sigprocmask");
}

/* Closes all fd:s except 0,1,2 and the passed in array of extra fds */
static int
close_extra_fds (void *data, int fd)
{
  int *extra_fds = (int *)data;
  int i;

  for (i = 0; extra_fds[i] != -1; i++)
    if (fd == extra_fds[i])
      return 0;

  if (fd <= 2)
    return 0;

  close (fd);
  return 0;
}

/* This stays around for as long as the initial process in the app does
 * and when that exits it exits, propagating the exit status. We do this
 * by having pid 1 in the sandbox detect this exit and tell the monitor
 * the exit status via a eventfd. We also track the exit of the sandbox
 * pid 1 via a signalfd for SIGCHLD, and exit with an error in this case.
 * This is to catch e.g. problems during setup. */
static void
monitor_child (int event_fd)
{
  int res;
  uint64_t val;
  ssize_t s;
  int signal_fd;
  sigset_t mask;
  struct pollfd fds[2];
  int num_fds;
  struct signalfd_siginfo fdsi;
  int dont_close[] = { event_fd, -1 };

  /* Close all extra fds in the monitoring process.
     Any passed in fds have been passed on to the child anyway. */
  fdwalk (proc_fd, close_extra_fds, dont_close);

  sigemptyset (&mask);
  sigaddset (&mask, SIGCHLD);

  signal_fd = signalfd (-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
  if (signal_fd == -1)
    die_with_error ("Can't create signalfd");

  num_fds = 1;
  fds[0].fd = signal_fd;
  fds[0].events = POLLIN;
  if (event_fd != -1)
    {
      fds[1].fd = event_fd;
      fds[1].events = POLLIN;
      num_fds++;
    }

  while (1)
    {
      fds[0].revents = fds[1].revents = 0;
      res = poll (fds, num_fds, -1);
      if (res == -1 && errno != EINTR)
        die_with_error ("poll");

      /* Always read from the eventfd first, if pid 2 died then pid 1 often
       * dies too, and we could race, reporting that first and we'd lose
       * the real exit status. */
      if (event_fd != -1)
        {
          s = read (event_fd, &val, 8);
          if (s == -1 && errno != EINTR && errno != EAGAIN)
            die_with_error ("read eventfd");
          else if (s == 8)
            exit ((int)val - 1);
        }

      s = read (signal_fd, &fdsi, sizeof (struct signalfd_siginfo));
      if (s == -1 && errno != EINTR && errno != EAGAIN)
        die_with_error ("read signalfd");
      else if (s == sizeof(struct signalfd_siginfo))
        {
          if (fdsi.ssi_signo != SIGCHLD)
            die ("Read unexpected signal\n");
          exit (1);
        }
    }
}

/* This is pid 1 in the app sandbox. It is needed because we're using
 * pid namespaces, and someone has to reap zombies in it. We also detect
 * when the initial process (pid 2) dies and report its exit status to
 * the monitor so that it can return it to the original spawner.
 *
 * When there are no other processes in the sandbox the wait will return
 * ECHILD, and we then exit pid 1 to clean up the sandbox. */
static int
do_init (int event_fd, pid_t initial_pid)
{
  int initial_exit_status = 1;
  LockFile *lock;

  for (lock = lock_files; lock != NULL; lock = lock->next)
    {
      int fd = open (lock->path, O_RDONLY | O_CLOEXEC);
      struct flock l = {0};

      if (fd == -1)
        die_with_error ("Unable to open lock file %s", lock->path);

      l.l_type = F_RDLCK;
      l.l_whence = SEEK_SET;
      l.l_start = 0;
      l.l_len = 0;

      if (fcntl (fd, F_SETLK, &l) < 0)
        die_with_error ("Unable to lock file %s", lock->path);

      /* Keep fd open to hang on to lock */
    }

  while (TRUE)
    {
      pid_t child;
      int status;

      child = wait (&status);
      if (child == initial_pid)
        {
          uint64_t val;

          if (WIFEXITED (status))
            initial_exit_status = WEXITSTATUS(status);

          val = initial_exit_status + 1;
          write (event_fd, &val, 8);
        }

      if (child == -1 && errno != EINTR)
        {
          if (errno != ECHILD)
            die_with_error ("init wait()");
          break;
        }
    }

  return initial_exit_status;
}

#define REQUIRED_CAPS (CAP_TO_MASK(CAP_SYS_ADMIN)|CAP_TO_MASK(CAP_SYS_CHROOT))

static void
acquire_caps (void)
{
  struct __user_cap_header_struct hdr;
  struct __user_cap_data_struct data;

  memset (&hdr, 0, sizeof(hdr));
  hdr.version = _LINUX_CAPABILITY_VERSION;

  if (capget (&hdr, &data)  < 0)
    die_with_error ("capget failed");

  if (((data.effective & REQUIRED_CAPS) == REQUIRED_CAPS) &&
      ((data.permitted & REQUIRED_CAPS) == REQUIRED_CAPS))
    is_privileged = TRUE;

  if (getuid () != geteuid ())
    {
      /* Tell kernel not clear capabilities when dropping root */
      if (prctl (PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
        die_with_error ("prctl(PR_SET_KEEPCAPS) failed");

      /* Drop root uid, but retain the required permitted caps */
      if (setuid (getuid ()) < 0)
        die_with_error ("unable to drop privs");
    }

  if (is_privileged)
    {
      memset (&hdr, 0, sizeof(hdr));
      hdr.version = _LINUX_CAPABILITY_VERSION;

      /* Drop all non-require capabilities */
      data.effective = REQUIRED_CAPS;
      data.permitted = REQUIRED_CAPS;
      data.inheritable = 0;
      if (capset (&hdr, &data) < 0)
        die_with_error ("capset failed");
    }
  /* Else, we try unprivileged user namespaces */
}

static void
drop_caps (void)
{
  struct __user_cap_header_struct hdr;
  struct __user_cap_data_struct data;

  if (!is_privileged)
    return;

  memset (&hdr, 0, sizeof(hdr));
  hdr.version = _LINUX_CAPABILITY_VERSION;
  data.effective = 0;
  data.permitted = 0;
  data.inheritable = 0;

  if (capset (&hdr, &data) < 0)
    die_with_error ("capset failed");

  if (prctl (PR_SET_DUMPABLE, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_DUMPABLE) failed");
}

static char *
get_newroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/newroot/", path);
}

static char *
get_oldroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/oldroot/", path);
}

static void
write_uid_gid_map (uid_t sandbox_uid,
                   uid_t parent_uid,
                   uid_t sandbox_gid,
                   uid_t parent_gid,
                   bool deny_groups)
{
  cleanup_free char *uid_map = NULL;
  cleanup_free char *gid_map = NULL;

  uid_map = strdup_printf ("%d %d 1\n", sandbox_uid, parent_uid);
  if (write_file_at (proc_fd, "self/uid_map", uid_map) != 0)
    die_with_error ("setting up uid map");

  if (deny_groups &&
      write_file_at (proc_fd, "self/setgroups", "deny\n") != 0)
    die_with_error ("error writing to setgroups");

  gid_map = strdup_printf ("%d %d 1\n", sandbox_gid, parent_gid);
  if (write_file_at (proc_fd, "self/gid_map", gid_map) != 0)
    die_with_error ("setting up gid map");
}

static void
privileged_op (int privileged_op_socket,
               uint32_t op,
               uint32_t flags,
               const char *arg1,
               const char *arg2)
{
  if (privileged_op_socket != -1)
    {
      uint32_t buffer[2048];  /* 8k, but is int32 to guarantee nice alignment */
      PrivSepOp *op_buffer = (PrivSepOp *)buffer;
      size_t buffer_size = sizeof (PrivSepOp);
      uint32_t arg1_offset = 0, arg2_offset = 0;
      if (arg1 != NULL)
        {
          arg1_offset = buffer_size;
          buffer_size += strlen (arg1) + 1;
        }
      if (arg2 != NULL)
        {
          arg2_offset = buffer_size;
          buffer_size += strlen (arg2) + 1;
        }

      if (buffer_size >= sizeof (buffer))
        die ("privilege separation operation to large");

      op_buffer->op = op;
      op_buffer->flags = flags;
      op_buffer->arg1_offset = arg1_offset;
      op_buffer->arg2_offset = arg2_offset;
      if (arg1 != NULL)
        strcpy ((char *)buffer + arg1_offset, arg1);
      if (arg2 != NULL)
        strcpy ((char *)buffer + arg2_offset, arg2);

      if (write (privileged_op_socket, buffer, buffer_size) != buffer_size)
        die ("Can't write to privileged_op_socket");

      if (read (privileged_op_socket, buffer, 1) != 1)
        die ("Can't read from privileged_op_socket");

      return;
    }

  switch (op)
    {
    case PRIV_SEP_OP_DONE:
      break;
    case PRIV_SEP_OP_BIND_MOUNT:
      /* We always bind directories recursively, otherwise this would let us
         access files that are otherwise covered on the host */
      if (bind_mount (proc_fd, arg1, arg2, BIND_RECURSIVE | flags) != 0)
        die_with_error ("Can't bind mount %s on %s", arg1, arg2);
      break;
    case PRIV_SEP_OP_PROC_MOUNT:
      if (mount ("proc", arg1, "proc", MS_MGC_VAL|MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) != 0)
        die_with_error ("Can't mount proc on %s", arg1);
      break;
    case PRIV_SEP_OP_TMPFS_MOUNT:
      if (mount ("tmpfs", arg1, "tmpfs", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC, "mode=0755") != 0)
        die_with_error ("Can't mount tmpfs on %s", arg1);
      break;
    case PRIV_SEP_OP_DEVPTS_MOUNT:
      if (mount ("devpts", arg1, "devpts", MS_MGC_VAL | MS_NOSUID | MS_NOEXEC,
                 "newinstance,ptmxmode=0666,mode=620") != 0)
        die_with_error ("Can't mount devpts on %s", arg1);
      break;
    default:
      die ("Unexpected privileged op %d", op);
    }
}

static void
setup_newroot (bool unshare_pid,
               int privileged_op_socket)
{
  SetupOp *op;

  for (op = ops; op != NULL; op = op->next)
    {
      cleanup_free char *source = NULL;
      cleanup_free char *dest = NULL;
      int source_mode = 0;
      int i;

      if (op->source &&
          op->type != SETUP_MAKE_SYMLINK)
        {
          source = get_oldroot_path (op->source);
          source_mode = get_file_mode (source);
          if (source_mode < 0)
            die_with_error ("Can't get type of source %s", op->source);
        }

      if (op->dest)
        {
          dest = get_newroot_path (op->dest);
          if (mkdir_with_parents (dest, 0755, FALSE) != 0)
            die_with_error ("Can't mkdir parents for %s", op->dest);
        }

      switch (op->type) {
      case SETUP_RO_BIND_MOUNT:
      case SETUP_DEV_BIND_MOUNT:
      case SETUP_BIND_MOUNT:
        if (source_mode == S_IFDIR)
          {
            if (mkdir (dest, 0755) != 0 && errno != EEXIST)
              die_with_error ("Can't mkdir %s", op->dest);
          }
        else
          {
            if (create_file (dest, 0666, NULL) != 0 && errno != EEXIST)
              die_with_error ("Can't create file at %s", op->dest);
          }

        privileged_op (privileged_op_socket,
                       PRIV_SEP_OP_BIND_MOUNT,
                       (op->type == SETUP_RO_BIND_MOUNT ? BIND_READONLY : 0) |
                       (op->type == SETUP_DEV_BIND_MOUNT ? BIND_DEVICES : 0),
                       source, dest);
        break;

      case SETUP_RO_BIND_MOUNT_DIR:
      case SETUP_BIND_MOUNT_DIR:
        if (source_mode != S_IFDIR)
          die_with_error ("Source %s is not a directory", op->dest);

        /* Ensure the target dir exists */
        if (mkdir (dest, 0755) != 0 && errno != EEXIST)
          die_with_error ("Can't mkdir %s", op->dest);

        {
          DIR *dir;
          struct dirent *dirent;

          dir = opendir (source);
          if (dir == NULL)
            die_with_error ("Can't opendir %s", op->source);

          while ((dirent = readdir (dir)))
            {
              cleanup_free char *dst_path = NULL;
              cleanup_free char *src_path = NULL;
              struct stat st;

              dst_path = strconcat3 (dest, "/", dirent->d_name);
              if (lstat (dst_path, &st) == 0)
                continue; /* Already exists, don't overwrite */

              src_path = strconcat3 (source, "/", dirent->d_name);
              if (lstat (src_path, &st) != 0)
                die_with_error ("can't get info for %s", src_path);;

              /* For symlinks we copy the actual symlink value, because
               * some things may rely on the file type */
              if (S_ISLNK (st.st_mode))
                {
                  cleanup_free char *target = NULL;
                  ssize_t r;

                  target = xmalloc (st.st_size + 1);
                  r = readlink (src_path, target, st.st_size);
                  if (r == -1)
                    die_with_error ("readlink %s", dst_path);
                  target[r] = 0;

                  if (symlink (target, dst_path) != 0)
                    die_with_error ("symlink %s", dst_path);
                }
              else
                {
                  if (S_ISDIR(st.st_mode))
                    {
                      if (mkdir (dst_path, 0755) != 0)
                        die_with_error ("Can't mkdir %s", dst_path);
                    }
                  else
                    {
                      if (create_file (dst_path, 0666, NULL) != 0)
                        die_with_error ("Can't create file at %s", dst_path);
                    }

                  privileged_op (privileged_op_socket,
                                 PRIV_SEP_OP_BIND_MOUNT,
                                 (op->type == SETUP_RO_BIND_MOUNT_DIR ? BIND_READONLY : 0),
                                 src_path, dst_path);
                }
            }
        }

        break;

      case SETUP_MOUNT_PROC:
        if (mkdir (dest, 0755) != 0 && errno != EEXIST)
          die_with_error ("Can't mkdir %s", op->dest);

        if (unshare_pid)
          {
            /* Our own procfs */
            privileged_op (privileged_op_socket,
                           PRIV_SEP_OP_PROC_MOUNT, 0,
                           dest, NULL);
          }
        else
          {
            /* Use system procfs, as we share pid namespace anyway */
            privileged_op (privileged_op_socket,
                           PRIV_SEP_OP_BIND_MOUNT, 0,
                           "oldroot/proc", dest);
          }

        /* There are a bunch of weird old subdirs of /proc that could potentially be
           problematic (for instance /proc/sysrq-trigger lets you shut down the machine
           if you have write access). We should not have access to these as a non-privileged
           user, but lets cover them anyway just to make sure */
        const char *cover_proc_dirs[] = { "sys", "sysrq-trigger", "irq", "bus" };
        for (i = 0; i < N_ELEMENTS (cover_proc_dirs); i++)
          {
            cleanup_free char *subdir = strconcat3 (dest, "/", cover_proc_dirs[i]);
            privileged_op (privileged_op_socket,
                           PRIV_SEP_OP_BIND_MOUNT, BIND_READONLY,
                           subdir, subdir);
          }

        break;

      case SETUP_MOUNT_DEV:
        if (mkdir (dest, 0755) != 0 && errno != EEXIST)
          die_with_error ("Can't mkdir %s", op->dest);

        privileged_op (privileged_op_socket,
                       PRIV_SEP_OP_TMPFS_MOUNT, 0,
                       dest, NULL);

        static const char *const devnodes[] = { "null", "zero", "full", "random", "urandom", "tty" };
        for (i = 0; i < N_ELEMENTS (devnodes); i++)
          {
            cleanup_free char *node_dest = strconcat3 (dest, "/", devnodes[i]);
            cleanup_free char *node_src = strconcat ("/oldroot/dev/", devnodes[i]);
            if (create_file (node_dest, 0666, NULL) != 0)
              die_with_error ("Can't create file %s/%s", op->dest, devnodes[i]);
            privileged_op (privileged_op_socket,
                           PRIV_SEP_OP_BIND_MOUNT, 0,
                           node_src, node_dest);
          }

        static const char *const stdionodes[] = { "stdin", "stdout", "stderr" };
        for (i = 0; i < N_ELEMENTS (stdionodes); i++)
          {
            cleanup_free char *target = strdup_printf ("/proc/self/fd/%d", i);
            cleanup_free char *node_dest = strconcat3 (dest, "/", stdionodes[i]);
            if (symlink (target, node_dest) < 0)
              die_with_error ("Can't create symlink %s/%s", op->dest, stdionodes[i]);
          }

        {
          cleanup_free char *pts = strconcat (dest, "/pts");
          cleanup_free char *ptmx = strconcat (dest, "/ptmx");
          cleanup_free char *shm = strconcat (dest, "/shm");

          if (mkdir (shm, 0755) == -1)
            die_with_error ("Can't create %s/shm", op->dest);

          if (mkdir (pts, 0755) == -1)
            die_with_error ("Can't create %s/devpts", op->dest);
          privileged_op (privileged_op_socket,
                         PRIV_SEP_OP_DEVPTS_MOUNT, 0,
                         pts, NULL);

          if (symlink ("pts/ptmx", ptmx) != 0)
            die_with_error ("Can't make symlink at %s/ptmx", op->dest);
        }

        /* If stdout is a tty, that means the sandbox can write to the
           outside-sandbox tty. In that case we also create a /dev/console
           that points to this tty device. This should not cause any more
           access than we already have, and it makes ttyname() work in the
           sandbox. */
        if (host_tty_dev != NULL && *host_tty_dev != 0)
          {
            cleanup_free char *src_tty_dev = strconcat ("/oldroot", host_tty_dev);
            cleanup_free char *dest_console = strconcat (dest, "/console");

            if (create_file (dest_console, 0666, NULL) != 0)
              die_with_error ("creating %s/console", op->dest);

            privileged_op (privileged_op_socket,
                           PRIV_SEP_OP_BIND_MOUNT, BIND_DEVICES,
                           src_tty_dev, dest_console);
          }

        break;

      case SETUP_MAKE_DIR:
        if (mkdir (dest, 0755) != 0 && errno != EEXIST)
          die_with_error ("Can't mkdir %s", op->dest);

        break;

      case SETUP_MAKE_FILE:
        {
          cleanup_fd int dest_fd = -1;

          dest_fd = creat (dest, 0666);
          if (dest_fd == -1)
            die_with_error ("Can't create file %s", op->dest);

          if (copy_file_data (op->fd, dest_fd) != 0)
            die_with_error ("Can't write data to file %s", op->dest);

          close (op->fd);
        }
        break;

      case SETUP_MAKE_SYMLINK:
        if (symlink (op->source, dest) != 0)
          die_with_error ("Can't make symlink at %s", op->dest);
        break;

      case SETUP_MAKE_PASSWD:
        {
          cleanup_free char *user_name = pwuid ? xstrdup (pwuid->pw_name) : strdup_printf ("%d", uid);
          cleanup_free char *content =
            strdup_printf ("%s:x:%d:%d:%s:%s:%s\n"
                           "nfsnobody:x:65534:65534:Unmapped user:/:/sbin/nologin\n",
                           user_name,
                           uid, gid,
                           pwuid ? pwuid->pw_gecos : "",
                           pwuid ? pwuid->pw_dir : "/",
                           pwuid ? pwuid->pw_shell : "/bin/sh");

          if (create_file (dest, 0755, content) != 0)
            die_with_error ("creating passwd at %s", op->dest);

        }
        break;

      case SETUP_MAKE_GROUP:
        {
          cleanup_free char *user_name = pwuid ? xstrdup (pwuid->pw_name) : strdup_printf ("%d", uid);
          cleanup_free char *group_name = grgid ? xstrdup (grgid->gr_name) : strdup_printf ("%d", gid);
          cleanup_free char *content =
            content = strdup_printf ("%s:x:%d:%s\n"
                                     "nfsnobody:x:65534:\n",
                                     group_name,
                                     gid, user_name);

          if (create_file (dest, 0755, content) != 0)
            die_with_error ("creating passwd at %s", op->dest);
        }
        break;

      default:
        die ("Unexpected type %d", op->type);
      }
    }
  privileged_op (privileged_op_socket,
                 PRIV_SEP_OP_DONE, 0, NULL, NULL);
}

static const char *
resolve_string_offset (void *buffer,
                       size_t buffer_size,
                       uint32_t offset)
{
  if (offset == 0)
    return NULL;

  if (offset > buffer_size)
    die ("Invalid string offset %d (buffer size %zd)", offset, buffer_size);

  return (const char *)buffer + offset;
}

static uint32_t
read_priv_sec_op (int read_socket,
                  void *buffer,
                  size_t buffer_size,
                  uint32_t *flags,
                  const char **arg1,
                  const char **arg2)
{
  const PrivSepOp *op = (const PrivSepOp *)buffer;
  ssize_t rec_len;

  do
    rec_len = read (read_socket, buffer, buffer_size - 1);
  while (rec_len == -1 && errno == EINTR);

  if (rec_len < 0)
    die_with_error ("Can't read from unprivileged helper");

  if (rec_len < sizeof (PrivSepOp))
    die ("Invalid size %zd from unprivileged helper", rec_len);

  /* Guarantee zero termination of any strings */
  ((char *)buffer)[rec_len] = 0;

  *flags = op->flags;
  *arg1 = resolve_string_offset (buffer, rec_len, op->arg1_offset);
  *arg2 = resolve_string_offset (buffer, rec_len, op->arg2_offset);

  return op->op;
}


int
main (int argc,
      char **argv)
{
  mode_t old_umask;
  cleanup_free char *base_path = NULL;
  char *chdir_path = NULL;
  bool unshare_pid = FALSE;
  bool unshare_ipc = FALSE;
  bool unshare_net = FALSE;
  bool unshare_uts = FALSE;
  int clone_flags;
  char *old_cwd = NULL;
  pid_t pid;
  int event_fd = -1;
  int sync_fd = -1;
  const char *new_cwd;
  uid_t ns_uid;
  gid_t ns_gid;
  SetupOp *op;

  /* Get the (optional) capabilities we need, drop root */
  acquire_caps ();

  /* Never gain any more privs during exec */
  if (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    die_with_error ("prctl(PR_SET_NO_NEW_CAPS) failed");

  /* The initial code is run with high permissions
     (i.e. CAP_SYS_ADMIN), so take lots of care. */

  argv0 = argv[0];

  if (isatty (1))
    host_tty_dev = ttyname (1);

  argv++;
  argc--;

  if (argc == 0)
    usage ();

  while (argc > 0)
    {
      const char *arg = argv[0];

      if (strcmp (arg, "--help") == 0)
        usage ();
      else if (strcmp (arg, "--version") == 0)
        {
          printf ("%s\n", PACKAGE_STRING);
          exit (0);
        }
      else if (strcmp (arg, "--unshare-ipc") == 0)
        unshare_ipc = TRUE;
      else if (strcmp (arg, "--unshare-pid") == 0)
        unshare_pid = TRUE;
      else if (strcmp (arg, "--unshare-net") == 0)
        unshare_net = TRUE;
      else if (strcmp (arg, "--unshare-uts") == 0)
        unshare_uts = TRUE;
      else if (strcmp (arg, "--chdir") == 0)
        {
          if (argc < 2)
            die ("--chdir takes one argument");

          chdir_path = argv[1];
          argv++;
          argc--;
        }
      else if (strcmp (arg, "--mount-bind-dir") == 0)
        {
          if (argc < 3)
            die ("--mount-bind-dir takes two arguments");

          op = setup_op_new (SETUP_BIND_MOUNT_DIR);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--mount-ro-bind-dir") == 0)
        {
          if (argc < 3)
            die ("--mount-ro-bind-dir takes two arguments");

          op = setup_op_new (SETUP_RO_BIND_MOUNT_DIR);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--mount-bind") == 0)
        {
          if (argc < 3)
            die ("--mount-bind takes two arguments");

          op = setup_op_new (SETUP_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--mount-ro-bind") == 0)
        {
          if (argc < 3)
            die ("--mount-ro-bind takes two arguments");

          op = setup_op_new (SETUP_RO_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--mount-dev-bind") == 0)
        {
          if (argc < 3)
            die ("--mount-dev-bind takes two arguments");

          op = setup_op_new (SETUP_DEV_BIND_MOUNT);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--mount-proc") == 0)
        {
          if (argc < 2)
            die ("--mount-proc takes an argument");

          op = setup_op_new (SETUP_MOUNT_PROC);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--mount-dev") == 0)
        {
          if (argc < 2)
            die ("--mount-dev takes an argument");

          op = setup_op_new (SETUP_MOUNT_DEV);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--make-dir") == 0)
        {
          if (argc < 2)
            die ("--make-dir takes an argument");

          op = setup_op_new (SETUP_MAKE_DIR);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--make-file") == 0)
        {
          int file_fd;
          char *endptr;

          if (argc < 3)
            die ("--make-file takes two arguments");

          file_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || file_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          op = setup_op_new (SETUP_MAKE_FILE);
          op->fd = file_fd;
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--make-symlink") == 0)
        {
          if (argc < 3)
            die ("--make-symlink takes two arguments");

          op = setup_op_new (SETUP_MAKE_SYMLINK);
          op->source = argv[1];
          op->dest = argv[2];

          argv += 2;
          argc -= 2;
        }
      else if (strcmp (arg, "--make-passwd") == 0)
        {
          if (argc < 2)
            die ("--make-passwd takes an argument");

          op = setup_op_new (SETUP_MAKE_PASSWD);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--make-group") == 0)
        {
          if (argc < 2)
            die ("--make-group takes an argument");

          op = setup_op_new (SETUP_MAKE_GROUP);
          op->dest = argv[1];

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--lock-file") == 0)
        {
          if (argc < 2)
            die ("--lock-file takes an argument");

          (void)lock_file_new (argv[1]);

          argv += 1;
          argc -= 1;
        }
      else if (strcmp (arg, "--sync-fd") == 0)
        {
          int the_fd;
          char *endptr;

          if (argc < 2)
            die ("--sync-fd takes an argument");

          the_fd = strtol (argv[1], &endptr, 10);
          if (argv[1][0] == 0 || endptr[0] != 0 || the_fd < 0)
            die ("Invalid fd: %s", argv[1]);

          sync_fd = the_fd;

          argv += 1;
          argc -= 1;
        }
      else if (*arg == '-')
        die ("Unknown option %s", arg);
      else
        break;

      argv++;
      argc--;
    }

  if (argc == 0)
    usage ();

  __debug__(("Creating root mount point\n"));

  uid = getuid ();
  gid = getgid ();
  pwuid = getpwuid (uid);
  grgid = getgrgid (gid);

  /* We need to read stuff from proc during the pivot_root dance, etc.
     Lets keep a fd to it open */
  proc_fd = open ("/proc", O_RDONLY | O_PATH);
  if (proc_fd == -1)
    die_with_error ("Can't open /proc");

  /* We need *some* mountpoint where we can mount the root tmpfs.
     We first try in /run, and if that fails, try in /tmp. */
  base_path = strdup_printf ("/run/user/%d/.bubblewrap", uid);
  if (mkdir (base_path, 0755) && errno != EEXIST)
    {
      free (base_path);
      base_path = strdup_printf ("/tmp/.bubblewrap-%d", uid);
      if (mkdir (base_path, 0755) && errno != EEXIST)
        die_with_error ("Creating root mountpoint failed");
    }

  __debug__(("creating new namespace\n"));

  if (unshare_pid)
    event_fd = eventfd (0, EFD_CLOEXEC | EFD_NONBLOCK);

  /* We block sigchild here so that we can use signalfd in the monitor. */
  block_sigchild ();

  clone_flags = SIGCHLD | CLONE_NEWNS;
  if (!is_privileged)
    clone_flags |= CLONE_NEWUSER;
  if (unshare_pid)
    clone_flags |= CLONE_NEWPID;
  if (unshare_net)
    clone_flags |= CLONE_NEWNET;
  if (unshare_ipc)
    clone_flags |= CLONE_NEWIPC;
  if (unshare_uts)
    clone_flags |= CLONE_NEWUTS;

  pid = raw_clone (clone_flags, NULL);
  if (pid == -1)
    {
      if (!is_privileged)
        {
          if (errno == EINVAL)
            die ("Creating new namespace failed, likely because the kernel does not support user namespaces. Give bubblewrap setuid root or cap_sys_admin+ep rights, or switch to a kernel with user namespace support.");
          else if (errno == EPERM)
            die ("No permissions to creating new namespace, likely because the kernel does not allow non-privileged user namespaces. On e.g. debian this can be enabled with 'sysctl kernel.unprivileged_userns_clone=1'.");
        }

      die_with_error ("Creating new namespace failed");
    }

  if (pid != 0)
    {
      /* Initial launched process, wait for exec:ed command to exit */

      /* We don't need any caps in the launcher, drop them immediately. */
      drop_caps ();
      monitor_child (event_fd);
      exit (0); /* Should not be reached, but better safe... */
    }

  ns_uid = uid;
  ns_gid = gid;
  if (!is_privileged)
    {
      /* This is a bit hacky, but we need to first map the real uid/gid to
         0, otherwise we can't mount the devpts filesystem because root is
         not mapped. Later we will create another child user namespace and
         map back to the real uid */
      ns_uid = 0;
      ns_gid = 0;

      write_uid_gid_map (ns_uid, uid,
                         ns_gid, gid,
                         TRUE);
    }

  old_umask = umask (0);

  /* Mark everything as slave, so that we still
   * receive mounts from the real root, but don't
   * propagate mounts to the real root. */
  if (mount (NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
    die_with_error ("Failed to make / slave");

  /* Create a tmpfs which we will use as / in the namespace */
  if (mount ("", base_path, "tmpfs", MS_NODEV|MS_NOSUID, NULL) != 0)
    die_with_error ("Failed to mount tmpfs");

  old_cwd = get_current_dir_name ();

  /* Chdir to the new root tmpfs mount. This will be the CWD during
     the entire setup. Access old or new root via "oldroot" and "newroot". */
  if (chdir (base_path) != 0)
      die_with_error ("chdir base_path");

  /* We create a subdir "$base_path/newroot" for the new root, that
   * way we can pivot_root to base_path, and put the old root at
   * "$base_path/oldroot". This avoids problems accessing the oldroot
   * dir if the user requested to bind mount something over / */

  if (mkdir ("newroot", 0755))
    die_with_error ("Creating newroot failed");

  if (mkdir ("oldroot", 0755))
    die_with_error ("Creating oldroot failed");

  if (pivot_root (base_path, "oldroot"))
    die_with_error ("pivot_root");

  if (chdir ("/") != 0)
    die_with_error ("chhdir / (base path)");

  if (is_privileged)
    {
      pid_t child;
      int privsep_sockets[2];

      if (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, privsep_sockets) != 0)
        die_with_error ("Can't create privsep socket");

      child = fork ();
      if (child == -1)
        die_with_error ("Can't fork unprivileged helper");

      if (child == 0)
        {
          /* Unprivileged setup process */
          drop_caps ();
          close (privsep_sockets[0]);
          setup_newroot (unshare_pid, privsep_sockets[1]);
          exit (0);
        }
      else
        {
          uint32_t buffer[2048];  /* 8k, but is int32 to guarantee nice alignment */
          uint32_t op, flags;
          const char *arg1, *arg2;
          cleanup_fd int unpriv_socket = -1;

          unpriv_socket = privsep_sockets[0];
          close (privsep_sockets[1]);

          do
            {
              op = read_priv_sec_op (unpriv_socket, buffer, sizeof (buffer),
                                     &flags, &arg1, &arg2);
              privileged_op (-1, op, flags, arg1, arg2);
              if (write (unpriv_socket, buffer, 1) != 1)
                die ("Can't write to op_socket");
            }
          while (op != PRIV_SEP_OP_DONE);

          /* Continue post setup */
        }
    }
  else
    setup_newroot (unshare_pid, -1);

  /* The old root better be rprivate or we will send unmount events to the parent namespace */
  if (mount ("oldroot", "oldroot", NULL, MS_REC|MS_PRIVATE, NULL) != 0)
    die_with_error ("Failed to make old root rprivate");

  if (umount2 ("oldroot", MNT_DETACH))
    die_with_error ("unmount old root");

  if (ns_uid != uid || ns_gid != gid)
    {
      /* Now that devpts is mounted and we've no need for mount
         permissions we can create a new userspace and map our uid
         1:1 */

      if (unshare (CLONE_NEWUSER))
        die_with_error ("unshare user ns");

      write_uid_gid_map (uid, ns_uid,
                         gid, ns_gid,
                         FALSE);
    }

  /* Now make /newroot the real root */
  if (chdir ("/newroot") != 0)
    die_with_error ("chdir newroot");
  if (chroot ("/newroot") != 0)
    die_with_error ("chroot /newroot");
  if (chdir ("/") != 0)
    die_with_error ("chhdir /");

  if (unshare_net && loopback_setup () != 0)
    die ("Can't create loopback device");

  /* Now we have everything we need CAP_SYS_ADMIN for, so drop it */
  drop_caps ();

  umask (old_umask);

  new_cwd = "/";
  if (chdir_path)
    {
      if (chdir (chdir_path))
        die_with_error ("Can't chdir to %s", chdir_path);
      new_cwd = chdir_path;
    }
  else if (chdir (old_cwd) == 0)
    {
      /* If the old cwd is mapped in the sandbox, go there */
      new_cwd = old_cwd;
    }
  else
    {
      /* If the old cwd is not mapped, go to home */
      const char *home = getenv ("HOME");
      if (home != NULL &&
          chdir (home) == 0)
        new_cwd = home;
    }
  xsetenv ("PWD", new_cwd, 1);
  free (old_cwd);

  /* We can't pass regular LD_LIBRARY_PATH, as it would affect the
     setuid helper aspect, so we use _LD_LIBRARY_PATH */
  if (getenv ("_LD_LIBRARY_PATH"))
    {
      xsetenv ("LD_LIBRARY_PATH", getenv("_LD_LIBRARY_PATH"), 1);
      xunsetenv ("_LD_LIBRARY_PATH");
    }
  else
    xunsetenv ("LD_LIBRARY_PATH"); /* Make sure to unset if it was not (i.e. unprivileged mode) */

  __debug__(("forking for child\n"));

  if (unshare_pid || lock_files != NULL || sync_fd != -1)
    {
      /* We have to have a pid 1 in the pid namespace, because
       * otherwise we'll get a bunch of zombies as nothing reaps
       * them. Alternatively if we're using sync_fd or lock_files we
       * need some process to own these.
       */

      pid = fork ();
      if (pid == -1)
        die_with_error("Can't fork for pid 1");

      if (pid != 0)
        {
          /* Close fds in pid 1, except stdio and optionally event_fd
             (for syncing pid 2 lifetime with monitor_child) and
             sync_fd (for syncing sandbox lifetime with outside
             process).
             Any other fds will been passed on to the child though. */
          {
            int dont_close[3];
            int j = 0;
            if (event_fd != -1)
              dont_close[j++] = event_fd;
            if (sync_fd != -1)
              dont_close[j++] = sync_fd;
            dont_close[j++] = -1;
            fdwalk (proc_fd, close_extra_fds, dont_close);
          }

          return do_init (event_fd, pid);
        }
    }

  __debug__(("launch executable %s\n", argv[0]));

  if (proc_fd != -1)
    close (proc_fd);

  if (sync_fd != -1)
    close (sync_fd);

  /* We want sigchild in the child */
  unblock_sigchild ();

  if (execvp (argv[0], argv) == -1)
    die_with_error ("execvp %s", argv[0]);

  return 0;
}
