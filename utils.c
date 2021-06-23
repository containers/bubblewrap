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

#include "utils.h"
#include <sys/syscall.h>
#include <sys/socket.h>
#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef HAVE_SELINUX_2_3
/* libselinux older than 2.3 weren't const-correct */
#define setexeccon(x) setexeccon ((security_context_t) x)
#define setfscreatecon(x) setfscreatecon ((security_context_t) x)
#define security_check_context(x) security_check_context ((security_context_t) x)
#endif

void
die_with_error (const char *format, ...)
{
  va_list args;
  int errsv;

  fprintf (stderr, "bwrap: ");

  errsv = errno;

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, ": %s\n", strerror (errsv));

  exit (1);
}

void
die (const char *format, ...)
{
  va_list args;

  fprintf (stderr, "bwrap: ");

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  fprintf (stderr, "\n");

  exit (1);
}

void
die_unless_label_valid (const char *label)
{
#ifdef HAVE_SELINUX
  if (is_selinux_enabled () == 1)
    {
      if (security_check_context (label) < 0)
        die_with_error ("invalid label %s", label);
      return;
    }
#endif
  die ("labeling not supported on this system");
}

void
die_oom (void)
{
  fputs ("Out of memory\n", stderr);
  exit (1);
}

/* Fork, return in child, exiting the previous parent */
void
fork_intermediate_child (void)
{
  int pid = fork ();
  if (pid == -1)
    die_with_error ("Can't fork for --pidns");

  /* Parent is an process not needed */
  if (pid != 0)
    exit (0);
}

void *
xmalloc (size_t size)
{
  void *res = malloc (size);

  if (res == NULL)
    die_oom ();
  return res;
}

void *
xcalloc (size_t size)
{
  void *res = calloc (1, size);

  if (res == NULL)
    die_oom ();
  return res;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *res = realloc (ptr, size);

  if (size != 0 && res == NULL)
    die_oom ();
  return res;
}

char *
xstrdup (const char *str)
{
  char *res;

  assert (str != NULL);

  res = strdup (str);
  if (res == NULL)
    die_oom ();

  return res;
}

void
strfreev (char **str_array)
{
  if (str_array)
    {
      int i;

      for (i = 0; str_array[i] != NULL; i++)
        free (str_array[i]);

      free (str_array);
    }
}

/* Compares if str has a specific path prefix. This differs
   from a regular prefix in two ways. First of all there may
   be multiple slashes separating the path elements, and
   secondly, if a prefix is matched that has to be en entire
   path element. For instance /a/prefix matches /a/prefix/foo/bar,
   but not /a/prefixfoo/bar. */
bool
has_path_prefix (const char *str,
                 const char *prefix)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*str == '/')
        str++;
      while (*prefix == '/')
        prefix++;

      /* No more prefix path elements? Done! */
      if (*prefix == 0)
        return TRUE;

      /* Compare path element */
      while (*prefix != 0 && *prefix != '/')
        {
          if (*str != *prefix)
            return FALSE;
          str++;
          prefix++;
        }

      /* Matched prefix path element,
         must be entire str path element */
      if (*str != '/' && *str != 0)
        return FALSE;
    }
}

bool
path_equal (const char *path1,
            const char *path2)
{
  while (TRUE)
    {
      /* Skip consecutive slashes to reach next path
         element */
      while (*path1 == '/')
        path1++;
      while (*path2 == '/')
        path2++;

      /* No more prefix path elements? Done! */
      if (*path1 == 0 || *path2 == 0)
        return *path1 == 0 && *path2 == 0;

      /* Compare path element */
      while (*path1 != 0 && *path1 != '/')
        {
          if (*path1 != *path2)
            return FALSE;
          path1++;
          path2++;
        }

      /* Matched path1 path element, must be entire path element */
      if (*path2 != '/' && *path2 != 0)
        return FALSE;
    }
}


bool
has_prefix (const char *str,
            const char *prefix)
{
  return strncmp (str, prefix, strlen (prefix)) == 0;
}

void
xclearenv (void)
{
  if (clearenv () != 0)
    die_with_error ("clearenv failed");
}

void
xsetenv (const char *name, const char *value, int overwrite)
{
  if (setenv (name, value, overwrite))
    die ("setenv failed");
}

void
xunsetenv (const char *name)
{
  if (unsetenv (name))
    die ("unsetenv failed");
}

char *
strconcat (const char *s1,
           const char *s2)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);

  res = xmalloc (len + 1);
  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);

  return res;
}

char *
strconcat3 (const char *s1,
            const char *s2,
            const char *s3)
{
  size_t len = 0;
  char *res;

  if (s1)
    len += strlen (s1);
  if (s2)
    len += strlen (s2);
  if (s3)
    len += strlen (s3);

  res = xmalloc (len + 1);
  *res = 0;
  if (s1)
    strcat (res, s1);
  if (s2)
    strcat (res, s2);
  if (s3)
    strcat (res, s3);

  return res;
}

char *
xasprintf (const char *format,
           ...)
{
  char *buffer = NULL;
  va_list args;

  va_start (args, format);
  if (vasprintf (&buffer, format, args) == -1)
    die_oom ();
  va_end (args);

  return buffer;
}

int
fdwalk (int proc_fd, int (*cb)(void *data,
                               int   fd), void *data)
{
  int open_max;
  int fd;
  int dfd;
  int res = 0;
  DIR *d;

  dfd = openat (proc_fd, "self/fd", O_DIRECTORY | O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOCTTY);
  if (dfd == -1)
    return res;

  if ((d = fdopendir (dfd)))
    {
      struct dirent *de;

      while ((de = readdir (d)))
        {
          long l;
          char *e = NULL;

          if (de->d_name[0] == '.')
            continue;

          errno = 0;
          l = strtol (de->d_name, &e, 10);
          if (errno != 0 || !e || *e)
            continue;

          fd = (int) l;

          if ((long) fd != l)
            continue;

          if (fd == dirfd (d))
            continue;

          if ((res = cb (data, fd)) != 0)
            break;
        }

      closedir (d);
      return res;
    }

  open_max = sysconf (_SC_OPEN_MAX);

  for (fd = 0; fd < open_max; fd++)
    if ((res = cb (data, fd)) != 0)
      break;

  return res;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
int
write_to_fd (int         fd,
             const char *content,
             ssize_t     len)
{
  ssize_t res;

  while (len > 0)
    {
      res = write (fd, content, len);
      if (res < 0 && errno == EINTR)
        continue;
      if (res <= 0)
        {
          if (res == 0) /* Unexpected short write, should not happen when writing to a file */
            errno = ENOSPC;
          return -1;
        }
      len -= res;
      content += res;
    }

  return 0;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
int
write_file_at (int         dirfd,
               const char *path,
               const char *content)
{
  int fd;
  bool res;
  int errsv;

  fd = openat (dirfd, path, O_RDWR | O_CLOEXEC, 0);
  if (fd == -1)
    return -1;

  res = 0;
  if (content)
    res = write_to_fd (fd, content, strlen (content));

  errsv = errno;
  close (fd);
  errno = errsv;

  return res;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
int
create_file (const char *path,
             mode_t      mode,
             const char *content)
{
  int fd;
  int res;
  int errsv;

  fd = creat (path, mode);
  if (fd == -1)
    return -1;

  res = 0;
  if (content)
    res = write_to_fd (fd, content, strlen (content));

  errsv = errno;
  close (fd);
  errno = errsv;

  return res;
}

int
ensure_file (const char *path,
             mode_t      mode)
{
  struct stat buf;

  /* We check this ahead of time, otherwise
     the create file will fail in the read-only
     case with EROFS instead of EEXIST.

     We're trying to set up a mount point for a non-directory, so any
     non-directory, non-symlink is acceptable - it doesn't necessarily
     have to be a regular file. */
  if (stat (path, &buf) ==  0 &&
      !S_ISDIR (buf.st_mode) &&
      !S_ISLNK (buf.st_mode))
    return 0;

  if (create_file (path, mode, NULL) != 0 &&  errno != EEXIST)
    return -1;

  return 0;
}


#define BUFSIZE 8192
/* Sets errno on error (!= 0), ENOSPC on short write */
int
copy_file_data (int sfd,
                int dfd)
{
  char buffer[BUFSIZE];
  ssize_t bytes_read;

  while (TRUE)
    {
      bytes_read = read (sfd, buffer, BUFSIZE);
      if (bytes_read == -1)
        {
          if (errno == EINTR)
            continue;

          return -1;
        }

      if (bytes_read == 0)
        break;

      if (write_to_fd (dfd, buffer, bytes_read) != 0)
        return -1;
    }

  return 0;
}

/* Sets errno on error (!= 0), ENOSPC on short write */
int
copy_file (const char *src_path,
           const char *dst_path,
           mode_t      mode)
{
  int sfd;
  int dfd;
  int res;
  int errsv;

  sfd = open (src_path, O_CLOEXEC | O_RDONLY);
  if (sfd == -1)
    return -1;

  dfd = creat (dst_path, mode);
  if (dfd == -1)
    {
      errsv = errno;
      close (sfd);
      errno = errsv;
      return -1;
    }

  res = copy_file_data (sfd, dfd);

  errsv = errno;
  close (sfd);
  close (dfd);
  errno = errsv;

  return res;
}

/* Sets errno on error (== NULL),
 * Always ensures terminating zero */
char *
load_file_data (int     fd,
                size_t *size)
{
  cleanup_free char *data = NULL;
  ssize_t data_read;
  ssize_t data_len;
  ssize_t res;
  int errsv;

  data_read = 0;
  data_len = 4080;
  data = xmalloc (data_len);

  do
    {
      if (data_len == data_read + 1)
        {
          data_len *= 2;
          data = xrealloc (data, data_len);
        }

      do
        res = read (fd, data + data_read, data_len - data_read - 1);
      while (res < 0 && errno == EINTR);

      if (res < 0)
        {
          errsv = errno;
          close (fd);
          errno = errsv;
          return NULL;
        }

      data_read += res;
    }
  while (res > 0);

  data[data_read] = 0;

  if (size)
    *size = (size_t) data_read;

  return steal_pointer (&data);
}

/* Sets errno on error (== NULL),
 * Always ensures terminating zero */
char *
load_file_at (int         dirfd,
              const char *path)
{
  int fd;
  char *data;
  int errsv;

  fd = openat (dirfd, path, O_CLOEXEC | O_RDONLY);
  if (fd == -1)
    return NULL;

  data = load_file_data (fd, NULL);

  errsv = errno;
  close (fd);
  errno = errsv;

  return data;
}

/* Sets errno on error (< 0) */
int
get_file_mode (const char *pathname)
{
  struct stat buf;

  if (stat (pathname, &buf) !=  0)
    return -1;

  return buf.st_mode & S_IFMT;
}

int
ensure_dir (const char *path,
            mode_t      mode)
{
  struct stat buf;

  /* We check this ahead of time, otherwise
     the mkdir call can fail in the read-only
     case with EROFS instead of EEXIST on some
     filesystems (such as NFS) */
  if (stat (path, &buf) == 0)
    {
      if (!S_ISDIR (buf.st_mode))
        {
          errno = ENOTDIR;
          return -1;
        }

      return 0;
    }

  if (mkdir (path, mode) == -1 && errno != EEXIST)
    return -1;

  return 0;
}


/* Sets errno on error (!= 0) */
int
mkdir_with_parents (const char *pathname,
                    int         mode,
                    bool        create_last)
{
  cleanup_free char *fn = NULL;
  char *p;

  if (pathname == NULL || *pathname == '\0')
    {
      errno = EINVAL;
      return -1;
    }

  fn = xstrdup (pathname);

  p = fn;
  while (*p == '/')
    p++;

  do
    {
      while (*p && *p != '/')
        p++;

      if (!*p)
        p = NULL;
      else
        *p = '\0';

      if (!create_last && p == NULL)
        break;

      if (ensure_dir (fn, mode) != 0)
        return -1;

      if (p)
        {
          *p++ = '/';
          while (*p && *p == '/')
            p++;
        }
    }
  while (p);

  return 0;
}

/* Send an ucred with current pid/uid/gid over a socket, it can be
   read back with read_pid_from_socket(), and then the kernel has
   translated it between namespaces as needed. */
void
send_pid_on_socket (int socket)
{
  char buf[1] = { 0 };
  struct msghdr msg = {};
  struct iovec iov = { buf, sizeof (buf) };
  const ssize_t control_len_snd = CMSG_SPACE(sizeof(struct ucred));
  char control_buf_snd[control_len_snd];
  struct cmsghdr *cmsg;
  struct ucred *cred;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf_snd;
  msg.msg_controllen = control_len_snd;

  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_CREDENTIALS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
  cred = (struct ucred *)CMSG_DATA(cmsg);

  cred->pid = getpid ();
  cred->uid = geteuid ();
  cred->gid = getegid ();

  if (sendmsg (socket, &msg, 0) < 0)
    die_with_error ("Can't send pid");
}

void
create_pid_socketpair (int sockets[2])
{
  int enable = 1;

  if (socketpair (AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) != 0)
    die_with_error ("Can't create intermediate pids socket");

  if (setsockopt (sockets[0], SOL_SOCKET, SO_PASSCRED, &enable, sizeof (enable)) < 0)
    die_with_error ("Can't set SO_PASSCRED");
}

int
read_pid_from_socket (int socket)
{
  char recv_buf[1] = { 0 };
  struct msghdr msg = {};
  struct iovec iov = { recv_buf, sizeof (recv_buf) };
  const ssize_t control_len_rcv = CMSG_SPACE(sizeof(struct ucred));
  char control_buf_rcv[control_len_rcv];
  struct cmsghdr* cmsg;

  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control_buf_rcv;
  msg.msg_controllen = control_len_rcv;

  if (recvmsg (socket, &msg, 0) < 0)
    die_with_error ("Cant read pid from socket");

  if (msg.msg_controllen <= 0)
    die ("Unexpected short read from pid socket");

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
      const unsigned payload_len = cmsg->cmsg_len - CMSG_LEN(0);
      if (cmsg->cmsg_level == SOL_SOCKET &&
          cmsg->cmsg_type == SCM_CREDENTIALS &&
          payload_len == sizeof(struct ucred))
        {
          struct ucred *cred = (struct ucred *)CMSG_DATA(cmsg);
          return cred->pid;
        }
    }
  die ("No pid returned on socket");
}

/* Sets errno on error (== NULL),
 * Always ensures terminating zero */
char *
readlink_malloc (const char *pathname)
{
  size_t size = 50;
  ssize_t n;
  cleanup_free char *value = NULL;

  do
    {
      size *= 2;
      value = xrealloc (value, size);
      n = readlink (pathname, value, size - 1);
      if (n < 0)
        return NULL;
    }
  while (size - 2 < n);

  value[n] = 0;
  return steal_pointer (&value);
}

char *
get_oldroot_path (const char *path)
{
  while (*path == '/')
    path++;
  return strconcat ("/oldroot/", path);
}

int
raw_clone (unsigned long flags,
           void         *child_stack)
{
#if defined(__s390__) || defined(__CRIS__)
  /* On s390 and cris the order of the first and second arguments
   * of the raw clone() system call is reversed. */
  return (int) syscall (__NR_clone, child_stack, flags);
#else
  return (int) syscall (__NR_clone, flags, child_stack);
#endif
}

int
pivot_root (const char * new_root, const char * put_old)
{
#ifdef __NR_pivot_root
  return syscall (__NR_pivot_root, new_root, put_old);
#else
  errno = ENOSYS;
  return -1;
#endif
}

char *
label_mount (const char *opt, const char *mount_label)
{
#ifdef HAVE_SELINUX
  if (mount_label)
    {
      if (opt)
        return xasprintf ("%s,context=\"%s\"", opt, mount_label);
      else
        return xasprintf ("context=\"%s\"", mount_label);
    }
#endif
  if (opt)
    return xstrdup (opt);
  return NULL;
}

int
label_create_file (const char *file_label)
{
#ifdef HAVE_SELINUX
  if (is_selinux_enabled () > 0 && file_label)
    return setfscreatecon (file_label);
#endif
  return 0;
}

int
label_exec (const char *exec_label)
{
#ifdef HAVE_SELINUX
  if (is_selinux_enabled () > 0 && exec_label)
    return setexeccon (exec_label);
#endif
  return 0;
}
