/* SPDX-License-Identifier: LGPL-2.0-or-later */

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include "network.h"
#include "utils.h"

enum condition
{
  READY,
  SOCKET_ERROR,
  FLAGS_ERROR,
  DOWN,
  NOT_LOOPBACK,
  ADDRESS_ERROR,
  WRONG_ADDRESS_FAMILY,
  WRONG_ADDRESS,
  MISSING_ADDRESS,
  MASK_ERROR,
  WRONG_MASK_FAMILY,
  WRONG_MASK,
  MISSING_MASK
};

static const char * const case_names[] = {
  "already configured",
  "socket error",
  "flags query error",
  "interface down",
  "not a loopback interface",
  "address query error",
  "wrong address family",
  "wrong address",
  "missing address",
  "netmask query error",
  "wrong netmask family",
  "wrong netmask",
  "missing netmask"
};

static enum condition current;
static int control = -1;

int __wrap_socket (int domain, int type, int protocol);
int __wrap_ioctl (int fd, unsigned long operation, ...);
unsigned int __wrap_if_nametoindex (const char *name);

static bool
closed (void)
{
  return control == -1 || (fcntl (control, F_GETFD) == -1 && errno == EBADF);
}

int
__wrap_socket (int domain, int type, int protocol)
{
  (void) protocol;
  /* Stop at the original setup path: errors and mismatches must reach it. */
  if (domain == AF_NETLINK)
    _exit (current != READY && closed () ? 0 : 1);
  if (domain != AF_INET || type != (SOCK_DGRAM | SOCK_CLOEXEC))
    _exit (2);
  if (current == SOCKET_ERROR)
    {
      errno = EMFILE;
      return -1;
    }
  control = open ("/dev/null", O_RDONLY | O_CLOEXEC);
  if (control < 0)
    _exit (3);
  return control;
}

static int
address_query (struct ifreq *query, bool mask)
{
  struct sockaddr_in *address = (struct sockaddr_in *) &query->ifr_addr;
  if (address->sin_family != AF_INET || address->sin_addr.s_addr != 0)
    _exit (4);
  if (current == (mask ? MASK_ERROR : ADDRESS_ERROR))
    {
      errno = EIO;
      return -1;
    }
  if (current == (mask ? MISSING_MASK : MISSING_ADDRESS))
    return 0;
  if (current == (mask ? WRONG_MASK_FAMILY : WRONG_ADDRESS_FAMILY))
    address->sin_family = AF_INET6;
  /* gVisor can write only the address, preserving the input family. */
  address->sin_addr.s_addr = htonl (mask ? 0xff000000 : INADDR_LOOPBACK);
  if (current == (mask ? WRONG_MASK : WRONG_ADDRESS))
    address->sin_addr.s_addr = htonl (mask ? 0xffffff00 : 0x7f000002);
  return 0;
}

int
__wrap_ioctl (int fd, unsigned long operation, ...)
{
  va_list arguments;
  struct ifreq *query;
  if (fd != control)
    _exit (5);
  va_start (arguments, operation);
  query = va_arg (arguments, struct ifreq *);
  va_end (arguments);
  if (strcmp (query->ifr_name, "lo") != 0)
    _exit (6);
  if (operation == SIOCGIFADDR || operation == SIOCGIFNETMASK)
    return address_query (query, operation == SIOCGIFNETMASK);
  if (operation != SIOCGIFFLAGS)
    _exit (7);
  if (current == FLAGS_ERROR)
    {
      errno = EIO;
      return -1;
    }
  query->ifr_flags = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
  if (current == DOWN)
    query->ifr_flags &= ~IFF_UP;
  if (current == NOT_LOOPBACK)
    query->ifr_flags &= ~IFF_LOOPBACK;
  return 0;
}

unsigned int
__wrap_if_nametoindex (const char *name)
{
  return strcmp (name, "lo") == 0 ? 1 : 0;
}

void
die_with_error (const char *format, ...)
{
  (void) format;
  _exit (8);
}

int
main (void)
{
  puts ("1..13");
  fflush (stdout);

  for (current = READY; current <= MISSING_MASK; current++)
    {
      pid_t child = fork ();
      int status;
      if (child == -1)
        {
          perror ("fork");
          return 9;
        }
      if (child == 0)
        {
          loopback_setup ();
          _exit (current == READY && closed () ? 0 : 10);
        }
      if (waitpid (child, &status, 0) != child || !WIFEXITED (status) || WEXITSTATUS (status) != 0)
        {
          printf ("not ok %u - %s\n", (unsigned int) current + 1, case_names[current]);
          return 11;
        }
      printf ("ok %u - %s; query descriptor closed\n", (unsigned int) current + 1, case_names[current]);
      fflush (stdout);
    }
  return 0;
}
