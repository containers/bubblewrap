#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <config.h>
#include "utils.h"

#ifndef DISABLE_SECCOMP
#include <seccomp.h>
#endif


int
main (int argc, char *argv[])
{
#ifndef DISABLE_SECCOMP
  scmp_filter_ctx ctx = NULL;
  int filter1_fd;
  int filter2_fd;
  int res;
  uint32_t extra_arches[][2] = {
    {SCMP_ARCH_X86_64, SCMP_ARCH_X86},
#ifdef SCMP_ARCH_AARCH64
    {SCMP_ARCH_AARCH64, SCMP_ARCH_ARM},
#endif
    {0}
  };
  int i;
  unsigned char *filter1;
  unsigned char *filter2;
  size_t filter1_size;
  size_t filter2_size;
  char tmpname1[] = "/tmp/bwrap-filterXXXXXX";
  char tmpname2[] = "/tmp/bwrap-filterXXXXXX";

  ctx = seccomp_init (SCMP_ACT_ALLOW);
  if (!ctx)
    {
      printf ("Initialize seccomp failed\n");
      return 1;
    }

  for (i = 0; extra_arches[i][0] != 0; i++)
    {
      if (seccomp_arch_native () == extra_arches[i][0])
        {
          res = seccomp_arch_add (ctx, extra_arches[i][1]);
          if (res < 0)
            {
              printf ("Error adding extra arch\n");
              return 1;
            }
        }
    }

  if (seccomp_rule_add (ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
                        SCMP_A1(SCMP_CMP_EQ, (int)TIOCSTI)) < 0)
    {
      printf ("Failed to add TIOCSTI rule\n");
      return 1;
    }

  filter1_fd = mkstemp (tmpname1);
  if (filter1_fd == -1)
    {
      perror ("Can't write filter");
      return 1;
    }

  unlink (tmpname1);

  res = seccomp_export_bpf (ctx, filter1_fd);
  if (res < 0)
    {
      printf ("Error exporting bpf\n");
      return 1;
    }


  filter2_fd = mkstemp (tmpname2);
  if (filter2_fd == -1)
    {
      perror ("Can't write filter");
      return 1;
    }

  unlink (tmpname2);

  res = seccomp_export_pfc (ctx, filter2_fd);
  if (res < 0)
    {
      printf ("Error exporting bpf\n");
      return 1;
    }

  seccomp_release (ctx);

  lseek (filter1_fd, 0, SEEK_SET);
  filter1 = (unsigned char *)load_file_data (filter1_fd, &filter1_size);

  lseek (filter2_fd, 0, SEEK_SET);
  filter2 = (unsigned char *)load_file_data (filter2_fd, &filter2_size);

  printf ("#define HAVE_BWRAP_SECCOMP_FILTER 1\n");
  printf ("/*\n"
          "%s\n"
          "*/\n",
          filter2);
  printf ("unsigned char bwrap_seccomp_filter[] = { ");
  for (i = 0; i < filter1_size; i++)
    {
      if (i != 0)
        printf (", ");
      printf ("%d", filter1[i]);
    }
  printf (" };\n");
#endif

  return 0;
}
