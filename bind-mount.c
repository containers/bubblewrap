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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <sys/mount.h>

#include "utils.h"
#include "bind-mount.h"
#include "data-structures/destinations-graph.h"

static bind_mount_result
retrieve_kernel_case (char *dest, char **result, char **failing_path)
{
  cleanup_free char *resolved_dest = NULL;
  cleanup_free char *dest_proc = NULL;
  cleanup_free char *oldroot_dest_proc = NULL;
  cleanup_free char *kernel_case_combination = NULL;
  cleanup_fd int dest_fd = -1;

  // The mount operation will resolve any symlinks in the destination
  // path, so to find it in the mount table we need to do that too.

  resolved_dest = realpath (dest, NULL);
  if (resolved_dest == NULL)
    return BIND_MOUNT_ERROR_REALPATH_DEST;

  dest_fd = open (resolved_dest, O_PATH | O_CLOEXEC);
  if (dest_fd < 0)
    {
      if (failing_path != NULL)
        *failing_path = steal_pointer (&resolved_dest);

      return BIND_MOUNT_ERROR_REOPEN_DEST;
    }

  /* If we are in a case-insensitive filesystem, mountinfo might contain a
   * different case combination of the path we requested to mount.
   * This is due to the fact that the kernel, as of the beginning of 2021,
   * populates mountinfo with whatever case combination first appeared in the
   * dcache; kernel developers plan to change this in future so that it
   * reflects the on-disk encoding instead.
   * To avoid throwing an error when this happens, we use readlink() result
   * instead of the provided @root_mount, so that we can compare the mountinfo
   * entries with the same case combination that the kernel is expected to
   * use. */

  dest_proc = xasprintf ("/proc/self/fd/%d", dest_fd);
  oldroot_dest_proc = get_oldroot_path (dest_proc);

  kernel_case_combination = readlink_malloc (oldroot_dest_proc);

  if (kernel_case_combination == NULL)
    {
      if (failing_path != NULL)
        *failing_path = steal_pointer (&resolved_dest);

      free(kernel_case_combination);
      return BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD;
    }

  *result = steal_pointer(&kernel_case_combination);
  return BIND_MOUNT_SUCCESS;
}

bind_mount_result
bind_mount_fixup (int proc_fd, BindOp *bind_ops, size_t bind_ops_quantity, char **failing_path)
{
  // The old bind_mount() contains note while recursive remount binds:
  //
  //   | We need to work around the fact that a bind mount does not apply the flags, so we need to manually
  //   | apply the flags to all submounts in the recursive case.
  //   | Note: This does not apply the flags to mounts which are later propagated into this namespace.
  //
  // With current fixup function this behaviour approaches with virtual propagation of mount flags
  // "Virtual" here means that we store all the information inside graph data structure
  // Here this data structure is an object of optimisation
  //
  // In this way first we just bind mount all the mount points and in the end
  // just remount everything with correct flags. That is, we perform fix up of mounts

  cleanup_destinations_graph DestinationsGraph *graph;
  cleanup_mount_tab MountTab mount_tab;
//   Here clang-tidy says allocated memory is leaked. It's not true, because of cleanup attribute usage
//   At least it seems so.
  cleanup_free DestinationsGraph_Node **mount_points = xcalloc (bind_ops_quantity, sizeof (DestinationsGraph_Node *));
  BindOp *bop;
  size_t current;

  __debug__("Performing bind mounting fix up:\n\n");

  // (0) Prepare
  graph = DestinationsGraph_create ();
  mount_tab = parse_mountinfo (proc_fd, "/newroot");

  // (1) Collect all information about actual mounts to the graph
  for (int i = 0; mount_tab[i].mountpoint != NULL; i++)
    {
      __debug__("(Initial) Mountinfo: %s (flags %lu)\n", mount_tab[i].mountpoint, mount_tab[i].options);
      DestinationsGraph_ensure_mount_point (graph, &mount_tab[i].mountpoint, NULL);
    }

  // (2) Initialize flags system.
  // 1. Performs Euler tour by graph to map each node to the index in segment tree
  // 2. And initializes segment trees for each of the flag
  DestinationsGraph_Flags_init (graph);

  // (3) Collect all nodes that correspond bind mount operations
  // (4) Lazy propagate desired flags in the graph
  for (bop = bind_ops, current = 0; bop != NULL; bop = bop->next, current++)
    {
      __debug__("BindOp: %s (readonly %d, nodev %d)\n",
                bop->dest,
                (bop->options & BIND_READONLY) != 0,
                (bop->options & BIND_DEVICES) != 0
      );

      // Retrieve real path after mounting
      cleanup_free char *kernel_case = NULL;
      bind_mount_result result = retrieve_kernel_case (bop->dest, &kernel_case, failing_path);

      if (result != BIND_MOUNT_SUCCESS)
          return result;

      // Get corresponding destinations graph node
      // Also check if node was already added on (1); if not - we're screwed up
      bool added = FALSE;
      mount_points[current] = DestinationsGraph_ensure_mount_point (graph, &kernel_case, &added);
      if(added)
        {
          if(failing_path != NULL)
            *failing_path = steal_pointer(&kernel_case);
          return BIND_MOUNT_ERROR_FIND_DEST_MOUNT;
        }
      assert(added == FALSE);

      // Lazy propagate flags specified in bind operation
      bool readonly = (bop->options & BIND_READONLY) != 0;
      bool devices = (bop->options & BIND_DEVICES) != 0;

      DestinationsGraph_Flags_set_readonly (graph, mount_points[current], readonly);
      DestinationsGraph_Flags_set_nodev (graph, mount_points[current], !devices);
    }

#ifdef DEBUG
  __debug__("Destinations graph: \n");
  DestinationsGraph_debug_pretty_print (graph, stderr);
#endif

  // (5) Go through all actual mountpoints and remount all of them with correct desired flags
  for (int i = 0; mount_tab[i].mountpoint != NULL; i++)
    {
      char *mount_point = mount_tab[i].mountpoint;

      bool added = FALSE;
      DestinationsGraph_Node *node = DestinationsGraph_ensure_mount_point (graph, &mount_point, &added);
      // Here we shouldn't even return any error. Because it shouldn't happen ever.
      // In case it did I'm screwed up.
      assert(added == FALSE);

      bool readonly = DestinationsGraph_Flags_check_readonly (graph, node);
      bool devices = !DestinationsGraph_Flags_check_nodev (graph, node);

      unsigned long current_flags, new_flags;
      current_flags = mount_tab[i].options;
      new_flags = current_flags | MS_NOSUID | (devices ? 0 : MS_NODEV) | (readonly ? MS_RDONLY : 0);

      if (new_flags != current_flags)
        {
          __debug__("Remount: %s (readonly %d, nodev %d) (old flags %lu | new flags %lu)\n",
                    mount_point,
                    readonly,
                    !devices,
                    current_flags,
                    new_flags
          );

          int mount_result = mount ("none", mount_point, NULL,
                                    MS_SILENT | MS_BIND | MS_REMOUNT | new_flags, NULL);

          /* If we can't read the mountpoint we can't remount it, but that should
                be safe to ignore because it's not something the user can access. */
          if (mount_result != 0 && errno != EACCES)
            {
              if (failing_path != NULL) *failing_path = steal_pointer (&mount_point);
              return BIND_MOUNT_ERROR_REMOUNT;
            }
        }
    }

#ifdef DEBUG
  mount_tab = parse_mountinfo (proc_fd, "/newroot");
  for (int i = 0; mount_tab[i].mountpoint != NULL; i++)
      __debug__("(Final) Mountinfo: %s (flags %lu)\n", mount_tab[i].mountpoint, mount_tab[i].options);
#endif

  return BIND_MOUNT_SUCCESS;
}

/**
 * Return a string representing bind_mount_result, like strerror().
 * If want_errno_p is non-NULL, *want_errno_p is used to indicate whether
 * it would make sense to print strerror(saved_errno).
 */
static char *
bind_mount_result_to_string (bind_mount_result res,
                             const char *failing_path,
                             bool *want_errno_p)
{
  char *string = NULL;
  bool want_errno = TRUE;

  switch (res)
    {
      case BIND_MOUNT_ERROR_MOUNT:
        string = xstrdup ("Unable to mount source on destination");
      break;

      case BIND_MOUNT_ERROR_REALPATH_DEST:
        string = xstrdup ("realpath(destination)");
      break;

      case BIND_MOUNT_ERROR_REOPEN_DEST:
        string = xasprintf ("open(\"%s\", O_PATH)", failing_path);
      break;

      case BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD:
        string = xasprintf ("readlink(/proc/self/fd/N) for \"%s\"", failing_path);
      break;

      case BIND_MOUNT_ERROR_FIND_DEST_MOUNT:
        string = xasprintf ("Unable to find \"%s\" in mount table", failing_path);
      want_errno = FALSE;
      break;

      case BIND_MOUNT_ERROR_REMOUNT:
        string = xasprintf ("Unable to apply mount flags: remount \"%s\"",
                            failing_path);
      break;

      case BIND_MOUNT_SUCCESS:
        string = xstrdup ("Success");
      break;

      default:
        string = xstrdup ("(unknown/invalid bind_mount_result)");
      break;
    }

  if (want_errno_p != NULL)
    *want_errno_p = want_errno;

  return string;
}

void
die_with_bind_result (bind_mount_result res,
                      int saved_errno,
                      const char *failing_path,
                      const char *format,
                      ...)
{
  va_list args;
  bool want_errno = TRUE;
  char *message;

  fprintf (stderr, "bwrap: ");

  va_start (args, format);
  vfprintf (stderr, format, args);
  va_end (args);

  message = bind_mount_result_to_string (res, failing_path, &want_errno);
  fprintf (stderr, ": %s", message);
  /* message is leaked, but we're exiting unsuccessfully anyway, so ignore */

  if (want_errno)
    {
      switch (res)
        {
          case BIND_MOUNT_ERROR_MOUNT:
          case BIND_MOUNT_ERROR_REMOUNT:
          case BIND_MOUNT_ERROR_FIND_DEST_MOUNT:
            fprintf (stderr, ": %s", mount_strerror (saved_errno));
          break;

          case BIND_MOUNT_ERROR_REALPATH_DEST:
          case BIND_MOUNT_ERROR_REOPEN_DEST:
          case BIND_MOUNT_ERROR_READLINK_DEST_PROC_FD:
          case BIND_MOUNT_SUCCESS:
          default:
            fprintf (stderr, ": %s", strerror (saved_errno));
        }
    }

  fprintf (stderr, "\n");
  exit (1);
}
