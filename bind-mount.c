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

#include <sys/mount.h>

#include "utils.h"
#include "bind-mount.h"

static char *
skip_token (char *line, bool eat_whitespace)
{
  while (*line != ' ' && *line != '\n')
    line++;

  if (eat_whitespace && *line == ' ')
    line++;

  return line;
}

static char *
unescape_inline (char *escaped)
{
  char *unescaped, *res;
  const char *end;

  res = escaped;
  end = escaped + strlen (escaped);

  unescaped = escaped;
  while (escaped < end)
    {
      if (*escaped == '\\')
        {
          *unescaped++ =
            ((escaped[1] - '0') << 6) |
            ((escaped[2] - '0') << 3) |
            ((escaped[3] - '0') << 0);
          escaped += 4;
        }
      else
        {
          *unescaped++ = *escaped++;
        }
    }
  *unescaped = 0;
  return res;
}

static bool
match_token (const char *token, const char *token_end, const char *str)
{
  while (token != token_end && *token == *str)
    {
      token++;
      str++;
    }
  if (token == token_end)
    return *str == 0;

  return FALSE;
}

static unsigned long
decode_mountoptions (const char *options)
{
  const char *token, *end_token;
  int i;
  unsigned long flags = 0;
  static const struct  { int   flag;
                         char *name;
  } flags_data[] = {
    { 0, "rw" },
    { MS_RDONLY, "ro" },
    { MS_NOSUID, "nosuid" },
    { MS_NODEV, "nodev" },
    { MS_NOEXEC, "noexec" },
    { MS_NOATIME, "noatime" },
    { MS_NODIRATIME, "nodiratime" },
    { MS_RELATIME, "relatime" },
    { 0, NULL }
  };

  token = options;
  do
    {
      end_token = strchr (token, ',');
      if (end_token == NULL)
        end_token = token + strlen (token);

      for (i = 0; flags_data[i].name != NULL; i++)
        {
          if (match_token (token, end_token, flags_data[i].name))
            {
              flags |= flags_data[i].flag;
              break;
            }
        }

      if (*end_token != 0)
        token = end_token + 1;
      else
        token = NULL;
    }
  while (token != NULL);

  return flags;
}

typedef struct MountInfo MountInfo;
struct MountInfo {
  char *mountpoint;
  unsigned long options;
};

typedef MountInfo *MountTab;

static void
mount_tab_free (MountTab tab)
{
  int i;

  /* An allocated MountTab always ends with a zeroed MountInfo, so we can tell
     when to stop freeing memory. */
  for (i = 0; tab[i].mountpoint != NULL; i++)
    free (tab[i].mountpoint);
  free (tab);
}

static inline void
cleanup_mount_tabp (void *p)
{
  void **pp = (void **) p;

  if (*pp)
    mount_tab_free ((MountTab)*pp);
}

#define cleanup_mount_tab __attribute__((cleanup (cleanup_mount_tabp)))

typedef struct MountInfoLine MountInfoLine;
struct MountInfoLine {
  char *mountpoint;
  unsigned long options;
  bool covered;
  int id;
  int parent_id;
  MountInfoLine *first_child;
  MountInfoLine *next_sibling;
};

typedef MountInfoLine *MountInfoLines;

static unsigned int
count_lines (const char *data)
{
  unsigned int count = 0;
  const char *p = data;

  while (*p != 0)
    {
      if (*p == '\n')
        count++;
      p++;
    }

  /* If missing final newline, add one */
  if (p > data && *(p-1) != '\n')
    count++;

  return count;
}

static int
count_mounts (MountInfoLine *line)
{
  MountInfoLine *child;
  int res = 0;

  if (!line->covered)
    res += 1;

  child = line->first_child;
  while (child != NULL)
    {
      res += count_mounts (child);
      child = child->next_sibling;
    }

  return res;
}

static MountInfo *
collect_mounts (MountInfo *info, MountInfoLine *line)
{
  MountInfoLine *child;

  if (!line->covered)
    {
      info->mountpoint = xstrdup (line->mountpoint);
      info->options = line->options;
      info ++;
    }

  child = line->first_child;
  while (child != NULL)
    {
      info = collect_mounts (info, child);
      child = child->next_sibling;
    }

  return info;
}

static MountInfoLines
read_mountinfo (int           proc_fd,
                unsigned int *mount_count)
{
  cleanup_free char *mountinfo = NULL;
  unsigned int n_lines;
  MountInfoLine *lines;
  char *line;
  int i;

  mountinfo = load_file_at (proc_fd, "self/mountinfo");
  if (mountinfo == NULL)
    die_with_error ("Can't open /proc/self/mountinfo");

  n_lines = count_lines (mountinfo);
  lines = xcalloc (n_lines * sizeof (MountInfoLine));

  line = mountinfo;
  i = 0;
  while (*line != 0)
    {
      int rc, consumed = 0;
      unsigned int maj, min;
      char *end;
      char *rest;
      char *mountpoint;
      char *mountpoint_end;
      char *options;
      char *options_end;
      char *next_line;

      assert (i < n_lines);

      end = strchr (line, '\n');
      if (end != NULL)
        {
          *end = 0;
          next_line = end + 1;
        }
      else
        next_line = line + strlen (line);

      rc = sscanf (line, "%d %d %u:%u %n", &lines[i].id, &lines[i].parent_id, &maj, &min, &consumed);
      if (rc != 4)
        die ("Can't parse mountinfo line");
      rest = line + consumed;

      rest = skip_token (rest, TRUE); /* mountroot */
      mountpoint = rest;
      rest = skip_token (rest, FALSE); /* mountpoint */
      mountpoint_end = rest++;
      options = rest;
      rest = skip_token (rest, FALSE); /* vfs options */
      options_end = rest;

      *mountpoint_end = 0;
      lines[i].mountpoint = xstrdup (unescape_inline (mountpoint));

      *options_end = 0;
      lines[i].options = decode_mountoptions (options);

      i++;
      line = next_line;
    }
  assert (i == n_lines);

  *mount_count = n_lines;
  return lines;
}

static int
max_mount_id (const MountInfoLines lines,
              unsigned int         n_lines)
{
  int i;
  int max_id;

  max_id = 0;
  for (i = 0; i < n_lines; i++)
    {
      if (lines[i].id > max_id)
        max_id = lines[i].id;
      if (lines[i].parent_id > max_id)
        max_id = lines[i].parent_id;
    }
  return max_id;
}

static MountTab
parse_mountinfo (const MountInfoLines  lines,
                 unsigned int          n_lines,
                 const char           *root_mount)
{
  int root;
  int i;
  int max_id;
  cleanup_mount_tab MountTab mount_tab = NULL;
  cleanup_free MountInfoLine **by_id = NULL;
  int n_mounts;
  MountInfo *end_tab;

  root = -1;
  for (i = 0; i < n_lines; i++)
    {
      if (path_equal (lines[i].mountpoint, root_mount))
        root = i;
    }
  if (root == -1)
    {
      /* Allocate one more than required, so cleanup_mount_tabp knows when to
         stop freeing memory. */
      mount_tab = xcalloc (sizeof (MountInfo));
      return steal_pointer (&mount_tab);
    }

  /* Allocate one more than required, so we can use IDs as indexes into
     by_id. */
  max_id = max_mount_id (lines, n_lines);
  by_id = xcalloc ((max_id + 1) * sizeof (MountInfoLine*));
  for (i = 0; i < n_lines; i++)
    by_id[lines[i].id] = &lines[i];

  for (i = 0; i < n_lines; i++)
    {
      MountInfoLine *this = &lines[i];
      MountInfoLine *parent = by_id[this->parent_id];
      MountInfoLine **to_sibling;
      MountInfoLine *sibling;
      bool covered = FALSE;

      if (!has_path_prefix (this->mountpoint, root_mount))
        continue;

      if (parent == NULL)
        continue;

      if (strcmp (parent->mountpoint, this->mountpoint) == 0)
        parent->covered = TRUE;

      to_sibling = &parent->first_child;
      sibling = parent->first_child;
      while (sibling != NULL)
        {
          /* If this mountpoint is a path prefix of the sibling, say
           * this->mountpoint == "/foo/bar" and sibling->mountpoiunt == "/foo",
           * then it is covered by the sibling, and we drop it. */
          if (has_path_prefix (this->mountpoint, sibling->mountpoint))
            {
              covered = TRUE;
              break;
            }

          /* If the sibling is a path prefix of this mount point, say
           * this->mountpoint == "/foo" and sibling->mountpoint == "/foo/bar",
           * then the sibling is covered, and we drop it.
            */
          if (has_path_prefix (sibling->mountpoint, this->mountpoint))
            *to_sibling = sibling->next_sibling;
          else
            to_sibling = &sibling->next_sibling;
          sibling = sibling->next_sibling;
        }

      if (covered)
          continue;

      *to_sibling = this;
    }

  n_mounts = count_mounts (&lines[root]);
  /* Allocate one more than required, so cleanup_mount_tabp knows when to stop
     freeing memory. */
  mount_tab = xcalloc ((n_mounts + 1) * sizeof (MountInfo));

  end_tab = collect_mounts (&mount_tab[0], &lines[root]);
  assert (end_tab == &mount_tab[n_mounts]);

  return steal_pointer (&mount_tab);
}

static int
find_parent (MountInfoLines  lines,
             unsigned int    line_count,
             const char     *mountpoint)
{
  cleanup_free char *prefix = NULL;
  int parent;
  const char *start;
  bool mount_found;
  int i;

  prefix = xcalloc (strlen (mountpoint) + 1);
  prefix[0] = '/';

  parent = -1;
  start = mountpoint;
  do
    {
      start = index (start, '/');
      if (start != NULL)
        {
          memcpy (prefix, mountpoint, start - mountpoint);
          start ++;
        }
      else
          strcpy (prefix, mountpoint);

      do
        {
          mount_found = FALSE;
          for (i = 0; i < line_count; i++)
            {
              if (strcmp (lines[i].mountpoint, prefix) == 0
                  && (parent == -1 || lines[i].parent_id == lines[parent].id))
                {
                  parent = i;
                  mount_found = 1;
                  break;
                }
            }
        }
      while (mount_found);
    }
  while (start != NULL);

  return parent;
}

static MountInfoLines
add_mountinfo (MountInfoLines  old_lines,
               unsigned int    line_count,
               const char     *src,
               char           *dest)
{
  MountInfoLines new_lines;
  int src_parent;
  int dest_parent;
  int i;

  src_parent = find_parent (old_lines, line_count, src);
  dest_parent = find_parent (old_lines, line_count, dest);

  new_lines = xcalloc ((line_count + 1)  * sizeof (MountInfoLine));
  for (i = 0; i < line_count; i++)
    {
      new_lines[i].mountpoint = old_lines[i].mountpoint;
      new_lines[i].options = old_lines[i].options;
      new_lines[i].id = old_lines[i].id;
      new_lines[i].parent_id = old_lines[i].parent_id;
    }
  new_lines[line_count].mountpoint = xstrdup (dest);
  new_lines[line_count].options = old_lines[src_parent].options;
  new_lines[line_count].id = max_mount_id (old_lines, line_count) + 1;
  new_lines[line_count].parent_id = old_lines[dest_parent].id;

  free (old_lines);

  return new_lines;
}

int
bind_mount (int           proc_fd,
            const char   *src,
            const char   *dest,
            bind_option_t options)
{
  static MountInfoLines mountinfo = NULL;
  static unsigned int mount_count = 0;

  bool readonly = (options & BIND_READONLY) != 0;
  bool devices = (options & BIND_DEVICES) != 0;
  bool recursive = (options & BIND_RECURSIVE) != 0;
  unsigned long current_flags, new_flags;
  cleanup_mount_tab MountTab mount_tab = NULL;
  cleanup_free char *resolved_src = NULL;
  cleanup_free char *resolved_dest = NULL;
  int i;

  if (mountinfo == NULL)
    mountinfo = read_mountinfo (proc_fd, &mount_count);

  /* The mount operation will resolve any symlinks in the destination path, so
     we need to do that too. */
  resolved_dest = realpath (dest, NULL);
  if (resolved_dest == NULL)
    return 2;

  if (src)
    {
      if (mount (src, dest, NULL, MS_SILENT | MS_BIND | (recursive ? MS_REC : 0), NULL) != 0)
        return 1;

      /* The mount operation will resolve any symlinks in the source path, so
         we need to do that too. */
      resolved_src = realpath (src, NULL);
      if (resolved_src == NULL)
        return 4;
      mountinfo = add_mountinfo (mountinfo, mount_count, resolved_src, resolved_dest);
      mount_count ++;
    }

  mount_tab = parse_mountinfo (mountinfo, mount_count, resolved_dest);
  assert (path_equal (mount_tab[0].mountpoint, resolved_dest));

  current_flags = mount_tab[0].options;
  new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
  if (new_flags != current_flags &&
      mount ("none", resolved_dest,
             NULL, MS_SILENT | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
    return 3;

  /* We need to work around the fact that a bind mount does not apply the
   * flags, so we need to manually apply the flags to all submounts in the
   * recursive case.
   *
   * Note: This does not apply the flags to mounts that are later propagated
   * into this namespace.
   */
  if (recursive)
    {
      for (i = 1; mount_tab[i].mountpoint != NULL; i++)
        {
          current_flags = mount_tab[i].options;
          new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
          if (new_flags != current_flags &&
              mount ("none", mount_tab[i].mountpoint,
                     NULL, MS_SILENT | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
            {
              /* If we can't read the mountpoint we can't remount it, but that should
                 be safe to ignore because its not something the user can access. */
              if (errno != EACCES)
                return 5;
            }
        }
    }

  return 0;
}
