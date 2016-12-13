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
  const char *mountpoint;
  const char *options;
  bool covered;
  int id;
  int parent_id;
  MountInfoLine *first_child;
  MountInfoLine *next_sibling;
};

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
      info->options = decode_mountoptions (line->options);
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

static MountTab
parse_mountinfo (int  proc_fd,
                 const char *root_mount)
{
  cleanup_free char *mountinfo = NULL;
  cleanup_free MountInfoLine *lines = NULL;
  cleanup_free MountInfoLine **by_id = NULL;
  cleanup_mount_tab MountTab mount_tab = NULL;
  MountInfo *end_tab;
  int n_mounts;
  char *line;
  int i;
  int max_id;
  unsigned int n_lines;
  int root;

  mountinfo = load_file_at (proc_fd, "self/mountinfo");
  if (mountinfo == NULL)
    die_with_error ("Can't open /proc/self/mountinfo");

  n_lines = count_lines (mountinfo);
  lines = xcalloc (n_lines * sizeof (MountInfoLine));

  max_id = 0;
  line = mountinfo;
  i = 0;
  root = -1;
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
      lines[i].mountpoint = unescape_inline (mountpoint);

      *options_end = 0;
      lines[i].options = options;

      if (lines[i].id > max_id)
        max_id = lines[i].id;
      if (lines[i].parent_id > max_id)
        max_id = lines[i].parent_id;

      if (path_equal (lines[i].mountpoint, root_mount))
        root = i;

      i++;
      line = next_line;
    }
  assert (i == n_lines);

  if (root == -1)
    {
      mount_tab = xcalloc (sizeof (MountInfo) * (1));
      return steal_pointer (&mount_tab);
    }

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
          /* If this mountpoint is a path prefix of the sibling,
           * say this->mp=/foo/bar and sibling->mp=/foo, then it is
           * covered by the sibling, and we drop it. */
          if (has_path_prefix (this->mountpoint, sibling->mountpoint))
            {
              covered = TRUE;
              break;
            }

          /* If the sibling is a path prefix of this mount point,
           * say this->mp=/foo and sibling->mp=/foo/bar, then the sibling
           * is covered, and we drop it.
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
  mount_tab = xcalloc (sizeof (MountInfo) * (n_mounts + 1));

  end_tab = collect_mounts (&mount_tab[0], &lines[root]);
  assert (end_tab == &mount_tab[n_mounts]);

  return steal_pointer (&mount_tab);
}

int
bind_mount (int           proc_fd,
            const char   *src,
            const char   *dest,
            bind_option_t options)
{
  bool readonly = (options & BIND_READONLY) != 0;
  bool devices = (options & BIND_DEVICES) != 0;
  bool recursive = (options & BIND_RECURSIVE) != 0;
  unsigned long current_flags, new_flags;
  cleanup_mount_tab MountTab mount_tab = NULL;
  cleanup_free char *resolved_dest = NULL;
  int i;

  if (src)
    {
      if (mount (src, dest, NULL, MS_MGC_VAL | MS_BIND | (recursive ? MS_REC : 0), NULL) != 0)
        return 1;
    }

  /* The mount operation will resolve any symlinks in the destination
     path, so to find it in the mount table we need to do that too. */
  resolved_dest = realpath (dest, NULL);
  if (resolved_dest == NULL)
    return 2;

  mount_tab = parse_mountinfo (proc_fd, resolved_dest);
  if (mount_tab[0].mountpoint == NULL)
    {
      errno = EINVAL;
      return 2; /* No mountpoint at dest */
    }

  assert (path_equal (mount_tab[0].mountpoint, resolved_dest));
  current_flags = mount_tab[0].options;
  new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
  if (new_flags != current_flags &&
      mount ("none", resolved_dest,
             NULL, MS_MGC_VAL | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
    return 3;

  /* We need to work around the fact that a bind mount does not apply the flags, so we need to manually
   * apply the flags to all submounts in the recursive case.
   * Note: This does not apply the flags to mounts which are later propagated into this namespace.
   */
  if (recursive)
    {
      for (i = 1; mount_tab[i].mountpoint != NULL; i++)
        {
          current_flags = mount_tab[i].options;
          new_flags = current_flags | (devices ? 0 : MS_NODEV) | MS_NOSUID | (readonly ? MS_RDONLY : 0);
          if (new_flags != current_flags &&
              mount ("none", mount_tab[i].mountpoint,
                     NULL, MS_MGC_VAL | MS_BIND | MS_REMOUNT | new_flags, NULL) != 0)
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
