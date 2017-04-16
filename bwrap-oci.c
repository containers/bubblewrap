/* bubblewrap-oci
 * Copyright (C) 2016 Giuseppe Scrivano
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
#include <unistd.h>
#include <stdlib.h>
#include <error.h>
#include <stdio.h>
#include <glib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <seccomp.h>
#include <errno.h>
#include <glib/gprintf.h>

static gboolean opt_dry_run;
static gboolean opt_version;
static const char *opt_configuration = "config.json";

static GOptionEntry entries[] =
{
  { "configuration", 'c', 0, G_OPTION_ARG_STRING, &opt_configuration, "Configuration file", "FILE" },
  { "dry-run", 'd', 0, G_OPTION_ARG_NONE, &opt_dry_run, "Print the command line for bubblewrap", NULL },
  { "version", 0, 0, G_OPTION_ARG_NONE, &opt_version, "Print version information and exit", NULL },
  { NULL }
};

struct context
{
  GList *options;
  GList *readonly_paths;
  GList *args;
  size_t total_elements;
  scmp_filter_ctx seccomp;
};

static uint32_t
get_seccomp_operator (const char *name)
{
  if (g_strcmp0 (name, "SCMP_CMP_NE") == 0)
    return SCMP_CMP_NE;
  if (g_strcmp0 (name, "SCMP_CMP_LT") == 0)
    return SCMP_CMP_LT;
  if (g_strcmp0 (name, "SCMP_CMP_LE") == 0)
    return SCMP_CMP_LE;
  if (g_strcmp0 (name, "SCMP_CMP_EQ") == 0)
    return SCMP_CMP_EQ;
  if (g_strcmp0 (name, "SCMP_CMP_GE") == 0)
    return SCMP_CMP_GE;
  if (g_strcmp0 (name, "SCMP_CMP_GT") == 0)
    return SCMP_CMP_GT;
  if (g_strcmp0 (name, "SCMP_CMP_MASKED_EQ") == 0)
    return SCMP_CMP_MASKED_EQ;
  else
    error (EXIT_FAILURE, 0, "unsupported seccomp operator %s\n", name);

  return -1;
}

static uint32_t
get_seccomp_action (const char *name)
{
  if (g_strcmp0 (name, "SCMP_ACT_KILL") == 0)
    return SCMP_ACT_KILL;
  if (g_strcmp0 (name, "SCMP_ACT_ALLOW") == 0)
    return SCMP_ACT_ALLOW;
  if (g_strcmp0 (name, "SCMP_ACT_TRAP") == 0)
    return SCMP_ACT_TRAP;
  if (g_strcmp0 (name, "SCMP_ACT_ERRNO") == 0)
    return SCMP_ACT_ERRNO(EPERM);
  if (g_strcmp0 (name, "SCMP_ACT_TRACE") == 0)
    return SCMP_ACT_TRACE(EPERM);
  else
    error (EXIT_FAILURE, 0, "unsupported seccomp action %s\n", name);

  return -1;
}

static GList *
append_to_list (struct context *context, GList *list, va_list valist)
{
  const char *val;
  while (1)
    {
      val = va_arg (valist, const char *);
      if (val == NULL)
        break;
      list = g_list_append (list, g_strdup (val));
      context->total_elements++;
    }
  return list;
}

static void
collect_options (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->options = append_to_list (context, context->options, valist);
  va_end (valist);
}

static void
add_readonly_path (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->readonly_paths = append_to_list (context, context->readonly_paths, valist);
  va_end (valist);
}

static void
collect_args (struct context *context, ...)
{
  va_list valist;
  va_start (valist, context);
  context->args = append_to_list (context, context->args, valist);
  va_end (valist);
}

static void
do_linux (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  if (json_object_has_member (root, "namespaces"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "namespaces");
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          const char *typeval;
          GVariant *type, *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          if (variant == NULL)
            error (EXIT_FAILURE, 0, "error while deserializing namespaces\n");

          type = g_variant_lookup_value (variant, "type", G_VARIANT_TYPE_STRING);
          typeval = g_variant_get_string (type, NULL);
          if (g_strcmp0 (typeval, "user") == 0)
            collect_options (con, "--unshare-user", NULL);
          else if (g_strcmp0 (typeval, "ipc") == 0)
            collect_options (con, "--unshare-ipc", NULL);
          else if (g_strcmp0 (typeval, "pid") == 0)
            collect_options (con, "--unshare-pid", NULL);
          else if (g_strcmp0 (typeval, "mount") == 0)
            ;
          else if (g_strcmp0 (typeval, "network") == 0)
            collect_options (con, "--unshare-net", NULL);
          else if (g_strcmp0 (typeval, "cgroup") == 0)
            collect_options (con, "--unshare-cgroup", NULL);
          else if (g_strcmp0 (typeval, "uts") == 0)
            collect_options (con, "--unshare-uts", NULL);
          else
            error (EXIT_FAILURE, 0, "unknown namespace %s\n", typeval);
          g_variant_unref (variant);
        }
    }
  if (json_object_has_member (root, "readonlyPaths"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "readonlyPaths");
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *variant = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *path = g_variant_get_string (variant, NULL);

          add_readonly_path (con, "--ro-bind", path, path, NULL);

          g_variant_unref (variant);
        }
    }
  if (json_object_has_member (root, "maskedPaths"))
    {
      JsonNode *namespaces;
      GList *members;
      GList *iter;
      namespaces = json_object_get_member (root, "maskedPaths");
      members = json_array_get_elements (json_node_get_array (namespaces));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *variant = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *path = g_variant_get_string (variant, NULL);

          add_readonly_path (con, "--bind", "/dev/null", path, NULL);

          g_variant_unref (variant);
        }
    }
  if (json_object_has_member (root, "mountLabel"))
    {
      JsonNode *label = json_object_get_member (root, "mountLabel");
      collect_options (con, "--mount-label", json_node_get_string (label), NULL);
    }
  if (json_object_has_member (root, "seccomp"))
    {
      GList *members;
      GList *iter;
      JsonObject *seccomp = json_node_get_object (json_object_get_member (root, "seccomp"));
      JsonNode *defaultAction = json_object_get_member (seccomp, "defaultAction");
      JsonNode *architectures = json_object_get_member (seccomp, "architectures");
      JsonNode *syscalls = json_object_get_member (seccomp, "syscalls");
      const char *defActionString = "SCMP_ACT_ALLOW";

      if (defaultAction)
        defActionString = json_node_get_string (defaultAction);

      con->seccomp = seccomp_init (get_seccomp_action (defActionString));
      if (con->seccomp == NULL)
        error (EXIT_FAILURE, 0, "error while setting up seccomp");

      if (architectures)
        {
          members = json_array_get_elements (json_node_get_array (architectures));
          for (iter = members; iter; iter = iter->next)
            {
              int ret;
              uint32_t arch_token;
              const char *arch = json_node_get_string (iter->data);
              gchar *arch_lowercase;

              if (g_str_has_prefix (arch, "SCMP_ARCH_"))
                arch += 10;

              arch_lowercase = g_ascii_strdown (arch, -1);
              arch_token = seccomp_arch_resolve_name (arch_lowercase);
              if (arch_token == 0)
                error (EXIT_FAILURE, 0, "error while setting up seccomp, unknown architecture %s", arch_lowercase);
              ret = seccomp_arch_add (con->seccomp, SCMP_ARCH_X86_64);
              if (ret < 0 && ret != -EEXIST)
                error (EXIT_FAILURE, errno, "error while setting up seccomp");
              g_free (arch_lowercase);
            }
        }

      members = json_array_get_elements (json_node_get_array (syscalls));
      for (iter = members; iter; iter = iter->next)
        {
          GArray *args_array = NULL;
          gsize child;
          GVariant *namevar, *actionvar, *args;
          const char *name = NULL, *action = NULL;
          GVariant *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

          namevar = g_variant_lookup_value (variant, "name", G_VARIANT_TYPE_STRING);
          actionvar = g_variant_lookup_value (variant, "action", G_VARIANT_TYPE_STRING);
          name = g_variant_get_string (namevar, NULL);
          action = g_variant_get_string (actionvar, NULL);
          args = g_variant_lookup_value (variant, "args", G_VARIANT_TYPE_ARRAY);

          if (args)
            args_array = g_array_new (FALSE, FALSE, sizeof (struct scmp_arg_cmp));

          for (child = 0; child < g_variant_n_children (args); child++)
            {
              struct scmp_arg_cmp arg_cmp;
              GVariant *indexvar, *valuevar, *valueTwovar, *opvar;
              guint64 index, value, valueTwo;
              const char *op = NULL;
              GVariant *arg = g_variant_get_variant (g_variant_get_child_value (args, child));

              indexvar = g_variant_lookup_value (arg, "index", G_VARIANT_TYPE_INT64);
              index = g_variant_get_int64 (indexvar);
              valuevar = g_variant_lookup_value (arg, "value", G_VARIANT_TYPE_INT64);
              value = g_variant_get_int64 (valuevar);
              valueTwovar = g_variant_lookup_value (arg, "valueTwo", G_VARIANT_TYPE_INT64);
              valueTwo = g_variant_get_int64 (valueTwovar);
              opvar = g_variant_lookup_value (arg, "op", G_VARIANT_TYPE_STRING);
              op = g_variant_get_string (opvar, NULL);

              arg_cmp.arg = index;
              arg_cmp.op = get_seccomp_operator (op);
              arg_cmp.datum_a = value;
              arg_cmp.datum_b = valueTwo;

              g_array_append_val (args_array, arg_cmp);
            }

          if (args)
            {
              if (seccomp_rule_add_array (con->seccomp,
                                          get_seccomp_action (action),
                                          seccomp_syscall_resolve_name (name),
                                          args_array->len,
                                          (const struct scmp_arg_cmp *) args_array->data) < 0)
                {
                  error (EXIT_FAILURE, 0, "error while setting up seccomp");
                }
            }
          else
            {
              if (seccomp_rule_add (con->seccomp,
                                    get_seccomp_action (action),
                                    seccomp_syscall_resolve_name (name), 0) < 0)
                {
                  error (EXIT_FAILURE, 0, "error while setting up seccomp");
                }
            }

          if (args_array)
            g_array_free (args_array, TRUE);
        }
    }
}

static void
do_root (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  gboolean readonly = FALSE;
  JsonNode *path = json_object_get_member (root, "path");

  if (json_object_has_member (root, "readonly"))
    readonly = json_node_get_boolean (json_object_get_member (root, "readonly"));

  collect_options (con, readonly ? "--ro-bind" : "--bind", json_node_get_string (path), "/", NULL);
}

static void
do_mounts (struct context *con, JsonNode *rootval)
{
  GList *members;
  GList *iter;
  members = json_array_get_elements (json_node_get_array (rootval));
  for (iter = members; iter; iter = iter->next)
    {
      const char *typeval = NULL, *destinationval = NULL;
      GVariant *destination, *type, *variant = json_gvariant_deserialize (iter->data, "a{sv}", NULL);

      if (variant == NULL)
        error (EXIT_FAILURE, 0, "error while deserializing mounts\n");

      type = g_variant_lookup_value (variant, "type", G_VARIANT_TYPE_STRING);
      if (type)
        typeval = g_variant_get_string (type, NULL);

      destination = g_variant_lookup_value (variant, "destination", G_VARIANT_TYPE_STRING);
      if (destination)
        destinationval = g_variant_get_string (destination, NULL);

      if (typeval == NULL || destinationval == NULL)
        error (EXIT_FAILURE, 0, "invalid mount type or destination\n");

      if (g_strcmp0 (typeval, "proc") == 0)
        collect_options (con, "--proc", destinationval, NULL);
      else if (g_strcmp0 (typeval, "mqueue") == 0)
        collect_options (con, "--mqueue", destinationval, NULL);
      else if (g_strcmp0 (typeval, "tmpfs") == 0)
        collect_options (con, "--tmpfs", destinationval, NULL);
      else if (g_strcmp0 (typeval, "bind") == 0)
        {
          const char *sourceval = NULL;
          GVariant *source;
          source = g_variant_lookup_value (variant, "source", G_VARIANT_TYPE_STRING);
          if (! source)
            error (EXIT_FAILURE, 0, "invalid source for bind mount\n");
          sourceval = g_variant_get_string (destination, NULL);
          collect_options (con, "--bind", sourceval, destinationval, NULL);
        }
      else if (g_strcmp0 (typeval, "cgroup") == 0)
        ;
      else if (g_strcmp0 (typeval, "devpts") == 0)
        ;
      else if (g_strcmp0 (typeval, "sysfs") == 0)
        ;
      else
        error (EXIT_FAILURE, 0, "unknown mount type %s\n", typeval);
      g_variant_unref (variant);
    }
}

static void
do_process (struct context *con, JsonNode *rootval)
{
  JsonObject *root = json_node_get_object (rootval);
  if (json_object_has_member (root, "terminal"))
    {
      gboolean terminal = json_node_get_boolean (json_object_get_member (root, "terminal"));
      if (terminal)
        collect_options (con, "--dev-bind", "/dev/tty", "/dev/tty", NULL);
    }
  if (json_object_has_member (root, "cwd"))
    {
      JsonNode *cwd = json_object_get_member (root, "cwd");
      collect_options (con, "--chdir", json_node_get_string (cwd), NULL);
    }
  if (json_object_has_member (root, "env"))
    {
      GList *members;
      GList *iter;
      members = json_array_get_elements (json_node_get_array (json_object_get_member (root, "env")));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *env = json_gvariant_deserialize (iter->data, "s", NULL);
          char *val = g_variant_dup_string (env, NULL);
          gchar *sep = g_strrstr (val, "=");
          if (!sep)
            error (EXIT_FAILURE, 0, "invalid env setting\n");
          *sep = '\0';
          collect_options (con, "--setenv", val, sep + 1, NULL);
          g_free (val);
          g_variant_unref (env);
        }
    }
  if (json_object_has_member (root, "selinuxLabel"))
    {
      JsonNode *label = json_object_get_member (root, "selinuxLabel");
      collect_options (con, "--exec-label", json_node_get_string (label), NULL);
    }
  if (json_object_has_member (root, "user"))
    {
      JsonNode *user = json_object_get_member (root, "user");
      JsonObject *userobj = json_node_get_object (user);
      if (json_object_has_member (userobj, "uid"))
        {
          gint64 uid = json_node_get_int (json_object_get_member (userobj, "uid"));
          gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, uid);
          collect_options (con, "--uid", argument, NULL);
          g_free (argument);
        }
      if (json_object_has_member (userobj, "gid"))
        {
          gint64 gid = json_node_get_int (json_object_get_member (userobj, "gid"));
          gchar *argument = g_strdup_printf ("%" G_GINT64_FORMAT, gid);
          collect_options (con, "--gid", argument, NULL);
          g_free (argument);
        }
    }
  if (json_object_has_member (root, "args"))
    {
      GList *members;
      GList *iter;
      members = json_array_get_elements (json_node_get_array (json_object_get_member (root, "args")));
      for (iter = members; iter; iter = iter->next)
        {
          GVariant *arg = json_gvariant_deserialize (iter->data, "s", NULL);
          const char *val = g_variant_get_string (arg, NULL);
          collect_args (con, val, NULL);
        }
    }
}

static void
dump_argv (char **argv)
{
  gboolean first = TRUE;
  while (*argv)
    {
      g_print ("%s%s", first ? "" : " ", *argv);
      first = FALSE;
      argv++;
    }
  g_print ("\n");
}

static void
generate_seccomp_rules_file (struct context *context)
{
  if (context->seccomp)
    {
      char fdstr[10];
      int fd = open (".", O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
      if (fd < 0)
        error (EXIT_FAILURE, errno, "error opening temp file");

      if (seccomp_export_bpf (context->seccomp, fd) < 0)
        error (EXIT_FAILURE, errno, "error writing seccomp rules file");
      if (lseek (fd, 0, SEEK_SET) < 0)
        error (EXIT_FAILURE, errno, "error seeking seccomp rules file");

      g_sprintf (fdstr, "%i", fd);
      collect_options (context, "--seccomp", fdstr);
    }
}

static char **
generate_bwrap_argv (struct context *context)
{
  int bwrap_argc = 0;
  char **bwrap_argv = bwrap_argv = g_new0 (char *, context->total_elements + 2);
  int current_list = 0;
  GList **lists[] = {&context->options, &context->readonly_paths, &context->args, NULL};

  bwrap_argv[bwrap_argc++] = "bwrap";
  while (lists[current_list])
    {
      GList *l = *lists[current_list];
      while (l != NULL)
        {
          bwrap_argv[bwrap_argc++] = (char *) l->data;
          l = l->next;
        }
      current_list++;
    }
  return bwrap_argv;
}

int
main (int argc, char *argv[])
{
  JsonNode *rootval;
  JsonObject *root;
  GError *gerror = NULL;
  struct context *context;
  char **bwrap_argv = NULL;
  JsonParser *parser;
  GOptionContext *opt_context;

  opt_context = g_option_context_new ("- converter from OCI configuration to bubblewrap command line");
  g_option_context_add_main_entries (opt_context, entries, PACKAGE_STRING);
  if (!g_option_context_parse (opt_context, &argc, &argv, &gerror))
    {
      error (EXIT_FAILURE, 0, "option parsing failed: %s", gerror->message);
    }
  g_option_context_free (opt_context);

  if (opt_version)
    {
      g_print ("%s\n", PACKAGE_STRING);
      exit (EXIT_SUCCESS);
    }

  context = g_new0 (struct context, 1);
  parser = json_parser_new ();
  json_parser_load_from_file (parser, opt_configuration, &gerror);
  if (gerror)
    {
      g_print ("Unable to parse `%s': %s\n", opt_configuration, gerror->message);
      g_error_free (gerror);
      g_object_unref (parser);
      return EXIT_FAILURE;
    }

  rootval = json_parser_get_root (parser);
  root = json_node_get_object (rootval);

  if (json_object_has_member (root, "root"))
    do_root (context, json_object_get_member (root, "root"));

  if (json_object_has_member (root, "linux"))
    do_linux (context, json_object_get_member (root, "linux"));

  if (json_object_has_member (root, "mounts"))
    do_mounts (context, json_object_get_member (root, "mounts"));

  if (json_object_has_member (root, "process"))
    do_process (context, json_object_get_member (root, "process"));

  g_object_unref (parser);

  generate_seccomp_rules_file (context);
  bwrap_argv = generate_bwrap_argv (context);

  g_free (context);

  if (opt_dry_run)
    {
      dump_argv (bwrap_argv);
      return EXIT_SUCCESS;
    }

  execvp (bwrap_argv[0], bwrap_argv);

  return EXIT_FAILURE;
}
