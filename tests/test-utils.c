/*
 * Copyright © 2019-2021 Collabora Ltd.
 *
 * SPDX-License-Identifier: LGPL-2-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>

#include "utils.h"

/* A small implementation of TAP */
static unsigned int test_number = 0;
static void
ok (const char *format, ...)
{
  va_list ap;

  printf ("ok %u - ", ++test_number);
  va_start (ap, format);
  vprintf (format, ap);
  va_end (ap);
  printf ("\n");
}

/* for simplicity we always die immediately on failure */
#define not_ok(fmt, ...) die (fmt, ## __VA_ARGS__)

/* approximately GLib-compatible helper macros */
#define g_test_message(fmt, ...) printf ("# " fmt "\n", ## __VA_ARGS__)
#define g_assert_cmpstr(left_expr, op, right_expr) \
  do { \
    const char *left = (left_expr); \
    const char *right = (right_expr); \
    if (strcmp0 (left, right) op 0) \
      ok ("%s (\"%s\") %s %s (\"%s\")", #left_expr, left, #op, #right_expr, right); \
    else \
      not_ok ("expected %s (\"%s\") %s %s (\"%s\")", \
              #left_expr, left, #op, #right_expr, right); \
  } while (0)
#define g_assert_cmpint(left_expr, op, right_expr) \
  do { \
    intmax_t left = (left_expr); \
    intmax_t right = (right_expr); \
    if (left op right) \
      ok ("%s (%ji) %s %s (%ji)", #left_expr, left, #op, #right_expr, right); \
    else \
      not_ok ("expected %s (%ji) %s %s (%ji)", \
              #left_expr, left, #op, #right_expr, right); \
  } while (0)
#define g_assert_cmpuint(left_expr, op, right_expr) \
  do { \
    uintmax_t left = (left_expr); \
    uintmax_t right = (right_expr); \
    if (left op right) \
      ok ("%s (%ju) %s %s (%ju)", #left_expr, left, #op, #right_expr, right); \
    else \
      not_ok ("expected %s (%ju) %s %s (%ju)", \
              #left_expr, left, #op, #right_expr, right); \
  } while (0)
#define g_assert_true(expr) \
  do { \
    if ((expr)) \
      ok ("%s", #expr); \
    else \
      not_ok ("expected %s to be true", #expr); \
  } while (0)
#define g_assert_false(expr) \
  do { \
    if (!(expr)) \
      ok ("!(%s)", #expr); \
    else \
      not_ok ("expected %s to be false", #expr); \
  } while (0)
#define g_assert_null(expr) \
  do { \
    if ((expr) == NULL) \
      ok ("%s was null", #expr); \
    else \
      not_ok ("expected %s to be null", #expr); \
  } while (0)
#define g_assert_nonnull(expr) \
  do { \
    if ((expr) != NULL) \
      ok ("%s wasn't null", #expr); \
    else \
      not_ok ("expected %s to be non-null", #expr); \
  } while (0)

static int
strcmp0 (const char *left,
         const char *right)
{
  if (left == right)
    return 0;

  if (left == NULL)
    return -1;

  if (right == NULL)
    return 1;

  return strcmp (left, right);
}

static void
test_n_elements (void)
{
  int three[] = { 1, 2, 3 };
  g_assert_cmpuint (N_ELEMENTS (three), ==, 3);
}

static void
test_strconcat (void)
{
  const char *a = "aaa";
  const char *b = "bbb";
  char *ab = strconcat (a, b);
  g_assert_cmpstr (ab, ==, "aaabbb");
  free (ab);
}

static void
test_strconcat3 (void)
{
  const char *a = "aaa";
  const char *b = "bbb";
  const char *c = "ccc";
  char *abc = strconcat3 (a, b, c);
  g_assert_cmpstr (abc, ==, "aaabbbccc");
  free (abc);
}

static void
test_has_prefix (void)
{
  g_assert_true (has_prefix ("foo", "foo"));
  g_assert_true (has_prefix ("foobar", "foo"));
  g_assert_false (has_prefix ("foobar", "fool"));
  g_assert_false (has_prefix ("foo", "fool"));
  g_assert_true (has_prefix ("foo", ""));
  g_assert_true (has_prefix ("", ""));
  g_assert_false (has_prefix ("", "no"));
  g_assert_false (has_prefix ("yes", "no"));
}

static void
test_has_path_prefix (void)
{
  static const struct
  {
    const char *str;
    const char *prefix;
    bool expected;
  } tests[] =
  {
    { "/run/host/usr", "/run/host", TRUE },
    { "/run/host/usr", "/run/host/", TRUE },
    { "/run/host", "/run/host", TRUE },
    { "////run///host////usr", "//run//host", TRUE },
    { "////run///host////usr", "//run//host////", TRUE },
    { "/run/hostage", "/run/host", FALSE },
    /* Any number of leading slashes is ignored, even zero */
    { "foo/bar", "/foo", TRUE },
    { "/foo/bar", "foo", TRUE },
  };
  size_t i;

  for (i = 0; i < N_ELEMENTS (tests); i++)
    {
      const char *str = tests[i].str;
      const char *prefix = tests[i].prefix;
      bool expected = tests[i].expected;

      if (expected)
        g_test_message ("%s should have path prefix %s", str, prefix);
      else
        g_test_message ("%s should not have path prefix %s", str, prefix);

      if (expected)
        g_assert_true (has_path_prefix (str, prefix));
      else
        g_assert_false (has_path_prefix (str, prefix));
    }
}

int
main (int argc,
      char **argv)
{
  setvbuf (stdout, NULL, _IONBF, 0);
  test_n_elements ();
  test_strconcat ();
  test_strconcat3 ();
  test_has_prefix ();
  test_has_path_prefix ();
  printf ("1..%u\n", test_number);
  return 0;
}
