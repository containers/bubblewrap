# Source library for shell script tests.
# Add non-bubblewrap-specific code to libtest-core.sh instead.
#
# Copyright (C) 2017 Colin Walters <walters@verbum.org>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.

if [ -n "${G_TEST_SRCDIR:-}" ]; then
  test_srcdir="${G_TEST_SRCDIR}/tests"
else
  test_srcdir=$(dirname $0)
fi

if [ -n "${G_TEST_BUILDDIR:-}" ]; then
  test_builddir="${G_TEST_BUILDDIR}/tests"
else
  test_builddir=$(dirname $0)
fi

. "${test_srcdir}/libtest-core.sh"

extract_child_pid() {
    grep child-pid "$1" | sed "s/^.*: \([0-9]*\).*/\1/"
}
