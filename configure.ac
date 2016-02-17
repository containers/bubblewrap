AC_PREREQ([2.63])
AC_INIT([bubblewrap], [0.1], [alexl@redhat.com])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])

AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([1.11 -Wno-portability foreign no-define tar-ustar no-dist-gzip dist-xz])
AM_MAINTAINER_MODE([enable])
AM_SILENT_RULES([yes])

AC_SYS_LARGEFILE

AC_PROG_CC
AM_PROG_CC_C_O

changequote(,)dnl
if test "x$GCC" = "xyes"; then
  WARN_CFLAGS="-Wall -Werror=missing-prototypes"
fi
changequote([,])dnl
AC_SUBST(WARN_CFLAGS)

# Initialize libtool
LT_PREREQ([2.2.4])
LT_INIT([disable-static])

PKG_CHECK_MODULES(LIBSECCOMP, [libseccomp])
AC_SUBST(LIBSECCOMP_CFLAGS)
AC_SUBST(LIBSECCOMP_LIBS)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT
