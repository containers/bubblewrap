AM_CFLAGS = $(WARN_CFLAGS)

bin_PROGRAMS = bwrap

bwrap_srcpath := $(srcdir)
include Makefile-bwrap.am

test-setuid: bwrap
	sudo chown root bwrap
	sudo sudo chmod u+s bwrap

test-setcaps: bwrap
	sudo setcap "cap_sys_admin+ep cap_sys_chroot+ep" bwrap

include Makefile-docs.am

TESTS = tests/test-basic.sh
TESTS_ENVIRONMENT = PATH=$$(cd $(top_builddir) && pwd):$${PATH}
