AM_CFLAGS = $(WARN_CFLAGS)
CLEANFILES =
EXTRA_DIST = \
	.dir-locals.el \
	.editorconfig \
	README.md \
	autogen.sh \
	demos/bubblewrap-shell.sh \
	demos/flatpak-run.sh \
	demos/flatpak.bpf \
	demos/userns-block-fd.py \
	packaging/bubblewrap.spec \
	uncrustify.cfg \
	uncrustify.sh \
	$(NULL)

GITIGNOREFILES = build-aux/ gtk-doc.make config.h.in aclocal.m4

bin_PROGRAMS = bwrap

bwrap_srcpath := $(srcdir)
include Makefile-bwrap.am

install-exec-hook:
if PRIV_MODE_SETUID
	$(SUDO_BIN) chown root $(DESTDIR)$(bindir)/bwrap
	$(SUDO_BIN) chmod u+s $(DESTDIR)$(bindir)/bwrap
endif

check_PROGRAMS = test-bwrap

test-bwrap: bwrap
	rm -rf test-bwrap
	cp bwrap test-bwrap
if PRIV_MODE_SETUID
	$(SUDO_BIN) chown root test-bwrap
	$(SUDO_BIN) chmod u+s test-bwrap
endif

test_bwrap_SOURCES=

include Makefile-docs.am

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_COMPILER =
TESTS = tests/test-run.sh
TESTS_ENVIRONMENT = BWRAP=$(abs_top_builddir)/test-bwrap

EXTRA_DIST += $(TESTS)
EXTRA_DIST += tests/libtest-core.sh

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = completions/bash/bwrap
endif

-include $(top_srcdir)/git.mk

AM_DISTCHECK_CONFIGURE_FLAGS =		\
	--with-bash-completion-dir="\$(datadir)"/bash-completion/ \
	$(NULL)
