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

test_programs = \
	tests/test-utils \
	$(NULL)
test_scripts = \
	tests/test-run.sh \
	tests/test-specifying-userns.sh \
	tests/test-specifying-pidns.sh \
	$(NULL)
test_extra_programs = \
	test-bwrap \
	$(NULL)

test-bwrap: bwrap
	rm -rf test-bwrap
	cp bwrap test-bwrap
	chmod 0755 test-bwrap
if PRIV_MODE_SETUID
	$(SUDO_BIN) chown root test-bwrap
	$(SUDO_BIN) chmod u+s test-bwrap
endif

tests_test_utils_SOURCES = \
	tests/test-utils.c \
	utils.h \
	utils.c \
	$(NULL)
tests_test_utils_LDADD = $(SELINUX_LIBS)

test_bwrap_SOURCES=

include Makefile-docs.am

LOG_DRIVER = env AM_TAP_AWK='$(AWK)' $(SHELL) $(top_srcdir)/build-aux/tap-driver.sh
LOG_COMPILER =
TESTS_ENVIRONMENT = \
	BWRAP=$(abs_top_builddir)/test-bwrap \
	G_TEST_BUILDDIR=$(abs_top_builddir) \
	G_TEST_SRCDIR=$(abs_top_srcdir) \
	$(NULL)
check_PROGRAMS = $(test_programs) $(test_extra_programs)
TESTS = $(test_programs) $(test_scripts)

EXTRA_DIST += $(test_scripts)
EXTRA_DIST += tests/libtest-core.sh
EXTRA_DIST += tests/libtest.sh

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
dist_bashcompletion_DATA = completions/bash/bwrap
endif

if ENABLE_ZSH_COMPLETION
zshcompletiondir = $(ZSH_COMPLETION_DIR)
dist_zshcompletion_DATA = completions/zsh/_bwrap
endif

-include $(top_srcdir)/git.mk

AM_DISTCHECK_CONFIGURE_FLAGS =		\
	--with-bash-completion-dir="\$(datadir)"/bash-completion/ \
	$(NULL)
