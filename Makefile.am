NULL =

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CPPFLAGS = -DDATADIR='"$(datadir)"' -DLIBEXECDIR='"$(libexecdir)"'
AM_CFLAGS = $(WARN_CFLAGS)

bin_PROGRAMS = bwrap

bwrap_SOURCES = \
	bubblewrap.c \
	bind-mount.h \
	bind-mount.c \
	network.h \
	network.c \
	utils.h \
	utils.c \
	$(NULL)

bwrap_CFLAGS = $(AM_CFLAGS)
bwrap_LDFLAGS =
