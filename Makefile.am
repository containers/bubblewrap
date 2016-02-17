NULL =

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CPPFLAGS = -DDATADIR='"$(datadir)"' -DLIBEXECDIR='"$(libexecdir)"'
AM_CFLAGS = $(WARN_CFLAGS)

bin_PROGRAMS = bubblewrap

bubblewrap_SOURCES = \
	bubblewrap.c \
	bind-mount.h \
	bind-mount.c \
	network.h \
	network.c \
	utils.h \
	utils.c \
	$(NULL)

bubblewrap_CFLAGS = $(AM_CFLAGS)
bubblewrap_LDFLAGS =
