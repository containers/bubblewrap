NULL =

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CPPFLAGS = -DDATADIR='"$(datadir)"' -DLIBEXECDIR='"$(libexecdir)"'
AM_CFLAGS = $(WARN_CFLAGS)

bin_PROGRAMS = build-root

build_root_SOURCES = \
	build-root.c \
	network.h \
	network.c \
	utils.h \
	utils.c \
	$(NULL)

build_root_CFLAGS = $(AM_CFLAGS)
build_root_LDFLAGS =
