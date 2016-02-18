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

setuid: bwrap
	sudo chown root bwrap
	sudo sudo chmod u+s bwrap

setcaps: bwrap
	sudo setcap "cap_sys_admin+ep cap_sys_chroot+ep" bwrap


bwrap_CFLAGS = $(AM_CFLAGS)
bwrap_LDFLAGS =
