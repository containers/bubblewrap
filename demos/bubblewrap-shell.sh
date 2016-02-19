#!/usr/bin/env bash
# Use bubblewrap to run /bin/sh in the host's rootfs.
set -euo pipefail
PASSWD=`mktemp`
getent passwd `id -u` 65534 > ${PASSWD}

GROUP=`mktemp`
getent group `id -g` 65534 > ${GROUP}

(   # Remove temporary files before calling bwrap, they are open in the fds anyway
    rm $GROUP
    rm $PASSWD
    bwrap --mount-ro-bind /usr /usr \
	   --make-dir /tmp \
	   --mount-proc /proc \
	   --mount-dev /dev \
	   --mount-ro-bind /etc/resolv.conf /etc/resolv.conf \
	   --make-file 11 /etc/passwd \
	   --make-file 12 /etc/group \
	   --make-symlink usr/lib /lib \
	   --make-symlink usr/lib64 /lib64 \
	   --make-symlink usr/bin /bin \
	   --make-symlink usr/sbin /sbin \
	   --chdir / \
	   --unshare-pid \
	   --make-dir /run/user/$(id -u) \
	   --setenv XDG_RUNTIME_DIR "/run/user/`id -u`" \
	   /bin/sh) 11< ${PASSWD} 12< ${GROUP}
