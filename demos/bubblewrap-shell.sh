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
    bwrap --ro-bind /usr /usr \
	   --dir /tmp \
	   --proc /proc \
	   --dev /dev \
	   --ro-bind /etc/resolv.conf /etc/resolv.conf \
	   --file 11 /etc/passwd \
	   --file 12 /etc/group \
	   --symlink usr/lib /lib \
	   --symlink usr/lib64 /lib64 \
	   --symlink usr/bin /bin \
	   --symlink usr/sbin /sbin \
	   --chdir / \
	   --unshare-pid \
	   --dir /run/user/$(id -u) \
	   --setenv XDG_RUNTIME_DIR "/run/user/`id -u`" \
	   /bin/sh) 11< ${PASSWD} 12< ${GROUP}
