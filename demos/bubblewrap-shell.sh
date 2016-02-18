#!/usr/bin/env bash
# Use bubblewrap to run /bin/sh in the host's rootfs.
set -euo pipefail
exec bwrap --mount-ro-bind /usr /usr \
	   --make-dir /tmp \
	   --mount-proc /proc \
	   --mount-dev /dev \
	   --make-symlink usr/lib /lib \
	   --make-symlink usr/lib64 /lib64 \
	   --make-symlink usr/bin /bin \
	   --make-symlink usr/sbin /sbin \
	   --make-dir /run/user/$(id -u) \
	   --chdir / \
	   --unshare-pid \
	   /bin/sh
