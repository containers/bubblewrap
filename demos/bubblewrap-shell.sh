#!/usr/bin/env bash
# Use bubblewrap to run /bin/sh reusing the host OS binaries (/usr), but with
# separate /tmp, /var, /run, and /etc. For /etc we just inherit the host's
# resolv.conf, and set up "stub" passwd/group files.
#
# You can build on this example; for example, use --unshare-net to disable
# networking.
set -euo pipefail
(exec bwrap --ro-bind /usr /usr \
      --dir /tmp \
      --dir /var \
      --symlink ../tmp var/tmp \
      --proc /proc \
      --dev /dev \
      --ro-bind /etc/resolv.conf /etc/resolv.conf \
      --symlink usr/lib /lib \
      --symlink usr/lib64 /lib64 \
      --symlink usr/bin /bin \
      --symlink usr/sbin /sbin \
      --chdir / \
      --unshare-pid \
      --dir /run/user/$(id -u) \
      --setenv XDG_RUNTIME_DIR "/run/user/`id -u`" \
      --setenv PS1 "bwrap-demo$ " \
      --file 11 /etc/passwd \
      --file 12 /etc/group \
      /bin/sh) \
    11< <(getent passwd $UID 65534) \
    12< <(getent group $(id -g) 65534)
