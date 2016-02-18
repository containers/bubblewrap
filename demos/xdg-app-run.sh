#!/bin/sh
# For this to work you first have to run these commands:
#  curl -O http://sdk.gnome.org/nightly/keys/nightly.gpg
#  xdg-app --user remote-add --gpg-key=nightly.gpg gnome-nightly http://sdk.gnome.org/nightly/repo/
#  xdg-app --user install gnome-nightly org.gnome.Platform
#  xdg-app --user install gnome-nightly org.gnome.Weather

export XDG_RUNTIME_DIR="/run/user/`id -u`"
export DISPLAY=:99
export GI_TYPELIB_PATH=/app/lib/girepository-1.0
export GST_PLUGIN_PATH=/app/lib/gstreamer-1.0
export _LD_LIBRARY_PATH=/app/lib:/usr/lib/GL
export DCONF_USER_CONFIG_DIR=.config/dconf
export PATH=/app/bin:/usr/bin
export XDG_CONFIG_DIRS=/app/etc/xdg:/etc/xdg
export XDG_DATA_DIRS=/app/share:/usr/share
export SHELL=/bin/sh
export XDG_CACHE_HOME=~/.var/app/org.gnome.Weather/cache
export XDG_CONFIG_HOME=~/.var/app/org.gnome.Weather/config
export XDG_DATA_HOME=~/.var/app/org.gnome.Weather/data

mkdir -p ~/.var/app/org.gnome.Weather/cache ~/.var/app/org.gnome.Weather/config ~/.var/app/org.gnome.Weather/data

APPINFO=`mktemp`
cat > ${APPINFO} <<EOF
[Application]
name=org.gnome.Weather
runtime=runtime/org.gnome.Platform/x86_64/master
EOF


exec ../bwrap \
    --mount-ro-bind ~/.local/share/xdg-app/runtime/org.gnome.Platform/x86_64/master/active/files /usr \
    --lock-file /usr/.ref \
    --mount-ro-bind ~/.local/share/xdg-app/app/org.gnome.Weather/x86_64/master/active/files/ /app \
    --lock-file /app/.ref \
    --mount-dev /dev \
    --mount-proc /proc \
    --make-dir /tmp \
    --make-symlink /tmp /var/tmp \
    --make-symlink /run /var/run \
    --make-symlink usr/lib /lib \
    --make-symlink usr/lib64 /lib64 \
    --make-symlink usr/bin /bin \
    --make-symlink usr/sbin /sbin \
    --make-dir /run/user/`id -u` \
    --make-passwd /etc/passwd \
    --make-group /etc/group \
    --mount-ro-bind /etc/machine-id /etc/machine-id \
    --mount-ro-bind /etc/resolv.conf /run/user/`id -u`/xdg-app-monitor/resolv.conf \
    --make-symlink /run/user/`id -u`/xdg-app-monitor/resolv.conf /etc/resolv.conf \
    --mount-ro-bind-dir ~/.local/share/xdg-app/runtime/org.gnome.Platform/x86_64/master/active/files/etc /etc \
    --make-file 10 /run/user/`id -u`/xdg-app-info \
    --mount-ro-bind /sys/block /sys/block \
    --mount-ro-bind /sys/bus /sys/bus \
    --mount-ro-bind /sys/class /sys/class \
    --mount-ro-bind /sys/dev /sys/dev \
    --mount-ro-bind /sys/devices /sys/devices \
    --mount-dev-bind /dev/dri /dev/dri \
    --mount-bind /tmp/.X11-unix/X0 /tmp/.X11-unix/X99 \
    --mount-bind ~/.var/app/org.gnome.Weather ~/.var/app/org.gnome.Weather \
    --mount-bind ~/.config/dconf ~/.config/dconf \
    --mount-bind /run/user/`id -u`/dconf /run/user/`id -u`/dconf  \
    --unshare-pid \
    gnome-weather 10< ${APPINFO}


# TODO:
# clean commandlines (pass args via file/fd?)
# seccomp
