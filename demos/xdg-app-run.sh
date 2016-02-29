#!/bin/sh
# For this to work you first have to run these commands:
#  curl -O http://sdk.gnome.org/nightly/keys/nightly.gpg
#  xdg-app --user remote-add --gpg-key=nightly.gpg gnome-nightly http://sdk.gnome.org/nightly/repo/
#  xdg-app --user install gnome-nightly org.gnome.Platform
#  xdg-app --user install gnome-nightly org.gnome.Weather

mkdir -p ~/.var/app/org.gnome.Weather/cache ~/.var/app/org.gnome.Weather/config ~/.var/app/org.gnome.Weather/data

APPINFO=`mktemp`
cat > ${APPINFO} <<EOF
[Application]
name=org.gnome.Weather
runtime=runtime/org.gnome.Platform/x86_64/master
EOF

PASSWD=`mktemp`
getent passwd `id -u` 65534 > ${PASSWD}

GROUP=`mktemp`
getent group `id -g` 65534 > ${GROUP}

(
    # Remove all temporary files before calling bwrap, they are open in the fds anyway
    rm $APPINFO
    rm $GROUP
    rm $PASSWD
    bwrap \
    --ro-bind ~/.local/share/xdg-app/runtime/org.gnome.Platform/x86_64/master/active/files /usr \
    --lock-file /usr/.ref \
    --ro-bind ~/.local/share/xdg-app/app/org.gnome.Weather/x86_64/master/active/files/ /app \
    --lock-file /app/.ref \
    --dev /dev \
    --proc /proc \
    --dir /tmp \
    --symlink /tmp /var/tmp \
    --symlink /run /var/run \
    --symlink usr/lib /lib \
    --symlink usr/lib64 /lib64 \
    --symlink usr/bin /bin \
    --symlink usr/sbin /sbin \
    --symlink usr/etc /etc \
    --dir /run/user/`id -u` \
    --bind-data 11 /usr/etc/passwd \
    --bind-data 12 /usr/etc/group \
    --ro-bind /etc/machine-id /usr/etc/machine-id \
    --ro-bind /etc/resolv.conf /run/host/monitor/resolv.conf \
    --file 10 /run/user/`id -u`/xdg-app-info \
    --ro-bind /sys/block /sys/block \
    --ro-bind /sys/bus /sys/bus \
    --ro-bind /sys/class /sys/class \
    --ro-bind /sys/dev /sys/dev \
    --ro-bind /sys/devices /sys/devices \
    --dev-bind /dev/dri /dev/dri \
    --bind /tmp/.X11-unix/X0 /tmp/.X11-unix/X99 \
    --bind ~/.var/app/org.gnome.Weather ~/.var/app/org.gnome.Weather \
    --bind ~/.config/dconf ~/.config/dconf \
    --bind /run/user/`id -u`/dconf /run/user/`id -u`/dconf  \
    --unshare-pid \
    --setenv XDG_RUNTIME_DIR "/run/user/`id -u`" \
    --setenv DISPLAY :99 \
    --setenv GI_TYPELIB_PATH /app/lib/girepository-1.0 \
    --setenv GST_PLUGIN_PATH /app/lib/gstreamer-1.0 \
    --setenv LD_LIBRARY_PATH /app/lib:/usr/lib/GL \
    --setenv DCONF_USER_CONFIG_DIR .config/dconf \
    --setenv PATH /app/bin:/usr/bin \
    --setenv XDG_CONFIG_DIRS /app/etc/xdg:/etc/xdg \
    --setenv XDG_DATA_DIRS /app/share:/usr/share \
    --setenv SHELL /bin/sh \
    --setenv XDG_CACHE_HOME ~/.var/app/org.gnome.Weather/cache \
    --setenv XDG_CONFIG_HOME ~/.var/app/org.gnome.Weather/config \
    --setenv XDG_DATA_HOME ~/.var/app/org.gnome.Weather/data \
    --seccomp 13 \
    gnome-weather) 10< ${APPINFO} 11< ${PASSWD} 12< ${GROUP} 13< `dirname $0`/xdg-app.bpf


# TODO:
# clean commandlines (pass args via file/fd?)
# seccomp
