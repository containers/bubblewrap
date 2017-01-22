#!/bin/bash

set -xeuo pipefail

srcd=$(cd $(dirname $0) && pwd)
bn=$(basename $0)
tempdir=$(mktemp -d /var/tmp/tap-test.XXXXXX)
touch ${tempdir}/.testtmp
function cleanup () {
    if test -n "${TEST_SKIP_CLEANUP:-}"; then
        echo "Skipping cleanup of ${test_tmpdir}"
    else if test -f ${tempdir}/.test; then
        rm "${tempdir}" -rf
    fi
    fi
}
trap cleanup EXIT
cd ${tempdir}

skip () {
    echo $@ 1>&2; exit 77
}

assert_not_reached () {
    echo $@ 1>&2; exit 1
}

assert_file_has_content () {
    if ! grep -q -e "$2" "$1"; then
        echo 1>&2 "File '$1' doesn't match regexp '$2'"; exit 1
    fi
}

FUSE_DIR=
for mp in $(cat /proc/self/mounts | grep " fuse[. ]" | grep user_id=$(id -u) | awk '{print $2}'); do
    if test -d $mp; then
        echo Using $mp as test fuse mount
        FUSE_DIR=$mp
        break
    fi
done

# This is supposed to be an otherwise readable file in an unreadable (by the user) dir
UNREADABLE=/root/.bashrc
if test -x `dirname $UNREADABLE`; then
    UNREADABLE=
fi

# Default arg, bind whole host fs to /, tmpfs on /tmp
RUN="${BWRAP:-bwrap} --bind / / --tmpfs /tmp"

if ! $RUN true; then
    skip Seems like bwrap is not working at all. Maybe setuid is not working
fi

for ALT in "" "--unshare-user-try"  "--unshare-pid" "--unshare-user-try --unshare-pid"; do
    # Test fuse fs as bind source
    if [ x$FUSE_DIR != x ]; then
        $RUN $ALT  --proc /proc --dev /dev --bind $FUSE_DIR /tmp/foo true
    fi
    # no --dev => no devpts => no map_root workaround
    $RUN $ALT --proc /proc true
    # No network
    $RUN $ALT --unshare-net --proc /proc --dev /dev true
    # Unreadable file
    echo -n "expect EPERM: "
    if $RUN $ALT --unshare-net --proc /proc --bind /etc/shadow  /tmp/foo cat /etc/shadow; then
        assert_not_reached Could read /etc/shadow
    fi
    # Unreadable dir
    if [ x$UNREADABLE != x ]; then
        echo -n "expect EPERM: "
        if $RUN $ALT --unshare-net --proc /proc --dev /dev --bind $UNREADABLE  /tmp/foo cat /tmp/foo ; then
            assert_not_reached Could read $UNREADABLE
        fi
    fi

    # bind dest in symlink (https://github.com/projectatomic/bubblewrap/pull/119)
    $RUN $ALT --dir /tmp/dir --symlink dir /tmp/link --bind /etc /tmp/link true
done
echo OK
