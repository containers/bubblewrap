#!/bin/bash

set -xeuo pipefail

# Make sure /sbin/getpcaps etc. are in our PATH even if non-root
PATH="$PATH:/usr/sbin:/sbin"

srcd=$(cd $(dirname $0) && pwd)

. ${srcd}/libtest-core.sh

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

: "${BWRAP:=bwrap}"
if test -u "$(type -p ${BWRAP})"; then
    bwrap_is_suid=true
fi

FUSE_DIR=
for mp in $(cat /proc/self/mounts | grep " fuse[. ]" | grep user_id=$(id -u) | awk '{print $2}'); do
    if test -d $mp; then
        echo Using $mp as test fuse mount
        FUSE_DIR=$mp
        break
    fi
done

if test "$(id -u)" = "0"; then
    is_uidzero=true
else
    is_uidzero=false
fi

# This is supposed to be an otherwise readable file in an unreadable (by the user) dir
UNREADABLE=/root/.bashrc
if ${is_uidzero} || test -x `dirname $UNREADABLE`; then
    UNREADABLE=
fi

# https://github.com/projectatomic/bubblewrap/issues/217
# are we on a merged-/usr system?
if [ /lib -ef /usr/lib ]; then
    BWRAP_RO_HOST_ARGS="--ro-bind /usr /usr
              --ro-bind /etc /etc
              --dir /var/tmp
              --symlink usr/lib /lib
              --symlink usr/lib64 /lib64
              --symlink usr/bin /bin
              --symlink usr/sbin /sbin
              --proc /proc
              --dev /dev"
else
    BWRAP_RO_HOST_ARGS="--ro-bind /usr /usr
              --ro-bind /etc /etc
              --ro-bind /bin /bin
              --ro-bind /lib /lib
              --ro-bind-try /lib64 /lib64
              --ro-bind /sbin /sbin
              --dir /var/tmp
              --proc /proc
              --dev /dev"
fi

# Default arg, bind whole host fs to /, tmpfs on /tmp
RUN="${BWRAP} --bind / / --tmpfs /tmp"

if ! $RUN true; then
    skip Seems like bwrap is not working at all. Maybe setuid is not working
fi

echo "1..49"

# Test help
${BWRAP} --help > help.txt
assert_file_has_content help.txt "usage: ${BWRAP}"
echo "ok - Help works"

for ALT in "" "--unshare-user-try"  "--unshare-pid" "--unshare-user-try --unshare-pid"; do
    # Test fuse fs as bind source
    if [ x$FUSE_DIR != x ]; then
        $RUN $ALT  --proc /proc --dev /dev --bind $FUSE_DIR /tmp/foo true
        echo "ok - can bind-mount a FUSE directory with $ALT"
    else
        echo "ok # SKIP no FUSE support"
    fi
    # no --dev => no devpts => no map_root workaround
    $RUN $ALT --proc /proc true
    echo "ok - can mount /proc with $ALT"
    # No network
    $RUN $ALT --unshare-net --proc /proc --dev /dev true
    echo "ok - can unshare network, create new /dev with $ALT"
    # Unreadable file
    echo -n "expect EPERM: " >&2

    # Test caps when bwrap is not setuid
    if test -n "${bwrap_is_suid:-}"; then
        CAP="--cap-add ALL"
    else
        CAP=""
    fi

    if ! ${is_uidzero} && $RUN $CAP $ALT --unshare-net --proc /proc --bind /etc/shadow  /tmp/foo cat /etc/shadow; then
        assert_not_reached Could read /etc/shadow
    fi
    echo "ok - cannot read /etc/shadow with $ALT"
    # Unreadable dir
    if [ x$UNREADABLE != x ]; then
        echo -n "expect EPERM: " >&2
        if $RUN $ALT --unshare-net --proc /proc --dev /dev --bind $UNREADABLE  /tmp/foo cat /tmp/foo ; then
            assert_not_reached Could read $UNREADABLE
        fi
        echo "ok - cannot read $UNREADABLE with $ALT"
    else
        echo "ok # SKIP not sure what unreadable file to use"
    fi

    # bind dest in symlink (https://github.com/projectatomic/bubblewrap/pull/119)
    $RUN $ALT --dir /tmp/dir --symlink dir /tmp/link --bind /etc /tmp/link true
    echo "ok - can bind a destination over a symlink"
done

# Test devices
$RUN --unshare-pid --dev /dev ls -al /dev/{stdin,stdout,stderr,null,random,urandom,fd,core} >/dev/null
echo "ok - all expected devices were created"

# Test --as-pid-1
$RUN --unshare-pid --as-pid-1 --bind / / bash -c 'echo $$' > as_pid_1.txt
assert_file_has_content as_pid_1.txt "1"
echo "ok - can run as pid 1"

# Test --info-fd and --json-status-fd
if $RUN --unshare-all --info-fd 42 --json-status-fd 43 -- bash -c 'exit 42' 42>info.json 43>json-status.json 2>err.txt; then
    fatal "should have been exit 42"
fi
assert_file_has_content info.json '"child-pid": [0-9]'
assert_file_has_content json-status.json '"child-pid": [0-9]'
assert_file_has_content_literal json-status.json '"exit-code": 42'
echo "ok info and json-status fd"

DATA=$($RUN --proc /proc --unshare-all --info-fd 42 --json-status-fd 43 -- bash -c 'stat -L --format "%n %i" /proc/self/ns/*' 42>info.json 43>json-status.json 2>err.txt)

for NS in "ipc" "mnt" "net" "pid" "uts"; do

    want=$(echo "$DATA" | grep "/proc/self/ns/$NS" | awk '{print $2}')
    assert_file_has_content info.json "$want"
    assert_file_has_content json-status.json "$want"
done

echo "ok namespace id info in info and json-status fd"

if ! which strace 2>/dev/null || ! strace -h | grep -v -e default | grep -e fault; then
    echo "ok - # SKIP no strace fault injection"
else
    ! strace -o /dev/null -f -e trace=prctl -e fault=prctl:when=39 $RUN --die-with-parent --json-status-fd 42 true 42>json-status.json
    assert_not_file_has_content json-status.json '"exit-code": [0-9]'
    echo "ok pre-exec failure doesn't include exit-code in json-status"
fi

notanexecutable=/
$RUN --json-status-fd 42 $notanexecutable 42>json-status.json || true
assert_not_file_has_content json-status.json '"exit-code": [0-9]'
echo "ok exec failure doesn't include exit-code in json-status"

# These tests require --unshare-user
if test -n "${bwrap_is_suid:-}"; then
    echo "ok - # SKIP no --cap-add support"
    echo "ok - # SKIP no --cap-add support"
else
    BWRAP_RECURSE="$BWRAP --unshare-all --uid 0 --gid 0 --cap-add ALL --bind / / --bind /proc /proc"
    $BWRAP_RECURSE -- $BWRAP --unshare-all --bind / / --bind /proc /proc echo hello > recursive_proc.txt
    assert_file_has_content recursive_proc.txt "hello"
    echo "ok - can mount /proc recursively"

    $BWRAP_RECURSE -- $BWRAP --unshare-all  ${BWRAP_RO_HOST_ARGS} findmnt > recursive-newroot.txt
    assert_file_has_content recursive-newroot.txt "/usr"
    echo "ok - can pivot to new rootfs recursively"
fi

# Test error prefixing
if $RUN --unshare-pid  --bind /source-enoent /dest true 2>err.txt; then
    assert_not_reached "bound nonexistent source"
fi
assert_file_has_content err.txt "^bwrap: Can't find source path.*source-enoent"
echo "ok error prefxing"

if ! ${is_uidzero}; then
    # When invoked as non-root, check that by default we have no caps left
    for OPT in "" "--unshare-user-try --as-pid-1" "--unshare-user-try" "--as-pid-1"; do
        e=0
        $RUN $OPT --unshare-pid getpcaps 1 2> caps.test || e=$?
        sed -e 's/^/# /' < caps.test >&2
        test "$e" = 0
        assert_not_file_has_content caps.test ': =.*cap'
    done
    echo "ok - we have no caps as uid != 0"
else
    capsh --print > caps.orig
    for OPT in "" "--as-pid-1"; do
        $RUN $OPT --unshare-pid capsh --print >caps.test
        diff -u caps.orig caps.test
    done
    # And test that we can drop all, as well as specific caps
    $RUN $OPT --cap-drop ALL --unshare-pid capsh --print >caps.test
    assert_file_has_content caps.test 'Current: =$'
    # Check for dropping kill/fowner (we assume all uid 0 callers have this)
    $RUN $OPT --cap-drop CAP_KILL --cap-drop CAP_FOWNER --unshare-pid capsh --print >caps.test
    assert_not_file_has_content caps.test '^Current: =.*cap_kill'
    assert_not_file_has_content caps.test '^Current: =.*cap_fowner'
    # But we should still have net_bind_service for example
    assert_file_has_content caps.test '^Current: =.*cap_net_bind_service'
    echo "ok - we have the expected caps as uid 0"
fi

# Test --die-with-parent

cat >lockf-n.py <<EOF
#!/usr/bin/env python
import struct,fcntl,sys
path = sys.argv[1]
if sys.argv[2] == 'wait':
  locktype = fcntl.F_SETLKW
else:
  locktype = fcntl.F_SETLK
lockdata = struct.pack("hhqqhh", fcntl.F_WRLCK, 0, 0, 0, 0, 0)
fd=open(sys.argv[1], 'a')
try:
  fcntl.fcntl(fd.fileno(), locktype, lockdata)
except IOError as e:
  sys.exit(1)
sys.exit(0)
EOF
chmod a+x lockf-n.py
touch lock

for die_with_parent_argv in "--die-with-parent" "--die-with-parent --unshare-pid"; do
    # We have to loop here, because bwrap doesn't wait for the lock if
    # another process is holding it. If we're unlucky, lockf-n.py will
    # be holding it.
    /bin/bash -c "while true; do $RUN ${die_with_parent_argv} --lock-file $(pwd)/lock sleep 1h; done" &
    childshellpid=$!

    # Wait for lock to be taken (yes hacky)
    for x in $(seq 10); do
        if ./lockf-n.py ./lock nowait; then
            sleep 1
        else
            break
        fi
    done
    if ./lockf-n.py ./lock nowait; then
        assert_not_reached "timed out waiting for lock"
    fi

    # Kill the shell, which should kill bwrap (and the sleep)
    kill -9 ${childshellpid}
    # Lock file should be unlocked
    ./lockf-n.py ./lock wait
    echo "ok die with parent ${die_with_parent_argv}"
done

printf '%s--dir\0/tmp/hello/world\0' '' > test.args
$RUN --args 3 test -d /tmp/hello/world 3<test.args
echo "ok - we can parse arguments from a fd"

mkdir bin
echo "#!/bin/sh" > bin/--inadvisable-executable-name--
echo "echo hello" >> bin/--inadvisable-executable-name--
chmod +x bin/--inadvisable-executable-name--
PATH="${srcd}:$PATH" $RUN -- sh -c "echo hello" > stdout
assert_file_has_content stdout hello
echo "ok - we can run with --"
PATH="$(pwd)/bin:$PATH" $RUN -- --inadvisable-executable-name-- > stdout
assert_file_has_content stdout hello
echo "ok - we can run an inadvisable executable name with --"
if $RUN -- --dev-bind /dev /dev sh -c 'echo should not have run'; then
    assert_not_reached "'--dev-bind' should have been interpreted as a (silly) executable name"
fi
echo "ok - options like --dev-bind are defanged by --"

if command -v mktemp > /dev/null; then
    tempfile="$(mktemp /tmp/bwrap-test-XXXXXXXX)"
    echo "hello" > "$tempfile"
    $BWRAP --bind / / cat "$tempfile" > stdout
    assert_file_has_content stdout hello
    echo "ok - bind-mount of / exposes real /tmp"
    $BWRAP --bind / / --bind /tmp /tmp cat "$tempfile" > stdout
    assert_file_has_content stdout hello
    echo "ok - bind-mount of /tmp exposes real /tmp"
    if [ -d /mnt ]; then
        $BWRAP --bind / / --bind /tmp /mnt cat "/mnt/${tempfile#/tmp/}" > stdout
        assert_file_has_content stdout hello
        echo "ok - bind-mount of /tmp onto /mnt exposes real /tmp"
    else
        echo "ok - # SKIP /mnt does not exist"
    fi
else
    echo "ok - # SKIP mktemp not found"
    echo "ok - # SKIP mktemp not found"
    echo "ok - # SKIP mktemp not found"
fi

if $RUN test -d /tmp/oldroot; then
    assert_not_reached "/tmp/oldroot should not be visible"
fi
if $RUN test -d /tmp/newroot; then
    assert_not_reached "/tmp/newroot should not be visible"
fi

echo "hello" > input.$$
$BWRAP --bind / / --bind "$(pwd)" /tmp cat /tmp/input.$$ > stdout
assert_file_has_content stdout hello
if $BWRAP --bind / / --bind "$(pwd)" /tmp test -d /tmp/oldroot; then
    assert_not_reached "/tmp/oldroot should not be visible"
fi
if $BWRAP --bind / / --bind "$(pwd)" /tmp test -d /tmp/newroot; then
    assert_not_reached "/tmp/newroot should not be visible"
fi
echo "ok - we can mount another directory onto /tmp"

echo "hello" > input.$$
$RUN --bind "$(pwd)" /tmp/here cat /tmp/here/input.$$ > stdout
assert_file_has_content stdout hello
if $RUN --bind "$(pwd)" /tmp/here test -d /tmp/oldroot; then
    assert_not_reached "/tmp/oldroot should not be visible"
fi
if $RUN --bind "$(pwd)" /tmp/here test -d /tmp/newroot; then
    assert_not_reached "/tmp/newroot should not be visible"
fi
echo "ok - we can mount another directory inside /tmp"

# These tests need user namespaces
if test -n "${bwrap_is_suid:-}"; then
    echo "ok - # SKIP no setuid support for --unshare-user"
    echo "ok - # SKIP no setuid support for --unshare-user"
else
    mkfifo donepipe

    $RUN --info-fd 42 --unshare-user sh -c 'ls -l /proc/self/ns/user > sandbox-userns; cat < donepipe' 42>info.json &
    while ! test -f sandbox-userns; do sleep 1; done
    SANDBOX1PID=$(extract_child_pid info.json)

    $RUN  --userns 11 ls -l /proc/self/ns/user > sandbox2-userns 11< /proc/$SANDBOX1PID/ns/user
    echo foo > donepipe

    assert_files_equal sandbox-userns sandbox2-userns

    rm donepipe info.json sandbox-userns

    echo "ok - Test --userns"

    mkfifo donepipe
    $RUN --info-fd 42 --unshare-user --unshare-pid sh -c 'ls -l /proc/self/ns/pid > sandbox-pidns; cat < donepipe' 42>info.json &
    while ! test -f sandbox-pidns; do sleep 1; done
    SANDBOX1PID=$(extract_child_pid info.json)

    $RUN --userns 11 --pidns 12 ls -l /proc/self/ns/pid > sandbox2-pidns 11< /proc/$SANDBOX1PID/ns/user 12< /proc/$SANDBOX1PID/ns/pid
    echo foo > donepipe

    assert_files_equal sandbox-pidns sandbox2-pidns

    rm donepipe info.json sandbox-pidns

    echo "ok - Test --pidns"
fi


echo "ok - End of test"
