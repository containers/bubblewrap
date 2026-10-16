#!/usr/bin/env bash

set -xeuo pipefail

srcd=$(cd $(dirname "$0") && pwd)
. "${srcd}/libtest.sh"

if test -n "${bwrap_is_suid:-}"; then
    skip "no setuid support for --unshare-user"
fi

echo "1..8"
test_count=0

ok () {
    test_count=$((test_count + 1))
    echo ok $test_count "$@"
}

SANDBOX="$BWRAP --unshare-user --uid 0 --gid 0 --unshare-pid --bind / / --proc /proc --dev /dev"

# wait_for SECONDS CMD...: poll until CMD succeeds, fail after SECONDS
wait_for () {
    local deadline=$((SECONDS + $1))
    shift
    until "$@"; do
        test "$SECONDS" -lt "$deadline" || assert_not_reached "timed out waiting for: $*"
        sleep 0.05
    done
}

# exited PID: PID is gone or a zombie
exited () {
    ! kill -0 "$1" 2>/dev/null || test "$(sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | cut -c1)" = Z
}

# child_pid FILE: the pid bwrap reported to --info-fd
child_pid () {
    wait_for 5 grep -qs child-pid "$1"
    sed -n 's/.*"child-pid": *\([0-9]*\).*/\1/p' "$1"
}

# A command that reports the signals it receives and keeps running
cat > handler.sh <<'EOF'
trap 'echo got-term >> "$1"' TERM
trap 'echo got-usr1 >> "$1"' USR1
echo ready >> "$1"
while :; do sleep 0.2; done
EOF

# start OPTIONS...: run $SANDBOX in its own process group, as a job would be,
# and set BWRAP_PID and SANDBOX_PID once the command is ready
start () {
    rm -f log info.json
    set -m
    $SANDBOX --info-fd 3 "$@" -- bash handler.sh "$(pwd)/log" 3> info.json > /dev/null 2>&1 &
    BWRAP_PID=$!
    set +m
    SANDBOX_PID=$(child_pid info.json)
    wait_for 5 grep -qs ready log
}

start
kill -TERM "$BWRAP_PID"
wait_for 2 exited "$BWRAP_PID"
sleep 0.5
assert_not_file_has_content log got-term
kill -KILL "$SANDBOX_PID" 2>/dev/null || true
ok "without --forward-signals, a signal is not forwarded"

# a command without a handler, so the forwarded SIGTERM kills it
rm -f log
set -m
$SANDBOX --forward-signals -- sh -c "echo ready >> $(pwd)/log; exec sleep 60" > /dev/null 2>&1 &
bwrap_pid=$!
set +m
wait_for 5 grep -qs ready log
kill -TERM "$bwrap_pid"
status=0
wait "$bwrap_pid" || status=$?
assert_streq "$status" 143
ok "SIGTERM reaches the command, which bwrap reports as 128+15"

start --forward-signals
kill -USR1 "$BWRAP_PID"
wait_for 2 grep -qs got-usr1 log
kill -0 "$BWRAP_PID"
kill -KILL "$SANDBOX_PID"
ok "a forwarded SIGUSR1 is handled and the sandbox keeps running"

start --forward-signals
kill -TERM "$SANDBOX_PID"
wait_for 2 grep -qs got-term log
kill -KILL "$SANDBOX_PID"
ok "a signal sent to the init process reaches the command"

# The command exits at once, a background process keeps the sandbox alive, and
# a new process takes the pid the command had. No --proc, as /proc/sys is
# read-only in the sandbox bwrap sets up.
rm -f log info.json
$SANDBOX --forward-signals --info-fd 3 -- sh -c 'sleep 60 > /dev/null 2>&1 &' 3> info.json
sandbox_pid=$(child_pid info.json)
set -m
$BWRAP --userns 11 --pidns 12 --cap-add ALL --bind / / -- \
    sh -c "echo 1 > /proc/sys/kernel/ns_last_pid && bash $(pwd)/handler.sh $(pwd)/log; true" \
    11< "/proc/$sandbox_pid/ns/user" 12< "/proc/$sandbox_pid/ns/pid" > /dev/null 2>&1 &
reuse_pid=$!
set +m
wait_for 5 grep -qs ready log
kill -TERM "$sandbox_pid"
sleep 0.5
assert_not_file_has_content log got-term
kill -KILL "$reuse_pid" "$sandbox_pid" 2>/dev/null || true
ok "once the command is reaped, its pid is not signalled again"

# Without --unshare-pid there is no init process, so bwrap's child is the command
rm -f log
set -m
$BWRAP --forward-signals --unshare-user --uid 0 --gid 0 --bind / / --proc /proc --dev /dev \
    -- bash handler.sh "$(pwd)/log" > /dev/null 2>&1 &
bwrap_pid=$!
set +m
wait_for 5 grep -qs ready log
kill -TERM "$bwrap_pid"
wait_for 2 grep -qs got-term log
kill -KILL "$bwrap_pid"
ok "a signal is forwarded when there is no init process"

# bwrap also runs an init process for --lock-file, where it is not pid 1
rm -f log
touch lock
set -m
$BWRAP --forward-signals --lock-file "$(pwd)/lock" --bind / / --proc /proc --dev /dev \
    -- bash handler.sh "$(pwd)/log" > /dev/null 2>&1 &
bwrap_pid=$!
set +m
wait_for 5 grep -qs ready log
kill -TERM "$bwrap_pid"
wait_for 2 grep -qs got-term log
kill -KILL "$bwrap_pid"
ok "a signal is forwarded through the init process of --lock-file"

# --block-fd holds the command back, so the signal arrives during setup
rm -f log info.json
mkfifo block
set -m
$SANDBOX --forward-signals --info-fd 3 --block-fd 4 -- sh -c "echo started >> $(pwd)/log" \
    3> info.json 4<> block > /dev/null 2>&1 &
bwrap_pid=$!
set +m
sandbox_pid=$(child_pid info.json)
kill -TERM "$bwrap_pid"
echo go > block
status=0
wait "$bwrap_pid" || status=$?
assert_streq "$status" 143
test ! -e log
ok "a signal arriving during setup is not lost and the command does not start"
