#!/usr/bin/env bash

set -xeuo pipefail

srcd=$(cd $(dirname "$0") && pwd)
. ${srcd}/libtest.sh
test_count=0
ok () {
    test_count=$((test_count + 1))
    echo ok $test_count "$@"
}
ok_skip () {
    ok "# SKIP" "$@"
}
done_testing () {
    echo "1..$test_count"
}

sh_path=/bin/sh

out=$(
        $RUN \
                "$sh_path" -c 'trap "echo USR1; exit" USR1; sleep 0.5' &
        sleep 0.1
        kill -USR1 $!
   )
if [ -z "$out" ]; then
    ok "No signals forwarded without --forward-signal"
else
    false
fi

out=$(
        $RUN --forward-signals \
                "$sh_path" -c 'trap "echo USR1; exit" USR1; sleep 0.5' &
        sleep 0.1
        kill -USR1 $!
   )
   
if [ "$out" = USR1 ]; then
    ok "Successfully forwarded signals with --forward-signals"
else
    false
fi
