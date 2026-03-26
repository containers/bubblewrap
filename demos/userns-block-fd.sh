#!/usr/bin/env bash
# This is an example of using the userns-block feature with bash.

# info pipe
exec 10<> <(:)
# userns_block pipe
exec 11<> <(:)

userns_setup() {
    child_pid=$(jq -rn 'input | .["child-pid"]' <&10)
    newuidmap $child_pid 0 $(id -u) 1
    newgidmap $child_pid 0 $(id -g) 1
    echo 1 >&11
    exec 11>&-
}
userns_setup 10<&10 11>&11 &

bwrap                       \
    --unshare-all           \
    --unshare-user          \
    --userns-block-fd 11    \
    --info-fd 10            \
    --bind / /              \
    cat /proc/self/uid_map  \
    10>&10 11<&11
