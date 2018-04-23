#!/usr/bin/env bash

set -xeuo pipefail

distro=$1

runcontainer() {
    docker run --rm --env=container=true --env=BWRAP_SUID=${BWRAP_SUID:-} --env CFLAGS="${CFLAGS:-}" --net=host --privileged -v /usr:/host/usr -v $(pwd):/srv/code -w /srv/code $distro ./ci/papr.sh $distro
}

buildinstall_to_host() {

    yum -y install git autoconf automake libtool make gcc redhat-rpm-config \
        libcap-devel  'pkgconfig(libselinux)' 'libxslt' 'docbook-style-xsl' \
        lib{a,ub,t}san /usr/bin/eu-readelf rsync

    echo testing: $(git describe --tags --always --abbrev=42)

    env NOCONFIGURE=1 ./autogen.sh
    ./configure --prefix=/usr --libdir=/usr/lib64
    make -j 8
    tmpd=$(mktemp -d)
    make install DESTDIR=${tmpd}
    for san in a t ub; do
        if eu-readelf -d ${tmpd}/usr/bin/bwrap | grep -q "NEEDED.*lib${san}san"; then
            for x in /usr/lib64/lib${san}san*.so.*; do
                install -D $x ${tmpd}${x}
            done
        fi
    done
    rsync -rlv ${tmpd}/usr/ /host/usr/
    if test -n "${BWRAP_SUID:-}"; then
        chmod u+s /host/usr/bin/bwrap
    fi
    rm ${tmpd} -rf
}

if test -z "${container:-}"; then
    ostree admin unlock
    useradd bwrap-tester
    runcontainer
    # Unprivileged invocation
    runuser -u bwrap-tester env ASAN_OPTIONS=detect_leaks=false ./tests/test-run.sh
    # Privileged invocation
    env ASAN_OPTIONS=detect_leaks=false ./tests/test-run.sh
else
    buildinstall_to_host
fi
