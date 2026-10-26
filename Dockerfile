ARG ALPINE_VERSION=3.23

FROM alpine:${ALPINE_VERSION} AS builder

RUN apk add --no-cache \
    build-base linux-headers python3 meson ninja \
    pkgconf git libcap-dev libcap-static

WORKDIR /src/bubblewrap

COPY . .

RUN meson setup build \
        --buildtype=release \
        -Dprefer_static=true \
        -Dc_link_args=-static \
        -Dselinux=disabled \
        -Dman=disabled \
        -Dbash_completion=disabled \
        -Dzsh_completion=disabled \
        -Dtests=false \
    && meson compile -C build \
    && mkdir -p /out \
    && install -m 755 build/bwrap /out/bwrap

FROM alpine:${ALPINE_VERSION} AS export
COPY --from=builder /out/bwrap /bwrap
