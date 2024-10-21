# syntax=docker/dockerfile:1
FROM --platform=linux/arm64/v8 debian:bookworm-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CPPCHECK_VERSION=2.7

# dependencies for cppcheck build
RUN <<EOF
#!/bin/bash
    set -eu

    useradd --home /build --create-home user

    apt-get update

    DEPS=(
        build-essential
        ca-certificates
        curl
        libpcre3-dev
        python-is-python3
    )

    apt-get -y --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

WORKDIR /build
USER user

# cppcheck release build (see cppcheck readme.md)
RUN <<EOF
#!/bin/bash
    set -eu

    curl -fsSLO https://github.com/danmar/cppcheck/archive/"$CPPCHECK_VERSION".tar.gz
    echo "5fd20549bb2fabf9a8026f772779d8cc6a5782c8f17500408529f7747afbc526  ${CPPCHECK_VERSION}.tar.gz" | sha256sum -c -

    tar oxf "$CPPCHECK_VERSION".tar.gz
    cd cppcheck-"$CPPCHECK_VERSION"

    MAKE_OPTS=(
        MATCHCOMPILER=yes
        DESTDIR=/build/out
        FILESDIR="/usr/share/cppcheck"
        HAVE_RULES=yes CXXFLAGS="-O2 -DNDEBUG -Wall -Wno-sign-compare -Wno-unused-function"
    )
    make install -j$(nproc) "${MAKE_OPTS[@]}"
EOF

FROM --platform=linux/arm64/v8 debian:bookworm-slim
COPY --from=builder /build/out/usr/bin/cppcheck /usr/bin/cppcheck
COPY --from=builder /build/out/usr/share/cppcheck /usr/share/cppcheck

LABEL maintainer.name="The Xen Project"
LABEL maintainer.email="xen-devel@lists.xenproject.org"

ENV DEBIAN_FRONTEND=noninteractive

# dependencies for cppcheck analysis including Xen-only build/cross-build
RUN <<EOF
#!/bin/bash
    set -eu

    useradd --create-home user

    apt-get update

    DEPS=(
        bison
        build-essential
        python-is-python3
        libpcre3
        flex
        gcc-arm-linux-gnueabihf
        gcc-x86-64-linux-gnu
    )

    apt-get --yes --no-install-recommends install "${DEPS[@]}"

    rm -rf /var/lib/apt/lists*
EOF

USER user
WORKDIR /build
