FROM mcr.microsoft.com/devcontainers/rust:2-bookworm

ENV OPENSSL_VER="3.0.17"
#ENV TPM2TSS_VER="4.1.3"

RUN apt-get update \
    && apt-get install -qyy --no-install-recommends \
    gcc-multilib-x86-64-linux-gnu \
    g++-x86-64-linux-gnu \
    pkg-config \
    make \
    autoconf \
    automake \
    autoconf-archive \
    cmake \
    libclang-dev \
    libtool \
    pkgconf \
    acl \
    libltdl-dev

ENV SYSROOT="/x86_64-sysroot"
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV PKG_CONFIG_PATH="${SYSROOT}/lib/pkgconfig:${SYSROOT}/share/pkgconfig"
ENV PKG_CONFIG_SYSROOT_DIR="$SYSROOT"

RUN wget \
    -O/tmp/openssl-${OPENSSL_VER}.tar.gz \
    https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VER}/openssl-${OPENSSL_VER}.tar.gz \
    && cd /tmp \
    && tar xvf /tmp/openssl-${OPENSSL_VER}.tar.gz \
    && cd openssl-${OPENSSL_VER} \
    && ./Configure linux-generic64 \
    --prefix=${SYSROOT} \
    --cross-compile-prefix=x86_64-linux-gnu- \
    && make -j$(nproc) \
    && make install \
    && rm -rf \
    /tmp/openssl-${OPENSSL_VER} \
    /tmp/openssl-${OPENSSL_VER}.tar.gz

RUN wget \
    https://zlib.net/zlib-1.3.2.tar.gz \
    -O /tmp/zlib-1.3.2.tar.gz \
    && cd /tmp \
    && tar xvf zlib-1.3.2.tar.gz \
    && cd zlib-1.3.2 \
    && CC=x86_64-linux-gnu-gcc CHOST=x86_64-linux- ./configure --prefix=${SYSROOT} \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/zlib-1.3.2 /tmp/zlib-1.3.2.tar.gz

RUN wget \
    https://curl.se/download/curl-8.7.1.tar.gz \
    -O /tmp/curl-8.7.1.tar.gz \
    && cd /tmp \
    && tar xvf curl-8.7.1.tar.gz \
    && cd curl-8.7.1 \
    && CPPFLAGS="-I${SYSROOT}/include" LDFLAGS="-L${SYSROOT}/lib" ./configure --prefix=${SYSROOT} --host=x86_64-linux-gnu --with-ssl=${SYSROOT} --disable-shared --enable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/curl-8.7.1 /tmp/curl-8.7.1.tar.gz

RUN \
    wget https://ftp.gnu.org/gnu/libtool/libtool-2.4.7.tar.gz -O /tmp/libtool-2.4.7.tar.gz \
    && cd /tmp \
    && tar xvf libtool-2.4.7.tar.gz \
    && cd libtool-2.4.7 \
    && ./configure --prefix=${SYSROOT} --host=x86_64-linux-gnu \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libtool-2.4.7 /tmp/libtool-2.4.7.tar.gz

# nvat-rs build
RUN \
    git clone https://gitlab.gnome.org/GNOME/libxml2.git -b v2.9.14 /tmp/libxml2 \
    && cd /tmp/libxml2 \
    && CFLAGS=-fPIC ./autogen.sh --prefix=${SYSROOT} --host=x86_64-linux-gnu --enable-static --disable-shared --with-lzma=no --with-zlib=no \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libxml2

RUN \
    git clone https://gitlab.gnome.org/GNOME/libxslt.git -b v1.1.39 \
      /tmp/libxslt \
    && cd /tmp/libxslt \
    && ./autogen.sh --prefix=${SYSROOT} --host=x86_64-linux-gnu --with-python=no --enable-shared --disable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libxslt

RUN \
    wget \
      https://github.com/lsh123/xmlsec/releases/download/1.3.9/xmlsec1-1.3.9.tar.gz \
      -O/tmp/xmlsec1-1.3.9.tar.gz \
    && cd /tmp \
    && tar xvf xmlsec1-1.3.9.tar.gz \
    && cd xmlsec1-1.3.9 \
    && ./configure --prefix=${SYSROOT} --host=x86_64-linux-gnu --with-libltdl=${SYSROOT} --enable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/xmlsec1-1.3.9 /tmp/xmlsec1-1.3.9.tar.gz

# RUN git clone \
#     https://github.com/tpm2-software/tpm2-tss.git \
#     -b ${TPM2TSS_VER} --depth 1 /tmp/tpm2-tss \
#     && cd /tmp/tpm2-tss \
#     && ./bootstrap \
#     && ./configure \
#     --disable-fapi \
#     --disable-policy \
#     --prefix="${SYSROOT}" \
#     --target=x86_64-linux-gnu \
#     --host=x86_64-linux-gnu \
#     CC=/usr/bin/x86_64-linux-gnu-gcc \
#     CXX=/usr/bin/x86_64-linux-gnu-cpp \
#     && make -j$(nproc) \
#     && make install \
#     && rm -rf /tmp/tpm2-tss

RUN rustup target add \
    x86_64-unknown-linux-gnu

RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
