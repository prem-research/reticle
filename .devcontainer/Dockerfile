FROM mcr.microsoft.com/devcontainers/rust:2-bookworm

ENV TARGET_TRIPLE=x86_64-linux-
ENV RUST_TARGET=x86_64-unknown-linux-gnu
ENV OPENSSL_TARGET=linux-generic64
ENV OPENSSL_VER="3.0.17"
ENV ZLIB_VER=1.3.2
ENV CURL_VER=8.7.1
ENV LIBTOOL_VER=2.4.7
ENV LIBXML2_VER=2.9.14
ENV LIBXSLT_VER=1.1.39
ENV XMLSEC_VER=1.3.9
#ENV TPM2TSS_VER="4.1.3"

RUN apt-get update \
    && apt-get install -qyy --no-install-recommends \
    gcc-x86-64-linux-gnu \
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
    libltdl-dev \
    clang

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
    && ./Configure ${OPENSSL_TARGET} \
        --prefix=${SYSROOT} \
        --cross-compile-prefix=${TARGET_TRIPLE}gnu- \
    && make -j$(nproc) \
    && make install \
    && rm -rf \
    /tmp/openssl-${OPENSSL_VER} \
    /tmp/openssl-${OPENSSL_VER}.tar.gz

RUN wget \
    https://zlib.net/zlib-${ZLIB_VER}.tar.gz \
    -O /tmp/zlib-${ZLIB_VER}.tar.gz \
    && cd /tmp \
    && tar xvf zlib-${ZLIB_VER}.tar.gz \
    && cd zlib-${ZLIB_VER} \
    && CC=${TARGET_TRIPLE}gnu-gcc CHOST=${TARGET_TRIPLE} ./configure --prefix=${SYSROOT} \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/zlib-${ZLIB_VER} /tmp/zlib-${ZLIB_VER}.tar.gz

RUN wget \
    https://curl.se/download/curl-${CURL_VER}.tar.gz \
    -O /tmp/curl-${CURL_VER}.tar.gz \
    && cd /tmp \
    && tar xvf curl-${CURL_VER}.tar.gz \
    && cd curl-${CURL_VER} \
    && CPPFLAGS="-I${SYSROOT}/include" LDFLAGS="-L${SYSROOT}/lib" ./configure \
        --prefix=${SYSROOT} \
        --host=${TARGET_TRIPLE}gnu \
        --with-ssl=${SYSROOT} \
        --disable-shared \
        --enable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/curl-${CURL_VER} /tmp/curl-${CURL_VER}.tar.gz

RUN \
    wget https://ftp.gnu.org/gnu/libtool/libtool-${LIBTOOL_VER}.tar.gz \
        -O /tmp/libtool-${LIBTOOL_VER}.tar.gz \
    && cd /tmp \
    && tar xvf libtool-${LIBTOOL_VER}.tar.gz \
    && cd libtool-${LIBTOOL_VER} \
    && ./configure --prefix=${SYSROOT} --host=${TARGET_TRIPLE}gnu \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libtool-${LIBTOOL_VER} /tmp/libtool-${LIBTOOL_VER}.tar.gz

# nvat-rs build
RUN \
    git clone https://gitlab.gnome.org/GNOME/libxml2.git \
        -b v${LIBXML2_VER} /tmp/libxml2 \
    && cd /tmp/libxml2 \
    && CFLAGS=-fPIC ./autogen.sh \
        --prefix=${SYSROOT} \
        --host=${TARGET_TRIPLE}gnu \
        --enable-static --disable-shared \
        --with-lzma=no --with-zlib=no \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libxml2

RUN \
    git clone https://gitlab.gnome.org/GNOME/libxslt.git -b v${LIBXSLT_VER} \
      /tmp/libxslt \
    && cd /tmp/libxslt \
    && ./autogen.sh \
        --prefix=${SYSROOT} --host=${TARGET_TRIPLE}gnu \
        --with-python=no --enable-shared --disable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/libxslt

RUN \
    wget \
      https://github.com/lsh123/xmlsec/releases/download/${XMLSEC_VER}/xmlsec1-${XMLSEC_VER}.tar.gz \
      -O/tmp/xmlsec1-${XMLSEC_VER}.tar.gz \
    && cd /tmp \
    && tar xvf xmlsec1-${XMLSEC_VER}.tar.gz \
    && cd xmlsec1-${XMLSEC_VER} \
    && ./configure \
        --prefix=${SYSROOT} --host=${TARGET_TRIPLE}gnu \
        --with-libltdl=${SYSROOT} --enable-static \
    && make -j$(nproc) \
    && make install \
    && rm -rf \
        /tmp/xmlsec1-${XMLSEC_VER} \
        /tmp/xmlsec1-${XMLSEC_VER}.tar.gz

# RUN git clone \
#     https://github.com/tpm2-software/tpm2-tss.git \
#     -b ${TPM2TSS_VER} --depth 1 /tmp/tpm2-tss \
#     && cd /tmp/tpm2-tss \
#     && ./bootstrap \
#     && ./configure \
#     --disable-fapi \
#     --disable-policy \
#     --prefix="${SYSROOT}" \
#     --target=${TARGET_TRIPLE}gnu \
#     --host=${TARGET_TRIPLE}gnu \
#     CC=/usr/bin/${TARGET_TRIPLE}gnu-gcc \
#     CXX=/usr/bin/${TARGET_TRIPLE}gnu-cpp \
#     && make -j$(nproc) \
#     && make install \
#     && rm -rf /tmp/tpm2-tss

RUN rustup target add \
        ${RUST_TARGET}

RUN apt-get autoremove -y \
    && apt-get clean -y \
    && rm -rf /var/lib/apt/lists/*
