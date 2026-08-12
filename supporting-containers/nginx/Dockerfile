# Copyright (c) 2024, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# NOTE: nginx is built from source against OpenSSL 4.0.1 so the image supports
# TLS ECH (Encrypted Client Hello). nginx only compiles in its ECH code -- and
# only then accepts the `ssl_ech_file` directive -- when it is linked against an
# OpenSSL that exposes the ECH API. The official nginx:1.31.2 image links the
# distro's OpenSSL 3.x, which has no ECH API, so it cannot be used as the runtime
# base any more.
#
# Because we now build the nginx binary AND its dynamic module in the same tree,
# the module is guaranteed to be ABI-compatible with the binary -- we own the
# whole build, so there is no need to mirror the official image's `nginx -V`.
FROM debian:trixie-slim AS builder

# please also fix the FROM tag of the runtime stage below
ENV NGINX_VERSION=1.31.2
ENV OPENSSL_VERSION=4.0.1
ENV PURGE_VERSION=3.0.2

# Supply-chain pins. The downloaded tarball is checked against this sha256 and
# each git clone is verified to resolve to the exact commit below, so a moved tag,
# a re-uploaded release asset, or a MITM'd download fails the build instead of
# silently linking untrusted code into the TLS-terminating nginx.
#   OPENSSL_SHA256: from the OpenSSL release's published openssl-4.0.1.tar.gz.sha256
#   *_COMMIT: the COMMIT each tag points to (git ls-remote; note nginx's release
#             tag is annotated, so this is the peeled `^{}` commit, not the tag obj)
ENV OPENSSL_SHA256=2db3f3a0d6ea4b59e1f094ace2c8cd536dffb87cdc39084c5afa1e6f7f37dd09
ENV NGINX_COMMIT=2fd01ed47a1fd2965754c83f53b33a789d0e07f1
ENV PURGE_COMMIT=523e66368922601dff10b71cceb868ff5db6ebf1

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    build-essential \
    perl \
    git \
    libpcre2-dev \
    zlib1g-dev \
    ca-certificates \
    wget

WORKDIR /root

# Build OpenSSL 4.0.1 (the ECH-capable libs nginx links against). The -rpath
# bakes the runtime library path into anything linked against it, so the nginx
# binary and its dynamic module find these libs without LD_LIBRARY_PATH.
RUN wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
    && echo "${OPENSSL_SHA256}  openssl-${OPENSSL_VERSION}.tar.gz" | sha256sum -c - \
    && tar -zxf "openssl-${OPENSSL_VERSION}.tar.gz" \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl \
        --libdir=lib shared \
        '-Wl,-rpath,/opt/openssl/lib' \
    && make -j"$(nproc)" \
    && make install_sw \
    && make install_ssldirs

# Clone the pinned tag, then hard-fail unless HEAD is the expected commit (guards
# against a tag being moved to point at different code after we pinned it).
RUN git clone https://github.com/nginx-modules/ngx_cache_purge --depth 1 --branch ${PURGE_VERSION} \
 && test "$(git -C ngx_cache_purge rev-parse HEAD)" = "${PURGE_COMMIT}"
RUN git clone https://github.com/nginx/nginx.git --depth 1 --branch release-${NGINX_VERSION} \
 && test "$(git -C nginx rev-parse HEAD)" = "${NGINX_COMMIT}"

WORKDIR /root/nginx

# XXX The flag set below mirrors `nginx -V` from the official nginx:1.31.2 image
# so the binary keeps every feature production relies on (HTTP/2, HTTP/3, stream,
# mail, realip, the cache_purge dynamic module, etc.). The deltas vs. that
# reference are:
#   * the --add-dynamic-module entry (cache_purge),
#   * the architecture-specific control-flow-protection flag (-fcf-protection on
#     amd64, -mbranch-protection=standard on arm64), detected at build time, and
#   * the -I/-L/-rpath additions that point cc/ld at the OpenSSL 4.0.1 built above
#     instead of the distro OpenSSL -- this is what enables ECH.
RUN set -eux \
 && ARCH_CC_OPT="$(case "$(dpkg --print-architecture)" in \
        amd64) echo '-fcf-protection' ;; \
        arm64) echo '-mbranch-protection=standard' ;; \
        *) echo '' ;; \
    esac)" \
 && ./auto/configure \
    --add-dynamic-module=/root/ngx_cache_purge/ \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --group=nginx \
    --http-client-body-temp-path=/var/cache/nginx/client_temp \
    --http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
    --http-log-path=/var/log/nginx/access.log \
    --http-proxy-temp-path=/var/cache/nginx/proxy_temp \
    --http-scgi-temp-path=/var/cache/nginx/scgi_temp \
    --http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
    --lock-path=/run/nginx.lock \
    --modules-path=/usr/lib/nginx/modules \
    --pid-path=/run/nginx.pid \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --user=nginx \
    --with-cc-opt="-g -O2 -ffile-prefix-map=/home/builder/debuild/nginx-${NGINX_VERSION}/debian/debuild-base/nginx-${NGINX_VERSION}=. -fstack-protector-strong -Wformat -Werror=implicit-function-declaration -fstack-clash-protection -Werror=format-security ${ARCH_CC_OPT} -Wp,-D_FORTIFY_SOURCE=2 -fPIC -I/opt/openssl/include" \
    --with-compat \
    --with-file-aio \
    --with-http_addition_module \
    --with-http_auth_request_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gunzip_module \
    --with-http_gzip_static_module \
    --with-http_mp4_module \
    --with-http_random_index_module \
    --with-http_realip_module \
    --with-http_secure_link_module \
    --with-http_slice_module \
    --with-http_ssl_module \
    --with-http_stub_status_module \
    --with-http_sub_module \
    --with-http_v2_module \
    --with-http_v3_module \
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie -L/opt/openssl/lib -Wl,-rpath,/opt/openssl/lib' \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-threads \
    && make -j"$(nproc)" \
    && make install

# please also fix the FROM tag of the builder stage above
FROM debian:trixie-slim AS runtime

ENV PURGE_MODULE_NAME=ngx_http_cache_purge_module_torden

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    libpcre2-8-0 \
    zlib1g \
    ca-certificates \
    psmisc \
 && rm -rf /var/lib/apt/lists/*

# OpenSSL 4.0.1 (libs + the ECH-capable `openssl` CLI), the nginx binary, and the
# cache_purge dynamic module -- all from the builder stage. The module is renamed
# to the name config_generation emits in its load_module lines.
COPY --from=builder /opt/openssl /opt/openssl
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder \
    /usr/lib/nginx/modules/ngx_http_cache_purge_module.so \
    /usr/lib/nginx/modules/${PURGE_MODULE_NAME}.so

# Make the OpenSSL 4.0.1 libs discoverable by the dynamic loader. The -rpath
# baked into the binary/module already covers this; the ld.so.conf.d entry is a
# belt-and-suspenders safeguard.
RUN echo /opt/openssl/lib > /etc/ld.so.conf.d/openssl.conf \
 && ldconfig

# The official image created the nginx user/group for us; recreate it here.
RUN groupadd --system nginx \
 && useradd --system --no-create-home --shell /usr/sbin/nologin -g nginx nginx

COPY nginx.conf /etc/nginx/

RUN mkdir -p /etc/nginx \
 && mkdir -p /etc/nginx/ech \
 && mkdir -p /usr/lib/nginx/modules \
 && mkdir -p /var/cache/nginx \
 && mkdir -p /var/log/nginx \
 && mkdir -p /data/nginx \
 && mkdir -p /etc/ssl/sites \
 && mkdir -p /etc/ssl-uploaded/sites \
 && mkdir -p /var/log/banjax
RUN rm -rf /var/log/nginx/* || true
RUN rm -rf /var/log/banjax/* || true
RUN rm -rf /data/nginx/* || true

# Self-signed cert for the localhost test vhost, so the :443 listener in
# nginx.conf comes up without any mounted key material. Replace it under
# /etc/ssl/sites for anything that is not the local compose stack.
RUN /opt/openssl/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -subj "/CN=localhost" \
      -addext "subjectAltName=DNS:localhost,DNS:www.localhost" \
      -keyout /etc/ssl/sites/localhost.key.pem \
      -out    /etc/ssl/sites/localhost.cert.pem \
 && chmod 600 /etc/ssl/sites/localhost.key.pem

# The ECH key pair + ECHConfigList consumed by `ssl_ech_file`. Only the OpenSSL
# 4.0.1 CLI copied above can emit this; the distro `openssl` cannot. The public
# half of this file is what has to be published in the HTTPS/SVCB RR (ech=...)
# for a client to actually attempt ECH.
RUN /opt/openssl/bin/openssl ech -public_name localhost -out /etc/nginx/ech/localhost.ech \
 || /opt/openssl/bin/openssl ech -public_name localhost -pemout /etc/nginx/ech/localhost.ech
RUN chmod 600 /etc/nginx/ech/localhost.ech

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
