# Copyright (c) 2024, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM debian:bookworm-slim AS purge-plugin-build-target

# please also fix version below
ENV NGINX_VERSION   1.27.0
ENV PURGE_VERSION   2.5.3

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    nginx-extras \
    build-essential \
    git \
    libpcre3-dev \
    libssl-dev \
    zlib1g-dev

WORKDIR /root

RUN git clone https://github.com/nginx-modules/ngx_cache_purge --depth 1 --branch ${PURGE_VERSION}
RUN git clone https://github.com/nginx/nginx.git --depth 1 --branch release-${NGINX_VERSION}

WORKDIR /root/nginx

# XXX the plugin needs to be build with exactly the same configuration as nginx
# itself.
# nginx -V
RUN ./auto/configure \
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
    --lock-path=/var/run/nginx.lock \
    --modules-path=/usr/lib/nginx/modules \
    --pid-path=/var/run/nginx.pid \
    --prefix=/etc/nginx \
    --sbin-path=/usr/sbin/nginx \
    --user=nginx \
    --with-cc-opt='-g -O2 -ffile-prefix-map=/data/builder/debuild/nginx-${NGINX_VERSION}/debian/debuild-base/nginx-${NGINX_VERSION}=. -fstack-protector-strong -Wformat -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
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
    --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
    --with-mail \
    --with-mail_ssl_module \
    --with-stream \
    --with-stream_realip_module \
    --with-stream_ssl_module \
    --with-stream_ssl_preread_module \
    --with-threads \
    && make modules

FROM nginx:1.27.0

ENV PURGE_MODULE_NAME ngx_http_cache_purge_module_torden

RUN set -x \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    psmisc

COPY --from=purge-plugin-build-target \
    /root/nginx/objs/ngx_http_cache_purge_module.so \
    /usr/lib/nginx/modules/${PURGE_MODULE_NAME}.so

COPY nginx.conf /etc/nginx/

RUN mkdir -p /etc/ssl/sites
RUN mkdir -p /etc/ssl-uploaded/sites
RUN mkdir -p /data/nginx
RUN mkdir -p /var/log/banjax

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
