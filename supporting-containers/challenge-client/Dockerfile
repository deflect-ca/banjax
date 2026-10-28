# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Deflect Challenge verifier. Slim on purpose: the script needs bash (for
# printf '\xHH', which busybox's printf does not support), curl, jq, and an
# openssl with Ed25519 support in pkeyutl -rawin, which is anything 3.x.
FROM alpine:3.20

RUN apk add --no-cache bash curl jq openssl

COPY deflect-challenge.sh /usr/local/bin/deflect-challenge.sh
RUN chmod +x /usr/local/bin/deflect-challenge.sh

# Talk to the other services over the compose network by default, so the client
# does not depend on any host port being published or free.
ENV EDGE_URL=http://nginx \
    EDGE_HOST=localhost \
    ADMIN_URL=http://nginx \
    ADMIN_HOST=banjax

# Args passed to `docker compose run challenge-client` become the case filter.
ENTRYPOINT ["/usr/local/bin/deflect-challenge.sh"]
