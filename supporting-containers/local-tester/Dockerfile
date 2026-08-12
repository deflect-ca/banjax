# Copyright (c) 2020, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Local-only test runner. Slim on purpose: the script only needs bash, curl and
# jq, so there is no toolchain or language runtime in here.
FROM alpine:3.20

RUN apk add --no-cache bash curl jq

COPY test-methods.sh /usr/local/bin/test-methods.sh
RUN chmod +x /usr/local/bin/test-methods.sh

# Talk to the other services over the compose network by default, so the runner
# does not depend on any host port being published or free.
ENV ORIGIN_URL=http://test-origin:8080 \
    EDGE_URL=http://nginx \
    EDGE_HOST=localhost

# Args passed to `docker compose run local-tester` become the case filter.
ENTRYPOINT ["/usr/local/bin/test-methods.sh"]
