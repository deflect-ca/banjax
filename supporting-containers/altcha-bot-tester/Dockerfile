# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Headless-browser bot simulator for comparing the sha-inverse and AltCha
# challenges. The Playwright image already ships Chromium and its system deps,
# so only the matching npm package is installed (same version as the image tag).
FROM mcr.microsoft.com/playwright:v1.49.1-noble

WORKDIR /opt/altcha-bot-tester
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY bot-test.mjs ./

# Talk to nginx over the compose network. The two hosts must match the
# per_site_user_agent_decision_lists entries in banjax-config.yaml.
ENV EDGE_ADDR=nginx \
    SHA_HOST=sha-test.banjax \
    ALTCHA_HOST=altcha-test.banjax \
    TEST_PATH=/hello

# Args passed to `docker compose run altcha-bot-tester` become the scenario filter.
ENTRYPOINT ["node", "/opt/altcha-bot-tester/bot-test.mjs"]
