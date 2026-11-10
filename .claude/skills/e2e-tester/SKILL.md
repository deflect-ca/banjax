---
name: e2e-tester
description: How to add or change an end-to-end test tool under supporting-containers/ for banjax, following altcha-bot-tester. Use when a behavior can only be proven through nginx and a real client (browser JS, challenge pages, cookies across redirects, nginx.conf, HTTP methods), or when editing an existing tool.
---

# Adding an end-to-end tool

Model to copy: `supporting-containers/altcha-bot-tester` (Dockerfile, package.json, bot-test.mjs, README.md). Read it fully first.

## Is an e2e tool warranted?

Write a Go test instead when the behavior is decided inside banjax: decisions, order, thresholds, cookie
validation, Kafka handling (see the `writing-tests` skill). Write an e2e tool only when proof needs the real
edge: JavaScript in a browser solving a challenge, a secure context, nginx locations and fail-open/closed,
method or body handling through nginx, a client sequence across several requests. A tool complements Go
tests; it never replaces them.

## Directory contents

- `Dockerfile`: license header; base image pinned to an exact tag (e.g. `mcr.microsoft.com/playwright:v1.49.1-noble`, `node:<x.y.z>-slim`, `golang:1.26.10-bookworm`); defaults as `ENV` (edge address, test hosts, paths); `ENTRYPOINT` so CLI args become a scenario filter.
- Dependency manifest with exact versions (`"playwright": "1.49.1"`, not `^1.49`); install with `--omit=dev --no-audit --no-fund`.
- The runner script: license header, a header comment with the run command, scenarios as data.
- `README.md`: what it compares or proves, config it relies on (the yaml snippet), how to run, a scenario table (scenario, client, should stop), ban/spacing notes, an environment table (variable, default, purpose).

## Wiring

- `docker-compose.yml`: a service under `profiles: [tools]` with a comment showing the run command, `depends_on: [nginx]`, `image: <name>`. No `env_file` unless it truly needs Kafka.
- Dedicated test hostnames (`<feature>-test.banjax`) configured in `banjax-config.yaml` (per-site lists, sitewide lists), with a comment pointing at the tool, so scenarios never disturb other hosts or other tools.
- Reach nginx as `nginx` on the compose network. Use https (port 443, self-signed, do not verify) when the feature needs a secure context; AltCha does. Browsers: map hosts with Chromium `--host-resolver-rules` instead of editing /etc/hosts.
- Use `/hello` as the origin path (test-origin answers `hello!`); static-file extensions bypass banjax.

## Scenario rules

- Each scenario has a name, a one-line `about`, and `shouldStop` (per challenge mode if they differ). It states what it proves.
- Exit 1 when a client that should have been stopped reaches the origin. Exit 2 when a preflight shows banjax is not configured for the test hosts (a run where nothing is challenged proves nothing). Exit 3 on a crash.
- Print a per-scenario line and a summary table; include the `X-Banjax-Decision` header in output.
- Scenarios that fail a challenge count towards the ban (3 failures in 10s per IP, then iptables): pause `PAUSE_SECONDS` (default 6) between them. A ban shows up as timeouts; report it as `timeout (banned?)`.
- No secrets, real hostnames or captured client data anywhere in the tool.

## Run and iterate

`scripts/dev up` first, then `scripts/dev tool <name>` (builds and runs) or `scripts/dev tool <name> <filter>`.
If a run gets banned: `scripts/dev banned`, `scripts/dev unban <ip>`. Config changes for the test hosts hot-reload
with air; check `scripts/dev logs` that the reload succeeded before rerunning.

## Skeleton

```yaml
  # <one line on what it proves>. In the "tools" profile; run it with
  #   docker compose run --rm <name>        (or: scripts/dev tool <name>)
  <name>:
    profiles:
      - tools
    image: <name>
    build:
      context: ./supporting-containers/<name>
      dockerfile: Dockerfile
    depends_on:
      - nginx
```

```dockerfile
# Copyright (c) <year>, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM node:<exact-version>-slim
WORKDIR /opt/<name>
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY run.mjs ./
ENV EDGE_ADDR=nginx EDGE_SCHEME=https TEST_HOST=<feature>-test.banjax TEST_PATH=/hello
ENTRYPOINT ["node", "/opt/<name>/run.mjs"]
```

```js
// (license header) Usage: docker compose run --rm <name> [scenario-filter]
const PAUSE_SECONDS = Number(process.env.PAUSE_SECONDS || 6);
const FILTER = process.argv[2] || "";

const SCENARIOS = [
    { name: "no-cookie", about: "plain client, no cookie", shouldStop: true, failsChallenge: true,
      run: (ctx) => plainGet(ctx, { ua: "..." }) },
    { name: "solved-cookie", about: "client replaying a valid cookie", shouldStop: false, failsChallenge: false,
      run: (ctx) => plainGet(ctx, { cookie: ctx.cookie }) },
];

async function main() {
    const ctx = await setup();                 // resolve EDGE_ADDR, launch browser if needed
    let regressions = 0;
    const rows = [];
    const scenarios = SCENARIOS.filter((s) => s.name.includes(FILTER));
    for (const [i, s] of scenarios.entries()) {
        const result = await s.run(ctx);       // { kind: "origin" | "denied" | "challenge" | "timeout (banned?)", decision }
        if (s.shouldStop && result.kind === "origin") regressions += 1;
        rows.push({ s, result });
        console.log(`${s.name}: ${s.about}\n  ${result.kind} ${result.decision || ""}`);
        if (s.failsChallenge && i < scenarios.length - 1) await sleep(PAUSE_SECONDS * 1000);
    }
    if (preflightShowsNoChallenge(rows)) process.exit(2);
    printSummary(rows);
    if (regressions > 0) process.exit(1);
}
main().catch((err) => { console.error(err); process.exit(3); });
```
