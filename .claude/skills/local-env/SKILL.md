---
name: local-env
description: Operate the banjax dev stack (docker compose with nginx, banjax, test-origin). Use when starting or rebuilding the stack, choosing which test command fits a change, sending requests through the edge, calling the admin API, running an on-demand tool, setting up an unattended /goal run, or when requests hang, ports collide, Kafka errors appear or hot reload seems stuck.
---

# Local environment

## First time on a clone

1. `touch .env`: compose loads it via `env_file`. The variables that matter locally:
   `ENABLE_AIR=1` (hot reload), `DISABLE_KAFKA` (no Kafka connection). `KAFKA_*` values are
   real settings; you never read or edit `.env`, ask the human to change it.
2. `scripts/dev up --build`, then `scripts/dev ps` (containers `banjax`, `nginx`, `test-origin`).
3. `scripts/dev hooks` to activate the git hooks (secret scan, gofmt).

## Daily loop

- `scripts/dev logs` shows the last 100 banjax lines (`-f` follows; avoid `-f` in an agent shell, it never returns). `scripts/dev logs nginx` for nginx.
- Hot reload (air, when ENABLE_AIR is set): rebuilds and restarts on `.go`/`.html` changes and on `banjax-config.yaml` changes; `_test.go` changes do not trigger it. A build error appears in `scripts/dev logs` and the old binary is stopped (`stop_on_error`), so nginx fails open on `/` and closed on password-protected locations until you fix it.
- Every restart starts with empty expiring decisions and failed-challenge counters. A SIGHUP reload (config reload in place) is covered by the integration tests (`reloadConfig` in `banjax_base_test.go`); under air a signal sent to the container reaches air, not banjax.
- `scripts/dev up --build` after changing `go.mod`, `Dockerfile`, `.air.toml`, nginx's Dockerfile, or a tool image.

## Which test for which change

| Change | Run |
| --- | --- |
| any Go change | `scripts/dev check` (fmt, vet, unit tests, secret scan) |
| one test while iterating | `scripts/dev test -run TestName -count=1` |
| decision path, cookies, config load/reload, fixtures | also `scripts/dev itest` (isolated container, about 35s) |
| shared state, mutexes, goroutines | also `scripts/dev race` (about 5 minutes) |
| challenge HTML/JS, nginx.conf, browser behavior | also the matching tool: `scripts/dev tool altcha-bot-tester` |
| POST/PUT/DELETE handling | `scripts/dev tool local-tester` |
| new dependency | `scripts/dev vuln` |

## Requests through the edge

Published ports: 80 and 8001 (nginx), 8080 (test-origin directly, bypassing banjax). 443 is not
published, so https works only inside the compose network.

```sh
# http from the host; nginx's server block is default_server, so any Host reaches banjax
curl -s -o /dev/null -D - -H 'Host: foo.test' http://localhost/hello | grep -i x-banjax
# https from inside the nginx network namespace (the banjax container shares it)
docker exec banjax-next-banjax-1 curl -sk -o /dev/null -w '%{http_code}\n' \
  --resolve altcha-test.banjax:443:127.0.0.1 -A HeadlessChrome https://altcha-test.banjax/hello
```

Use `/hello` (test-origin answers `hello!`). Paths ending in `.js`, `.css`, `.png` and similar skip
banjax entirely (a static-file location in nginx.conf). `example.com` is on the sitewide challenge
lists in the dev config; pick a neutral host such as `foo.test` for "allowed" checks. Read the
`X-Banjax-Decision` header rather than the body; challenge pages are large.

## Admin API (unauthenticated, 127.0.0.1:8081 inside the container)

`scripts/dev api /info` (config_version), `/decision_lists`, `/rate_limit_states`,
`/is_banned?ip=1.2.3.4`, `/banned?domain=foo.test`, `/deflect_challenge/pubkey`.
`scripts/dev banned` lists the ipset. `scripts/dev unban 1.2.3.4` clears an IP;
`scripts/dev unban host=foo.test ua='Bad UA'` or `scripts/dev unban subnet=10.1.0.0/24` clear the other lists.
From the host the same API answers on `curl -H 'Host: banjax' http://localhost/info`.

## On-demand tools (compose profile `tools`)

`scripts/dev tool` lists them; `scripts/dev tool <name> [args]` builds and runs one. Each has a README in
`supporting-containers/<name>/`. `kafka-cmd-tester` needs the real Kafka from `.env`, so it usually cannot
run locally; the others only need the stack up. Note the CLI form uses `--build`, so the first run is slow.

## Unattended runs

For long or unattended work the human starts the session with `/goal scripts/dev check passes`. A separate
model checks that condition after every turn, so the done condition is the check, not the model's own
judgment. That only works while `scripts/dev check` stays deterministic, exits non-zero on any failure and
prints its PASS/FAIL summary last; keep it that way if you edit `scripts/dev`. The goal check runs after
every turn, so it costs tokens on every step.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| requests from a tool or curl hang, then time out | the client was iptables-banned after 3 failed challenges in 10s (or 403s). `scripts/dev banned`, then `scripts/dev unban <ip>`, or wait `iptables_ban_seconds` (10 in the dev config). Space out failing requests. |
| `scripts/dev up`: port 80, 8001 or 8080 already allocated | another local server or an old stack holds it: `docker ps`, stop it, retry |
| integration tests fail with "address already in use" on 8081 | they ran inside the dev container; use `scripts/dev itest`, which uses a one-off container |
| build fails on a new import, or behavior does not match the code | stale image after a go.mod change: `scripts/dev up --build` |
| `KAFKA: ... failed to dial ... i/o timeout` in logs | normal locally, the brokers are not reachable; set `DISABLE_KAFKA=true` in `.env` (ask the human) to silence it |
| change not live | check `scripts/dev logs` for an air build error; `_test.go` and files outside include_ext do not trigger reloads |
| AltCha page says verification failed | the widget needs a secure context: use https inside the compose network (tools default to it), not http from the host |
| `scripts/dev` says the Docker daemon is not reachable | start Docker Desktop |
