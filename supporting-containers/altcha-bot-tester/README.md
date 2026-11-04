# altcha-bot-tester

Local-only bot simulator for comparing the sha-inverse and AltCha challenges.
Each scenario runs against two hosts that challenge the same User-Agent: the
`HeadlessChrome` UA that stock headless Chromium sends. `sha-test.banjax`
serves the sha-inverse challenge and `altcha-test.banjax` serves AltCha. The
results print side by side.

The hosts come from `per_site_user_agent_decision_lists` in
`banjax-config.yaml`:

```yaml
per_site_user_agent_decision_lists:
  "sha-test.banjax":
    challenge:
      - "HeadlessChrome"
  "altcha-test.banjax":
    altcha_challenge:
      - "HeadlessChrome"
```

Neither host is in `use_user_agent_in_cookie`, so both bind solved cookies to
the client IP. That keeps the comparison fair.

## Running

```sh
docker compose up --build -d
docker compose run --rm --build altcha-bot-tester            # every scenario
docker compose run --rm altcha-bot-tester headless           # scenarios matching a substring
```

Chromium is pointed at nginx with `--host-resolver-rules`, so the test hosts
do not need DNS or `/etc/hosts` entries.

## Scenarios

| Scenario | Client | Should stop |
| --- | --- | --- |
| `no-js-client` | plain HTTP request with the headless UA, no cookie | yes |
| `forged-cookie` | plain HTTP request with a made-up solution cookie | yes |
| `js-disabled-browser` | headless Chromium with JavaScript off | yes |
| `headless-browser` | stock headless Chromium (`navigator.webdriver` is `true`) | no |
| `cookie-replay` | plain HTTP request reusing the cookie the browser earned | no |
| `spoofed-ua` | plain HTTP request with a normal desktop Chrome UA | no |

The "should stop" column describes what each challenge is built to do.

- **Proof-of-work only:** both challenges are proof-of-work puzzles, and any
  client that runs the page's JavaScript solves them.
- **Bot score not enforced:** AltCha's page sets the integrity cookie, but
  banjax does not use its bot score to decide access.
- **What to compare:** expect `headless-browser` to get through on both hosts.
  The differences are the solve time and the number of challenge pages.
- **Cookie replay:** `cookie-replay` shows that a solved cookie works for any
  client on the same IP until it expires (`altcha_cookie_ttl_seconds`,
  `sha_inv_cookie_ttl_seconds`).
- **UA spoofing:** `spoofed-ua` shows that a UA rule is only as strong as the
  UA string.

The exit code is non-zero only when a "should stop" client reaches the origin,
or when neither host challenged the headless UA (banjax config not loaded).

## Failed-challenge bans

- **Each scenario counts:** every scenario except `cookie-replay` and
  `spoofed-ua` fails one challenge per host.
- **Ban threshold:** banjax bans an IP that fails 3 challenges within 10s, per
  challenge type, so the runner waits `PAUSE_SECONDS` (default 6) between
  those scenarios.
- **When a run gets banned:** if you lower that and the tester's IP is banned,
  requests time out with `timeout (banned?)` until `iptables_ban_seconds`
  passes.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `EDGE_ADDR` | `nginx` | where nginx is reachable |
| `EDGE_PORT` | `80` | nginx port |
| `SHA_HOST` | `sha-test.banjax` | host with the sha-inverse UA rule |
| `ALTCHA_HOST` | `altcha-test.banjax` | host with the AltCha UA rule |
| `TEST_PATH` | `/hello` | origin path; test-origin answers it with `hello!` |
| `SOLVE_TIMEOUT_MS` | `30000` | how long a browser gets to reach the origin |
| `PAUSE_SECONDS` | `6` | gap after scenarios that fail a challenge |
