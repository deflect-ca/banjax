# kafka-cmd-tester

One-off tool for sending a single simulated banjax kafka command message,
without needing baskerville running. Useful for exercising
`internal/kafka.go`'s `handleCommand` by hand: `block_ip`, `challenge_ip`,
`block_subnet`, `challenge_subnet`, `block_session`, `challenge_session`,
`challenge_all`, `block_ua`, `challenge_ua`, `altcha_challenge_ip`,
`altcha_challenge_subnet`, `altcha_challenge_session`, `altcha_challenge_all`,
`altcha_challenge_ua`, `clear_rules`.

The message JSON matches the `commandMessage` struct banjax's kafka reader
unmarshals, so what you send here is exactly what banjax would receive from
baskerville.

It is declared in the root `docker-compose.yml` under the `tools` profile, so
it never starts as part of `docker compose up`.

## Running

```sh
docker compose run --rm kafka-cmd-tester -cmd challenge_all -host localhost
docker compose run --rm kafka-cmd-tester -cmd block_ip -value 192.168.65.1 -host localhost -ttl 3600
docker compose run --rm kafka-cmd-tester -cmd block_session -value 192.168.65.1 -session-id 'Qe5jhD1T6K8AAAAAapmM0w==' -host localhost
docker compose run --rm kafka-cmd-tester -cmd challenge_ip -value 192.168.65.1 -host localhost
docker compose run --rm kafka-cmd-tester -cmd block_subnet -value 192.168.65.0/24 -host localhost -ttl 1800
docker compose run --rm kafka-cmd-tester -cmd challenge_subnet -value 192.168.65.0/24 -host localhost
docker compose run --rm kafka-cmd-tester -cmd challenge_session -value 192.168.65.1 -session-id 'Qe5jhD1T6K8AAAAAapmM0w==' -host localhost
docker compose run --rm kafka-cmd-tester -cmd block_ua -ua 'curl/7.68.0' -host localhost
docker compose run --rm kafka-cmd-tester -cmd challenge_ua -ua 'curl/7.68.0' -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_ip -value 192.168.65.1 -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_subnet -value 192.168.65.0/24 -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_session -value 192.168.65.1 -session-id 'Qe5jhD1T6K8AAAAAapmM0w==' -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_all -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_ua -ua 'curl/7.68.0' -host localhost
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_all -host localhost -altcha-max-number 20000
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_all -host localhost -altcha-click
docker compose run --rm kafka-cmd-tester -cmd altcha_challenge_all -host localhost -altcha-force-new
docker compose run --rm kafka-cmd-tester -cmd clear_rules -host localhost
docker compose run --rm kafka-cmd-tester -cmd clear_rules -value 192.168.65.1 -session-id 'Qe5jhD1T6K8AAAAAapmM0w=='
docker compose run --rm kafka-cmd-tester -cmd clear_rules -ua 'curl/7.68.0'
docker compose run --rm kafka-cmd-tester -cmd clear_rules -ua 'curl/7.68.0' -host localhost
docker compose run --rm kafka-cmd-tester -cmd clear_rules -value 192.168.65.0/24
```

`block_subnet`/`challenge_subnet` work like `block_ip`/`challenge_ip` (same
TTL config), but `-value` is an IPv4 subnet in CIDR notation and the decision
covers every IP in it. Banjax normalizes it to the network address
(`192.168.65.7/24` becomes `192.168.65.0/24`) and ignores IPv6 subnets and
anything broader than `/16`. A `clear_rules` `-value` containing a `/` clears
that subnet entry instead of a single IP.

`block_ua`/`challenge_ua` match the client's User-Agent exactly (no
substring or regex matching, unlike the static
`per_site_user_agent_decision_lists`/`global_user_agent_decision_lists` in
`banjax-config.yaml`), and only on the `-host` they were sent for.

Each `altcha_challenge_*` command takes the same fields as its `challenge_*`
counterpart (same TTL default too), but banjax serves the Altcha challenge
instead of the sha-inverse one. `clear_rules` clears them the same way.

`-altcha-max-number` sets the difficulty of the challenge that one
`altcha_challenge_*` decision serves, in place of `altcha_max_number` from the
banjax config. Banjax clamps it to 1000..20000, so anything outside that
range is set to the nearest limit. Without the flag the field is left out and
the config value applies. Sending the same `altcha_challenge_*` command again
with a different `-altcha-max-number` changes the difficulty of the existing
decision.

`-altcha-click` makes that decision serve the one-click "I'm not a robot"
checkbox: the proof of work only starts when the visitor ticks it. Without it
the AltCha challenge solves on page load. Resending the command with or without
`-altcha-click` switches an existing decision. A click decision is its own
decision type (AltChaClickChallenge), so banjax reports it as
`*AltChaClickChallenge` in `X-Banjax-Decision` / `banjax_decision`.

`-altcha-force-new` makes that decision reject Altcha cookies minted before
the command arrived, so clients that already passed must solve a new
challenge (once; the new cookie is accepted). Without it a valid cookie keeps
passing until it expires. Every resend with `-altcha-force-new` forces
another new challenge.

`clear_rules` takes any combination of `-host`, `-value`, `-session-id`, and
`-ua`; each one present clears that entry independently from the expiring
decision list (at least one is required). The exception is `-ua` together
with `-host`: that clears the UA only on that host (and still clears the
host's sitewide challenge). `-ua` alone clears the UA on every host.

Preview the JSON without sending anything with `-dry-run`:

```sh
docker compose run --rm kafka-cmd-tester -cmd block_ip -value 192.168.65.1 -dry-run
```

Send the same message a few times, e.g. to test TTL expiry or rate limiting:

```sh
docker compose run --rm kafka-cmd-tester -cmd block_ip -value 192.168.65.1 -count 3 -interval 5s
```

By default it uses SSL client cert auth against the dev kafka cluster
(`kafkadev{0,1,2}.prod.deflect.network:9094`, `banjax_command_topic_dev`),
using the certs already mounted at `/etc/banjax` from `./keys` (the same ones
the main `banjax` service uses). `KAFKA_BROKERS` is set in the untracked
`.env` file (same as the `banjax` service's `ENABLE_AIR`), `KAFKA_TOPIC` is
set inline in `docker-compose.yml`. Pass `-insecure` to skip TLS, and
`-brokers`/`-topic` to target a different cluster, e.g. a local, plaintext
kafka.

SASL username/password auth uses the same `.env` variables as banjax:
`KAFKA_SASL_MECHANISM` (`PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`, the
default when a username and password are set; `none` turns SASL off even
when a username and password are set),
`KAFKA_SASL_USERNAME` and `KAFKA_SASL_PASSWORD`. `-sasl-mechanism` and
`-sasl-username` override the first two; the password is read only from the
environment so it never shows up in the process list or shell history. When
only `KAFKA_SASL_PASSWORD` is set, the username defaults to `banjax`, the same
default as `kafka_sasl_username` in `banjax-config.yaml` (this tool does not
read that file).

## Flags

| Flag | Purpose |
| --- | --- |
| `-cmd` | required: `block_ip`, `challenge_ip`, `block_subnet`, `challenge_subnet`, `block_session`, `challenge_session`, `challenge_all`, `block_ua`, `challenge_ua`, `altcha_challenge_ip`, `altcha_challenge_subnet`, `altcha_challenge_session`, `altcha_challenge_all`, `altcha_challenge_ua`, or `clear_rules` |
| `-host` | site; required for `*_all` and `*_ua` commands, optional for `clear_rules` |
| `-value` | IP address (IPv4 CIDR for `*_subnet`); required for `*_ip`, `*_subnet` and `*_session` commands (including the `altcha_challenge_*` ones), optional for `clear_rules` |
| `-session-id` | required for `*_session` commands, optional for `clear_rules` |
| `-ua` | exact User-Agent string; required for `*_ua` commands, optional for `clear_rules` (at least one of `-host`/`-value`/`-session-id`/`-ua` is required) |
| `-ttl` | TTL override in seconds (omitted by default, banjax falls back to its own config) |
| `-altcha-click` | `altcha_challenge_*` only: serve the one-click checkbox challenge instead of the default one that solves on page load (sends `"altcha_click": true`) |
| `-altcha-force-new` | `altcha_challenge_*` only: reject Altcha cookies minted before this command, forcing clients to solve a new challenge (sends `"altcha_force_new": true`) |
| `-altcha-max-number` | `altcha_challenge_*` only: challenge difficulty, clamped by banjax to 1000..20000 (omitted by default, banjax falls back to `altcha_max_number`) |
| `-source` | tags the command's `source` field (default `kafka-cmd-tester`) |
| `-print-log` | set `print_log` so banjax logs the command even outside debug mode (default `true`) |
| `-count`, `-interval` | send the message more than once, with a delay between sends |
| `-dry-run` | print the message instead of sending it |
| `-brokers`, `-topic`, `-partition` | override the kafka target |
| `-ssl-ca`, `-ssl-cert`, `-ssl-key`, `-insecure` | override TLS auth |
| `-sasl-mechanism`, `-sasl-username` | override SASL auth (defaults from `KAFKA_SASL_MECHANISM` / `KAFKA_SASL_USERNAME`; the password comes only from `KAFKA_SASL_PASSWORD`) |

Run `docker compose run --rm kafka-cmd-tester -h` for the full list.
