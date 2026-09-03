# kafka-cmd-tester

One-off tool for sending a single simulated banjax kafka command message,
without needing baskerville running. Useful for exercising
`internal/kafka.go`'s `handleCommand` by hand: `block_ip`, `challenge_ip`,
`block_session`, `challenge_session`, `challenge_all`.

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
docker compose run --rm kafka-cmd-tester -cmd challenge_session -value 192.168.65.1 -session-id 'Qe5jhD1T6K8AAAAAapmM0w==' -host localhost
```

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

## Flags

| Flag | Purpose |
| --- | --- |
| `-cmd` | required: `block_ip`, `challenge_ip`, `block_session`, `challenge_session`, or `challenge_all` |
| `-host` | site; required for `challenge_all` |
| `-value` | IP address; required for `*_ip` and `*_session` commands |
| `-session-id` | required for `*_session` commands |
| `-ttl` | TTL override in seconds (omitted by default, banjax falls back to its own config) |
| `-source` | tags the command's `source` field (default `kafka-cmd-tester`) |
| `-print-log` | set `print_log` so banjax logs the command even outside debug mode (default `true`) |
| `-count`, `-interval` | send the message more than once, with a delay between sends |
| `-dry-run` | print the message instead of sending it |
| `-brokers`, `-topic`, `-partition` | override the kafka target |
| `-ssl-ca`, `-ssl-cert`, `-ssl-key`, `-insecure` | override TLS auth |

Run `docker compose run --rm kafka-cmd-tester -h` for the full list.
