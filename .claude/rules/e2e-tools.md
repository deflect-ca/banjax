---
paths:
  - "supporting-containers/**"
  - "docker-compose.yml"
---

# On-demand tools under supporting-containers/

Full method and a skeleton: the `e2e-tester` skill. Model: `supporting-containers/altcha-bot-tester`.

- Every tool is a compose service under `profiles: [tools]`, with a comment showing how to run it; it must not start with `scripts/dev up`.
- Pin the base image tag and every dependency version (no `latest`, no ranges).
- No secrets, real hostnames or captured client data in the tool, its README or its defaults. Kafka settings come from `.env` at run time only.
- README with a scenario table (scenario, client, should stop) and an environment-variable table.
- Each scenario states what it proves; exit non-zero when a security expectation is violated (a client that should be stopped reached the origin), and when the preflight shows banjax is not configured for the test hosts.
- Space out scenarios that fail challenges: 3 failures in 10s gets the runner iptables-banned.
- Use dedicated test hostnames wired in `banjax-config.yaml`; reach nginx as `nginx` on the compose network (https when the feature needs a secure context).
- Run with `scripts/dev tool <name> [args]`.
