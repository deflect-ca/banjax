# banjax

Go service that nginx asks, per request, whether to let a client through (`/auth_request`):
allow, deny, or serve a challenge page (sha-inverse PoW, AltCha PoW, password, 429). Decisions
come from config lists, regex rate limits over the nginx log, Kafka commands from Baskerville,
and failed-challenge counters; bans use iptables/ipset. `PSEUDOCODE_DESCRIPTION.md` is the
authoritative description of the decision order and Kafka commands.

## Commands (all through scripts/dev; run `scripts/dev help` for the rest)

- `scripts/dev up [--build]`, `down`, `ps`, `logs [svc] [-f]`: the compose stack (banjax hot-reloads on .go/.html/config changes when ENABLE_AIR is set)
- `scripts/dev test`: unit tests (`go test ./internal/`); one test: `scripts/dev test -run TestName -count=1`
- `scripts/dev itest`: integration tests (`-tags=integration`, root package)
- `scripts/dev race`: unit tests with -race, about 5 minutes; run it when you touch shared state
- `scripts/dev vet`, `scripts/dev fmt [--fix]`, `scripts/dev vuln`
- `scripts/dev check`: the pre-handoff gate (fmt on changed files, vet, unit tests, secret scan)
- `scripts/dev api /decision_lists`, `unban <ip>`, `banned`: admin API of the running banjax
- `scripts/dev tool [name]`: on-demand e2e tools (altcha-bot-tester, local-tester, ...)

## Rules, with the reason

- Go runs only in Docker (`scripts/dev`), never `go` on the host: the toolchain, iptables and ipset live in the image.
- Integration tests always run in a one-off container (`scripts/dev itest` does this): they start banjax on 127.0.0.1:8081, which the dev container already holds.
- Never read, print or copy `.env` or anything under `keys/`: they hold real Kafka settings and private keys. Listing names is fine. Tests generate their own throwaway keys.
- One of the remotes is a public GitHub repo and branches are pushed there routinely, so anything committed may become public: no secrets, internal hostnames, client IPs from logs, or personal paths in code, tests, fixtures or docs.
- Do not bypass hooks (`--no-verify`, `-n`, changing core.hooksPath). Fix what they report. Run `scripts/dev hooks` once per clone.
- Do not push. The human pushes after reviewing.
- The main branch is `main`: branch from it, diff and review against it (`git diff main...HEAD`). `master` is an old line that shares almost no history with `main`; never use it as a base.
- `X-Banjax-Decision` strings (`DecisionListResultToString`) are a log contract read from nginx logs by downstream tooling: never rename one; add new ones.
- When behavior changes, update `PSEUDOCODE_DESCRIPTION.md` and the README in the same change.

## Code here that new code must not copy

- HMAC and solution checks use `bytes.Equal` (`challenge_response.go`, `session_cookie.go`): use `hmac.Equal` or `subtle.ConstantTimeCompare`.
- Session ids come from `math/rand` (`session_cookie.go` newID): use `crypto/rand` for anything an attacker must not predict.
- `kafka.go` sets `InsecureSkipVerify: true`: never in new TLS code.
- `internal/integrity_check.go`, `internal/integrity_check_test.go` and `internal/kafka.go` are not gofmt-clean on `main`. Format them only in a separate commit; `scripts/dev fmt` checks changed files only.
- Comments marked `XXX` are open questions, not patterns.

## A feature usually touches these places (check each, skip what does not apply)

1. `Config` field with yaml tag (`internal/config.go`); default in `load()` (`config_holder.go`) when zero is dangerous (a zero threshold bans on the first request).
2. Documented entry in `banjax-config.yaml`; matching `fixtures/*.yaml` if integration tests exercise it.
3. New `Decision` / `DecisionListResult` plus its string in `DecisionListResultToString`.
4. Its place in `decisionForNginx2` relative to every neighbor; exemptions: protected IPs (`config.IsProtectedIP`), per-site allowlist, `sites_to_disable_baskerville`.
5. Kafka command in `handleCommand` (validate and clamp fields) plus a flag and README entry in `supporting-containers/kafka-cmd-tester`.
6. Cleanup: `POST /unban` and the Kafka `clear_rules` command must be able to remove what you add.
7. Metrics (`Metrics*` on the decision lists, `WriteMetricsToEncoder`).
8. SIGHUP reload (`banjax.go`): it reloads config, refreshes static lists and clears all expiring decisions; state captured at startup elsewhere keeps old values.
9. README and `PSEUDOCODE_DESCRIPTION.md`.

## Conventions seen in this code

- Wrap errors with `fmt.Errorf("...: %w", err)`; log with a subsystem prefix (`INIT:`, `KAFKA:`, `HOT-RELOAD:`, `DEFLECT-CHALLENGE:`).
- Comments say why, not what. New files start with the BSD license header used in the other files (current year).
- Decision lists are touched only through their methods (`DynamicDecisionLists` holds a mutex; `StaticDecisionLists` swaps an atomic pointer); never reach into their maps.
- Tests: testify `assert`, table-driven with `t.Run` and sentence-like case names (see `internal/two_step_ban_test.go`).
- No new dependency without a clear need; pin it and run `scripts/dev vuln`.

## Definition of done

1. `scripts/dev check` passes.
2. `scripts/dev itest` passes when the HTTP path, config loading/reload or fixtures changed.
3. After check passes on a non-trivial change, run `/code-review` (built in: a fresh subagent reviews the diff without this conversation) and fix the correctness findings you confirm.
4. Run `/verify` when the change affects runtime behavior of the HTTP path, challenge pages or nginx config. Here that means: the stack via `scripts/dev up`, real requests through the edge (see the local-env skill), and the matching e2e tool via `scripts/dev tool <name>`.
5. Docs updated (README, PSEUDOCODE_DESCRIPTION.md, banjax-config.yaml comments, tool README).
6. Final report: what changed, each command run with its real result, what was not run and why, and for security-relevant changes the security notes from the secure-change skill.

## Unattended runs

For long or unattended work the human starts with `/goal scripts/dev check passes`: a separate model
checks that condition after every turn, so "done" is the check, not your own judgment. Keep
`scripts/dev check` deterministic, exiting non-zero on any failure, with the PASS/FAIL summary
printed last. The goal check runs after every turn, which costs tokens; use it for real long runs only.

## Skills (load the one that matches before starting)

- `local-env`: running the stack, requests through the edge, admin API, troubleshooting (hangs, ports, Kafka).
- `writing-tests`: before writing or reviewing any test; the moving-parts list and the break-it check.
- `secure-change`: before designing anything on the request path, crypto/cookies, Kafka input, bans or config defaults.
- `e2e-tester`: adding or changing a tool under `supporting-containers/`.
- `advisor`: when to consult the Opus advisor agent, or how to brief the executor agent.
- `code-review-codex`: started by the human only (`/code-review-codex`), sends the diff to Codex for a second review.
