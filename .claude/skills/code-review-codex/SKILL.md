---
name: code-review-codex
description: Second-opinion code review of the current banjax change by the Codex CLI (codex review), with findings checked against the code before they are reported. Started only by the human as /code-review-codex, because it sends the diff to an external service.
disable-model-invocation: true
argument-hint: "[base-branch | commit-sha]"
---

# /code-review-codex [base-branch | commit-sha]

Runs `codex review` on the change and reports each finding as confirmed, rejected or unverified.
Argument: `$ARGUMENTS` (may be empty). Never fix anything unless the human asks afterwards.

## 1. Secret scan first (the diff leaves this machine)

Run `scripts/secret-scan.sh --worktree`. For a base-branch review also run
`scripts/secret-scan.sh --range <base>..HEAD`; for a commit review run
`scripts/secret-scan.sh --range <sha>^!`. If any scan reports findings, stop here and tell the human;
do not run codex.

Also check `codex login status`. If codex is not installed or not logged in, stop and say so.

## 2. Pick the scope

- No argument and `git status --porcelain` is not empty: the uncommitted changes (staged, unstaged, untracked).
- No argument and a clean tree: the branch against `main`.
- Argument that is a branch (`git rev-parse --verify --quiet refs/heads/<arg>` or `refs/remotes/<arg>` succeeds): the branch against `<arg>`.
- Otherwise an argument that is a commit (`git rev-parse --verify --quiet "<arg>^{commit}"` succeeds): that commit.
- Anything else: stop and ask.

## 3. Build the command

In codex-cli 0.166.0 the custom-instructions PROMPT cannot be combined with `--uncommitted`, `--base`
or `--commit` (it errors "cannot be used with '[PROMPT]'"). So the scope goes into the prompt text, and
the prompt is read from stdin (`-`). Force a read-only sandbox so codex cannot modify files:

```sh
codex review -c 'sandbox_mode="read-only"' - <<'EOF'
Scope: <one of>
  the uncommitted changes in this repo: `git diff HEAD` plus untracked files from `git status --porcelain`
  the changes of this branch against <base>: `git diff <base>...HEAD`
  commit <sha>: `git show <sha>`
Review only that scope, for correctness and security. Skip style, naming and formatting.
This is banjax, a Go service nginx consults per request to allow, deny or challenge a client. What matters:
- the decision order in decisionForNginx2 (internal/http_server.go) and PSEUDOCODE_DESCRIPTION.md
- protected IPs (config.IsProtectedIP) and per-site allowlisted IPs must never be blocked by any path
- fail-open versus fail-closed on errors and panics
- attacker-controlled input (cookies, UA, host, path, Kafka fields) reaching HTML, headers, logs or iptables
- HMAC/signature checks: constant-time compare, binding to IP or UA, expiry, verify before use
- maps keyed by attacker input without expiry or a cap
- zero-valued config thresholds without a default in load() (a zero threshold bans on the first request)
- tests that could not fail if the behavior regressed
For each finding give file:line, why it is wrong, and a concrete fix. If nothing is wrong, say so.
EOF
```

If the human asks for codex's built-in review format instead, use the flag form without a prompt:
`codex review --uncommitted`, `codex review --base <branch>` or `codex review --commit <sha> --title "<subject>"`.

## 4. Run it

- Run with the Bash tool in the background (`run_in_background: true`), redirecting output to a file in
  the scratchpad; a review can take several minutes. Wait for the completion notice, then read the file.
- Review mode only. Never run `codex apply`, `codex exec` or anything that lets codex write to the tree.
- Afterwards `git status --short` must be unchanged from before the run; if it changed, tell the human.

## 5. Report

Codex is a second opinion, not a verdict. For each finding, open the cited code and decide:
- confirmed: the problem is real (say how you checked);
- rejected: it is wrong, with the reason (for example the check it says is missing exists at file:line);
- unverified: you could not settle it, and what would settle it.

Report to the human as that list, most important first, plus anything codex could not see (for example
the scope was empty). Do not edit code unless the human asks.
