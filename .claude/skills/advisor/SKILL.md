---
name: advisor
description: Two-tier workflow for banjax. Use in a Sonnet session to decide when and how to consult the Opus advisor agent (plan review before risky changes, when stuck, diff review before declaring a security-relevant change done). Also use in a higher-tier session that delegates implementation to the executor agent, for how to brief it and review its result.
---

# Working with the advisor (Sonnet main session)

You do the work. The `advisor` agent (Opus, read-only, `.claude/agents/advisor.md`) reviews plans and
diffs. It costs more per token, so use it where a mistake is expensive, not as a habit.

## When to consult

- Before starting a change that touches the decision path (`decisionForNginx2`), crypto or cookies,
  Kafka command handling, config defaults, ban code, or more than about 3 files: get the plan reviewed.
- When stuck: two failed attempts at the same problem. Ask before the third.
- Before declaring done on a security-relevant change: get the diff reviewed.

Do not consult for mechanical edits, single-file fixes with a passing test, or questions you can
answer by reading the code.

## How to brief it cheaply

The advisor reads the repo and `git diff` itself. Give it:
- Goal: one or two sentences.
- Constraints: what must not change (decision strings, fail direction, existing behavior).
- What you tried, if stuck, and the exact error.
- The exact question ("is the order right?", "review the diff for security").
- File paths and the skill to read, never file contents.

Example: "Goal: add a per-site cap on failed AltCha challenges. Plan: new config key X with default
in load(), check in tooManyFailedChallenges before the ban. Files: internal/config.go,
internal/http_server.go. Read secure-change. Question: is the placement right, and what tests am I missing?"

## Using the answer

- Continue the same advisor with SendMessage for follow-ups; do not spawn a new one, it would
  re-read everything.
- Treat the advice as input to verify, not orders: check each point against the code before acting.
  If you disagree after checking, say why in your report.
- Cap: about three consultations per task. If you need more, the task is underspecified; stop and ask
  the human.
- Review order on a non-trivial change: `scripts/dev check` passes, then the built-in `/code-review`
  (a fresh subagent reviews the diff without this conversation), then the advisor for security-relevant
  diffs. Fix the findings you confirm.

# The inverse: a planning session delegating to the executor

A higher-tier session plans and reviews; the `executor` agent (Sonnet, `.claude/agents/executor.md`)
implements.

Write the brief with:
- Goal and the behavior expected, in terms of requests and decisions.
- Files to change, and files that must not change.
- Decisions already made (names, config keys, order, fail direction, decision strings), so it does not redesign.
- Acceptance checks: `scripts/dev check`, specific tests by name with the boundary they cover, `scripts/dev itest` or a tool run when relevant.

Review the result yourself:
- Read the diff (`git diff`), not just the summary.
- Rerun `scripts/dev check` and the acceptance checks; do not trust reported output you have not reproduced.
- Spot-check one break-it claim: break the guarded line, see the test fail, restore.
- Send fixes back to the same executor with SendMessage, as a short list.
