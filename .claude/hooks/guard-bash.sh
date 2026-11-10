#!/usr/bin/env bash
# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# PreToolUse hook for Bash. Reads the hook JSON on stdin and prints a deny or ask
# decision for commands that read secret material, bypass the git hooks, or
# destroy work. Prints nothing (allow) otherwise.
#
# This is a seatbelt, not a sandbox: it pattern-matches the command text and a
# determined or creative command gets past it (grep -r ., a script file, an
# interpreter). It exists to stop the common accidents. `git push` is gated by
# the permissions.ask rule in .claude/settings.json, not here.

command -v jq >/dev/null 2>&1 || {
    echo "guard-bash: jq is required" >&2
    exit 2
}

cmd="$(jq -r '.tool_input.command // empty')"
[ -n "$cmd" ] || exit 0

deny_reason=""
ask_reason=""
deny() { [ -n "$deny_reason" ] || deny_reason="$1"; }
ask() { [ -n "$ask_reason" ] || ask_reason="$1"; }

# a path token for the real .env (not .env.example) or for anything under keys/
ENV_PATH_RE='(^|[[:space:]/"'"'"'=<])\.env([[:space:]"'"'"';|&)>*]|$)'
KEYS_PATH_RE='(^|[[:space:]/"'"'"'=<])keys/'
READ_VERB='(^|[[:space:]/(])(cat|bat|less|more|head|tail|nl|tac|grep|egrep|fgrep|rg|ag|sed|awk|cut|sort|uniq|diff|base64|xxd|od|hexdump|strings|cp|scp|rsync|tar|zip|source|open|pbcopy|vi|vim|nano|jq|\.)([[:space:]]|$)'

# split on ; && || | newlines, $( and backticks so each simple command is judged alone
segments="$(printf '%s\n' "$cmd" | awk '{ gsub(/&&|\|\||;|\||\$\(|`/, "\n"); print }')"

while IFS= read -r seg; do
    [ -n "$seg" ] || continue

    # --- secret material ---
    if printf '%s' "$seg" | grep -Eq "$READ_VERB"; then
        if printf '%s' "$seg" | grep -Eq "$ENV_PATH_RE"; then
            deny "Reading or copying .env is blocked: it holds real Kafka settings. The variables are named in the README and the local-env skill (ENABLE_AIR, DISABLE_KAFKA, KAFKA_*); ask the human if you need to know a value or change one."
        fi
        if printf '%s' "$seg" | grep -Eq "$KEYS_PATH_RE"; then
            deny "Reading or copying files under keys/ is blocked: they are real private keys and certificates. Listing names (ls keys) is fine; tests generate their own throwaway keys."
        fi
    fi
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])printenv([[:space:]]|$)'; then
        deny "printenv is blocked: the environment can carry credentials. Ask the human for the specific non-secret value you need."
    fi
    if printf '%s' "$seg" | grep -Eq 'docker([[:space:]]+compose|-compose)[[:space:]].*exec[[:space:]].*(^|[[:space:]])env([[:space:]]|$)|docker[[:space:]]+exec[[:space:]].*[[:space:]]env([[:space:]]|$)'; then
        deny "Dumping a container's environment is blocked: the banjax container gets .env through env_file. Use scripts/dev api /info or the logs instead."
    fi
    if printf '%s' "$seg" | grep -Eq 'docker([[:space:]]+compose|-compose)[[:space:]]+([^[:space:]]+[[:space:]]+)*config([[:space:]]|$)' &&
        ! printf '%s' "$seg" | grep -Eq '[[:space:]](--services|--images|--volumes|-q|--quiet)([[:space:]]|$)'; then
        deny "docker compose config prints .env values resolved into the file. Use docker compose config --services (or --images, --volumes, -q), or read docker-compose.yml directly."
    fi
    if printf '%s' "$seg" | grep -Eq 'Config\.Env'; then
        deny "Reading a container's Config.Env is blocked: it carries .env values. Use scripts/dev ps or docker inspect -f '{{.State.Status}}'."
    fi

    # --- git: never stage secrets, never bypass hooks ---
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+add([[:space:]]|$)'; then
        if printf '%s' "$seg" | grep -Eq '[[:space:]](--force|-[a-zA-Z]*f[a-zA-Z]*)([[:space:]]|$)'; then
            deny "git add -f/--force is blocked: it stages ignored files such as .env, keys/ and logs. If a file truly belongs in the repo, ask the human to change .gitignore."
        fi
        if printf '%s' "$seg" | grep -Eq "$ENV_PATH_RE|$KEYS_PATH_RE"; then
            deny "Staging .env or keys/ is blocked: real credentials must never be committed (one remote is public)."
        fi
    fi
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+(commit|push)([[:space:]]|$)' &&
        printf '%s' "$seg" | grep -Eq '[[:space:]]--no-verify([[:space:]]|$)'; then
        deny "--no-verify is blocked: the hooks are the secret scan and gofmt gate. Fix what the hook reports (scripts/dev fmt --fix, remove the secret), then commit normally."
    fi
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+commit([[:space:]]|$)' &&
        printf '%s' "$seg" | grep -Eq '[[:space:]]-[a-zA-Z]*n[a-zA-Z]*([[:space:]]|$)'; then
        deny "git commit -n skips the pre-commit hook (secret scan, gofmt). Fix what the hook reports, then commit without -n."
    fi
    if printf '%s' "$seg" | grep -Eiq 'core\.hookspath'; then
        if printf '%s' "$seg" | grep -Eiq '(-c[[:space:]]+core\.hookspath=|--unset|--unset-all|core\.hookspath[[:space:]]+[^[:space:]-])'; then
            deny "Changing core.hooksPath is blocked: it disables the secret scan. To (re)activate the repo hooks run scripts/dev hooks."
        fi
    fi

    # --- destructive: let the human confirm ---
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+reset([[:space:]].*)?[[:space:]]--hard([[:space:]]|$)'; then
        ask "git reset --hard discards uncommitted work. Prefer git stash, or git restore <file> for one file."
    fi
    if printf '%s' "$seg" | grep -Eq '(^|[[:space:]])git([[:space:]]+-C[[:space:]]+[^[:space:]]+)?[[:space:]]+clean([[:space:]]|$)'; then
        ask "git clean deletes untracked files, which may include the human's work. Remove specific files by name instead, or run git clean -n first to list them."
    fi
    if printf '%s' "$seg" | grep -Eq 'docker([[:space:]]+compose|-compose)[[:space:]]+down([[:space:]].*)?[[:space:]](-v|--volumes)([[:space:]]|$)'; then
        ask "docker compose down -v deletes volumes. scripts/dev down keeps them; that is usually what you want."
    fi
    if printf '%s' "$seg" | grep -Eq 'docker[[:space:]]+(system[[:space:]]+prune|volume[[:space:]]+(rm|prune)|image[[:space:]]+prune|builder[[:space:]]+prune)'; then
        ask "This deletes Docker data that may belong to other projects (and the Go module cache volumes). Ask whether it is wanted."
    fi
done <<EOF
$segments
EOF

emit() {
    jq -cn --arg d "$1" --arg r "$2" \
        '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: $d, permissionDecisionReason: $r}}'
}

if [ -n "$deny_reason" ]; then
    emit deny "$deny_reason"
elif [ -n "$ask_reason" ]; then
    emit ask "$ask_reason"
fi
exit 0
