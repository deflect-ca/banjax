#!/usr/bin/env bash
# Copyright (c) 2026, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Scans ADDED lines (never unchanged content) for secrets, and changed paths for
# files that must never be committed. One of this repo's remotes is public, so
# whatever gets committed may end up public. Exit 1 on findings.
#
#   scripts/secret-scan.sh --staged              index vs HEAD (pre-commit)
#   scripts/secret-scan.sh --worktree            tracked changes vs HEAD + untracked files
#   scripts/secret-scan.sh --range <rev args>    every commit in the range (pre-push), so a
#                                                secret added then removed is still caught
#
# Findings print file, line and rule only, never the matched value.
# A line containing the marker secret-scan:allow is skipped.
# Needs only git, grep, awk, sed; bash 3.2 compatible. Runs gitleaks too when installed.

set -u

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "secret-scan: not inside a git repository" >&2
    exit 2
}
cd "$ROOT" || exit 2

mode="${1:-}"
[ $# -gt 0 ] && shift
case "$mode" in
--staged | --worktree) ;;
--range)
    [ $# -gt 0 ] || {
        echo "secret-scan: --range needs rev-list arguments, e.g. main..HEAD" >&2
        exit 2
    }
    ;;
*)
    echo "usage: $0 --staged | --worktree | --range <rev-list args>" >&2
    exit 2
    ;;
esac

TMP="$(mktemp -d "${TMPDIR:-/tmp}/secret-scan.XXXXXX")" || exit 2
chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT

# base tree to diff against; an empty tree before the first commit
if git rev-parse --verify -q HEAD >/dev/null; then
    BASE=HEAD
else
    BASE=4b825dc642cb6eb9a060e54bf8d69288fbee4904
fi

GITDIFF="git -c core.quotepath=off"

# ---- 1. collect changed paths and a unified diff of added lines ----------------

paths="$TMP/paths"
diff="$TMP/diff"
case "$mode" in
--staged)
    $GITDIFF diff --cached --name-only --diff-filter=ACMR "$BASE" >"$paths"
    $GITDIFF diff --cached --no-color --no-ext-diff --no-textconv -U0 --diff-filter=ACMR "$BASE" >"$diff"
    ;;
--worktree)
    $GITDIFF diff --name-only --diff-filter=ACMR "$BASE" >"$paths"
    $GITDIFF diff --no-color --no-ext-diff --no-textconv -U0 --diff-filter=ACMR "$BASE" >"$diff"
    # untracked, non-ignored files count as entirely added
    git ls-files -z --others --exclude-standard | while IFS= read -r -d '' f; do
        printf '%s\n' "$f" >>"$paths"
        [ -f "$f" ] || continue
        # skip binaries (grep -I treats them as non-matching)
        LC_ALL=C grep -Iq . "$f" 2>/dev/null || continue
        printf 'diff --git a/%s b/%s\n+++ b/%s\n@@ -0,0 +1 @@\n' "$f" "$f" "$f" >>"$diff"
        sed 's/^/+/' "$f" >>"$diff"
    done
    ;;
--range)
    $GITDIFF log --format= --name-only --diff-filter=ACMR "$@" >"$paths" || exit 2
    $GITDIFF log -p --no-color --no-ext-diff --no-textconv -U0 --diff-filter=ACMR \
        --format='commit %H' "$@" >"$diff" || exit 2
    ;;
esac

findings="$TMP/findings"
: >"$findings"

# ---- 2. forbidden paths ---------------------------------------------------------

sort -u "$paths" | while IFS= read -r p; do
    [ -n "$p" ] || continue
    base="${p##*/}"
    rule=""
    case "$base" in
    .env.example) ;;
    .env | .env.*) rule="env file (real credentials live only in .env)" ;;
    *.pem | *.key | *.p12 | *.pfx | *.jks) rule="key or certificate file" ;;
    id_rsa* | id_ed25519*) rule="ssh key file" ;;
    banning-log-file.txt | testing-log-file.txt | gin.log | list-metrics.log)
        rule="runtime log (contains client IPs)" ;;
    esac
    case "$p" in
    keys/* | */keys/*) rule="file under keys/ (TLS and challenge private keys)" ;;
    logs/*) rule="runtime log under logs/ (contains client IPs)" ;;
    .claude/settings.local.json) rule="personal Claude settings (.claude/settings.local.json)" ;;
    esac
    [ -n "$rule" ] && printf '%s\t-\t-\tforbidden path\t%s\n' "$p" "$rule" >>"$findings"
done

# ---- 3. local .env values (names only, values never printed) -------------------

envvals="$TMP/envvals"
: >"$envvals"
if [ -f "$ROOT/.env" ]; then
    # KEY=value, optionally prefixed by export and quoted; written to a private
    # temp file so the values never appear in argv or output
    sed -n -E 's/^[[:space:]]*(export[[:space:]]+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/\2	\3/p' "$ROOT/.env" |
        while IFS='	' read -r name value; do
            value="${value%%[[:space:]]#*}"
            value="${value#\"}"
            value="${value%\"}"
            value="${value#\'}"
            value="${value%\'}"
            [ "${#value}" -ge 6 ] || continue
            case "$value" in
            true | false | TRUE | FALSE | True | False) continue ;;
            *[!0-9]*) ;;
            *) continue ;;
            esac
            printf '%s\t%s\n' "$name" "$value"
        done >"$envvals"
fi

# ---- 4. content rules on added lines -------------------------------------------

awk -v envfile="$envvals" '
BEGIN {
    FS = "\n"
    while ((getline l < envfile) > 0) {
        t = index(l, "\t")
        if (t == 0) continue
        nenv++
        envname[nenv] = substr(l, 1, t - 1)
        envval[nenv] = substr(l, t + 1)
    }
    close(envfile)
    split("password passwd secret some_secret changeme example dummy test xxx none null placeholder redacted", ph, " ")
    for (i in ph) placeholder[ph[i]] = 1
}
# fields must never be empty: the shell reads them with IFS=tab, which collapses runs
function report(rule, detail) {
    printf "%s\t%s\t%s\t%s\t%s\n", path, ln, (commit == "" ? "-" : commit), rule, (detail == "" ? "-" : detail)
}
function filekind(p,    b, ext) {
    b = p; sub(/.*\//, "", b)
    if (b ~ /^\.env/) return "config"
    if (b !~ /\./) return "code"   # extensionless scripts (scripts/dev, git hooks)
    ext = b; sub(/.*\./, "", ext); ext = tolower(ext)
    if (ext ~ /^(ya?ml|env|json|conf|toml|ini)$/) return "config"
    if (ext ~ /^(go|js|mjs|sh|py)$/) return "code"
    return "other"
}
function is_placeholder(v,    lv) {
    lv = tolower(v)
    if (lv in placeholder) return 1
    if (v ~ /^<.*>$/ || v ~ /^\$\{.*\}$/ || v ~ /^\$/ || v ~ /^\//) return 1
    if (lv ~ /(example|dummy|changeme|placeholder|redacted|xxxx|your[_-]|fake|correct-horse|hunter2)/) return 1
    if (v ~ /^[0-9.]+$/) return 1
    return 0
}
# generic_assignment looks for key [:=] value where the key names a secret
function generic_assignment(s, kind,    low, rest, q, v, key, start) {
    low = tolower(s)
    # the key must END with the secret word (hmac_secret, apiToken, kafka_ssl_key_password),
    # so names like PasswordCookieName or password_protected_paths are not keys of a secret
    if (!match(low, /[a-z0-9_.-]*(password|passwd|secret|token|api[_-]?key|private[_-]?key|secret[_-]?key|access[_-]?key)s?["\x27]?[[:space:]]*[:=]+[[:space:]]*/))
        return
    key = substr(s, RSTART, RLENGTH); sub(/["\x27]?[[:space:]]*[:=]+[[:space:]]*$/, "", key)
    rest = substr(s, RSTART + RLENGTH)
    q = substr(rest, 1, 1)
    if (q == "\"" || q == "\x27" || q == "`") {
        rest = substr(rest, 2)
        start = index(rest, q)
        if (start == 0) return
        v = substr(rest, 1, start - 1)
        if (kind == "code" && length(v) < 12) return
        if (kind == "config" && length(v) < 8) return
    } else {
        if (kind != "config") return   # code: only quoted string literals
        v = rest; sub(/[[:space:],#].*$/, "", v)
        if (length(v) < 8) return
    }
    if (is_placeholder(v)) return
    if (v == key) return   # name-to-string tables: ErrorNoPassword: "ErrorNoPassword"
    report("generic secret assignment", "key " key)
}
/^commit [0-9a-f]+$/ { commit = substr($0, 8, 12); inhunk = 0; next }
/^diff --git / { inhunk = 0; path = ""; next }
!inhunk && /^\+\+\+ / {
    path = substr($0, 5); if (path == "/dev/null") path = ""; else sub(/^b\//, "", path)
    kind = filekind(path)
    next
}
/^@@ / {
    h = $0; sub(/^@@ -[0-9,]+ \+/, "", h); sub(/[, ].*$/, "", h)
    ln = h + 0; inhunk = 1
    next
}
inhunk && /^\+/ {
    s = substr($0, 2)
    if (path != "" && index(s, "secret-scan:allow") == 0) {
        if (s ~ /-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----/) report("private key (PEM)", "")
        if (s ~ /(AKIA|ASIA)[0-9A-Z]{16}/) report("AWS access key id", "")
        if (s ~ /(ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{36}/ || s ~ /github_pat_[A-Za-z0-9_]{22,}/) report("GitHub token", "")
        if (s ~ /glpat-[A-Za-z0-9_-]{20}/) report("GitLab token", "")
        if (s ~ /xox[baprs]-[A-Za-z0-9-]{10,}/) report("Slack token", "")
        if (s ~ /eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./) report("JWT", "")
        if (match(s, /[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\/:@[:space:]"\x27]+:[^\/@[:space:]"\x27]+@/)) {
            cred = substr(s, RSTART, RLENGTH); sub(/^.*:\/\/[^:]*:/, "", cred); sub(/@$/, "", cred)
            if (!is_placeholder(cred)) report("URL with embedded credentials", "")
        }
        if (kind == "config" || kind == "code") generic_assignment(s, kind)
        for (i = 1; i <= nenv; i++)
            if (index(s, envval[i]) > 0) report("value from local .env", "variable " envname[i])
    }
    ln++
    next
}
' "$diff" >>"$findings"

# ---- 5. gitleaks, when installed -------------------------------------------------

if command -v gitleaks >/dev/null 2>&1; then
    case "$mode" in
    --staged) gitleaks protect --staged --redact --no-banner >"$TMP/gl" 2>&1 ;;
    --worktree) gitleaks protect --redact --no-banner >"$TMP/gl" 2>&1 ;;
    --range) gitleaks detect --redact --no-banner --log-opts="$*" >"$TMP/gl" 2>&1 ;;
    esac
    if [ $? -ne 0 ]; then
        printf 'gitleaks\t-\t-\tgitleaks finding\tsee: gitleaks %s --redact -v\n' \
            "$([ "$mode" = "--range" ] && echo detect || echo protect)" >>"$findings"
    fi
fi

# ---- 6. report -----------------------------------------------------------------

if [ ! -s "$findings" ]; then
    echo "secret-scan ($mode): no findings"
    exit 0
fi

echo "secret-scan ($mode): FOUND possible secrets or forbidden files:" >&2
sort -u "$findings" | while IFS='	' read -r p line commit rule detail; do
    loc="$p"
    [ "$line" != "-" ] && loc="$p:$line"
    [ "$commit" != "-" ] && loc="$loc (commit $commit)"
    if [ "$detail" != "-" ]; then
        printf '  %s: %s [%s]\n' "$loc" "$rule" "$detail" >&2
    else
        printf '  %s: %s\n' "$loc" "$rule" >&2
    fi
done
cat >&2 <<'EOF'

Remove the secret or file (unstage with: git restore --staged <file>). Real values
belong only in .env or keys/, which are gitignored. If a finding is a false positive,
use an obvious placeholder value or add the marker secret-scan:allow to that line.
For a secret already in a commit, rewrite that commit before pushing, and rotate
the secret if it ever left this machine.
EOF
exit 1
