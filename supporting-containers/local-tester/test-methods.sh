#!/usr/bin/env bash
#
# Local-only helper for debugging how POST/PUT/DELETE requests survive the
# nginx + banjax proxy chain.
#
# Each request is sent twice: straight at test-origin, and through the edge
# (nginx -> banjax auth_request -> X-Accel-Redirect -> test-origin). The origin
# echoes back the Content-Length the client claimed and the number of body
# bytes it actually received, so a body dropped in the proxy chain shows up as a
# mismatch between the DIRECT and EDGE rows.
#
# Usage, from the repo root with the stack up (docker compose up --build -d):
#   docker compose run --rm local-tester           # run every case
#   docker compose run --rm local-tester login     # only cases matching a substring
#
# The URLs default to the published host ports so the script also works when run
# outside the container; the image overrides them with compose service names.
# See README.md in this directory.

set -u -o pipefail

ORIGIN_URL="${ORIGIN_URL:-http://localhost:8080}"
EDGE_URL="${EDGE_URL:-http://localhost}"
EDGE_HOST="${EDGE_HOST:-localhost}"
FILTER="${1:-}"

if command -v jq >/dev/null 2>&1; then
    HAVE_JQ=1
else
    HAVE_JQ=0
    echo "note: jq not found, printing raw response bodies" >&2
fi

if [ -t 1 ]; then
    BOLD=$(printf '\033[1m'); RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
    DIM=$(printf '\033[2m'); RESET=$(printf '\033[0m')
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; DIM=""; RESET=""
fi

PASS=0
FAIL=0

# jqf FILE FILTER - read one field out of a JSON body, empty string if the
# response was not JSON (a 403 ban page, nginx HTML, etc).
jqf() {
    if [ "$HAVE_JQ" -eq 1 ]; then
        jq -r "$2 // empty" <"$1" 2>/dev/null
    fi
}

# send LABEL BASE_URL METHOD PATH CONTENT_TYPE BODY
# Prints one result row and updates the PASS/FAIL counters.
send() {
    local label="$1" base="$2" method="$3" path="$4" ctype="$5" body="$6"
    local out status args

    # Reset origin state before every send so DIRECT and EDGE start from the
    # same seed data - otherwise the DIRECT delete makes the EDGE delete 404.
    curl -sS -o /dev/null -X POST "$ORIGIN_URL/api/resources/reset" --max-time 10 2>/dev/null

    out=$(mktemp)
    args=(-sS -o "$out" -w '%{http_code}' -X "$method" --max-time 10)

    # The edge routes by Host header; nginx's server_name is localhost.
    if [ "$base" = "$EDGE_URL" ]; then
        args+=(-H "Host: $EDGE_HOST")
    fi
    if [ -n "$ctype" ]; then
        args+=(-H "Content-Type: $ctype")
    fi
    if [ -n "$body" ]; then
        args+=(--data-binary "$body")
    fi

    status=$(curl "${args[@]}" "$base$path" 2>/dev/null)
    if [ -z "$status" ]; then
        printf '  %-8s %s%s%s\n' "$label" "$RED" "connection failed ($base$path)" "$RESET"
        FAIL=$((FAIL + 1))
        rm -f "$out"
        return
    fi

    local claimed received complete err
    claimed=$(jqf "$out" '.request.content_length_header')
    received=$(jqf "$out" '.request.body_bytes_received')
    complete=$(jqf "$out" '.request.body_complete')
    err=$(jqf "$out" '.error')

    local verdict color
    if [ "$complete" = "true" ]; then
        verdict="body intact"; color="$GREEN"; PASS=$((PASS + 1))
    elif [ "$method" = "DELETE" ] && [ -z "$body" ]; then
        # A bodyless DELETE is expected to report no body.
        verdict="no body sent"; color="$DIM"; PASS=$((PASS + 1))
    elif [ -n "$complete" ]; then
        verdict="BODY LOST"; color="$RED"; FAIL=$((FAIL + 1))
    else
        verdict="no origin report"; color="$YELLOW"; FAIL=$((FAIL + 1))
    fi

    printf '  %-8s HTTP %-3s  sent=%-4s got=%-4s  %s%s%s' \
        "$label" "$status" "${claimed:-?}" "${received:-?}" "$color" "$verdict" "$RESET"
    if [ -n "$err" ]; then
        printf '  %s(%s)%s' "$DIM" "$err" "$RESET"
    fi
    printf '\n'

    if [ "$HAVE_JQ" -eq 0 ]; then
        printf '    %s%s%s\n' "$DIM" "$(head -c 300 "$out")" "$RESET"
    fi
    rm -f "$out"
}

# case NAME METHOD PATH CONTENT_TYPE BODY - run one case against both targets.
run_case() {
    local name="$1" method="$2" path="$3" ctype="$4" body="$5"

    if [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]]; then
        return
    fi

    printf '\n%s%s %s%s%s\n' "$BOLD" "$method" "$path" "$RESET" "${DIM} - $name$RESET"
    send DIRECT "$ORIGIN_URL" "$method" "$path" "$ctype" "$body"
    send EDGE   "$EDGE_URL"   "$method" "$path" "$ctype" "$body"
}

printf '%sbanjax method test%s\n' "$BOLD" "$RESET"
printf '  origin (direct): %s\n' "$ORIGIN_URL"
printf '  edge (nginx):    %s (Host: %s)\n' "$EDGE_URL" "$EDGE_HOST"

# Reset the origin's resource table so PUT/DELETE cases are repeatable.
curl -sS -o /dev/null -X POST "$ORIGIN_URL/api/resources/reset" --max-time 10 2>/dev/null \
    || echo "  ${YELLOW}warning: could not reset origin state${RESET}"

run_case "login, json body"        POST   /login              application/json                    '{"username":"alice","password":"correct-horse"}'
run_case "login, form body"        POST   /login              application/x-www-form-urlencoded   'username=alice&password=correct-horse'
run_case "login, bad password"     POST   /login              application/json                    '{"username":"alice","password":"wrong"}'
run_case "modify a resource"       PUT    /api/resources/1    application/json                    '{"name":"renamed","value":"updated-by-test"}'
run_case "delete a resource"       DELETE /api/resources/2    ""                                  ''
run_case "echo a large body"       POST   /echo               text/plain                          "$(printf 'x%.0s' $(seq 1 4096))"

# A 200 with an intact body still would not prove the origin applied the write,
# so send one PUT through the edge and read the state back to confirm it landed.
printf '\n%sdoes an edge write actually land?%s\n' "$BOLD" "$RESET"
curl -sS -o /dev/null -X POST "$ORIGIN_URL/api/resources/reset" --max-time 10 2>/dev/null
curl -sS -o /dev/null -X PUT "$EDGE_URL/api/resources/1" \
    -H "Host: $EDGE_HOST" -H 'Content-Type: application/json' \
    --data-binary '{"value":"written-through-edge"}' --max-time 10 2>/dev/null

landed=$(curl -sS --max-time 10 "$ORIGIN_URL/api/resources" 2>/dev/null \
    | jq -r '.resources[]? | select(.id=="1") | .value' 2>/dev/null)
if [ "$landed" = "written-through-edge" ]; then
    printf '  %sconfirmed: origin state shows the edge write%s\n' "$GREEN" "$RESET"
    PASS=$((PASS + 1))
else
    printf '  %sedge write did not land (id 1 value = %s)%s\n' "$RED" "${landed:-unreadable}" "$RESET"
    FAIL=$((FAIL + 1))
fi

printf '\n%s%d passed, %d failed%s\n' "$BOLD" "$PASS" "$FAIL" "$RESET"
if [ "$FAIL" -gt 0 ]; then
    printf '%sIf DIRECT rows pass and EDGE rows say BODY LOST, the body is being\n' "$DIM"
    printf 'discarded in the proxy chain, not by the origin.%s\n' "$RESET"
    exit 1
fi
