#!/usr/bin/env bash
#
# Deflect Challenge client: proves cryptographically that the thing answering
# for a domain is really a Deflect edge.
#
# The client sends a random nonce in X-Deflect-Challenge; the edge replies with
# an Ed25519 signature in X-Deflect-Challenge-Response. If the signature
# verifies under the domain's public key, the responder holds that domain's
# private key. If it does not, something in the middle is answering.
#
# The signed message is domain-bound, with no trailing newline:
#
#     deflect-challenge-v1 LF <host> LF <challenge>
#
# This must match internal/deflect_challenge.go's DeflectChallengeMessage
# exactly, byte for byte.
#
# Usage, from the repo root with the stack up (docker compose up --build -d):
#   docker compose run --rm challenge-client            # every case
#   docker compose run --rm challenge-client tamper     # only cases matching a substring
#
# The URLs default to the published host ports so the script also works when run
# outside the container; the image overrides them with compose service names.
# See README.md in this directory.

set -u -o pipefail

EDGE_URL="${EDGE_URL:-http://localhost}"
EDGE_HOST="${EDGE_HOST:-localhost}"
ADMIN_URL="${ADMIN_URL:-http://localhost}"
ADMIN_HOST="${ADMIN_HOST:-banjax}"
# Kept in sync with deflect_challenge_max_length in banjax-config.yaml.
MAX_LENGTH="${MAX_LENGTH:-512}"

# The edge lowercases the host before signing, so the client has to match or the
# reconstructed message will not be the one that was signed.
EDGE_HOST=$(printf '%s' "$EDGE_HOST" | tr '[:upper:]' '[:lower:]')

CONTEXT="deflect-challenge-v1"

# TRANSCRIPT=0 drops the full exchange dump and prints only the result rows.
TRANSCRIPT="${TRANSCRIPT:-1}"
FILTER=""
for arg in "$@"; do
    case "$arg" in
        -q|--quiet)   TRANSCRIPT=0 ;;
        -v|--verbose) TRANSCRIPT=1 ;;
        *)            FILTER="$arg" ;;
    esac
done

if [ -t 1 ]; then
    BOLD=$(printf '\033[1m'); RED=$(printf '\033[31m')
    GREEN=$(printf '\033[32m'); YELLOW=$(printf '\033[33m')
    DIM=$(printf '\033[2m'); RESET=$(printf '\033[0m')
else
    BOLD=""; RED=""; GREEN=""; YELLOW=""; DIM=""; RESET=""
fi

PASS=0
FAIL=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# ok NAME DETAIL / bad NAME DETAIL - one result row each, in the style of
# local-tester's test-methods.sh.
ok()  { printf '  %s%-34s%s %sPASS%s  %s%s%s\n' "$BOLD" "$1" "$RESET" "$GREEN" "$RESET" "$DIM" "${2:-}" "$RESET"; PASS=$((PASS + 1)); }
bad() { printf '  %s%-34s%s %sFAIL%s  %s\n'     "$BOLD" "$1" "$RESET" "$RED"   "$RESET" "${2:-}";                FAIL=$((FAIL + 1)); }

# wanted NAME - should this case run, given the substring filter?
wanted() { [ -z "$FILTER" ] || [[ "$1" == *"$FILTER"* ]]; }

# check NAME CONDITION_EXIT_CODE DETAIL
check() {
    if [ "$2" -eq 0 ]; then ok "$1" "$3"; else bad "$1" "$3"; fi
}

# der_from_raw B64_RAW_PUBKEY OUTFILE
#
# openssl needs a SubjectPublicKeyInfo, but the edge hands out the raw 32 bytes.
# For Ed25519 the SPKI wrapper is a fixed 12-byte prefix, so it can just be
# prepended: 30 2a (SEQUENCE, 42 bytes) 30 05 06 03 2b 65 70 (AlgorithmIdentifier,
# OID 1.3.101.112 = Ed25519) 03 21 00 (BIT STRING, 33 bytes, 0 unused bits).
# Fed to pkeyutl with -keyform DER, so no PEM wrapping is needed.
#
# This needs bash's printf for \xHH; busybox's does not handle it.
der_from_raw() {
    { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
      printf '%s' "$1" | base64 -d
    } > "$2"
}

# verify PUBKEY_DER HOST CHALLENGE SIG_FILE - exit 0 iff the signature is good.
#
# -rawin is required: Ed25519 signs the whole message itself and cannot be
# driven through -digest.
verify() {
    printf 'deflect-challenge-v1\n%s\n%s' "$2" "$3" > "$WORK/msg.bin"
    openssl pkeyutl -verify -pubin -inkey "$1" -keyform DER \
        -rawin -in "$WORK/msg.bin" -sigfile "$4" >/dev/null 2>&1
}

# challenge HOST CHALLENGE [KEY_ID] - POST to the edge, leaving the status in
# $C_STATUS, the proof headers in $C_SIG / $C_KEY_ID, and the body in $WORK/body.
challenge() {
    local host="$1" nonce="$2" key_id="${3:-}"
    local args=(-sS -o "$WORK/body" -D "$WORK/headers" -w '%{http_code}'
                -X POST --max-time 10 -H "Host: $host")

    # Record what we send, so the transcript shows the real request rather than
    # a hand-written approximation of it.
    : > "$WORK/reqheaders"
    printf 'POST %s/_deflect/challenge HTTP/1.1\n' "$EDGE_URL" >> "$WORK/reqheaders"
    printf 'Host: %s\n' "$host" >> "$WORK/reqheaders"

    # An empty nonce means "send no challenge header at all", which is case 10.
    if [ -n "$nonce" ]; then
        args+=(-H "X-Deflect-Challenge: $nonce")
        printf 'X-Deflect-Challenge: %s\n' "$nonce" >> "$WORK/reqheaders"
    fi
    if [ -n "$key_id" ]; then
        args+=(-H "X-Deflect-Challenge-Key-ID: $key_id")
        printf 'X-Deflect-Challenge-Key-ID: %s\n' "$key_id" >> "$WORK/reqheaders"
    fi

    C_STATUS=$(curl "${args[@]}" "$EDGE_URL/_deflect/challenge" 2>/dev/null)
    C_SIG=$(header_value X-Deflect-Challenge-Response)
    C_KEY_ID=$(header_value X-Deflect-Challenge-Key-ID)
}

# transcript HOST NONCE - dump the exchange that just happened: what went out,
# what came back, the body, and the exact bytes the signature covers.
transcript() {
    local host="$1" nonce="$2"
    [ "$TRANSCRIPT" -eq 1 ] || return 0

    printf '\n%s>> request%s %s(no body; the nonce rides in a header)%s\n' \
        "$BOLD" "$RESET" "$DIM" "$RESET"
    sed 's/^/  /' "$WORK/reqheaders"

    printf '\n%s<< response head%s\n' "$BOLD" "$RESET"
    # Strip the CRs curl leaves on, and drop the blank line that ends the block.
    tr -d '\r' < "$WORK/headers" | sed '/^$/d' | sed 's/^/  /'

    printf '\n%s<< response body%s\n' "$BOLD" "$RESET"
    if jq . "$WORK/body" >/dev/null 2>&1; then
        jq . "$WORK/body" | sed 's/^/  /'
    else
        sed 's/^/  /' "$WORK/body"; printf '\n'
    fi

    # The crux of the protocol: three fields joined by LF, no trailing newline.
    printf 'deflect-challenge-v1\n%s\n%s' "$host" "$nonce" > "$WORK/shown.bin"

    printf '\n%ssigned message%s %s(%s bytes, verbatim -- no trailing newline)%s\n' \
        "$BOLD" "$RESET" "$DIM" "$(wc -c < "$WORK/shown.bin" | tr -d ' ')" "$RESET"
    printf '  %s%s%s\n' "$YELLOW" "$CONTEXT" "$RESET"
    printf '  %s\\n%s %s<- context label%s\n' "$DIM" "$RESET" "$DIM" "$RESET"
    printf '  %s%s%s\n' "$GREEN" "$host" "$RESET"
    printf '  %s\\n%s %s<- domain binding (lowercased)%s\n' "$DIM" "$RESET" "$DIM" "$RESET"
    printf '  %s\n' "$nonce"
    printf '  %s<- client nonce%s\n' "$DIM" "$RESET"

    printf '\n%s  on the wire%s\n' "$DIM" "$RESET"
    od -c "$WORK/shown.bin" | sed 's/^/  /'

    printf '\n%ssignature%s %s(base64 of 64 raw bytes)%s\n' "$BOLD" "$RESET" "$DIM" "$RESET"
    printf '  %s\n' "${C_SIG:-<none>}"
    printf '\n%sverified with%s\n' "$BOLD" "$RESET"
    printf '  %sopenssl pkeyutl -verify -pubin -inkey pub.der -keyform DER \\\n' "$DIM"
    printf '                  -rawin -in msg.bin -sigfile sig.bin%s\n' "$RESET"
}

# header_value NAME - pull one header out of the last response, case
# insensitively, with the trailing CR stripped.
header_value() {
    grep -i "^$1:" "$WORK/headers" 2>/dev/null | tail -1 | cut -d' ' -f2- | tr -d '\r'
}

nonce() { openssl rand -hex 32; }

printf '%sdeflect challenge client%s\n' "$BOLD" "$RESET"
printf '  edge:   %s (Host: %s)\n' "$EDGE_URL" "$EDGE_HOST"
printf '  admin:  %s (Host: %s)\n' "$ADMIN_URL" "$ADMIN_HOST"

# ---------------------------------------------------------------------------
# Bootstrap: fetch the public key.
#
# Fetching it from the very edge we are about to test proves nothing on its own.
# It is a convenience for this POC; a real client is handed the public key out
# of band and pins it.
# ---------------------------------------------------------------------------
printf '\n%sfetching the public key%s\n' "$BOLD" "$RESET"
printf '  %snote: fetched from the edge under test, so this bootstrap is not itself a trust anchor%s\n' \
    "$YELLOW" "$RESET"

if ! curl -sS --max-time 10 -H "Host: $ADMIN_HOST" \
        "$ADMIN_URL/deflect_challenge/pubkey?domain=$EDGE_HOST" -o "$WORK/pubkey.json" 2>/dev/null; then
    printf '  %scould not reach the admin API at %s%s\n' "$RED" "$ADMIN_URL" "$RESET"
    exit 2
fi

PUB_B64=$(jq -r '.public_key // empty' "$WORK/pubkey.json" 2>/dev/null)
EXPECT_KEY_ID=$(jq -r '.key_id // empty' "$WORK/pubkey.json" 2>/dev/null)
if [ -z "$PUB_B64" ] || [ -z "$EXPECT_KEY_ID" ]; then
    printf '  %sno public key for %s: %s%s\n' "$RED" "$EDGE_HOST" "$(head -c 200 "$WORK/pubkey.json")" "$RESET"
    printf '  %sis "%s" listed under deflect_challenge_sites in banjax-config.yaml?%s\n' \
        "$DIM" "$EDGE_HOST" "$RESET"
    exit 2
fi

der_from_raw "$PUB_B64" "$WORK/pub.der"
if [ ! -s "$WORK/pub.der" ]; then
    printf '  %scould not decode the public key%s\n' "$RED" "$RESET"
    exit 2
fi
printf '  key_id %s, public key %s\n' "$EXPECT_KEY_ID" "$PUB_B64"
if [ "$TRANSCRIPT" -eq 1 ]; then
    printf '\n%s<< %s/deflect_challenge/pubkey?domain=%s%s\n' \
        "$BOLD" "$ADMIN_URL" "$EDGE_HOST" "$RESET"
    jq . "$WORK/pubkey.json" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$WORK/pubkey.json"
fi

# ---------------------------------------------------------------------------
# One full exchange, shown end to end, then checked.
# ---------------------------------------------------------------------------
if [ "$TRANSCRIPT" -eq 1 ]; then
    printf '\n%sthe exchange%s\n' "$BOLD" "$RESET"
fi

NONCE_A=$(nonce)
challenge "$EDGE_HOST" "$NONCE_A"
printf '%s' "$C_SIG" | base64 -d > "$WORK/sig_a.bin" 2>/dev/null
transcript "$EDGE_HOST" "$NONCE_A"

# ---------------------------------------------------------------------------
# Positive cases.
# ---------------------------------------------------------------------------
printf '\n%sis this edge really Deflect?%s\n' "$BOLD" "$RESET"

if wanted "signature verifies"; then
    if [ "$C_STATUS" != "200" ]; then
        bad "signature verifies" "expected HTTP 200, got ${C_STATUS:-no response}"
    elif [ ! -s "$WORK/sig_a.bin" ]; then
        bad "signature verifies" "no X-Deflect-Challenge-Response header"
    else
        verify "$WORK/pub.der" "$EDGE_HOST" "$NONCE_A" "$WORK/sig_a.bin"
        check "signature verifies" $? "the edge holds $EDGE_HOST's private key"
    fi
fi

if wanted "returned key id matches"; then
    [ "$C_KEY_ID" = "$EXPECT_KEY_ID" ]
    check "returned key id matches" $? "$C_KEY_ID"
fi

if wanted "body agrees with headers"; then
    body_sig=$(jq -r '.response // empty' "$WORK/body" 2>/dev/null)
    body_challenge=$(jq -r '.challenge // empty' "$WORK/body" 2>/dev/null)
    [ "$body_sig" = "$C_SIG" ] && [ "$body_challenge" = "$NONCE_A" ]
    check "body agrees with headers" $? "the nonce came back unmangled"
fi

if wanted "advisory key id accepted"; then
    challenge "$EDGE_HOST" "$(nonce)" "$EXPECT_KEY_ID"
    [ "$C_STATUS" = "200" ] && [ "$C_KEY_ID" = "$EXPECT_KEY_ID" ]
    check "advisory key id accepted" $? "requesting the current key id still signs"
fi

# ---------------------------------------------------------------------------
# Negative cases. These are the ones that matter: a client that only ever runs
# the happy path cannot tell a working verifier from one that returns success
# unconditionally.
# ---------------------------------------------------------------------------
printf '\n%swould a forgery be caught?%s\n' "$BOLD" "$RESET"

if wanted "tampered signature rejected"; then
    # Flip the low bit of the first byte of a genuine signature.
    first=$(od -An -N1 -tu1 < "$WORK/sig_a.bin" | tr -d ' \n')
    { printf "\\$(printf '%03o' $(( first ^ 1 )))"; tail -c +2 "$WORK/sig_a.bin"; } > "$WORK/sig_tampered.bin"
    verify "$WORK/pub.der" "$EDGE_HOST" "$NONCE_A" "$WORK/sig_tampered.bin"
    [ $? -ne 0 ]
    check "tampered signature rejected" $? "one flipped bit invalidates it"
fi

if wanted "wrong key rejected"; then
    # A throwaway keypair standing in for a middlebox with its own key.
    openssl genpkey -algorithm ed25519 -out "$WORK/impostor.pem" 2>/dev/null
    openssl pkey -in "$WORK/impostor.pem" -pubout -outform DER -out "$WORK/impostor.der" 2>/dev/null
    verify "$WORK/impostor.der" "$EDGE_HOST" "$NONCE_A" "$WORK/sig_a.bin"
    [ $? -ne 0 ]
    check "wrong key rejected" $? "a signature only verifies under its own key"
fi

if wanted "nonce binding holds"; then
    # A signature for nonce A must not verify as a signature for nonce B, or a
    # recorded response could be replayed forever.
    verify "$WORK/pub.der" "$EDGE_HOST" "$(nonce)" "$WORK/sig_a.bin"
    [ $? -ne 0 ]
    check "nonce binding holds" $? "an old response cannot be replayed"
fi

if wanted "domain binding holds"; then
    # The host is inside the signed message, so a signature collected for one
    # domain must not verify as proof of another.
    verify "$WORK/pub.der" "evil.example" "$NONCE_A" "$WORK/sig_a.bin"
    [ $? -ne 0 ]
    check "domain binding holds" $? "cannot be re-presented as another domain"
fi

if wanted "signatures are not constant"; then
    NONCE_B=$(nonce)
    challenge "$EDGE_HOST" "$NONCE_B"
    [ -n "$C_SIG" ] && [ "$C_SIG" != "$(base64 < "$WORK/sig_a.bin" | tr -d '\n')" ]
    check "signatures are not constant" $? "a different nonce gives a different signature"
fi

# ---------------------------------------------------------------------------
# Protocol handling.
# ---------------------------------------------------------------------------
printf '\n%sdoes the endpoint handle bad input?%s\n' "$BOLD" "$RESET"

if wanted "disabled host is 404"; then
    challenge "sub.localhost" "$(nonce)"
    [ "$C_STATUS" = "404" ]
    check "disabled host is 404" $? "got ${C_STATUS:-no response}"
fi

if wanted "missing challenge is 400"; then
    challenge "$EDGE_HOST" ""
    [ "$C_STATUS" = "400" ]
    check "missing challenge is 400" $? "got ${C_STATUS:-no response}"
fi

if wanted "oversized challenge is 400"; then
    challenge "$EDGE_HOST" "$(head -c $(( MAX_LENGTH + 1 )) < /dev/zero | tr '\0' 'x')"
    [ "$C_STATUS" = "400" ]
    check "oversized challenge is 400" $? "got ${C_STATUS:-no response}"
fi

if wanted "GET is 405"; then
    status=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        -H "Host: $EDGE_HOST" -H "X-Deflect-Challenge: $(nonce)" \
        "$EDGE_URL/_deflect/challenge" 2>/dev/null)
    [ "$status" = "405" ]
    check "GET is 405" $? "got ${status:-no response}"
fi

if wanted "no private key is exported"; then
    # The admin vhost is reachable by anyone who can set a Host header, so the
    # pubkey endpoint must never leak private key material.
    ! grep -Eqi '"(seed|private|private_key|secret)"' "$WORK/pubkey.json"
    check "no private key is exported" $? "pubkey response is public halves only"
fi

printf '\n%s%d passed, %d failed%s\n' "$BOLD" "$PASS" "$FAIL" "$RESET"
if [ "$FAIL" -gt 0 ]; then
    printf '%sA failing "signature verifies" means the responder does not hold this\n' "$DIM"
    printf 'domain'"'"'s key: either the wrong public key was fetched, or something is\n'
    printf 'answering in place of the Deflect edge.%s\n' "$RESET"
    exit 1
fi
