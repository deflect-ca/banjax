#!/usr/bin/env bash
#
# Deflect Challenge client, remote edition: point it at any edge, anywhere.
#
# Same protocol and same checks as deflect-challenge.sh next to it, but built
# for an edge you do not control the network path to: a real domain over TLS, a
# single node pinned by IP, a staging box with a self-signed certificate. The
# public key is supplied out of band and pinned, which is how a real client is
# meant to work; the sibling script's bootstrap-from-the-edge-under-test is
# available here only when you explicitly point at an admin vhost.
#
# The client sends a random nonce in X-RePress-Challenge; the edge replies with
# an Ed25519 signature in X-RePress-Challenge-Response. If the signature
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
# ---------------------------------------------------------------------------
# Usage:
#   ./deflect-challenge-remote.sh [options] <target> [name-filter]
#
# <target> is a bare domain or a URL. A bare domain means https.
#
# Examples:
#
#   # The realistic case: a public key handed to you out of band, pinned.
#   ./deflect-challenge-remote.sh -p 'kWVh0m9mQ2p...=' example.com
#
#   # Same, reading the operator's key file. Either public_key or seed will do;
#   # with a seed the public half is derived locally.
#   ./deflect-challenge-remote.sh -f example.com.json example.com
#
#   # One specific edge node, bypassing DNS, keeping the real Host and SNI.
#   # Run it once per node to find the one that is answering wrong.
#   ./deflect-challenge-remote.sh -f example.com.json -r 203.0.113.10 example.com
#
#   # Staging edge on a nonstandard port with a self-signed certificate.
#   ./deflect-challenge-remote.sh -f staging.json -k https://staging.example.com:8443
#
#   # An edge reached by IP only, with the vhost set by hand.
#   ./deflect-challenge-remote.sh -p 'kWVh...=' -H example.com -k https://203.0.113.10
#
#   # No key in hand: bootstrap from an admin vhost you can reach, e.g. through
#   # an SSH tunnel (ssh -L 8081:127.0.0.1:80 edge). Fetching the key from the
#   # thing you are testing proves nothing on its own, so this is a convenience,
#   # not a trust anchor.
#   ./deflect-challenge-remote.sh --admin-url http://127.0.0.1:8081 --admin-host banjax example.com
#
#   # The local dev stack, equivalent to deflect-challenge.sh with no arguments.
#   ./deflect-challenge-remote.sh --admin-url http://localhost --admin-host banjax \
#       --disabled-host sub.localhost http://localhost
#
#   # Quiet, and only the cases whose name contains "binding".
#   ./deflect-challenge-remote.sh -q -f example.com.json example.com binding
#
# Options:
#   -p, --pubkey B64       the domain's public key, base64 of the raw 32 bytes
#   -f, --pubkey-file F    read it from a file: a banjax key file (public_key,
#                          or seed, from which the public half is derived), a
#                          saved /deflect_challenge/pubkey response, or a text
#                          file holding just the base64
#       --key-id ID        refuse to run unless the key has this ID
#   -r, --resolve IP       connect to this IP, keeping the Host header and SNI
#   -H, --host HOST        Host header to send (default: the host in <target>)
#   -s, --signed-host HOST host expected inside the signed message (default: the
#                          Host header). nginx signs $host, which has no port;
#                          banjax hit directly signs Host verbatim, port and all
#       --admin-url URL    fetch the public key from this admin vhost instead
#       --admin-host HOST  Host header for it (default: banjax)
#       --disabled-host H  a host on this edge with the feature off, for the 404 case
#       --max-length N     deflect_challenge_max_length on the edge (default 512)
#   -t, --timeout SEC      per request timeout (default 10)
#   -k, --insecure         do not verify the edge's TLS certificate
#   -q, --quiet            results only; -v, --verbose forces the transcript back on
#       --only SUB         run only the cases whose name contains SUB
#
# Needs bash, curl, jq and OpenSSL 3.x. Exit 0 if every case passed, 1 if a case
# failed, 2 if the run could not start (no usable public key, edge unreachable).
# ---------------------------------------------------------------------------

set -u -o pipefail

TARGET=""
FILTER=""
PUB_B64="${PUB_B64:-}"
PUB_FILE=""
PIN_KEY_ID=""
RESOLVE_IP=""
HOST_OVERRIDE=""
SIGNED_HOST=""
ADMIN_URL=""
ADMIN_HOST="banjax"
DISABLED_HOST=""
INSECURE=0
TIMEOUT=10
# Kept in sync with deflect_challenge_max_length in banjax-config.yaml.
MAX_LENGTH="${MAX_LENGTH:-512}"
# TRANSCRIPT=0 drops the full exchange dump and prints only the result rows.
TRANSCRIPT="${TRANSCRIPT:-1}"

CONTEXT="deflect-challenge-v1"

# usage - the header comment from "Usage:" to the end of that block, which is
# where the option list lives, so there is only ever one copy of it.
usage() { sed -n '/^# Usage:/,/^# ---/p' "$0" | sed -e '$d' -e 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
    case "$1" in
        -p|--pubkey)        PUB_B64="$2"; shift 2 ;;
        -f|--pubkey-file)   PUB_FILE="$2"; shift 2 ;;
        --key-id)           PIN_KEY_ID="$2"; shift 2 ;;
        -r|--resolve)       RESOLVE_IP="$2"; shift 2 ;;
        -H|--host)          HOST_OVERRIDE="$2"; shift 2 ;;
        -s|--signed-host)   SIGNED_HOST="$2"; shift 2 ;;
        --admin-url)        ADMIN_URL="$2"; shift 2 ;;
        --admin-host)       ADMIN_HOST="$2"; shift 2 ;;
        --disabled-host)    DISABLED_HOST="$2"; shift 2 ;;
        --max-length)       MAX_LENGTH="$2"; shift 2 ;;
        -t|--timeout)       TIMEOUT="$2"; shift 2 ;;
        -k|--insecure)      INSECURE=1; shift ;;
        -q|--quiet)         TRANSCRIPT=0; shift ;;
        -v|--verbose)       TRANSCRIPT=1; shift ;;
        --only)             FILTER="$2"; shift 2 ;;
        -h|--help)          usage; exit 0 ;;
        -*)                 printf 'unknown option: %s\n' "$1" >&2; exit 2 ;;
        *)
            if [ -z "$TARGET" ]; then TARGET="$1"; else FILTER="$1"; fi
            shift ;;
    esac
done

if [ -z "$TARGET" ]; then
    usage >&2
    exit 2
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
SKIP=0
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# ---------------------------------------------------------------------------
# Work out what to connect to, what Host to send, and what host the signature
# is expected to be bound to. These are three separate things once DNS is out
# of the picture, which is the whole point of testing remotely.
# ---------------------------------------------------------------------------
case "$TARGET" in
    http://*|https://*) EDGE_URL="$TARGET" ;;
    *)                  EDGE_URL="https://$TARGET" ;;
esac
EDGE_URL="${EDGE_URL%/}"

SCHEME="${EDGE_URL%%://*}"
HOSTPORT="${EDGE_URL#*://}"
HOSTPORT="${HOSTPORT%%/*}"
EDGE_URL="$SCHEME://$HOSTPORT"

case "$HOSTPORT" in
    \[*\]:*) URL_HOST="${HOSTPORT%:*}"; URL_PORT="${HOSTPORT##*:}" ;;
    \[*\])   URL_HOST="$HOSTPORT";      URL_PORT="" ;;
    *:*)     URL_HOST="${HOSTPORT%:*}"; URL_PORT="${HOSTPORT##*:}" ;;
    *)       URL_HOST="$HOSTPORT";      URL_PORT="" ;;
esac
if [ -z "$URL_PORT" ]; then
    if [ "$SCHEME" = "https" ]; then URL_PORT=443; else URL_PORT=80; fi
fi

# The Host header: whatever was asked for, else let the URL speak for itself.
HOST_HEADER="${HOST_OVERRIDE:-$URL_HOST}"
HOST_HEADER="${HOST_HEADER#[}"; HOST_HEADER="${HOST_HEADER%]}"

# The host inside the signed message. nginx signs $host, which is the Host
# header with the port stripped and lowercased, so that is the default. Hitting
# banjax directly with no nginx in front signs Host verbatim, port included:
# that is what --signed-host is for.
if [ -z "$SIGNED_HOST" ]; then SIGNED_HOST="$HOST_HEADER"; fi
SIGNED_HOST=$(lower "$SIGNED_HOST")

# Common curl arguments for every request this script makes.
CURL_COMMON=(-sS --max-time "$TIMEOUT")
[ "$INSECURE" -eq 1 ] && CURL_COMMON+=(-k)
# --resolve pins the connection to one node while leaving the Host header and
# the TLS SNI alone, which is exactly how you test one edge out of a rotation.
[ -n "$RESOLVE_IP" ] && CURL_COMMON+=(--resolve "$URL_HOST:$URL_PORT:$RESOLVE_IP")

# ok NAME DETAIL / bad NAME DETAIL / skip NAME REASON - one result row each, in
# the style of local-tester's test-methods.sh.
ok()   { printf '  %s%-34s%s %sPASS%s  %s%s%s\n' "$BOLD" "$1" "$RESET" "$GREEN"  "$RESET" "$DIM" "${2:-}" "$RESET"; PASS=$((PASS + 1)); }
bad()  { printf '  %s%-34s%s %sFAIL%s  %s\n'     "$BOLD" "$1" "$RESET" "$RED"    "$RESET" "${2:-}";                FAIL=$((FAIL + 1)); }
skip() { printf '  %s%-34s%s %sSKIP%s  %s%s%s\n' "$BOLD" "$1" "$RESET" "$YELLOW" "$RESET" "$DIM" "${2:-}" "$RESET"; SKIP=$((SKIP + 1)); }

# wanted NAME - should this case run, given the substring filter?
wanted() { [ -z "$FILTER" ] || [[ "$1" == *"$FILTER"* ]]; }

# check NAME CONDITION_EXIT_CODE DETAIL
check() {
    if [ "$2" -eq 0 ]; then ok "$1" "$3"; else bad "$1" "$3"; fi
}

die() { printf '  %s%s%s\n' "$RED" "$1" "$RESET" >&2; exit 2; }

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

# pub_from_seed B64_SEED - echo the base64 raw public key for a 32-byte seed.
#
# The key file's public_key field is optional (the seed is the source of truth),
# so a client handed only a seed still has to get there. PKCS#8 for Ed25519 is
# another fixed prefix: 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20, then
# the seed. openssl derives the public half from that.
pub_from_seed() {
    { printf '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20'
      printf '%s' "$1" | base64 -d
    } > "$WORK/priv.der"
    openssl pkey -inform DER -in "$WORK/priv.der" -pubout -outform DER \
        -out "$WORK/derived_pub.der" 2>/dev/null || return 1
    # The last 32 bytes of the SPKI are the raw key.
    tail -c 32 "$WORK/derived_pub.der" | base64 | tr -d '\n'
}

# key_id_from_raw B64_RAW_PUBKEY - the first 8 bytes of sha256(public key), hex.
# Mirrors DeflectChallengeKeyID, so the expected ID comes from the pinned key
# rather than from anything the edge said about itself.
key_id_from_raw() {
    printf '%s' "$1" | base64 -d | openssl dgst -sha256 2>/dev/null \
        | awk '{print $NF}' | cut -c1-16
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

# header_value NAME - pull one header out of the last response, case
# insensitively, with the trailing CR stripped.
header_value() {
    grep -i "^$1:" "$WORK/headers" 2>/dev/null | tail -1 \
        | sed 's/^[^:]*:[[:space:]]*//' | tr -d '\r'
}

# challenge HOST CHALLENGE [KEY_ID] - POST to the edge, leaving the status in
# $C_STATUS, the proof headers in $C_SIG / $C_KEY_ID, the body in $WORK/body,
# and what the transport did in $C_REMOTE_IP / $C_HTTP_VERSION / $C_TLS_VERIFY.
challenge() {
    local host="$1" nonce="$2" key_id="${3:-}"
    local args=("${CURL_COMMON[@]}" -o "$WORK/body" -D "$WORK/headers"
                -w '%{http_code}\n%{remote_ip}\n%{http_version}\n%{ssl_verify_result}'
                -X POST -H "Host: $host")

    # Record what we send, so the transcript shows the real request rather than
    # a hand-written approximation of it.
    : > "$WORK/reqheaders"
    printf 'POST %s/_deflect/challenge HTTP/1.1\n' "$EDGE_URL" >> "$WORK/reqheaders"
    printf 'Host: %s\n' "$host" >> "$WORK/reqheaders"

    # An empty nonce means "send no challenge header at all".
    if [ -n "$nonce" ]; then
        args+=(-H "X-RePress-Challenge: $nonce")
        printf 'X-RePress-Challenge: %s\n' "$nonce" >> "$WORK/reqheaders"
    fi
    if [ -n "$key_id" ]; then
        args+=(-H "X-RePress-Challenge-Key-ID: $key_id")
        printf 'X-RePress-Challenge-Key-ID: %s\n' "$key_id" >> "$WORK/reqheaders"
    fi

    local out
    out=$(curl "${args[@]}" "$EDGE_URL/_deflect/challenge" 2>"$WORK/curlerr")
    C_STATUS=$(printf '%s\n' "$out" | sed -n 1p)
    C_REMOTE_IP=$(printf '%s\n' "$out" | sed -n 2p)
    C_HTTP_VERSION=$(printf '%s\n' "$out" | sed -n 3p)
    C_TLS_VERIFY=$(printf '%s\n' "$out" | sed -n 4p)
    C_SIG=$(header_value X-RePress-Challenge-Response)
    C_KEY_ID=$(header_value X-RePress-Challenge-Key-ID)
}

# transcript HOST NONCE - dump the exchange that just happened: what went out,
# what came back, the body, and the exact bytes the signature covers.
transcript() {
    local host="$1" nonce="$2"
    [ "$TRANSCRIPT" -eq 1 ] || return 0

    printf '\n%s>> request%s %s(no body; the nonce rides in a header)%s\n' \
        "$BOLD" "$RESET" "$DIM" "$RESET"
    sed 's/^/  /' "$WORK/reqheaders"

    printf '\n%s<< response head%s %s(from %s, HTTP/%s)%s\n' \
        "$BOLD" "$RESET" "$DIM" "${C_REMOTE_IP:-?}" "${C_HTTP_VERSION:-?}" "$RESET"
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

nonce() { openssl rand -hex 32; }

printf '%sdeflect challenge client (remote)%s\n' "$BOLD" "$RESET"
printf '  edge:        %s\n' "$EDGE_URL"
printf '  host header: %s\n' "$HOST_HEADER"
printf '  signed host: %s\n' "$SIGNED_HOST"
[ -n "$RESOLVE_IP" ] && printf '  pinned to:   %s:%s (DNS bypassed)\n' "$RESOLVE_IP" "$URL_PORT"

# ---------------------------------------------------------------------------
# Get the public key. Pinning one supplied out of band is the point; fetching
# it from the edge under test is a fallback, and proves nothing on its own.
# ---------------------------------------------------------------------------
printf '\n%sthe public key%s\n' "$BOLD" "$RESET"

KEY_SOURCE=""
BOOTSTRAPPED=0

if [ -n "$PUB_FILE" ]; then
    [ -r "$PUB_FILE" ] || die "cannot read $PUB_FILE"
    if jq -e . "$PUB_FILE" >/dev/null 2>&1; then
        # A banjax key file, or a saved /deflect_challenge/pubkey response.
        from_file=$(jq -r '.public_key // empty' "$PUB_FILE")
        if [ -n "$from_file" ]; then
            PUB_B64="$from_file"
            KEY_SOURCE="public_key in $PUB_FILE"
        else
            seed=$(jq -r '.seed // empty' "$PUB_FILE")
            [ -n "$seed" ] || die "$PUB_FILE has neither public_key nor seed"
            PUB_B64=$(pub_from_seed "$seed") || die "could not derive a public key from the seed"
            KEY_SOURCE="derived from the seed in $PUB_FILE"
        fi
        file_key_id=$(jq -r '.key_id // empty' "$PUB_FILE")
        [ -z "$PIN_KEY_ID" ] && PIN_KEY_ID="$file_key_id"
    else
        # A plain text file holding just the base64 key.
        PUB_B64=$(tr -d ' \t\n\r' < "$PUB_FILE")
        KEY_SOURCE="$PUB_FILE"
    fi
elif [ -n "$PUB_B64" ]; then
    KEY_SOURCE="--pubkey on the command line"
elif [ -n "$ADMIN_URL" ]; then
    printf '  %snote: fetched from the deployment under test, so this bootstrap is not itself a trust anchor%s\n' \
        "$YELLOW" "$RESET"
    curl "${CURL_COMMON[@]}" -H "Host: $ADMIN_HOST" \
        "${ADMIN_URL%/}/deflect_challenge/pubkey?domain=$SIGNED_HOST" \
        -o "$WORK/pubkey.json" 2>/dev/null \
        || die "could not reach the admin API at $ADMIN_URL"
    PUB_B64=$(jq -r '.public_key // empty' "$WORK/pubkey.json" 2>/dev/null)
    [ -n "$PUB_B64" ] || die "no public key for $SIGNED_HOST: $(head -c 200 "$WORK/pubkey.json")"
    KEY_SOURCE="$ADMIN_URL (Host: $ADMIN_HOST)"
    BOOTSTRAPPED=1
else
    printf '  %sno public key given%s\n' "$RED" "$RESET"
    printf '  %spass one of -p/--pubkey, -f/--pubkey-file, or --admin-url. On an edge box\n' "$DIM"
    printf '  the operator copy lives at <deflect_challenge_key_dir>/%s.json%s\n' \
        "$(printf '%s' "$SIGNED_HOST" | tr ':' '_')" "$RESET"
    exit 2
fi

der_from_raw "$PUB_B64" "$WORK/pub.der"
KEY_BYTES=$(printf '%s' "$PUB_B64" | base64 -d 2>/dev/null | wc -c | tr -d ' ')
[ "$KEY_BYTES" = "32" ] || die "the public key decodes to ${KEY_BYTES:-0} bytes, expected 32"

# The expected key ID comes from the key itself, not from what the edge says.
EXPECT_KEY_ID=$(key_id_from_raw "$PUB_B64")
printf '  source: %s\n' "$KEY_SOURCE"
printf '  key_id %s, public key %s\n' "$EXPECT_KEY_ID" "$PUB_B64"

if [ -n "$PIN_KEY_ID" ] && [ "$PIN_KEY_ID" != "$EXPECT_KEY_ID" ]; then
    die "the pinned key id $PIN_KEY_ID does not belong to this public key ($EXPECT_KEY_ID)"
fi

if [ "$BOOTSTRAPPED" -eq 1 ] && [ "$TRANSCRIPT" -eq 1 ]; then
    printf '\n%s<< %s/deflect_challenge/pubkey?domain=%s%s\n' \
        "$BOLD" "${ADMIN_URL%/}" "$SIGNED_HOST" "$RESET"
    jq . "$WORK/pubkey.json" 2>/dev/null | sed 's/^/  /' || sed 's/^/  /' "$WORK/pubkey.json"
fi

# ---------------------------------------------------------------------------
# One full exchange, shown end to end, then checked.
# ---------------------------------------------------------------------------
NONCE_A=$(nonce)
challenge "$HOST_HEADER" "$NONCE_A"
printf '%s' "$C_SIG" | base64 -d > "$WORK/sig_a.bin" 2>/dev/null

# Nothing came back at all: DNS, the route, TLS, or a firewall. Say so before
# dumping a transcript of an exchange that never happened.
if [ -z "$C_STATUS" ] || [ "$C_STATUS" = "000" ]; then
    printf '\n  %scould not reach %s: %s%s\n' \
        "$RED" "$EDGE_URL" "$(head -1 "$WORK/curlerr" | tr -d '\r')" "$RESET" >&2
    exit 2
fi

if [ "$TRANSCRIPT" -eq 1 ]; then
    printf '\n%sthe exchange%s\n' "$BOLD" "$RESET"
fi
transcript "$SIGNED_HOST" "$NONCE_A"

# ---------------------------------------------------------------------------
# The network path itself. Only interesting remotely, where there is one.
# ---------------------------------------------------------------------------
printf '\n%swhat answered?%s\n' "$BOLD" "$RESET"

if wanted "reached the edge"; then
    ok "reached the edge" "$C_REMOTE_IP, HTTP/${C_HTTP_VERSION}, status $C_STATUS"
fi

if wanted "tls certificate verified"; then
    if [ "$SCHEME" != "https" ]; then
        skip "tls certificate verified" "plain http target"
    elif [ "$INSECURE" -eq 1 ]; then
        skip "tls certificate verified" "--insecure was passed"
    else
        [ "$C_TLS_VERIFY" = "0" ]
        check "tls certificate verified" $? "openssl verify result ${C_TLS_VERIFY}"
    fi
fi

if wanted "response is not cacheable"; then
    # A signature is single use, so anything in the path that caches this
    # response would hand out a stale proof. Worth checking on a real path,
    # where there usually is something in the middle.
    cc=$(header_value Cache-Control)
    [[ "$(lower "$cc")" == *"no-store"* ]]
    check "response is not cacheable" $? "Cache-Control: ${cc:-<none>}"
fi

# ---------------------------------------------------------------------------
# Positive cases.
# ---------------------------------------------------------------------------
printf '\n%sis this edge really Deflect?%s\n' "$BOLD" "$RESET"

if wanted "signature verifies"; then
    if [ "$C_STATUS" = "404" ]; then
        bad "signature verifies" "404: is $SIGNED_HOST listed in deflect_challenge_sites?"
    elif [ "${C_STATUS:0:1}" = "3" ]; then
        bad "signature verifies" "redirect to $(header_value Location); try that URL directly"
    elif [ "$C_STATUS" != "200" ]; then
        bad "signature verifies" "expected HTTP 200, got ${C_STATUS:-no response}"
    elif [ ! -s "$WORK/sig_a.bin" ]; then
        bad "signature verifies" "no X-RePress-Challenge-Response header"
    else
        if verify "$WORK/pub.der" "$SIGNED_HOST" "$NONCE_A" "$WORK/sig_a.bin"; then
            ok  "signature verifies" "the responder holds $SIGNED_HOST's private key"
        else
            bad "signature verifies" "signed, but not by the key we pinned"
        fi
    fi
fi

if wanted "returned key id matches"; then
    # Against the ID derived from the pinned key, so this is a real check even
    # when the key was never fetched from the edge.
    [ -n "$C_KEY_ID" ] && [ "$C_KEY_ID" = "$EXPECT_KEY_ID" ]
    check "returned key id matches" $? "${C_KEY_ID:-<none>} vs pinned $EXPECT_KEY_ID"
fi

if wanted "signed domain is ours"; then
    # The edge reports the domain it signed for. If it differs from the host we
    # think we asked for, a vhost somewhere in the path rewrote it.
    body_domain=$(jq -r '.domain // empty' "$WORK/body" 2>/dev/null)
    [ "$body_domain" = "$SIGNED_HOST" ]
    check "signed domain is ours" $? "edge signed for ${body_domain:-<none>}, we verified $SIGNED_HOST"
fi

if wanted "body agrees with headers"; then
    body_sig=$(jq -r '.response // empty' "$WORK/body" 2>/dev/null)
    body_challenge=$(jq -r '.challenge // empty' "$WORK/body" 2>/dev/null)
    if [ "$body_sig" = "$C_SIG" ] && [ "$body_challenge" = "$NONCE_A" ]; then
        ok  "body agrees with headers" "the nonce came back unmangled"
    elif [ "$body_challenge" != "$NONCE_A" ]; then
        bad "body agrees with headers" "the nonce came back as ${body_challenge:-<none>}"
    else
        bad "body agrees with headers" "body signature and header signature differ"
    fi
fi

if wanted "advisory key id accepted"; then
    challenge "$HOST_HEADER" "$(nonce)" "$EXPECT_KEY_ID"
    [ "$C_STATUS" = "200" ] && [ "$C_KEY_ID" = "$EXPECT_KEY_ID" ]
    check "advisory key id accepted" $? \
        "asked for $EXPECT_KEY_ID, got status $C_STATUS and key id ${C_KEY_ID:-<none>}"
fi

# ---------------------------------------------------------------------------
# Negative cases. These are the ones that matter: a client that only ever runs
# the happy path cannot tell a working verifier from one that returns success
# unconditionally.
# ---------------------------------------------------------------------------
printf '\n%swould a forgery be caught?%s\n' "$BOLD" "$RESET"

if wanted "tampered signature rejected"; then
    if [ -s "$WORK/sig_a.bin" ]; then
        # Flip the low bit of the first byte of a genuine signature.
        first=$(od -An -N1 -tu1 < "$WORK/sig_a.bin" | tr -d ' \n')
        { printf "\\$(printf '%03o' $(( first ^ 1 )))"; tail -c +2 "$WORK/sig_a.bin"; } > "$WORK/sig_tampered.bin"
        verify "$WORK/pub.der" "$SIGNED_HOST" "$NONCE_A" "$WORK/sig_tampered.bin"
        [ $? -ne 0 ]
        check "tampered signature rejected" $? "one flipped bit invalidates it"
    else
        skip "tampered signature rejected" "no signature to tamper with"
    fi
fi

if wanted "wrong key rejected"; then
    if [ -s "$WORK/sig_a.bin" ]; then
        # A throwaway keypair standing in for a middlebox with its own key.
        openssl genpkey -algorithm ed25519 -out "$WORK/impostor.pem" 2>/dev/null
        openssl pkey -in "$WORK/impostor.pem" -pubout -outform DER -out "$WORK/impostor.der" 2>/dev/null
        verify "$WORK/impostor.der" "$SIGNED_HOST" "$NONCE_A" "$WORK/sig_a.bin"
        [ $? -ne 0 ]
        check "wrong key rejected" $? "a signature only verifies under its own key"
    else
        skip "wrong key rejected" "no signature to check"
    fi
fi

if wanted "nonce binding holds"; then
    if [ -s "$WORK/sig_a.bin" ]; then
        # A signature for nonce A must not verify as a signature for nonce B, or a
        # recorded response could be replayed forever.
        verify "$WORK/pub.der" "$SIGNED_HOST" "$(nonce)" "$WORK/sig_a.bin"
        [ $? -ne 0 ]
        check "nonce binding holds" $? "an old response cannot be replayed"
    else
        skip "nonce binding holds" "no signature to check"
    fi
fi

if wanted "domain binding holds"; then
    if [ -s "$WORK/sig_a.bin" ]; then
        # The host is inside the signed message, so a signature collected for one
        # domain must not verify as proof of another.
        verify "$WORK/pub.der" "evil.example" "$NONCE_A" "$WORK/sig_a.bin"
        [ $? -ne 0 ]
        check "domain binding holds" $? "cannot be re-presented as another domain"
    else
        skip "domain binding holds" "no signature to check"
    fi
fi

if wanted "signatures are not constant"; then
    NONCE_B=$(nonce)
    challenge "$HOST_HEADER" "$NONCE_B"
    [ -n "$C_SIG" ] && [ "$C_SIG" != "$(base64 < "$WORK/sig_a.bin" | tr -d '\n')" ]
    check "signatures are not constant" $? "a different nonce gives a different signature"
fi

if wanted "second signature verifies"; then
    # The second exchange, verified too. On a rotation this may well land on a
    # different node than the first, which is the interesting part: run with
    # --resolve to name the node instead of guessing.
    printf '%s' "$C_SIG" | base64 -d > "$WORK/sig_b.bin" 2>/dev/null
    verify "$WORK/pub.der" "$SIGNED_HOST" "$NONCE_B" "$WORK/sig_b.bin"
    check "second signature verifies" $? "answered by $C_REMOTE_IP"
fi

# ---------------------------------------------------------------------------
# Protocol handling.
# ---------------------------------------------------------------------------
printf '\n%sdoes the endpoint handle bad input?%s\n' "$BOLD" "$RESET"

if wanted "missing challenge is 400"; then
    challenge "$HOST_HEADER" ""
    [ "$C_STATUS" = "400" ]
    check "missing challenge is 400" $? "got ${C_STATUS:-no response}"
fi

if wanted "oversized challenge is 400"; then
    challenge "$HOST_HEADER" "$(head -c $(( MAX_LENGTH + 1 )) < /dev/zero | tr '\0' 'x')"
    [ "$C_STATUS" = "400" ]
    check "oversized challenge is 400" $? "got ${C_STATUS:-no response}, max_length $MAX_LENGTH"
fi

if wanted "GET is 405"; then
    status=$(curl "${CURL_COMMON[@]}" -o /dev/null -w '%{http_code}' \
        -H "Host: $HOST_HEADER" -H "X-RePress-Challenge: $(nonce)" \
        "$EDGE_URL/_deflect/challenge" 2>/dev/null)
    [ "$status" = "405" ]
    check "GET is 405" $? "got ${status:-no response}"
fi

if wanted "disabled host is 404"; then
    if [ -n "$DISABLED_HOST" ]; then
        challenge "$DISABLED_HOST" "$(nonce)"
        [ "$C_STATUS" = "404" ]
        check "disabled host is 404" $? "got ${C_STATUS:-no response} for $DISABLED_HOST"
    else
        skip "disabled host is 404" "pass --disabled-host a domain on this edge with the feature off"
    fi
fi

if wanted "no private key is exported"; then
    if [ "$BOOTSTRAPPED" -eq 1 ]; then
        # The admin vhost is reachable by anyone who can set a Host header, so the
        # pubkey endpoint must never leak private key material.
        ! grep -Eqi '"(seed|private|private_key|secret)"' "$WORK/pubkey.json"
        check "no private key is exported" $? "pubkey response is public halves only"
    else
        skip "no private key is exported" "no admin endpoint was queried"
    fi
fi

printf '\n%s%d passed, %d failed, %d skipped%s\n' "$BOLD" "$PASS" "$FAIL" "$SKIP" "$RESET"
if [ "$FAIL" -gt 0 ]; then
    printf '%sA failing "signature verifies" means the responder does not hold this\n' "$DIM"
    printf 'domain'"'"'s key: either the wrong public key was pinned, or something is\n'
    printf 'answering in place of the Deflect edge. Re-run with --resolve <ip> per\n'
    printf 'node to find which one.%s\n' "$RESET"
    exit 1
fi
