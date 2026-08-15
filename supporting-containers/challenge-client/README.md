# challenge-client

A test client for the **Deflect Challenge**: a virtual endpoint on the edge that
lets a client cryptographically verify it is really connected to Deflect, and not
to a middlebox impersonating it.

## The protocol

1. The client `POST`s to `/_deflect/challenge`, setting `X-Deflect-Challenge` to a
   random string, and optionally `X-Deflect-Challenge-Key-ID` to the ID of the
   keypair it expects.
2. The edge responds `200 OK` with `X-Deflect-Challenge-Response` set to an
   Ed25519 signature, and `X-Deflect-Challenge-Key-ID` set to the ID of the key it
   actually signed with.
3. The client verifies the signature with the domain's public key. If it
   verifies, the responder holds that domain's private key. If it does not, the
   edge may be compromised by a malicious middle box.

The signed message is **domain-bound**, with no trailing newline:

```
deflect-challenge-v1 LF <host> LF <challenge>
```

The version label means a future construction can never be confused with this
one, and the host means a signature collected for one domain cannot be
re-presented as proof of another by an edge holding both keys. This must match
`DeflectChallengeMessage` in [internal/deflect_challenge.go](../../internal/deflect_challenge.go)
byte for byte.

The request's `X-Deflect-Challenge-Key-ID` is advisory. The edge always signs
with its current key and returns that key's real ID; deciding whether the
returned ID is trusted is the client's job. That is what will make key rotation
possible without a protocol change.

## Running it

With the stack up:

```sh
docker compose up --build -d
docker compose run --rm challenge-client            # every case
docker compose run --rm challenge-client tamper     # only cases matching a substring
```

Or from the host against the published port:

```sh
EDGE_URL=http://localhost ADMIN_URL=http://localhost \
    supporting-containers/challenge-client/deflect-challenge.sh
```

Needs `bash`, `curl`, `jq`, and OpenSSL 3.x. Exits non-zero if any case fails: 1
if a check failed, 2 if the run could not start (edge unreachable, no public key
for the domain).

| Env | Default in the image | Meaning |
|---|---|---|
| `EDGE_URL` | `http://nginx` | Base URL of the edge under test |
| `EDGE_HOST` | `localhost` | `Host` header, and the host inside the signed message |
| `ADMIN_URL` | `http://nginx` | Where to fetch the public key |
| `ADMIN_HOST` | `banjax` | `Host` for the admin vhost |
| `MAX_LENGTH` | `512` | Must match `deflect_challenge_max_length` |

## What it checks

Positive: the signature verifies, the returned key ID is the expected one, the
JSON body agrees with the headers and echoes the nonce back unmangled, and
supplying a matching key ID still signs.

Negative, which is the part that makes the tool worth anything, since a client
that only runs the happy path cannot tell a working verifier from one that
returns success unconditionally:

- a signature with one flipped bit is rejected
- a signature does not verify under a different (impostor) key
- a signature for nonce A does not verify for nonce B, so responses cannot be replayed
- a signature does not verify against a different host, so it cannot be re-presented as another domain
- two different nonces produce two different signatures

Protocol handling: a host without the feature on gets 404, a missing or
oversized challenge gets 400, `GET` gets 405, and the public key endpoint
exports no private key material.

## Getting the public key

For convenience the client bootstraps by fetching the key from the edge's admin
vhost:

```sh
curl -s -H 'Host: banjax' 'http://localhost/deflect_challenge/pubkey?domain=localhost'
curl -s -H 'Host: banjax' 'http://localhost/deflect_challenge/keys'
```

**Fetching the public key from the edge you are about to test proves nothing on
its own.** It is a POC convenience. A real client is handed the public key out of
band and pins it. On the dev stack the keys are also readable directly at
`keys/deflect-challenge/<domain>.json` (gitignored), which is the realistic
operator handoff: `jq -r .public_key` one of those and give it to the client.

## Verifying Ed25519 with openssl

The edge serves the **raw 32-byte** public key, but openssl wants a
SubjectPublicKeyInfo. For Ed25519 that wrapper is a fixed 12-byte prefix, so the
script prepends it and skips PEM entirely:

```sh
{ printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'
  printf '%s' "$PUB_B64" | base64 -d
} > pub.der

printf 'deflect-challenge-v1\n%s\n%s' "$HOST" "$CHALLENGE" > msg.bin
printf '%s' "$SIG_B64" | base64 -d > sig.bin

openssl pkeyutl -verify -pubin -inkey pub.der -keyform DER \
                -rawin -in msg.bin -sigfile sig.bin
```

`-rawin` is required: Ed25519 signs the whole message itself and cannot be driven
through `-digest`. The `printf '\xHH'` needs bash's builtin, not busybox's.

## Turning the feature on for a domain

Add it to `deflect_challenge_sites` in `banjax-config.yaml` and reload. banjax
mints the keypair the first time it sees a domain listed there:

```sh
docker exec banjax-next-banjax-1 sh -c 'kill -HUP $(pgrep -x banjax)'
docker compose logs banjax | grep DEFLECT-CHALLENGE
```

Signal the `banjax` process, not the container. On the dev stack PID 1 is `air`,
so `docker compose kill -s HUP banjax` stops the container instead of reloading
the config. In production, where banjax itself is PID 1, `kill -HUP 1` is fine.

Key files land in `deflect_challenge_key_dir` at mode 0600. An existing file
always wins over generating a new one, so a reload never invalidates a public key
that has already been handed out.

### Where keys come from in production

banjax minting its own keys is a dev convenience, gated on
`deflect_challenge_generate_missing_keys`, which is **off by default**. In
production a provisioning script writes the key files and banjax only ever loads
them. A domain enabled with no key file then logs an error and 404s, rather than
banjax inventing a key whose public half nobody holds: that key would fail every
client's verification, which looks exactly like the compromised edge this feature
is meant to detect.

The private key stays out of `banjax-config.yaml` deliberately. The config holds
a *path*, the way `kafka_ssl_key` already does, because the config is generated
centrally, shipped to every edge, and dumped verbatim to the log when `debug` is
on.

## What this does and does not prove

It proves **key possession**: something holding this domain's private key saw
this nonce. It does **not** prove channel binding. An active attacker can relay,
forwarding the nonce to the real edge and returning the genuine signature, and
this check still passes while every subsequent byte flows through the attacker.

Closing that requires folding something unique to the client's own TLS
connection into the signed message (the server certificate's SPKI hash, or an
RFC 5705 exporter). The `deflect-challenge-v1` label exists so a v2 can add it
unambiguously. Do not deploy this as an anti-MITM control until then.
