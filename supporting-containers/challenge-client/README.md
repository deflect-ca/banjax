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
docker compose run --rm challenge-client            # every case, with the transcript
docker compose run --rm challenge-client tamper     # only cases matching a substring
docker compose run --rm challenge-client -q         # results only, no transcript
```

By default it prints a full transcript of one exchange before running the cases:
the request headers it sent, the response head, the JSON body, the exact bytes
the signature covers (as an `od -c` dump, so the `\n` separators are visible),
and the signature itself. That is the whole protocol in one screen. `-q` /
`--quiet` (or `TRANSCRIPT=0`) drops it; `-v` / `--verbose` forces it back on. A
flag and a filter can be combined: `challenge-client -q binding`.

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
| `EDGE_HOST` | `localhost` | `Host` header, and the host inside the signed message (lowercased to match what the edge signs) |
| `TRANSCRIPT` | `1` | `0` suppresses the exchange dump, same as `-q` |
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

The key file is JSON, at `<deflect_challenge_key_dir>/<domain>.json`, mode 0600.
For a domain like `localhost:8081` the colon becomes an underscore in the
filename (`localhost_8081.json`).

```json
{
  "version": 1,
  "algorithm": "ed25519",
  "domain": "example.com",
  "seed": "<base64 of 32 random bytes>",
  "key_id": "3f9a1c0b7e2d4a55",
  "public_key": "<base64 of the 32 raw public bytes>",
  "created_at": "2026-08-14T00:00:00Z"
}
```

**Only `version`, `algorithm`, `domain` and `seed` are required.** The seed is
the source of truth: the private key is expanded from it and the public key and
key ID are derived, so `key_id`, `public_key` and `created_at` can be omitted. If
present they are verified, since a stale copy would mislead whoever reads the
file. That means a generator needs no Ed25519 implementation at all — 32 random
bytes is a complete key:

```python
import base64, json, os, pathlib

def provision(domain, key_dir="/etc/banjax/deflect_challenge_keys"):
    path = pathlib.Path(key_dir) / (domain.replace(":", "_") + ".json")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    # The seed is the whole key. banjax derives the rest on load.
    key = {
        "version": 1,
        "algorithm": "ed25519",
        "domain": domain,
        "seed": base64.b64encode(os.urandom(32)).decode(),
    }
    # Write-then-chmod would leave the key briefly world readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(key, f, indent=2)
```

`O_EXCL` is deliberate: it refuses to clobber an existing key rather than
silently invalidating a public key already handed out.

To read the public half back out for a client, ask banjax (`/deflect_challenge/pubkey`
above), or compute it from the seed with `cryptography`:

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

seed = base64.b64decode(json.loads(path.read_text())["seed"])
public = Ed25519PrivateKey.from_private_bytes(seed).public_key()
print(base64.b64encode(public.public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode())
```

A key file that is malformed, has the wrong `version` or `algorithm`, has a seed
that is not 32 bytes, or **names a different domain than its filename** is
refused and never overwritten. That last check is the one that catches a key file
copied or renamed onto a second domain, which would otherwise silently give two
domains one keypair.

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
