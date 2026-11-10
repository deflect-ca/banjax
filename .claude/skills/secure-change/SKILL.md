---
name: secure-change
description: Security design checklist for banjax changes, applied while designing rather than after. Use before changing anything on the request path (decisionForNginx2, challenge pages, cookies, HMAC/signatures), Kafka command handling, ban/iptables code, admin routes, config defaults, nginx.conf, or adding a dependency; and to fill in the security notes of the final report.
---

# Secure change checklist

banjax is a security control: a bug here either lets attackers through or blocks real users at scale.
Go through each section while designing; write down the answer for each that applies.

## 1. Trust boundaries

- Trusted only because nginx overwrites them on every request: `X-Client-IP`, `X-Requested-Host`, `X-Requested-Path`, `X-Client-User-Agent`. That holds only for requests that came through nginx's `proxy_set_header` locations.
- Attacker-controlled: cookie values, the UA string, host and path contents, query strings, request bodies, anything decoded from a cookie or a challenge solution, and every field of a Kafka message (treat Kafka as authenticated but still validate: a bad command must not crash or over-ban).
- Do not add a route that the public vhost can reach except `/auth_request` (via the nginx locations) and the deflect challenge. Admin routes (`/info`, `/decision_lists`, `/unban`, `/ipset/list`, ...) are unauthenticated; banjax binds 127.0.0.1:8081 and they must never be proxied from a public site vhost (the dev `banjax` vhost in nginx.conf exists for local convenience only).

## 2. Output encoding

- Anything placed in a page goes through `html.EscapeString` (pattern: `applyArgsToTooManyRequestsPage`).
- Values inserted into the challenge HTML templates may land in a JS context (string literals, attributes): encode for that context (JSON-encode, then HTML-escape for attributes, as `altcha_challenge.go` does for the challenge attribute), never splice raw.
- Header values: no CR/LF from request data; prefer fixed strings.
- Logs: banjax tails the nginx log with regexes and downstream tools parse banjax logs. Write request data as JSON-encoded fields, never raw into a line where it could forge another entry or match a ban regex.

## 3. Crypto

- Randomness: `crypto/rand` only.
- Comparisons of MACs, signatures, solutions: `hmac.Equal` or `subtle.ConstantTimeCompare`.
- Signed messages are domain-separated (pattern: `deflect-challenge-v1\n<host>\n<challenge>` in deflect_challenge.go) so a signature for one purpose never verifies for another.
- Tokens and cookies are bound to the client (IP, or UA where `use_user_agent_in_cookie` says so) and carry an expiry covered by the MAC.
- Verify the MAC or signature before using any decoded field (length, expiry, binding).
- Known debt, do not copy: `bytes.Equal` HMAC checks in `challenge_response.go` and `session_cookie.go`, `math/rand` session ids in `session_cookie.go`, `InsecureSkipVerify: true` in `kafka.go`.

## 4. Fail direction and defaults

- State it per new path: on error, does the request get through or not? A panic becomes 500 + `X-Accel-Redirect: @fail_open`; nginx fails open on `/` and closed on password-protected locations. A DDoS filter may fail open; an access control (passwords) must fail closed.
- A zero value from a missing yaml key must be safe. Thresholds and intervals default in `load()` (a zero threshold bans on the first request); clamp ranges (pattern: `ClampAltChaMaxNumber`).

## 5. Who can be blocked

- Never block a protected IP (`config.IsProtectedIP`) or an IP allowlisted for that site (`CheckIsPerSiteAllowed`) through any new path; test both.
- Route bans through the `Banner` / `BannerInterface`, never call iptables/ipset directly, so protected-IP handling and logging stay in one place.
- Kafka subnet commands accept IPv4 only and nothing broader than /16 (`ParseSubnet`); keep any new scope at least that narrow.

## 6. Resource bounds

- Every map keyed by attacker-chosen values (IP, session id, UA, host) needs expiry or a size cap; say which.
- Bound input sizes (cookie length, header length, Kafka value length) before parsing or storing.

## 7. Untrusted data into system calls

- Parse IPs and subnets with `net/netip` and use the parsed value; never pass request or Kafka strings to exec, file paths, or iptables/ipset arguments.

## 8. Concurrency

- Decision lists are accessed only through their methods (mutex in `DynamicDecisionLists`, atomic snapshot in `StaticDecisionLists`). New shared state gets the same treatment; run `scripts/dev race` (about 5 minutes) when you touch it.

## 9. Third-party code

- JS in challenge pages is pinned to one version with an SRI hash (pattern: the ALTCHA widget from jsDelivr).
- Go and tool dependencies are pinned; run `scripts/dev vuln` after adding or bumping one.

## 10. Secrets hygiene

- Never log secrets, cookies, HMACs or full Kafka payloads with credentials.
- Real values live only in `.env` and `keys/`; config in the repo uses obvious placeholders (`hmac_secret: secret`). Test values are obviously fake.
- The pre-commit and pre-push hooks run `scripts/secret-scan.sh` (forbidden paths, key/token patterns, generic `secret: value` assignments, values from your local `.env`). They are a backstop, not permission to be careless; one remote is public.

## Security notes for the final report

```
Security notes
- Inputs trusted / untrusted: <which inputs the change reads, and why each is or is not trusted>
- Fail direction: <what happens on error or panic, and why that is right here>
- Abuse case considered: <how an attacker would use or overload this, and what stops them>
- Exemptions: <protected and allowlisted IPs unaffected: how verified>
- Bounds: <state growth and input size limits>
- Tests that lock it: <test names, and which line each was shown to catch>
```
