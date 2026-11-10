---
paths:
  - "internal/**/*.go"
  - "banjax.go"
  - "internal/**/*.html"
  - "supporting-containers/nginx/**"
---

# Security rules for request-path code

Full checklist and the report template: the `secure-change` skill.

- Trust boundary: `X-Client-IP`, `X-Requested-Host`, `X-Requested-Path`, `X-Client-User-Agent` are trusted only because nginx overwrites them. Cookies, UA, host, path and Kafka fields are attacker-controlled. No new route reachable from the public vhost besides `/auth_request` and the deflect challenge; admin routes are unauthenticated: banjax binds 127.0.0.1:8081, and they must never be proxied from a public site vhost (the dev nginx `banjax` vhost does so for local convenience only).
- Escape output: `html.EscapeString` for anything placed in a page (see `applyArgsToTooManyRequestsPage`); mind JS-string context in the challenge HTML; no raw request data in headers or unstructured log lines (banjax tails logs with regexes).
- Crypto: `crypto/rand`, `hmac.Equal`, domain-separated signed messages, tokens bound to IP or UA plus expiry, verify before using any decoded field. Do not copy `bytes.Equal` HMAC checks or `InsecureSkipVerify`.
- State the fail direction of every new path: a panic becomes 500 + `@fail_open`; password-protected locations fail closed.
- Never block a protected IP (`config.IsProtectedIP`) or a per-site allowlisted IP; route bans through the `Banner`.
- Bound every map keyed by attacker-chosen values (expiry or cap) and every input size.
- Zero-valued thresholds and intervals are dangerous: default them in `load()`.
- Parse IPs and subnets with `netip` before they reach iptables/ipset; never pass request data to exec or file paths.
