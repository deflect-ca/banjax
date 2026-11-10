---
paths:
  - "**/*_test.go"
  - "fixtures/**"
---

# Tests in banjax

A test earns its place by failing when the behavior regresses. Full method: the `writing-tests` skill.

Name one case per moving part that applies:
- config key: its dangerous zero value and the `load()` default
- order in `decisionForNginx2` against each neighbor that could also match
- threshold boundary: N requests pass, N+1 trips
- expiry/TTL edge, and no downgrade of a stronger decision by a weaker one
- exemptions: protected IPs, per-site allowlist, `sites_to_disable_baskerville`
- cookies: binding (IP or UA), expiry, tampered value
- Kafka input: malformed, out of range, IPv6 or too-broad subnet
- reload, `/unban` and `clear_rules` cleanup
- the exact `X-Banjax-Decision` string, and fail-open versus fail-closed

Break-it check: break the guarded line, see the test fail, restore. A test that cannot fail is deleted.

Helpers: `MockBanner` (regex_rate_limiter_test.go), `loadConfigString` (config_test.go, no `load()` defaults),
`buildDecisionForNginxTestContext` (http_server_expiring_order_test.go), `withProtectedIPs` (protected_ip_test.go);
root integration helpers in `banjax_base_test.go`.

Run: `scripts/dev test -run TestName -count=1`; integration: `scripts/dev itest -run TestName`.
