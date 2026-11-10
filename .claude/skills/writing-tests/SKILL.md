---
name: writing-tests
description: How to write tests for banjax that catch regressions instead of raising coverage. Use before writing, extending or reviewing any Go test in internal/ or the root integration tests, when adding a feature or config key that needs tests, or when deciding between a unit test, an integration test and an e2e tool.
---

# Writing tests for banjax

A test earns its place by failing when the feature's behavior regresses. Coverage is a side effect.

## Method

1. Before writing anything, list the feature's moving parts. Go through this list and keep each item that applies:
   - config key: its zero value (is zero dangerous?) and the default `load()` sets
   - order in `decisionForNginx2` against each neighbor that could also match the same request
   - threshold boundary: exactly N passes, N+1 trips (and the interval window)
   - expiry/TTL: just before and just after expiry
   - no downgrade: a weaker decision does not replace a stronger one (see `supersededBy` in decision.go)
   - exemptions: protected IPs (`withProtectedIPs`), the per-site allowlist, `sites_to_disable_baskerville` for Baskerville-originated decisions
   - cookies: bound to IP (or UA when configured), expired, tampered or truncated value, cookie from another host
   - Kafka input: malformed JSON fields, missing host, out-of-range numbers (clamped?), IPv6 or broader-than-/16 subnet
   - lifecycle: config reload, `POST /unban`, Kafka `clear_rules` remove what the feature added
   - output: the exact `X-Banjax-Decision` string, status code and `X-Accel-Redirect`
   - failure direction: what happens on error or panic (fail open versus fail closed)
2. Write one named case per kept item. The case name is the behavior in a sentence ("protected ip is never counted").
3. Break-it check, for every test: temporarily break the line it guards (flip the comparison, drop the exemption, change N to N+1, swap two checks in the order), run `scripts/dev test -run TestName -count=1`, confirm it fails for the right reason, restore. A test you cannot make fail is deleted or rewritten. Say in your report which lines you broke.

## What not to write

- Tests of getters, constructors or struct literals.
- Assertions on log text or on how many times an internal function was called; assert the decision, status, header, list contents.
- `time.Sleep` where the code takes a time or expiry argument; pass `time.Now().Add(...)` instead. Sleep only in integration tests that need a real clock.
- An expected value computed by copying the implementation; write the literal you expect.
- Giant golden strings (whole HTML pages); assert the few markers that matter.
- Tests that need the real Kafka, real iptables or the network.

## Which level

| Level | Use for | How |
| --- | --- | --- |
| unit, `internal/*_test.go` | decisions, order, thresholds, cookies, Kafka command handling, config parsing | call `decisionForNginx2` with `buildDecisionForNginxTestContext` and `MockBanner`; `handleCommand(config, commandMessage{...}, decisionLists)` |
| integration, root `banjax_*_test.go` (`//go:build integration`) | real HTTP through gin, config reload via fixtures, cookies across requests | `httpTester`, `httpTesterWithCookie`, `reloadConfig("fixtures/x.yaml", n, t)`; run `scripts/dev itest` |
| e2e tool, `supporting-containers/` | browser behavior, JS challenges, nginx config | see the `e2e-tester` skill |

## Helper catalog (verify the signature before use)

- `internal/regex_rate_limiter_test.go`: `MockBanner` (records `bannedIp`, `bannedDecision`, `tooManyRequestsIp/Host`)
- `internal/config_test.go`: `loadConfigString(yaml)`; it only unmarshals, it does not apply `load()` defaults, so set thresholds explicitly
- `internal/http_server_expiring_order_test.go`: `buildDecisionForNginxTestContext(ip, host, path, ua, sessionId)`, `listDecisionRecordingBanner`
- `internal/protected_ip_test.go`: `withProtectedIPs(t, config, entries...)`, `ipsetRecordingBanner`
- `internal/two_step_ban_test.go`: `newStandaloneBanner(decisionLists)` (the production Banner; bans really land in the lists)
- `internal/http_server_unban_test.go`: `newUnbanTestRouter(decisionLists)`, `postUnban(t, r, form)`
- `internal/altcha_challenge_test.go`: `altchaTestConfig()`, `solveAltCha`, `solveAltChaToCookie`, `altchaChallengeFromPage`
- `internal/kafka_test.go`: `assertDecisionListsEmpty(t, decisionLists)`
- `internal/decision_test.go`: `mustParseSubnet(t, s)`
- `internal/deflect_challenge_test.go`: `newDeflectChallengeTestServer`, `doDeflectChallenge`, `newTestDeflectChallengeKeys`
- `banjax_base_test.go`: `httpTester`, `httpTesterWithCookie`, `reloadConfig`, `ClientIP(ip)`, `ClientUserAgent(ua)`, `ClientIPAndUserAgent`, `randomXClientIP()`

## Worked example (shape of `internal/two_step_ban_test.go`)

```go
func TestTooMany403s(t *testing.T) {
	newConfig := func(enabled bool) *Config {
		return &Config{TooMany403BanToIptablesBan: enabled, TooMany403BanIntervalSeconds: 60, TooMany403BanThreshold: 3}
	}

	t.Run("bans with iptables once over the threshold", func(t *testing.T) {
		config := newConfig(true)
		lists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		states, banner := NewFailedChallengeRateLimitStates(), &MockBanner{}

		for i := 0; i < 3; i++ { // exactly the threshold: no ban
			assert.False(t, tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, lists).Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)

		// threshold + 1: banned, and with the right decision
		assert.True(t, tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, lists).Exceeded)
		assert.Equal(t, IptablesBlock, banner.bannedDecision)
	})

	t.Run("off never counts", ...)                       // the off-switch
	t.Run("protected ip is never counted", ...)          // exemption 1
	t.Run("ip allowlisted on the host is never counted", ...) // exemption 2, and still counted on another host
}
```

Each case maps to one moving part: boundary, off-switch, two exemptions. Breaking the `>` into `>=`, the
`IsProtectedIP` check, or the per-site allowlist lookup each fails exactly one case. For precedence, copy
`TestDecisionForNginx2_ExpiringDecisionOrder`: put a decision in every list, assert the narrowest wins, then
remove the winner and assert the next one wins.
