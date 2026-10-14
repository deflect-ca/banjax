// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/hpcloud/tail"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

const globalAllowlistRateLimitConfig = `
global_decision_lists:
  allow:
    - 1.2.3.4
    - 5.5.5.0/24
per_site_decision_lists:
  opted.com:
    allow:
      - 9.9.9.9
regexes_with_rates:
  - decision: iptables_block
    rule: 'two per interval'
    regex: 'GET .* GET /limited.*'
    interval: 60
    hits_per_interval: 1
  - decision: allow
    rule: 'unblock backdoor'
    regex: '.*allowme.*'
    interval: 1
    hits_per_interval: 0
sites_to_rate_limit_global_allowlist:
  opted.com: true
  opted2.com: true
expiring_decision_ttl_seconds: 300
`

func newGlobalAllowlistRateLimitConfig(t *testing.T) (*Config, *StaticDecisionLists) {
	config := &Config{}
	err := yaml.Unmarshal([]byte(globalAllowlistRateLimitConfig), config)
	assert.Nil(t, err)
	decisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	return config, decisionLists
}

func logLine(ip string, host string, path string) *tail.Line {
	lineTime := fmt.Sprintf("%f", float64(time.Now().UnixNano())/1e9)
	return &tail.Line{Text: lineTime + " " + ip + " GET " + host + " GET " + path + " HTTP/1.1 Googlebot/2.1 | 200"}
}

func TestParseDecision_TooManyRequests(t *testing.T) {
	decision, err := ParseDecision("too_many_requests")
	assert.Nil(t, err)
	assert.Equal(t, TooManyRequests, decision)
	assert.Equal(t, "TooManyRequests", decision.String())

	// severity sits between a challenge and a block
	assert.True(t, Challenge < TooManyRequests)
	assert.True(t, TooManyRequests < NginxBlock)
}

func TestConsumeLine_GlobalAllowlist(t *testing.T) {
	config, decisionLists := newGlobalAllowlistRateLimitConfig(t)

	t.Run("site not opted in keeps allowlisted ips exempt", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		for i := 0; i < 3; i++ {
			result := consumeLine(logLine("1.2.3.4", "other.com", "/limited"), states, &mockBanner, config, decisionLists)
			assert.True(t, result.Exempted)
		}
		assert.Equal(t, "", mockBanner.bannedIp)
		assert.Equal(t, "", mockBanner.tooManyRequestsIp)
	})

	t.Run("opted in site rate limits an exact allowlisted ip with a per-host 429", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		consumeLine(logLine("1.2.3.4", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		result := consumeLine(logLine("1.2.3.4", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)

		assert.False(t, result.Exempted)
		assert.True(t, result.GlobalAllowlistRateLimiting)
		assert.True(t, result.RuleResults[0].RateLimitResult.Exceeded)
		// the rule says iptables_block, but an allowlisted ip is never blocked
		assert.Equal(t, "", mockBanner.bannedIp)
		assert.Equal(t, "1.2.3.4", mockBanner.tooManyRequestsIp)
		assert.Equal(t, "opted.com", mockBanner.tooManyRequestsHost)
	})

	t.Run("opted in site rate limits an allowlisted CIDR ip", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		consumeLine(logLine("5.5.5.5", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		consumeLine(logLine("5.5.5.5", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)

		assert.Equal(t, "", mockBanner.bannedIp)
		assert.Equal(t, "5.5.5.5", mockBanner.tooManyRequestsIp)
	})

	t.Run("hits are counted per host", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		consumeLine(logLine("1.2.3.4", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		consumeLine(logLine("1.2.3.4", "opted2.com", "/limited"), states, &mockBanner, config, decisionLists)
		assert.Equal(t, "", mockBanner.tooManyRequestsIp)

		consumeLine(logLine("1.2.3.4", "opted2.com", "/limited"), states, &mockBanner, config, decisionLists)
		assert.Equal(t, "opted2.com", mockBanner.tooManyRequestsHost)
	})

	t.Run("per-site allow stays exempt on an opted in site", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		result := consumeLine(logLine("9.9.9.9", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		assert.True(t, result.Exempted)
	})

	t.Run("an allow rule is not turned into a 429", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		consumeLine(logLine("1.2.3.4", "opted.com", "/allowme"), states, &mockBanner, config, decisionLists)
		assert.Equal(t, "", mockBanner.tooManyRequestsIp)
	})

	t.Run("ips not in any allow list are unaffected", func(t *testing.T) {
		mockBanner := MockBanner{}
		states := NewRegexRateLimitStates()
		consumeLine(logLine("7.7.7.7", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		result := consumeLine(logLine("7.7.7.7", "opted.com", "/limited"), states, &mockBanner, config, decisionLists)
		assert.False(t, result.GlobalAllowlistRateLimiting)
		assert.Equal(t, "7.7.7.7", mockBanner.bannedIp)
		assert.Equal(t, "", mockBanner.tooManyRequestsIp)
	})
}

func TestDynamicDecisionLists_IpHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByIpHost(config, "1.2.3.4", "opted.com", time.Now().Add(time.Minute), TooManyRequests)

	decision, ok := decisionLists.CheckByIpHost("1.2.3.4", "opted.com")
	assert.True(t, ok)
	assert.Equal(t, TooManyRequests, decision.Decision)

	_, ok = decisionLists.CheckByIpHost("1.2.3.4", "opted2.com")
	assert.False(t, ok, "a per-host decision must not leak to other hosts")
	_, ok = decisionLists.Check("", "1.2.3.4")
	assert.False(t, ok, "a per-host decision must not land in the ip-wide list")

	entries := decisionLists.CheckByDomain("opted.com")
	assert.Equal(t, 1, len(entries))
	assert.Equal(t, "TooManyRequests", entries[0].Decision)
	assert.Equal(t, 1, decisionLists.MetricsTooManyRequests())

	decisionLists.RemoveByIp("1.2.3.4")
	_, ok = decisionLists.CheckByIpHost("1.2.3.4", "opted.com")
	assert.False(t, ok)

	decisionLists.UpdateByIpHost(config, "1.2.3.4", "opted.com", time.Now().Add(-time.Second), TooManyRequests)
	_, ok = decisionLists.CheckByIpHost("1.2.3.4", "opted.com")
	assert.False(t, ok, "expired decisions are ignored")
}

func TestDecisionForNginx2_GlobalAllowlistTooManyRequests(t *testing.T) {
	config, staticDecisionLists := newGlobalAllowlistRateLimitConfig(t)
	config.TooManyRequestsPageBytes = tooManyRequestsEmbed
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()
	banner := &MockBanner{}

	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByIpHost(config, "1.2.3.4", "opted.com", time.Now().Add(time.Minute), TooManyRequests)

	t.Run("rate limited host gets a 429 without a challenge", func(t *testing.T) {
		c := buildDecisionForNginxTestContext("1.2.3.4", "opted.com", "/", "Googlebot", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, GlobalAllowlistTooManyRequests, result.DecisionListResult)
		assert.Equal(t, 429, c.Writer.Status())
		assert.Nil(t, result.ShaChallengeResult)
		retryAfter, err := strconv.Atoi(c.Writer.Header().Get("Retry-After"))
		assert.Nil(t, err)
		assert.True(t, retryAfter > 0 && retryAfter <= 60)
		for _, setCookie := range c.Writer.Header().Values("Set-Cookie") {
			assert.NotContains(t, setCookie, ChallengeCookieName)
		}
	})

	t.Run("other opted in hosts are still granted", func(t *testing.T) {
		c := buildDecisionForNginxTestContext("1.2.3.4", "opted2.com", "/", "Googlebot", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)
		assert.Equal(t, GlobalAccessGranted, result.DecisionListResult)
	})

	t.Run("a site that opts out again is granted immediately", func(t *testing.T) {
		optedOut := *config
		optedOut.SitesToRateLimitGlobalAllowlist = map[string]bool{}
		c := buildDecisionForNginxTestContext("1.2.3.4", "opted.com", "/", "Googlebot", "")
		result := decisionForNginx2(c, &optedOut, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)
		assert.Equal(t, GlobalAccessGranted, result.DecisionListResult)
	})

	t.Run("an ip-wide too_many_requests decision gets a 429", func(t *testing.T) {
		ipDecisionLists := NewDynamicDecisionLists()
		ipDecisionLists.Update(config, "7.7.7.7", time.Now().Add(time.Minute), TooManyRequests, false, "opted.com")
		c := buildDecisionForNginxTestContext("7.7.7.7", "any.com", "/", "some-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, ipDecisionLists, passwordProtectedPaths, failedChallengeStates, banner)
		assert.Equal(t, ExpiringTooManyRequests, result.DecisionListResult)
		assert.Equal(t, 429, c.Writer.Status())
	})
}

func TestUnban_ByIp_ClearsPerHostTooManyRequests(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByIpHost(config, "1.2.3.4", "opted.com", time.Now().Add(time.Minute), TooManyRequests)
	r := newUnbanTestRouter(decisionLists)

	code, body := postUnban(t, r, url.Values{"ip": {"1.2.3.4"}})

	assert.Equal(t, 200, code)
	assert.Equal(t, true, body["found_in_decision_list"])
	assert.Equal(t, "TooManyRequests", body["decision"])
	assert.Equal(t, true, body["unban"])

	_, ok := decisionLists.CheckByIpHost("1.2.3.4", "opted.com")
	assert.False(t, ok)
}

func TestApplyArgsToTooManyRequestsPage(t *testing.T) {
	config := &Config{TooManyRequestsPageBytes: tooManyRequestsEmbed}

	page := string(applyArgsToTooManyRequestsPage(config, "example.com"))
	assert.NotContains(t, page, "{{host}}")
	assert.Contains(t, page, `<span class="website-title">example.com</span>`)
	assert.Contains(t, page, `<span class="website-title-footer">example.com</span> is protected by`)
	assert.NotContains(t, page, "<script")

	page = string(applyArgsToTooManyRequestsPage(config, `<img src=x onerror=alert(1)>`))
	assert.NotContains(t, page, "<img src=x")
	assert.Contains(t, page, "&lt;img src=x onerror=alert(1)&gt;")
}
