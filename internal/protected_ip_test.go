// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gonetx/ipset"
	"github.com/stretchr/testify/assert"
)

// ipsetRecordingBanner is a MockBanner that records ipset calls.
type ipsetRecordingBanner struct {
	MockBanner
	added       []string
	deleted     []string
	listEntries []string
}

func (b *ipsetRecordingBanner) IPSetAdd(config *Config, ip string) error {
	b.added = append(b.added, ip)
	return nil
}

func (b *ipsetRecordingBanner) IPSetList() (*ipset.Info, error) {
	return &ipset.Info{Entries: b.listEntries}, nil
}

func (b *ipsetRecordingBanner) IPSetDel(ip string) error {
	b.deleted = append(b.deleted, ip)
	return nil
}

// withProtectedIPs parses entries into config as load() does.
func withProtectedIPs(t *testing.T, config *Config, entries ...string) *Config {
	t.Helper()
	parsed, err := parseProtectedIPs(entries)
	assert.Nil(t, err)
	config.ProtectedIPs = entries
	config.protectedIPs = parsed
	return config
}

func TestIsProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{}, "10.0.0.1", " 192.168.100.0/24 ", "2001:db8::1", "2001:db8:1::/48")

	for ip, want := range map[string]bool{
		"10.0.0.1":         true,
		"10.0.0.2":         false,
		"192.168.100.0":    true,
		"192.168.100.255":  true,
		"192.168.101.1":    false,
		"::ffff:10.0.0.1":  true, // ipv4-mapped
		"2001:db8::1":      true,
		"2001:db8::2":      false,
		"2001:db8:1::abcd": true,
		"":                 false,
		"not-an-ip":        false,
	} {
		assert.Equal(t, want, config.IsProtectedIP(ip), ip)
	}

	assert.False(t, (&Config{}).IsProtectedIP("10.0.0.1"), "nothing is protected without protected_ips")
}

func TestParseProtectedIPsRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{"10.0.0.256", "10.0.0.0/33", "example.com", ""} {
		_, err := parseProtectedIPs([]string{entry})
		assert.NotNil(t, err, entry)
	}
}

func TestLoadParsesProtectedIPs(t *testing.T) {
	const base = "server_log_file: x.log\niptables_ban_seconds: 10\nkafka_brokers: [localhost:9092]\n"
	dir := t.TempDir()

	path := filepath.Join(dir, "ok.yaml")
	assert.Nil(t, os.WriteFile(path, []byte(base+"protected_ips: [10.0.0.1, 192.168.0.0/16]\n"), 0644))
	config, err := load(path, 0, false, false)
	assert.Nil(t, err)
	assert.True(t, config.IsProtectedIP("10.0.0.1"))
	assert.True(t, config.IsProtectedIP("192.168.3.4"))
	assert.False(t, config.IsProtectedIP("10.0.0.2"))

	path = filepath.Join(dir, "bad.yaml")
	assert.Nil(t, os.WriteFile(path, []byte(base+"protected_ips: [10.0.0.300]\n"), 0644))
	_, err = load(path, 0, false, false)
	assert.NotNil(t, err)
}

func TestBanIpSkipsProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{IptablesBanSeconds: 10}, "10.0.0.1")
	banner := &ipsetRecordingBanner{}

	banIp(config, "10.0.0.1", banner)
	banIp(config, "10.0.0.2", banner)

	assert.Equal(t, []string{"10.0.0.2"}, banner.added)
}

func TestUnbanProtectedIPs(t *testing.T) {
	config := withProtectedIPs(t, &Config{}, "10.0.0.1", "192.168.100.0/24")
	banner := &ipsetRecordingBanner{listEntries: []string{
		"10.0.0.1 timeout 298",
		"10.0.0.2 timeout 100",
		"192.168.100.7 timeout 5",
	}}

	UnbanProtectedIPs(config, banner)

	assert.Equal(t, []string{"10.0.0.1", "192.168.100.7"}, banner.deleted)
}

func TestDynamicDecisionListsRefuseBlockForProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{}, "10.0.0.1")
	expires := time.Now().Add(time.Minute)

	for _, decision := range []Decision{NginxBlock, IptablesBlock} {
		lists := NewDynamicDecisionLists()
		lists.Update(config, "10.0.0.1", expires, decision, true, "example.com", AltChaOptions{})
		lists.UpdateBySessionId(config, "10.0.0.1", "session-a", expires, decision, true, "example.com", AltChaOptions{})

		_, ok := lists.Check("", "10.0.0.1")
		assert.False(t, ok, "ip %s", decision)
		_, ok = lists.Check("session-a", "")
		assert.False(t, ok, "session %s", decision)
	}

	// a block is refused, but a challenge is still stored
	lists := NewDynamicDecisionLists()
	lists.Update(config, "10.0.0.1", expires, Challenge, true, "example.com", AltChaOptions{})
	decision, ok := lists.Check("", "10.0.0.1")
	assert.True(t, ok)
	assert.Equal(t, Challenge, decision.Decision)

	// other ips are blocked as before
	lists.Update(config, "10.0.0.2", expires, NginxBlock, true, "example.com", AltChaOptions{})
	decision, ok = lists.Check("", "10.0.0.2")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision.Decision)
}

func TestKafkaBlockCommandsSkipProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{ExpiringDecisionTtlSeconds: 60, BlockIPTtlSeconds: 60, BlockSessionTtlSeconds: 60}, "10.0.0.1")

	lists := NewDynamicDecisionLists()
	handleCommand(config, commandMessage{Name: "block_ip", Value: "10.0.0.1", Host: "example.com"}, lists)
	_, ok := lists.Check("", "10.0.0.1")
	assert.False(t, ok)

	handleCommand(config, commandMessage{Name: "block_session", Value: "10.0.0.1", SessionId: "session-a", Host: "example.com"}, lists)
	_, ok = lists.Check("session-a", "")
	assert.False(t, ok)

	// a challenge after a refused block still applies
	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "10.0.0.1", Host: "example.com"}, lists)
	decision, ok := lists.Check("", "10.0.0.1")
	assert.True(t, ok)
	assert.Equal(t, Challenge, decision.Decision)
}

func TestTooManyFailedChallengesNeverBansProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{}, "10.0.0.1")
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	states := NewFailedChallengeRateLimitStates()

	banner := &MockBanner{}
	for i := 0; i < 5; i++ {
		result := tooManyFailedChallenges(config, "10.0.0.1", "ua", "example.com", "/", banner, "sha_inv", states, 60, 0, "GET", staticDecisionLists)
		assert.False(t, result.Exceeded)
	}
	assert.Equal(t, "", banner.bannedIp)

	result := tooManyFailedChallenges(config, "10.0.0.2", "ua", "example.com", "/", banner, "sha_inv", states, 60, 0, "GET", staticDecisionLists)
	assert.True(t, result.Exceeded)
	assert.Equal(t, "10.0.0.2", banner.bannedIp)
	assert.Equal(t, IptablesBlock, banner.bannedDecision)
}

func TestDecisionForNginx2SkipsBlocksForProtectedIP(t *testing.T) {
	const protectedIp = "10.0.0.1"
	const otherIp = "10.0.0.2"
	const host = "example.com"
	const blockedUA = "BadBot"
	expires := time.Now().Add(time.Minute)

	run := func(t *testing.T, config *Config, lists *DynamicDecisionLists, ip string, ua string, sessionId string) DecisionListResult {
		t.Helper()
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
		assert.Nil(t, err)
		c := buildDecisionForNginxTestContext(ip, host, "/", ua, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, lists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
		return result.DecisionListResult
	}

	staticConfig := func() *Config {
		config := loadConfigString(`
global_decision_lists:
  nginx_block: [10.0.0.1, 10.0.0.2]
per_site_decision_lists:
  example.com:
    iptables_block: [10.0.0.1, 10.0.0.2]
global_user_agent_decision_lists:
  nginx_block: [BadBot]
per_site_user_agent_decision_lists:
  example.com:
    nginx_block: [BadBot]
`)
		return withProtectedIPs(t, config, protectedIp)
	}

	t.Run("static ip and ua lists", func(t *testing.T) {
		config := staticConfig()
		assert.Equal(t, PerSiteBlock, run(t, config, NewDynamicDecisionLists(), otherIp, blockedUA, ""))
		assert.Equal(t, ProtectedIPException, run(t, config, NewDynamicDecisionLists(), protectedIp, blockedUA, ""))
	})

	t.Run("a skipped block falls through to the next check", func(t *testing.T) {
		config := loadConfigString(`
global_decision_lists:
  nginx_block: [10.0.0.1]
global_user_agent_decision_lists:
  challenge: [BadBot]
`)
		config = withProtectedIPs(t, config, protectedIp)
		assert.Equal(t, GlobalUAChallenge, run(t, config, NewDynamicDecisionLists(), protectedIp, blockedUA, ""))
	})

	t.Run("expiring ua block", func(t *testing.T) {
		config := withProtectedIPs(t, &Config{}, protectedIp)
		lists := NewDynamicDecisionLists()
		lists.UpdateByUA(config, blockedUA, expires, NginxBlock, true, host, AltChaOptions{})
		assert.Equal(t, ExpiringUABlock, run(t, config, lists, otherIp, blockedUA, ""))
		assert.Equal(t, ProtectedIPException, run(t, config, lists, protectedIp, blockedUA, ""))
	})

	t.Run("expiring session block from another ip", func(t *testing.T) {
		config := withProtectedIPs(t, &Config{}, protectedIp)
		lists := NewDynamicDecisionLists()
		lists.UpdateBySessionId(config, otherIp, "session-a", expires, NginxBlock, true, host, AltChaOptions{})
		assert.Equal(t, ExpiringBlock, run(t, config, lists, otherIp, "ua", "session-a"))
		assert.Equal(t, ProtectedIPException, run(t, config, lists, protectedIp, "ua", "session-a"))
	})

	t.Run("expiring subnet block", func(t *testing.T) {
		config := withProtectedIPs(t, &Config{}, protectedIp)
		lists := NewDynamicDecisionLists()
		subnet, err := ParseSubnet("10.0.0.0/24")
		assert.Nil(t, err)
		lists.UpdateBySubnet(config, subnet, expires, NginxBlock, true, host, AltChaOptions{})
		assert.Equal(t, ExpiringSubnetBlock, run(t, config, lists, otherIp, "ua", ""))
		assert.Equal(t, ProtectedIPException, run(t, config, lists, protectedIp, "ua", ""))

		// the subnet block does not hide the protected ip's own challenge
		lists.Update(config, protectedIp, expires, Challenge, true, host, AltChaOptions{})
		assert.Equal(t, ExpiringChallenge, run(t, config, lists, protectedIp, "ua", ""))
	})
}

func TestDynamicDecisionListsRefuseRateLimitForProtectedIP(t *testing.T) {
	config := withProtectedIPs(t, &Config{}, "10.0.0.1")
	expires := time.Now().Add(time.Minute)
	lists := NewDynamicDecisionLists()

	lists.Update(config, "10.0.0.1", expires, TooManyRequests, false, "example.com", AltChaOptions{})
	_, ok := lists.Check("", "10.0.0.1")
	assert.False(t, ok)

	lists.UpdateByIpHost(config, "10.0.0.1", "example.com", expires, TooManyRequests)
	_, ok = lists.CheckByIpHost("10.0.0.1", "example.com")
	assert.False(t, ok)

	lists.UpdateByIpHost(config, "10.0.0.2", "example.com", expires, TooManyRequests)
	_, ok = lists.CheckByIpHost("10.0.0.2", "example.com")
	assert.True(t, ok)
}

func TestRegexRulesNeverBlockOrRateLimitProtectedIP(t *testing.T) {
	config := loadConfigString(`
regexes_with_rates:
  - decision: too_many_requests
    rule: 'slow down'
    regex: 'GET .* GET /slow.*'
    interval: 60
    hits_per_interval: 0
  - decision: nginx_block
    rule: 'block'
    regex: 'GET .* GET /blockme.*'
    interval: 60
    hits_per_interval: 0
  - decision: challenge
    rule: 'challenge'
    regex: 'GET .* GET /challengeme.*'
    interval: 60
    hits_per_interval: 0
expiring_decision_ttl_seconds: 300
`)
	config = withProtectedIPs(t, config, "7.7.7.7")
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	for _, path := range []string{"/slow", "/blockme"} {
		banner := MockBanner{}
		consumeLine(logLine("7.7.7.7", "example.com", path), NewRegexRateLimitStates(), &banner, config, staticDecisionLists)
		assert.Equal(t, "", banner.bannedIp, path)
		assert.Equal(t, Decision(0), banner.regexBanDecision, "no ban is logged for %s", path)

		banner = MockBanner{}
		consumeLine(logLine("7.7.7.8", "example.com", path), NewRegexRateLimitStates(), &banner, config, staticDecisionLists)
		assert.Equal(t, "7.7.7.8", banner.bannedIp, path)
	}

	// challenge rules still apply
	banner := MockBanner{}
	consumeLine(logLine("7.7.7.7", "example.com", "/challengeme"), NewRegexRateLimitStates(), &banner, config, staticDecisionLists)
	assert.Equal(t, "7.7.7.7", banner.bannedIp)
	assert.Equal(t, Challenge, banner.bannedDecision)
}

func TestRegexRulesNeverRateLimitProtectedGlobalAllowlistedIP(t *testing.T) {
	config, staticDecisionLists := newGlobalAllowlistRateLimitConfig(t)
	config = withProtectedIPs(t, config, "1.2.3.4")

	banner := MockBanner{}
	states := NewRegexRateLimitStates()
	for i := 0; i < 3; i++ {
		consumeLine(logLine("1.2.3.4", "opted.com", "/limited"), states, &banner, config, staticDecisionLists)
	}
	assert.Equal(t, "", banner.tooManyRequestsIp)
	assert.Equal(t, Decision(0), banner.regexBanDecision)

	// another allowlisted ip is still rate limited
	for i := 0; i < 2; i++ {
		consumeLine(logLine("5.5.5.5", "opted.com", "/limited"), states, &banner, config, staticDecisionLists)
	}
	assert.Equal(t, "5.5.5.5", banner.tooManyRequestsIp)
}

func TestDecisionForNginx2SkipsRateLimitsForProtectedIP(t *testing.T) {
	const host = "opted.com"
	expires := time.Now().Add(time.Minute)

	run := func(t *testing.T, config *Config, lists *DynamicDecisionLists, ip string) DecisionListResult {
		t.Helper()
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
		assert.Nil(t, err)
		c := buildDecisionForNginxTestContext(ip, host, "/", "ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, lists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
		return result.DecisionListResult
	}

	// decisions stored before the ip was protected (e.g. by an older config)
	unprotected := &Config{}

	t.Run("expiring ip rate limit", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		lists.Update(unprotected, "10.0.0.1", expires, TooManyRequests, false, host, AltChaOptions{})
		assert.Equal(t, ExpiringTooManyRequests, run(t, &Config{}, lists, "10.0.0.1"))
		assert.Equal(t, ProtectedIPException, run(t, withProtectedIPs(t, &Config{}, "10.0.0.1"), lists, "10.0.0.1"))
	})

	t.Run("global allowlist rate limit", func(t *testing.T) {
		config, _ := newGlobalAllowlistRateLimitConfig(t)
		lists := NewDynamicDecisionLists()
		lists.UpdateByIpHost(unprotected, "1.2.3.4", host, expires, TooManyRequests)
		assert.Equal(t, GlobalAllowlistTooManyRequests, run(t, config, lists, "1.2.3.4"))

		config = withProtectedIPs(t, config, "1.2.3.4")
		assert.Equal(t, ProtectedIPException, run(t, config, lists, "1.2.3.4"))
	})
}

func TestProtectedIPExceptionInBanjaxDecisionHeader(t *testing.T) {
	config := loadConfigString(`
global_decision_lists:
  nginx_block: [10.0.0.1]
`)
	config = withProtectedIPs(t, config, "10.0.0.1", "10.0.0.3")
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)

	decide := func(ip string) (DecisionListResult, string) {
		c := buildDecisionForNginxTestContext(ip, "example.com", "/", "ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, NewDynamicDecisionLists(), passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
		return result.DecisionListResult, c.Writer.Header().Get("X-Banjax-Decision")
	}

	// a block was skipped: nginx logs it as banjax_decision ProtectedIPException
	result, header := decide("10.0.0.1")
	assert.Equal(t, ProtectedIPException, result)
	assert.Equal(t, "ProtectedIPException", header)

	// a protected ip with nothing to skip is not an exception
	result, header = decide("10.0.0.3")
	assert.Equal(t, NoMention, result)
	assert.Equal(t, "NoMention", header)
}
