// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func unifiedTestConfig() *Config {
	return &Config{ExpiringDecisionTtlSeconds: 60, BlockIPTtlSeconds: 60, BlockSessionTtlSeconds: 60}
}

func unifiedCommand(name string, host string, value string, sessionId string, ua string) commandMessage {
	return commandMessage{Name: name, Host: host, Value: value, SessionId: sessionId, UA: ua}
}

// decideUnified runs decisionForNginx2 for one request and returns the result and the banner.
func decideUnified(t *testing.T, config *Config, lists *DynamicDecisionLists, ip string, host string, path string, ua string, sessionId string) (DecisionListResult, *MockBanner) {
	t.Helper()
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	banner := &MockBanner{}
	c := buildDecisionForNginxTestContext(ip, host, path, ua, sessionId)
	result := decisionForNginx2(c, config, staticDecisionLists, lists, passwordProtectedPaths,
		NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), banner)
	return result.DecisionListResult, banner
}

func TestParseUnifiedRuleKey(t *testing.T) {
	key, err := parseUnifiedRuleKey("1.2.3.4", "", "")
	assert.Nil(t, err)
	assert.Equal(t, "ip=1.2.3.4", key.String())
	assert.Equal(t, 1, key.fields())

	key, err = parseUnifiedRuleKey("::ffff:1.2.3.4", "", "")
	assert.Nil(t, err)
	assert.Equal(t, "ip=1.2.3.4", key.String(), "ipv4-mapped is stored as ipv4")

	key, err = parseUnifiedRuleKey("2001:db8::1", "", "")
	assert.Nil(t, err)
	assert.Equal(t, "ip=2001:db8::1", key.String())

	key, err = parseUnifiedRuleKey(" 1.2.3.4/24 ", "a%2Bb%3D%3D", "curl/8.0")
	assert.Nil(t, err)
	assert.Equal(t, `subnet=1.2.3.0/24 session_id=a+b== ua="curl/8.0"`, key.String())
	assert.Equal(t, 3, key.fields())

	key, err = parseUnifiedRuleKey("", "", "")
	assert.Nil(t, err)
	assert.Equal(t, "all", key.String())
	assert.Equal(t, 0, key.fields())

	for _, value := range []string{"1.2.3.0/8", "2001:db8::/64", "1.2.3", "example.com"} {
		_, err := parseUnifiedRuleKey(value, "", "")
		assert.NotNil(t, err, value)
	}
	_, err = parseUnifiedRuleKey("", "%zz", "")
	assert.NotNil(t, err)
}

func TestKafkaUnifiedCommandsRequireHost(t *testing.T) {
	config := unifiedTestConfig()
	lists := NewDynamicDecisionLists()

	for _, name := range []string{"unified_challenge", "unified_altcha_challenge", "unified_block"} {
		handleCommand(config, unifiedCommand(name, "", "1.2.3.4", "", ""), lists)
	}
	assert.Empty(t, lists.value.expiringDecisionListsUnified)

	// malformed fields drop the command too
	handleCommand(config, unifiedCommand("unified_block", "example.com", "1.2.3.0/8", "", ""), lists)
	assert.Empty(t, lists.value.expiringDecisionListsUnified)
}

func TestKafkaUnifiedHostOnly(t *testing.T) {
	config := unifiedTestConfig()

	t.Run("host-only block is dropped", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", "example.com", "", "", ""), lists)
		assert.Empty(t, lists.value.expiringDecisionListsUnified)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", "example.com", "/", "ua", "")
		assert.Equal(t, NoMention, result)
	})

	t.Run("host-only challenge challenges the whole site, and only that site", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_challenge", "example.com", "", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", "example.com", "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", "other.com", "/", "ua", "")
		assert.Equal(t, NoMention, result)
	})
}

func TestUnifiedRulesNarrowTheBlastRadius(t *testing.T) {
	config := unifiedTestConfig()
	const host = "example.com"

	t.Run("host + ip", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", "other.com", "/", "ua", "")
		assert.Equal(t, NoMention, result, "other hosts are not affected, unlike block_ip")
		result, _ = decideUnified(t, config, lists, "1.1.1.2", host, "/", "ua", "")
		assert.Equal(t, NoMention, result)
	})

	t.Run("host + ip + ua", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", "BadBot"), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "BadBot", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "Firefox", "")
		assert.Equal(t, NoMention, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.2", host, "/", "BadBot", "")
		assert.Equal(t, NoMention, result)
	})

	t.Run("host + subnet", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_altcha_challenge", host, "10.1.0.0/16", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "10.1.200.3", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedAltChaChallenge, result)
		result, _ = decideUnified(t, config, lists, "10.2.0.1", host, "/", "ua", "")
		assert.Equal(t, NoMention, result)
	})

	t.Run("host + session id (url-encoded in the command)", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_challenge", host, "", "abc%3D%3D", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "abc==")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "other")
		assert.Equal(t, NoMention, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, NoMention, result)
	})

	t.Run("host + ip + session id + ua", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "s1", "BadBot"), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "BadBot", "s1")
		assert.Equal(t, ExpiringUnifiedBlock, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "BadBot", "s2")
		assert.Equal(t, NoMention, result)
	})
}

func TestUnifiedMostSpecificRuleWins(t *testing.T) {
	config := unifiedTestConfig()
	const host = "example.com"

	t.Run("a narrow challenge overrides a broader block", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", ""), lists)
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", "GoodBot"), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "GoodBot", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "Other", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
	})

	t.Run("a single ip is more specific than the subnet holding it", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.0/24", "", ""), lists)
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.2", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
	})

	t.Run("equally specific rules: the most serious wins", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)
		handleCommand(config, unifiedCommand("unified_block", host, "", "", "BadBot"), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "BadBot", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
	})

	t.Run("the same fields: a less serious command does not replace a block", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", ""), lists)
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)
	})

	t.Run("unified rules are checked before the older expiring lists", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("block_ip", host, "1.1.1.1", "", ""), lists)
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", "other.com", "/", "ua", "")
		assert.Equal(t, ExpiringBlock, result)
	})
}

func TestUnifiedRulesExpire(t *testing.T) {
	config := unifiedTestConfig()
	lists := NewDynamicDecisionLists()
	key, _ := parseUnifiedRuleKey("1.1.1.1", "", "")
	assert.Nil(t, lists.UpdateUnified(config, "example.com", key, time.Now().Add(-time.Second), NginxBlock, true, AltChaOptions{}))

	result, _ := decideUnified(t, config, lists, "1.1.1.1", "example.com", "/", "ua", "")
	assert.Equal(t, NoMention, result)

	// an expired block does not stop a new, less serious rule with the same fields
	assert.Nil(t, lists.UpdateUnified(config, "example.com", key, time.Now().Add(-time.Second), NginxBlock, true, AltChaOptions{}))
	assert.Nil(t, lists.UpdateUnified(config, "example.com", key, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{}))
	result, _ = decideUnified(t, config, lists, "1.1.1.1", "example.com", "/", "ua", "")
	assert.Equal(t, ExpiringUnifiedChallenge, result)
}

func TestUnifiedChallengeExceptionsAndEscalation(t *testing.T) {
	const host = "example.com"

	t.Run("sha_inv_path_exceptions apply", func(t *testing.T) {
		config := unifiedTestConfig()
		config.SitesToShaInvPathExceptions = map[string][]string{host: {"/no_challenge"}}
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/no_challenge", "ua", "")
		assert.Equal(t, PerSiteShaInvPathException, result)
	})

	t.Run("failing a unified challenge too often still ends in an iptables ban", func(t *testing.T) {
		config := unifiedTestConfig() // too_many_failed_challenges_threshold 0: the first failure trips it
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_challenge", host, "1.1.1.1", "", ""), lists)

		result, banner := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
		assert.Equal(t, "1.1.1.1", banner.bannedIp)
		assert.Equal(t, IptablesBlock, banner.bannedDecision)
	})

	t.Run("sites_to_disable_baskerville drops the command", func(t *testing.T) {
		config := unifiedTestConfig()
		config.SitesToDisableBaskerville = map[string]bool{host: true}
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", ""), lists)
		assert.Empty(t, lists.value.expiringDecisionListsUnified)
	})
}

func TestUnifiedRulesAndProtectedIPs(t *testing.T) {
	const host = "example.com"
	config := withProtectedIPs(t, unifiedTestConfig(), "1.1.1.1")

	t.Run("a block on a protected ip is not stored", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.1", "", "BadBot"), lists)
		assert.Empty(t, lists.value.expiringDecisionListsUnified)
	})

	t.Run("a subnet block is skipped, a less specific challenge still applies", func(t *testing.T) {
		lists := NewDynamicDecisionLists()
		handleCommand(config, unifiedCommand("unified_block", host, "1.1.1.0/24", "", ""), lists)

		result, _ := decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ProtectedIPException, result)
		result, _ = decideUnified(t, config, lists, "1.1.1.2", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedBlock, result)

		handleCommand(config, unifiedCommand("unified_challenge", host, "", "", ""), lists)
		result, _ = decideUnified(t, config, lists, "1.1.1.1", host, "/", "ua", "")
		assert.Equal(t, ExpiringUnifiedChallenge, result)
	})
}

func TestKafkaUnifiedClear(t *testing.T) {
	config := unifiedTestConfig()
	const host = "example.com"

	setup := func() *DynamicDecisionLists {
		lists := NewDynamicDecisionLists()
		for _, command := range []commandMessage{
			unifiedCommand("unified_challenge", host, "", "", ""),
			unifiedCommand("unified_block", host, "1.1.1.1", "", ""),
			unifiedCommand("unified_block", host, "1.1.1.1", "", "BadBot"),
			unifiedCommand("unified_block", host, "1.1.1.1", "s1", ""),
			unifiedCommand("unified_block", host, "1.1.1.0/24", "", ""),
			unifiedCommand("unified_block", host, "2.2.2.2", "", "BadBot"),
			unifiedCommand("unified_block", "other.com", "1.1.1.1", "", ""),
		} {
			handleCommand(config, command, lists)
		}
		return lists
	}
	remaining := func(lists *DynamicDecisionLists, host string) []string {
		keys := []string{}
		for key := range lists.value.expiringDecisionListsUnified[host] {
			keys = append(keys, key.String())
		}
		return keys
	}

	t.Run("host + ip clears that ip's rules, with or without other fields", func(t *testing.T) {
		lists := setup()
		handleCommand(config, unifiedCommand("unified_clear", host, "1.1.1.1", "", ""), lists)
		assert.ElementsMatch(t, []string{"all", "subnet=1.1.1.0/24", `ip=2.2.2.2 ua="BadBot"`}, remaining(lists, host))
		assert.ElementsMatch(t, []string{"ip=1.1.1.1"}, remaining(lists, "other.com"))
	})

	t.Run("host + ua clears that ua's rules", func(t *testing.T) {
		lists := setup()
		handleCommand(config, unifiedCommand("unified_clear", host, "", "", "BadBot"), lists)
		assert.ElementsMatch(t, []string{"all", "ip=1.1.1.1", "ip=1.1.1.1 session_id=s1", "subnet=1.1.1.0/24"}, remaining(lists, host))
	})

	t.Run("host + subnet clears only that exact subnet", func(t *testing.T) {
		lists := setup()
		handleCommand(config, unifiedCommand("unified_clear", host, "1.1.1.0/24", "", ""), lists)
		assert.Len(t, remaining(lists, host), 5)
		assert.NotContains(t, remaining(lists, host), "subnet=1.1.1.0/24")
	})

	t.Run("host only clears every unified rule on the host", func(t *testing.T) {
		lists := setup()
		handleCommand(config, unifiedCommand("unified_clear", host, "", "", ""), lists)
		assert.Empty(t, remaining(lists, host))
		assert.Len(t, remaining(lists, "other.com"), 1)
	})

	t.Run("no host is dropped", func(t *testing.T) {
		lists := setup()
		handleCommand(config, unifiedCommand("unified_clear", "", "1.1.1.1", "", ""), lists)
		assert.Len(t, remaining(lists, host), 6)
	})
}

func TestUnifiedRulesInBannedListAndMetrics(t *testing.T) {
	config := unifiedTestConfig()
	lists := NewDynamicDecisionLists()
	handleCommand(config, unifiedCommand("unified_block", "example.com", "1.1.1.1", "", "BadBot"), lists)
	handleCommand(config, unifiedCommand("unified_altcha_challenge", "example.com", "", "", ""), lists)
	handleCommand(config, unifiedCommand("unified_challenge", "other.com", "2.2.2.2", "", ""), lists)

	entries := lists.CheckByDomain("example.com")
	assert.Len(t, entries, 2)
	for _, entry := range entries {
		assert.Equal(t, "unified", entry.Type)
	}

	challenges, altchaChallenges, blocks := lists.MetricsUnified()
	assert.Equal(t, 1, challenges)
	assert.Equal(t, 1, altchaChallenges)
	assert.Equal(t, 1, blocks)

	lists.Clear()
	challenges, altchaChallenges, blocks = lists.MetricsUnified()
	assert.Equal(t, 0, challenges+altchaChallenges+blocks)
}
