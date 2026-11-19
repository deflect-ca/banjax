// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// challenge_ip, block_ip and altcha_challenge_ip apply to the ip only on the host the
// command names.

const (
	hostIpTestIp        = "1.2.3.4"
	hostIpTestHost      = "example.com"
	hostIpTestOtherHost = "other.com"
)

func hostIpTestConfig() *Config {
	config := altchaTestConfig()
	config.ExpiringDecisionTtlSeconds = 300
	config.BlockIPTtlSeconds = 600
	return config
}

func decideHostIp(t *testing.T, config *Config, decisionLists *DynamicDecisionLists, ip, host string) DecisionListResult {
	t.Helper()
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	c := buildDecisionForNginxTestContext(ip, host, "/", "some-ua", "")
	return decisionForNginx2(
		c,
		config,
		staticDecisionLists,
		decisionLists,
		passwordProtectedPaths,
		NewFailedChallengeRateLimitStates(),
		NewFailedChallengeRateLimitStates(),
		&MockBanner{},
	).DecisionListResult
}

func TestKafkaIpCommandsApplyOnlyOnTheirHost(t *testing.T) {
	cases := []struct {
		command string
		want    DecisionListResult
	}{
		{"challenge_ip", ExpiringChallenge},
		{"block_ip", ExpiringBlock},
		{"altcha_challenge_ip", ExpiringAltChaChallenge},
	}
	for _, tc := range cases {
		t.Run(tc.command+" applies on the command's host and nowhere else", func(t *testing.T) {
			config := hostIpTestConfig()
			decisionLists := NewDynamicDecisionLists()

			handleCommand(config, commandMessage{Name: tc.command, Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

			assert.Equal(t, tc.want, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
			assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestOtherHost))
			assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, "1.2.3.5", hostIpTestHost))
		})
	}

	t.Run("commands for two hosts keep separate decisions", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()

		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestOtherHost}, decisionLists)

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
		assert.Equal(t, ExpiringChallenge, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestOtherHost))
	})
}

func TestKafkaIpCommandsRejectBadInput(t *testing.T) {
	cases := map[string]commandMessage{
		"a command without a host is dropped, not applied on every host": {Name: "block_ip", Value: hostIpTestIp},
		"a host longer than a dns name is dropped":                       {Name: "block_ip", Value: hostIpTestIp, Host: strings.Repeat("a", 254)},
		"a value that is not an ip is dropped":                           {Name: "block_ip", Value: "1.2.3.4.5", Host: hostIpTestHost},
		"a subnet in an ip command is dropped":                           {Name: "challenge_ip", Value: "1.2.3.0/24", Host: hostIpTestHost},
		"an ipv6 address with a zone is dropped":                         {Name: "altcha_challenge_ip", Value: "fe80::1%eth0", Host: hostIpTestHost},
	}
	for name, command := range cases {
		t.Run(name, func(t *testing.T) {
			decisionLists := NewDynamicDecisionLists()

			handleCommand(hostIpTestConfig(), command, decisionLists)

			assertDecisionListsEmpty(t, decisionLists)
		})
	}

	t.Run("an ipv4-mapped ipv6 value matches the ipv4 address nginx sends", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()

		handleCommand(config, commandMessage{Name: "block_ip", Value: " ::ffff:1.2.3.4 ", Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})
}

// The ip's own decision (regex rules) and covering subnet decisions still apply on every host;
// on the command's host the most serious of the three wins.
func TestKafkaIpCommandsRankAgainstIpAndSubnetDecisions(t *testing.T) {
	expires := time.Now().Add(time.Minute)

	t.Run("a kafka block on the host beats the ip's own challenge", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, hostIpTestIp, expires, Challenge, false, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
		assert.Equal(t, ExpiringChallenge, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestOtherHost))
	})

	t.Run("the ip's own block beats a kafka challenge on the host", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, hostIpTestIp, expires, NginxBlock, false, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("on a tie the kafka decision's altcha settings are used", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, hostIpTestIp, expires, AltChaChallenge, false, hostIpTestHost, AltChaOptions{})
		maxNumber := int64(5000)
		handleCommand(config, commandMessage{Name: "altcha_challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost, AltChaMaxNumber: &maxNumber}, decisionLists)

		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
		assert.Nil(t, err)
		c := buildDecisionForNginxTestContext(hostIpTestIp, hostIpTestHost, "/", "some-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, ExpiringAltChaChallenge, result.DecisionListResult)
		if assert.NotNil(t, result.AltChaOptions) {
			assert.Equal(t, int64(5000), result.AltChaOptions.MaxNumber)
		}
	})

	t.Run("a subnet block beats a kafka challenge on the host", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "1.2.3.0/24"), expires, NginxBlock, true, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringSubnetBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("a kafka block on the host beats a subnet challenge", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "1.2.3.0/24"), expires, Challenge, true, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
		assert.Equal(t, ExpiringSubnetChallenge, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestOtherHost))
	})
}

func TestKafkaIpCommandsExemptions(t *testing.T) {
	t.Run("a kafka block stored before the ip was protected is not applied", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		protected := withProtectedIPs(t, hostIpTestConfig(), hostIpTestIp)

		assert.Equal(t, ProtectedIPException, decideHostIp(t, protected, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("a kafka challenge still applies to a protected ip", func(t *testing.T) {
		config := withProtectedIPs(t, hostIpTestConfig(), hostIpTestIp)
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringChallenge, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("a kafka block is skipped once its host disables baskerville", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		config.SitesToDisableBaskerville = map[string]bool{hostIpTestHost: true}

		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("a kafka block is skipped for an ip allowlisted on its host", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		config.PerSiteDecisionLists = map[string]map[string][]string{hostIpTestHost: {"allow": {hostIpTestIp}}}

		assert.Equal(t, PerSiteAccessGranted, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("a skipped kafka block on a protected ip does not hide the ip's own challenge", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)
		decisionLists.Update(config, hostIpTestIp, time.Now().Add(time.Minute), Challenge, false, hostIpTestHost, AltChaOptions{})

		protected := withProtectedIPs(t, hostIpTestConfig(), hostIpTestIp)

		assert.Equal(t, ExpiringChallenge, decideHostIp(t, protected, decisionLists, hostIpTestIp, hostIpTestHost))
	})
}

func TestKafkaIpCommandsLifecycle(t *testing.T) {
	t.Run("an expired kafka block does not stop a new challenge being stored", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHostIp(config, hostIpTestIp, hostIpTestHost, time.Now().Add(-time.Second), NginxBlock, true, AltChaOptions{})

		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		assert.Equal(t, ExpiringChallenge, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("unban by ip removes the kafka decision on every host", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestOtherHost}, decisionLists)

		code, body := postUnban(t, newUnbanTestRouter(decisionLists), url.Values{"ip": {hostIpTestIp}})

		assert.Equal(t, 200, code)
		assert.Equal(t, true, body["found_in_decision_list"])
		assert.Equal(t, "NginxBlock", body["decision"])
		assert.Equal(t, true, body["unban"])
		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestOtherHost))
	})

	t.Run("clear_rules with the ip removes the kafka decision", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		handleCommand(config, commandMessage{Name: "clear_rules", Value: hostIpTestIp}, decisionLists)

		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("banned lists the kafka decision as an ip entry of its host only", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		entries := decisionLists.CheckByDomain(hostIpTestHost)
		if assert.Len(t, entries, 1) {
			assert.Equal(t, "ip", entries[0].Type)
			assert.Equal(t, hostIpTestIp, entries[0].IpOrSessionId)
			assert.Equal(t, "NginxBlock", entries[0].Decision)
		}
		assert.Empty(t, decisionLists.CheckByDomain(hostIpTestOtherHost))
	})

	t.Run("metrics count kafka ip decisions with the ip decisions", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "challenge_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)
		handleCommand(config, commandMessage{Name: "block_ip", Value: "1.2.3.5", Host: hostIpTestHost}, decisionLists)

		lenExpiringChallenges, lenExpiringBlocks, _, _, _, _, _, _ := decisionLists.Metrics()
		assert.Equal(t, 1, lenExpiringChallenges)
		assert.Equal(t, 1, lenExpiringBlocks)
	})
}

func TestKafkaIpCommandsReviewFixes(t *testing.T) {
	t.Run("a skipped kafka block on a baskerville-disabled site does not hide the ip's own block", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, hostIpTestIp, time.Now().Add(time.Minute), NginxBlock, false, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		config.SitesToDisableBaskerville = map[string]bool{hostIpTestHost: true}

		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})

	t.Run("clear_rules removes a kafka decision sent with a non-canonical ip", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		handleCommand(config, commandMessage{Name: "block_ip", Value: "2001:DB8::1", Host: hostIpTestHost}, decisionLists)
		assert.Equal(t, ExpiringBlock, decideHostIp(t, config, decisionLists, "2001:db8::1", hostIpTestHost))

		handleCommand(config, commandMessage{Name: "clear_rules", Value: "2001:DB8::1"}, decisionLists)

		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, "2001:db8::1", hostIpTestHost))
	})

	t.Run("unban removes a kafka decision given an ipv4-mapped ip and reports the most serious decision", func(t *testing.T) {
		config := hostIpTestConfig()
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, hostIpTestIp, time.Now().Add(time.Minute), Challenge, false, hostIpTestHost, AltChaOptions{})
		handleCommand(config, commandMessage{Name: "block_ip", Value: hostIpTestIp, Host: hostIpTestHost}, decisionLists)

		code, body := postUnban(t, newUnbanTestRouter(decisionLists), url.Values{"ip": {"::ffff:1.2.3.4"}})

		assert.Equal(t, 200, code)
		assert.Equal(t, "NginxBlock", body["decision"])
		assert.Equal(t, true, body["unban"])
		assert.Equal(t, NoMention, decideHostIp(t, config, decisionLists, hostIpTestIp, hostIpTestHost))
	})
}
