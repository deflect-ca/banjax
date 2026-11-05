// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDynamicDecisionLists_UpdateByHost_UpgradeOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
	expiringDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a lower-severity decision should not downgrade the existing one
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Allow, true, AltChaOptions{})
	expiringDecision, ok = decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a higher-severity decision should upgrade it
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), NginxBlock, true, AltChaOptions{})
	expiringDecision, ok = decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
}

func TestDynamicDecisionLists_CheckByHost_NotFound(t *testing.T) {
	decisionLists := NewDynamicDecisionLists()

	_, ok := decisionLists.CheckByHost("unknown.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_CheckByHost_LazyExpiry(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(-time.Second), Challenge, true, AltChaOptions{})

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveByHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
	decisionLists.RemoveByHost("example.com")

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveBySessionId(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-b", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})

	decisionLists.RemoveBySessionId("session-a")

	_, okA := decisionLists.Check("session-a", "")
	_, okB := decisionLists.Check("session-b", "")
	assert.False(t, okA)
	assert.True(t, okB)
}

func TestDynamicDecisionLists_Clear_WipesHostMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
	decisionLists.Clear()

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveExpired_SweepsHostMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "expired.com", time.Now().Add(-time.Second), Challenge, true, AltChaOptions{})
	decisionLists.UpdateByHost(config, "live.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

	decisionLists.removeExpired()

	decisionLists.mutex.Lock()
	_, expiredStillThere := decisionLists.value.expiringDecisionListsHost["expired.com"]
	_, liveStillThere := decisionLists.value.expiringDecisionListsHost["live.com"]
	decisionLists.mutex.Unlock()

	assert.False(t, expiredStillThere)
	assert.True(t, liveStillThere)
}

func TestDynamicDecisionLists_Metrics_CountsHostEntries(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "challenged.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
	decisionLists.UpdateByHost(config, "blocked.com", time.Now().Add(time.Minute), NginxBlock, true, AltChaOptions{})

	_, _, lenExpiringSitewideChallenges, lenExpiringSitewideBlocks, _, _, _, _ := decisionLists.Metrics()
	assert.Equal(t, 1, lenExpiringSitewideChallenges)
	assert.Equal(t, 1, lenExpiringSitewideBlocks)
}

func TestDynamicDecisionLists_UpdateByUA_UpgradeOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a lower-severity decision should not downgrade the existing one
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Allow, true, "example.com", AltChaOptions{})
	expiringDecision, ok = decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a higher-severity decision should upgrade it
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})
	expiringDecision, ok = decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
}

func TestDynamicDecisionLists_CheckByUA_NotFound(t *testing.T) {
	decisionLists := NewDynamicDecisionLists()

	_, ok := decisionLists.CheckByUA("unknown-agent", "example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_CheckByUA_LazyExpiry(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(-time.Second), Challenge, true, "example.com", AltChaOptions{})

	_, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_CheckByUA_ExactMatchOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	_, ok := decisionLists.CheckByUA("curl/7.68.0 extra", "example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveByUA(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.RemoveByUA("curl/7.68.0", "")

	_, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_Clear_WipesUAMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.Clear()

	_, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveExpired_SweepsUAMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "expired-agent", time.Now().Add(-time.Second), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "live-agent", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})

	decisionLists.removeExpired()

	decisionLists.mutex.Lock()
	_, expiredStillThere := decisionLists.value.expiringDecisionListsUA[uaHostKey{"expired-agent", "example.com"}]
	_, liveStillThere := decisionLists.value.expiringDecisionListsUA[uaHostKey{"live-agent", "example.com"}]
	decisionLists.mutex.Unlock()

	assert.False(t, expiredStillThere)
	assert.True(t, liveStillThere)
}

func TestDynamicDecisionLists_Metrics_CountsUAEntries(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "challenged-agent", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "blocked-agent", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	_, _, _, _, lenExpiringUAChallenges, lenExpiringUABlocks, _, _ := decisionLists.Metrics()
	assert.Equal(t, 1, lenExpiringUAChallenges)
	assert.Equal(t, 1, lenExpiringUABlocks)
}

func TestDynamicDecisionLists_Metrics_IptablesBlockAndAllow(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByHost(config, "iptables.com", time.Now().Add(time.Minute), IptablesBlock, true, AltChaOptions{})
	decisionLists.UpdateByHost(config, "allowed.com", time.Now().Add(time.Minute), Allow, true, AltChaOptions{})
	decisionLists.UpdateByUA(config, "iptables-agent", time.Now().Add(time.Minute), IptablesBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "allowed-agent", time.Now().Add(time.Minute), Allow, true, "example.com", AltChaOptions{})

	lenExpiringChallenges, lenExpiringBlocks, lenExpiringSitewideChallenges, lenExpiringSitewideBlocks, lenExpiringUAChallenges, lenExpiringUABlocks, _, _ := decisionLists.Metrics()

	// ip entries are only counted in the ip metrics
	assert.Equal(t, 1, lenExpiringChallenges)
	assert.Equal(t, 0, lenExpiringBlocks)

	// iptables_block counts as a block, allow counts as neither
	assert.Equal(t, 0, lenExpiringSitewideChallenges)
	assert.Equal(t, 1, lenExpiringSitewideBlocks)
	assert.Equal(t, 0, lenExpiringUAChallenges)
	assert.Equal(t, 1, lenExpiringUABlocks)
}

func TestDynamicDecisionLists_HostUAAndIpMapsAreIndependent(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	// the same key in one map must not leak into the others
	decisionLists.UpdateByHost(config, "shared-key", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

	_, uaOk := decisionLists.CheckByUA("shared-key", "example.com")
	_, ipOk := decisionLists.Check("", "shared-key")
	assert.False(t, uaOk)
	assert.False(t, ipOk)

	decisionLists.UpdateByUA(config, "shared-key", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	// removing from the ua map leaves the host map alone, and vice versa
	decisionLists.RemoveByUA("shared-key", "")
	_, hostOk := decisionLists.CheckByHost("shared-key")
	assert.True(t, hostOk)

	decisionLists.UpdateByUA(config, "shared-key", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.RemoveByHost("shared-key")
	_, uaOk = decisionLists.CheckByUA("shared-key", "example.com")
	assert.True(t, uaOk)
}

func TestFormatDecisionLists_IncludesSitewideAndUA(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()

	expires := time.Now().Add(time.Hour)
	decisionLists.UpdateByHost(config, "example.com", expires, Challenge, true, AltChaOptions{})
	decisionLists.UpdateByUA(config, "curl/7.68.0", expires, NginxBlock, false, "example.com", AltChaOptions{})

	out := FormatDecisionLists(staticDecisionLists, decisionLists)

	assert.Contains(t, out, "expiring_sitewide:\nexample.com:\n\tChallenge until "+expires.Format("15:04:05")+" (baskerville: true)\n")
	assert.Contains(t, out, "expiring_ua:\nexample.com curl/7.68.0:\n\tNginxBlock until "+expires.Format("15:04:05")+" (baskerville: false)\n")
}

func TestParseSubnet(t *testing.T) {
	valid := map[string]string{
		"202.46.62.0/24":  "202.46.62.0/24",
		"202.46.62.77/24": "202.46.62.0/24", // normalized to the network address
		" 10.1.0.0/16 ":   "10.1.0.0/16",
		"1.2.3.4/32":      "1.2.3.4/32",
		"172.16.255.1/17": "172.16.128.0/17",
	}
	for input, expected := range valid {
		subnet, err := ParseSubnet(input)
		assert.Nil(t, err, input)
		assert.Equal(t, expected, subnet.String(), input)
	}

	invalid := []string{
		"",
		"202.46.62.1",    // plain ip, use block_ip
		"202.46.62.0/33", // bad prefix length
		"202.46.62/24",
		"not-a-subnet",
		"2001:db8::/32",      // ipv6
		"::ffff:1.2.3.0/120", // ipv4-mapped ipv6
		"0.0.0.0/0",          // too broad
		"10.0.0.0/8",         // too broad
		"10.0.0.0/15",        // too broad
	}
	for _, input := range invalid {
		_, err := ParseSubnet(input)
		assert.NotNil(t, err, input)
	}
}

func mustParseSubnet(t *testing.T, s string) netip.Prefix {
	t.Helper()
	subnet, err := ParseSubnet(s)
	assert.Nil(t, err)
	return subnet
}

func TestDynamicDecisionLists_CheckBySubnet(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	_, ok := decisionLists.CheckBySubnet("202.46.62.1")
	assert.False(t, ok, "empty subnet list")

	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "202.46.62.0/24"), time.Now().Add(time.Minute), NginxBlock, true, "my.wiki", AltChaOptions{})

	for _, ip := range []string{"202.46.62.0", "202.46.62.1", "202.46.62.254", "202.46.62.255", "::ffff:202.46.62.9"} {
		expiringDecision, ok := decisionLists.CheckBySubnet(ip)
		assert.True(t, ok, ip)
		assert.Equal(t, NginxBlock, expiringDecision.Decision, ip)
		assert.Equal(t, "202.46.62.0/24", expiringDecision.IpAddress, ip)
	}

	for _, ip := range []string{"202.46.63.1", "202.46.61.255", "2001:db8::1", "garbage", ""} {
		_, ok := decisionLists.CheckBySubnet(ip)
		assert.False(t, ok, ip)
	}

	// the exact ip list is untouched by a subnet entry
	_, ipOk := decisionLists.Check("", "202.46.62.1")
	assert.False(t, ipOk)
}

func TestDynamicDecisionLists_CheckBySubnet_MostSeriousOverlapWins(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "10.1.2.0/24"), time.Now().Add(time.Minute), Challenge, true, "a.com", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "10.1.0.0/16"), time.Now().Add(time.Minute), NginxBlock, true, "b.com", AltChaOptions{})

	expiringDecision, ok := decisionLists.CheckBySubnet("10.1.2.3")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.Equal(t, "10.1.0.0/16", expiringDecision.IpAddress)

	expiringDecision, ok = decisionLists.CheckBySubnet("10.1.9.9")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
}

func TestDynamicDecisionLists_UpdateBySubnet_NeverDowngrades(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	subnet := mustParseSubnet(t, "10.1.2.0/24")

	decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), NginxBlock, true, "a.com", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Hour), Challenge, true, "a.com", AltChaOptions{})

	expiringDecision, ok := decisionLists.CheckBySubnet("10.1.2.3")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(time.Minute), expiringDecision.Expires, 5*time.Second)
}

func TestDynamicDecisionLists_Subnet_ExpiryAndRemoval(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	expired := mustParseSubnet(t, "10.1.2.0/24")
	live := mustParseSubnet(t, "10.9.9.0/24")

	decisionLists.UpdateBySubnet(config, expired, time.Now().Add(-time.Second), NginxBlock, true, "a.com", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, live, time.Now().Add(time.Minute), NginxBlock, true, "a.com", AltChaOptions{})

	_, ok := decisionLists.CheckBySubnet("10.1.2.3")
	assert.False(t, ok)

	decisionLists.removeExpired()
	decisionLists.mutex.Lock()
	_, expiredStillThere := decisionLists.value.expiringDecisionListsSubnet[expired]
	_, liveStillThere := decisionLists.value.expiringDecisionListsSubnet[live]
	decisionLists.mutex.Unlock()
	assert.False(t, expiredStillThere)
	assert.True(t, liveStillThere)

	removed, ok := decisionLists.RemoveBySubnet(live)
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, removed.Decision)
	_, ok = decisionLists.CheckBySubnet("10.9.9.1")
	assert.False(t, ok)

	_, ok = decisionLists.RemoveBySubnet(live)
	assert.False(t, ok, "removing again finds nothing")
}

func TestDynamicDecisionLists_Subnet_MetricsBannedAndFormat(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()
	expires := time.Now().Add(time.Hour)

	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "10.1.2.0/24"), expires, Challenge, true, "my.wiki", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "10.3.0.0/16"), expires, NginxBlock, true, "my.wiki", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "10.4.4.0/24"), expires, NginxBlock, true, "other.wiki", AltChaOptions{})

	lenExpiringChallenges, lenExpiringBlocks, _, _, _, _, lenExpiringSubnetChallenges, lenExpiringSubnetBlocks := decisionLists.Metrics()
	assert.Equal(t, 0, lenExpiringChallenges)
	assert.Equal(t, 0, lenExpiringBlocks)
	assert.Equal(t, 1, lenExpiringSubnetChallenges)
	assert.Equal(t, 2, lenExpiringSubnetBlocks)

	banned := decisionLists.CheckByDomain("my.wiki")
	bannedSubnets := []string{}
	for _, entry := range banned {
		bannedSubnets = append(bannedSubnets, entry.IpOrSessionId)
	}
	assert.ElementsMatch(t, []string{"10.1.2.0/24", "10.3.0.0/16"}, bannedSubnets)

	out := FormatDecisionLists(staticDecisionLists, decisionLists)
	assert.Contains(t, out, "expiring_subnet:\n")
	assert.Contains(t, out, "10.3.0.0/16:\n\tmy.wiki NginxBlock until "+expires.Format("15:04:05")+" (baskerville: true)\n")

	decisionLists.Clear()
	_, ok := decisionLists.CheckBySubnet("10.3.1.1")
	assert.False(t, ok)
}

const staticCIDRConfString = `
global_decision_lists:
  allow:
    - 20.20.20.20
    - 10.10.0.0/16
  challenge:
    - 8.8.8.8
    - 192.0.2.77/24
    - 2001:db8::/32
  nginx_block:
    - 70.80.90.100/32
    - not-an-ip
    - 172.16.0.0/40
  iptables_block:
    - 30.40.50.0/24
    - 30.40.50.60
per_site_decision_lists:
  example.com:
    allow:
      - 5.5.5.0/24
    challenge:
      - 6.6.6.6
      - 6.6.0.0/16
    nginx_block:
      - 7.7.7.0/24
      - 2001:db8:1::1
  empty.com:
    allow: []
`

func TestStaticDecisionLists_CheckGlobal_CIDR(t *testing.T) {
	config := loadConfigString(staticCIDRConfString)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	cases := map[string]Decision{
		"20.20.20.20":       Allow,     // exact
		"10.10.0.1":         Allow,     // cidr
		"10.10.255.255":     Allow,     // cidr upper bound
		"::ffff:10.10.3.4":  Allow,     // ipv4-mapped ipv6 matches the ipv4 cidr
		"8.8.8.8":           Challenge, // exact
		"192.0.2.1":         Challenge, // non-canonical cidr 192.0.2.77/24 covers the whole /24
		"192.0.2.255":       Challenge,
		"2001:db8:ffff::1":  Challenge,  // ipv6 cidr
		"2001:0db8:0000::0": Challenge,  // non-canonical ipv6 spelling
		"70.80.90.100":      NginxBlock, // /32 behaves like a plain ip
		"30.40.50.1":        IptablesBlock,
		"30.40.50.60":       IptablesBlock,
	}
	for ip, expected := range cases {
		decision, ok := staticDecisionLists.CheckGlobal(config, ip)
		assert.True(t, ok, ip)
		assert.Equal(t, expected, decision, ip)
	}

	for _, ip := range []string{"10.11.0.1", "192.0.3.1", "2001:db9::1", "70.80.90.101", "172.16.0.1", "", "garbage"} {
		_, ok := staticDecisionLists.CheckGlobal(config, ip)
		assert.False(t, ok, ip)
	}
}

func TestStaticDecisionLists_CheckGlobal_AllowWinsOverlap(t *testing.T) {
	config := loadConfigString(`
global_decision_lists:
  allow:
    - 9.9.9.9
  nginx_block:
    - 9.9.9.0/24
`)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	decision, ok := staticDecisionLists.CheckGlobal(config, "9.9.9.9")
	assert.True(t, ok)
	assert.Equal(t, Allow, decision)

	decision, ok = staticDecisionLists.CheckGlobal(config, "9.9.9.8")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision)
}

func TestStaticDecisionLists_CheckPerSite_CIDR(t *testing.T) {
	config := loadConfigString(staticCIDRConfString)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	cases := map[string]Decision{
		"5.5.5.5":         Allow,
		"6.6.6.6":         Challenge,
		"6.6.1.1":         Challenge,
		"7.7.7.200":       NginxBlock,
		"::ffff:7.7.7.1":  NginxBlock,
		"2001:db8:1:0::1": NginxBlock, // plain ipv6 written differently still matches
	}
	for ip, expected := range cases {
		decision, ok := staticDecisionLists.CheckPerSite(config, "example.com", ip)
		assert.True(t, ok, ip)
		assert.Equal(t, expected, decision, ip)
	}

	for _, ip := range []string{"5.5.6.5", "8.8.8.8", "20.20.20.20", "garbage"} {
		_, ok := staticDecisionLists.CheckPerSite(config, "example.com", ip)
		assert.False(t, ok, ip)
	}

	// per-site entries don't leak to other sites
	_, ok := staticDecisionLists.CheckPerSite(config, "other.com", "5.5.5.5")
	assert.False(t, ok)
	_, ok = staticDecisionLists.CheckPerSite(config, "empty.com", "5.5.5.5")
	assert.False(t, ok)
}

func TestStaticDecisionLists_CheckIsAllowed_CIDR(t *testing.T) {
	config := loadConfigString(staticCIDRConfString)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	assert.True(t, staticDecisionLists.CheckIsPerSiteAllowed("example.com", "5.5.5.9")) // per-site cidr
	assert.False(t, staticDecisionLists.CheckIsPerSiteAllowed("other.com", "5.5.5.9"))
	assert.False(t, staticDecisionLists.CheckIsPerSiteAllowed("example.com", "10.10.1.1")) // global only
	assert.False(t, staticDecisionLists.CheckIsPerSiteAllowed("example.com", "6.6.6.6"))   // challenge, not allow
	assert.False(t, staticDecisionLists.CheckIsPerSiteAllowed("example.com", "garbage"))

	assert.True(t, staticDecisionLists.CheckIsGlobalAllowed("10.10.1.1")) // global cidr
	assert.True(t, staticDecisionLists.CheckIsGlobalAllowed("20.20.20.20"))
	assert.False(t, staticDecisionLists.CheckIsGlobalAllowed("5.5.5.9")) // per-site only
	assert.False(t, staticDecisionLists.CheckIsGlobalAllowed("6.6.6.6"))
	assert.False(t, staticDecisionLists.CheckIsGlobalAllowed("garbage"))
}

func TestIPMatcher(t *testing.T) {
	m := newIPMatcher([]string{
		"1.1.1.1",
		"10.0.0.0/8",
		"192.0.2.77/24",      // non-canonical, covers the whole /24
		"70.80.90.100/32",    // single ip
		"::ffff:5.5.5.5",     // ipv4-mapped plain ip matches its ipv4 form
		"::ffff:6.6.6.6/128", // so does an ipv4-mapped single ip cidr
		"::ffff:7.7.7.0/120", // and an ipv4-mapped subnet its ipv4 form (ipfilter matched nothing here)
		"2001:db8::/32",
		"fe80::1",
		"garbage",
		"1.2.3.0/40",
		"",
	})

	for _, ip := range []string{
		"1.1.1.1", "::ffff:1.1.1.1",
		"10.255.255.255", "10.0.0.0",
		"192.0.2.0", "192.0.2.255",
		"70.80.90.100",
		"5.5.5.5", "6.6.6.6",
		"::ffff:7.7.7.9", "7.7.7.9",
		"2001:db8:abcd::1",
		"fe80::1", "FE80:0:0::1",
	} {
		assert.True(t, m.Contains(ip), ip)
	}

	for _, ip := range []string{
		"1.1.1.2", "11.0.0.1", "192.0.3.0", "70.80.90.101", "7.7.8.9",
		"2001:db9::1", "garbage", "", "1.2.3.4",
	} {
		assert.False(t, m.Contains(ip), ip)
	}

	var nilMatcher *ipMatcher
	assert.False(t, nilMatcher.Contains("1.1.1.1"))
	assert.False(t, newIPMatcher(nil).Contains("1.1.1.1"))
}

func TestDynamicDecisionLists_UAIsPerHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, "example.com", expiringDecision.domain)
	_, ok = decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.False(t, ok)

	// a less serious decision on another host is stored separately, not refused as a downgrade
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "other.com", AltChaOptions{})
	expiringDecision, ok = decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
}

func TestDynamicDecisionLists_RemoveByUA_ScopedToHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "other.com", AltChaOptions{})

	removed, ok := decisionLists.RemoveByUA("curl/7.68.0", "other.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, removed.Decision)

	_, exampleOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	_, otherOk := decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.True(t, exampleOk)
	assert.False(t, otherOk)
}

func TestDynamicDecisionLists_RemoveByUA_EmptyHostClearsEveryHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "other.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "other-agent", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	// the most serious removed decision is reported
	removed, ok := decisionLists.RemoveByUA("curl/7.68.0", "")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, removed.Decision)

	_, exampleOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	_, otherOk := decisionLists.CheckByUA("curl/7.68.0", "other.com")
	_, otherAgentOk := decisionLists.CheckByUA("other-agent", "example.com")
	assert.False(t, exampleOk)
	assert.False(t, otherOk)
	assert.True(t, otherAgentOk)
}

func TestDynamicDecisionLists_RemoveByUA_ExpiredNotReported(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(-time.Second), NginxBlock, true, "example.com", AltChaOptions{})

	_, ok := decisionLists.RemoveByUA("curl/7.68.0", "")
	assert.False(t, ok)
}

func TestExpiringDecision_SupersededBy(t *testing.T) {
	altcha := ExpiringDecision{Decision: AltChaChallenge, altcha: AltChaOptions{MaxNumber: 300000}}
	challenge := ExpiringDecision{Decision: Challenge}

	assert.True(t, altcha.supersededBy(NginxBlock, AltChaOptions{}), "more serious decision")
	assert.False(t, altcha.supersededBy(Challenge, AltChaOptions{}), "less serious decision")
	assert.True(t, altcha.supersededBy(AltChaChallenge, AltChaOptions{MaxNumber: 600000}), "same altcha decision, new difficulty")
	assert.True(t, altcha.supersededBy(AltChaChallenge, AltChaOptions{}), "same altcha decision, back to config difficulty")
	assert.False(t, altcha.supersededBy(AltChaChallenge, AltChaOptions{MaxNumber: 300000}), "same altcha decision, same difficulty")
	// equal non-altcha decisions are still never replaced
	assert.False(t, challenge.supersededBy(Challenge, AltChaOptions{}))
}

func TestDynamicDecisionLists_AltChaMaxNumberStoredAndReplaced(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), AltChaChallenge, true, AltChaOptions{MaxNumber: 300000})
	expiringDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, int64(300000), expiringDecision.altcha.MaxNumber)

	// a repeated altcha command at a new difficulty replaces the stored one
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), AltChaChallenge, true, AltChaOptions{MaxNumber: 600000})
	expiringDecision, _ = decisionLists.CheckByHost("example.com")
	assert.Equal(t, int64(600000), expiringDecision.altcha.MaxNumber)

	// a less serious decision does not
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
	expiringDecision, _ = decisionLists.CheckByHost("example.com")
	assert.Equal(t, AltChaChallenge, expiringDecision.Decision)
	assert.Equal(t, int64(600000), expiringDecision.altcha.MaxNumber)
}

func TestCheckByDomain_ReportsEveryExpiringList(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()
	expires := time.Now().Add(time.Minute)
	subnet, err := ParseSubnet("10.1.2.0/24")
	assert.Nil(t, err)

	decisionLists.Update(config, "1.2.3.4", expires, NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", expires, AltChaChallenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateBySubnet(config, subnet, expires, Challenge, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByIpHost(config, "5.6.7.8", "example.com", expires, TooManyRequests)
	decisionLists.UpdateByHost(config, "example.com", expires, AltChaChallenge, true, AltChaOptions{MaxNumber: 5000})
	decisionLists.UpdateByUA(config, "curl/7.68.0", expires, NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "bad-bot/1.0", expires, AltChaChallenge, true, "example.com", AltChaOptions{MaxNumber: 5000})

	// none of these may show up for example.com
	decisionLists.UpdateByHost(config, "other.com", expires, Challenge, true, AltChaOptions{})
	decisionLists.UpdateByUA(config, "curl/7.68.0", expires, NginxBlock, true, "other.com", AltChaOptions{})
	decisionLists.Update(config, "9.9.9.9", expires, NginxBlock, true, "other.com", AltChaOptions{})
	decisionLists.Update(config, "8.8.8.8", expires, Allow, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByUA(config, "expired-agent", time.Now().Add(-time.Second), NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.Update(config, "7.7.7.7", time.Now().Add(-time.Second), NginxBlock, true, "example.com", AltChaOptions{})

	type row struct{ entryType, ip, ua, decision string }
	var got []row
	for _, entry := range decisionLists.CheckByDomain("example.com") {
		got = append(got, row{entry.Type, entry.IpOrSessionId, entry.UA, entry.Decision})
		assert.True(t, entry.FromBaskerville || entry.Type == "ip_host")
	}
	assert.ElementsMatch(t, []row{
		{"ip", "1.2.3.4", "", "NginxBlock"},
		{"session", "session-a", "", "AltChaChallenge"},
		{"subnet", "10.1.2.0/24", "", "Challenge"},
		{"ip_host", "5.6.7.8", "", "TooManyRequests"},
		{"host", "", "", "AltChaChallenge"},
		{"ua", "", "curl/7.68.0", "NginxBlock"},
		{"ua", "", "bad-bot/1.0", "AltChaChallenge"},
	}, got)
}

func TestBannedEntry_JSON(t *testing.T) {
	expires := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	uaJSON, err := json.Marshal(BannedEntry{UA: "curl/7.68.0", Type: "ua", Decision: "NginxBlock", Expires: expires, FromBaskerville: true})
	assert.Nil(t, err)
	assert.JSONEq(t, `{"ip": "", "ua": "curl/7.68.0", "type": "ua", "decision": "NginxBlock", "expires": "2026-11-04T12:00:00Z", "from_baskerville": true}`, string(uaJSON))

	// existing entries keep their shape, plus type; ua is left out when empty
	ipJSON, err := json.Marshal(BannedEntry{IpOrSessionId: "1.2.3.4", Type: "ip", Decision: "Challenge", Expires: expires})
	assert.Nil(t, err)
	assert.JSONEq(t, `{"ip": "1.2.3.4", "type": "ip", "decision": "Challenge", "expires": "2026-11-04T12:00:00Z", "from_baskerville": false}`, string(ipJSON))
}
