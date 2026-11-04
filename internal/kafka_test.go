// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const kafkaTestConfString = `
expiring_decision_ttl_seconds: 300
block_ip_ttl_seconds: 600
block_session_ttl_seconds: 900
`

func TestHandleCommand_ChallengeIP_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	expiringDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeIP_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", Host: "example.com", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockIP_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	expiringDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(600*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockIP_SiteTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString + `
sites_to_block_ip_ttl_seconds:
  example.com: 1200
`)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "block_ip", Value: "5.6.7.8", Host: "other.com"}, decisionLists)

	siteDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(1200*time.Second), siteDecision.Expires, 5*time.Second)

	// a host without a site-specific ttl falls back to block_ip_ttl_seconds
	otherDecision, ok := decisionLists.Check("", "5.6.7.8")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(600*time.Second), otherDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockSession_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	expiringDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(900*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockSession_SiteTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString + `
sites_to_block_session_ttl_seconds:
  example.com: 1200
`)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "block_session", SessionId: "session-b", Value: "1.2.3.4", Host: "other.com"}, decisionLists)

	siteDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(1200*time.Second), siteDecision.Expires, 5*time.Second)

	// a host without a site-specific ttl falls back to block_session_ttl_seconds
	otherDecision, ok := decisionLists.Check("session-b", "")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(900*time.Second), otherDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockSession_TTLOverrideBeatsSiteTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString + `
sites_to_block_session_ttl_seconds:
  example.com: 1200
`)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeSession_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	expiringDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeSession_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockIP_TTLOverrideBeatsSiteTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString + `
sites_to_block_ip_ttl_seconds:
  example.com: 900
`)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ip", Value: "1.2.3.4", Host: "example.com", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_NonPositiveTTLUsesDefault(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_all", Host: "example.com", TTL: -1}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_ua", Host: "example.com", UA: "curl/7.68.0", TTL: 0}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", TTL: -1}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_session", SessionId: "session-a", TTL: -1}, decisionLists)

	sessionDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), sessionDecision.Expires, 5*time.Second)

	hostDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), hostDecision.Expires, 5*time.Second)

	uaDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), uaDecision.Expires, 5*time.Second)

	ipDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), ipDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeAll_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_all", Host: "example.com"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.True(t, expiringDecision.fromBaskerville)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeAll_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_all", Host: "example.com", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeAll_EmptyHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_all", Host: ""}, decisionLists)

	_, ok := decisionLists.CheckByHost("")
	assert.False(t, ok)
}

func TestHandleCommand_ChallengeAll_OtherHostUnaffected(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_all", Host: "example.com"}, decisionLists)

	_, ok := decisionLists.CheckByHost("other.com")
	assert.False(t, ok)
}

func TestHandleCommand_ChallengeUA_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.True(t, expiringDecision.fromBaskerville)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeUA_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", Host: "example.com", UA: "curl/7.68.0", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeUA_EmptyUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", Host: "example.com", UA: ""}, decisionLists)

	_, ok := decisionLists.CheckByUA("", "example.com")
	assert.False(t, ok)
}

func TestHandleCommand_ChallengeUA_OtherUAUnaffected(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	_, ok := decisionLists.CheckByUA("other-agent", "example.com")
	assert.False(t, ok)
}

func TestHandleCommand_BlockUA_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.True(t, expiringDecision.fromBaskerville)
	assert.WithinDuration(t, time.Now().Add(600*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockUA_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", Host: "example.com", UA: "curl/7.68.0", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockUA_EmptyUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", Host: "example.com", UA: ""}, decisionLists)

	_, ok := decisionLists.CheckByUA("", "example.com")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, 0)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com"}, decisionLists)

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", UA: "curl/7.68.0"}, decisionLists)

	_, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByIp(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", Value: "1.2.3.4"}, decisionLists)

	_, ok := decisionLists.Check("", "1.2.3.4")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_BySessionId(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", SessionId: "session-a"}, decisionLists)

	_, ok := decisionLists.Check("session-a", "")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_UrlEncodedSessionId(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session with spaces", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", SessionId: "session%20with%20spaces"}, decisionLists)

	_, ok := decisionLists.Check("session with spaces", "")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_AllAtOnce(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, 0)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)

	handleCommand(config, commandMessage{
		Name:      "clear_rules",
		Host:      "example.com",
		Value:     "1.2.3.4",
		SessionId: "session-a",
		UA:        "curl/7.68.0",
	}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	_, sessionOk := decisionLists.Check("session-a", "")
	_, uaOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.False(t, hostOk)
	assert.False(t, ipOk)
	assert.False(t, sessionOk)
	assert.False(t, uaOk)
}

func TestHandleCommand_ClearRules_OnlyClearsGivenKeys(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, 0)
	decisionLists.UpdateByHost(config, "other.com", time.Now().Add(time.Minute), Challenge, true, 0)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)
	decisionLists.UpdateByUA(config, "other-agent", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	_, otherHostOk := decisionLists.CheckByHost("other.com")
	_, otherUAOk := decisionLists.CheckByUA("other-agent", "example.com")
	assert.True(t, otherHostOk)
	assert.True(t, otherUAOk)
}

func TestHandleCommand_ClearRules_InvalidSessionIdStillClearsOthers(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, 0)
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "%zz", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	// "%zz" is not a valid url escape, so the session part is skipped but the host is still cleared
	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com", SessionId: "%zz"}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, sessionOk := decisionLists.Check("%zz", "")
	assert.False(t, hostOk)
	assert.True(t, sessionOk)
}

const kafkaDisabledBaskervilleConfString = kafkaTestConfString + `
sites_to_disable_baskerville:
  disabled.com: true
`

// assertDecisionListsEmpty checks that nothing was written to any of the expiring decision lists.
func assertDecisionListsEmpty(t *testing.T, decisionLists *DynamicDecisionLists) {
	t.Helper()

	decisionLists.mutex.Lock()
	defer decisionLists.mutex.Unlock()

	assert.Empty(t, decisionLists.value.expiringDecisionLists)
	assert.Empty(t, decisionLists.value.expiringDecisionListsSessionId)
	assert.Empty(t, decisionLists.value.expiringDecisionListsHost)
	assert.Empty(t, decisionLists.value.expiringDecisionListsUA)
	assert.Empty(t, decisionLists.value.expiringDecisionListsSubnet)
}

func TestHandleCommand_DisabledBaskerville_DropsCommands(t *testing.T) {
	commands := []commandMessage{
		{Name: "challenge_ip", Value: "1.2.3.4", Host: "disabled.com"},
		{Name: "block_ip", Value: "1.2.3.4", Host: "disabled.com"},
		{Name: "challenge_session", Value: "1.2.3.4", SessionId: "session-a", Host: "disabled.com"},
		{Name: "block_session", Value: "1.2.3.4", SessionId: "session-a", Host: "disabled.com"},
		{Name: "challenge_all", Host: "disabled.com"},
		{Name: "challenge_ua", UA: "curl/7.68.0", Host: "disabled.com"},
		{Name: "block_ua", UA: "curl/7.68.0", Host: "disabled.com"},
		{Name: "challenge_subnet", Value: "1.2.3.0/24", Host: "disabled.com"},
		{Name: "block_subnet", Value: "1.2.3.0/24", Host: "disabled.com"},
	}

	// the drop must not depend on debug mode
	for _, debug := range []bool{false, true} {
		for _, command := range commands {
			t.Run(fmt.Sprintf("%s/debug=%v", command.Name, debug), func(t *testing.T) {
				config := loadConfigString(kafkaDisabledBaskervilleConfString)
				config.Debug = debug
				decisionLists := NewDynamicDecisionLists()

				handleCommand(config, command, decisionLists)

				assertDecisionListsEmpty(t, decisionLists)
			})
		}
	}
}

func TestHandleCommand_DisabledBaskerville_OtherHostsUnaffected(t *testing.T) {
	config := loadConfigString(kafkaDisabledBaskervilleConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", Host: "enabled.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_all", Host: "enabled.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "block_ua", Host: "enabled.com", UA: "curl/7.68.0"}, decisionLists)

	_, ipOk := decisionLists.Check("", "1.2.3.4")
	_, hostOk := decisionLists.CheckByHost("enabled.com")
	_, uaOk := decisionLists.CheckByUA("curl/7.68.0", "enabled.com")
	assert.True(t, ipOk)
	assert.True(t, hostOk)
	assert.True(t, uaOk)
}

func TestHandleCommand_DisabledBaskerville_DropsClearRules(t *testing.T) {
	for _, debug := range []bool{false, true} {
		t.Run(fmt.Sprintf("debug=%v", debug), func(t *testing.T) {
			config := loadConfigString(kafkaDisabledBaskervilleConfString)
			config.Debug = debug
			decisionLists := NewDynamicDecisionLists()
			decisionLists.UpdateByHost(config, "disabled.com", time.Now().Add(time.Minute), Challenge, true, 0)
			decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), NginxBlock, true, "disabled.com", 0)
			decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), NginxBlock, true, "disabled.com", 0)
			decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)

			// the whole command is dropped, including the fields that are not per-site
			handleCommand(config, commandMessage{
				Name:      "clear_rules",
				Host:      "disabled.com",
				Value:     "1.2.3.4",
				SessionId: "session-a",
				UA:        "curl/7.68.0",
			}, decisionLists)

			_, hostOk := decisionLists.CheckByHost("disabled.com")
			_, ipOk := decisionLists.Check("", "1.2.3.4")
			_, sessionOk := decisionLists.Check("session-a", "")
			_, uaOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
			assert.True(t, hostOk)
			assert.True(t, ipOk)
			assert.True(t, sessionOk)
			assert.True(t, uaOk)
		})
	}
}

func TestHandleCommand_ClearRules_NoFieldsIsNoop(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, 0)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules"}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	assert.True(t, hostOk)
	assert.True(t, ipOk)
}

func TestHandleCommand_BlockSubnet_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_subnet", Value: "202.46.62.0/24", Host: "my.wiki"}, decisionLists)

	for _, ip := range []string{"202.46.62.1", "202.46.62.120", "202.46.62.254"} {
		expiringDecision, ok := decisionLists.CheckBySubnet(ip)
		assert.True(t, ok, ip)
		assert.Equal(t, NginxBlock, expiringDecision.Decision, ip)
		assert.WithinDuration(t, time.Now().Add(600*time.Second), expiringDecision.Expires, 5*time.Second)
	}
	_, ok := decisionLists.CheckBySubnet("202.46.63.1")
	assert.False(t, ok)
}

func TestHandleCommand_BlockSubnet_SiteTtlAndTTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString + `
sites_to_block_ip_ttl_seconds:
  my.wiki: 120
`)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_subnet", Value: "10.1.1.0/24", Host: "my.wiki"}, decisionLists)
	handleCommand(config, commandMessage{Name: "block_subnet", Value: "10.2.2.0/24", Host: "my.wiki", TTL: 1800}, decisionLists)

	siteTtl, ok := decisionLists.CheckBySubnet("10.1.1.1")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(120*time.Second), siteTtl.Expires, 5*time.Second)

	overrideTtl, ok := decisionLists.CheckBySubnet("10.2.2.1")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(1800*time.Second), overrideTtl.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeSubnet_DefaultTtlAndTTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_subnet", Value: "10.1.1.0/24", Host: "my.wiki"}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_subnet", Value: "10.2.2.0/24", Host: "my.wiki", TTL: 15}, decisionLists)

	defaultTtl, ok := decisionLists.CheckBySubnet("10.1.1.1")
	assert.True(t, ok)
	assert.Equal(t, Challenge, defaultTtl.Decision)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), defaultTtl.Expires, 5*time.Second)

	overrideTtl, ok := decisionLists.CheckBySubnet("10.2.2.1")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), overrideTtl.Expires, 5*time.Second)
}

func TestHandleCommand_Subnet_NormalizesToNetworkAddress(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_subnet", Value: "202.46.62.77/24", Host: "my.wiki"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckBySubnet("202.46.62.1")
	assert.True(t, ok)
	assert.Equal(t, "202.46.62.0/24", expiringDecision.IpAddress)
}

func TestHandleCommand_Subnet_InvalidValueIgnored(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)

	for _, value := range []string{"", "202.46.62.1", "202.46.62.0/33", "2001:db8::/32", "0.0.0.0/0", "garbage"} {
		for _, name := range []string{"block_subnet", "challenge_subnet"} {
			decisionLists := NewDynamicDecisionLists()
			handleCommand(config, commandMessage{Name: name, Value: value, Host: "my.wiki"}, decisionLists)
			assertDecisionListsEmpty(t, decisionLists)
		}
	}
}

func TestHandleCommand_ClearRules_Subnet(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "202.46.62.0/24"), time.Now().Add(time.Minute), NginxBlock, true, "my.wiki", 0)
	decisionLists.Update(config, "202.46.62.1", time.Now().Add(time.Minute), NginxBlock, true, "my.wiki", 0)

	// a non-normalized subnet still clears the normalized entry, and leaves the exact ip alone
	handleCommand(config, commandMessage{Name: "clear_rules", Value: "202.46.62.9/24"}, decisionLists)

	_, subnetOk := decisionLists.CheckBySubnet("202.46.62.1")
	_, ipOk := decisionLists.Check("", "202.46.62.1")
	assert.False(t, subnetOk)
	assert.True(t, ipOk)

	// a plain ip clears the ip, not a subnet covering it
	decisionLists.UpdateBySubnet(config, mustParseSubnet(t, "202.46.62.0/24"), time.Now().Add(time.Minute), NginxBlock, true, "my.wiki", 0)
	handleCommand(config, commandMessage{Name: "clear_rules", Value: "202.46.62.1"}, decisionLists)

	_, subnetOk = decisionLists.CheckBySubnet("202.46.62.1")
	_, ipOk = decisionLists.Check("", "202.46.62.1")
	assert.True(t, subnetOk)
	assert.False(t, ipOk)
}

func TestHandleCommand_UA_EmptyHostDropped(t *testing.T) {
	for _, name := range []string{"challenge_ua", "block_ua"} {
		t.Run(name, func(t *testing.T) {
			config := loadConfigString(kafkaTestConfString)
			decisionLists := NewDynamicDecisionLists()

			handleCommand(config, commandMessage{Name: name, UA: "curl/7.68.0"}, decisionLists)

			assertDecisionListsEmpty(t, decisionLists)
		})
	}
}

func TestHandleCommand_UA_OtherHostUnaffected(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	_, ok := decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByUAAndHost_OnlyThatHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "other.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	_, exampleOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	_, otherOk := decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.False(t, exampleOk)
	assert.True(t, otherOk)
}

func TestHandleCommand_ClearRules_ByUAWithoutHost_EveryHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", 0)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true, "other.com", 0)

	handleCommand(config, commandMessage{Name: "clear_rules", UA: "curl/7.68.0"}, decisionLists)

	_, exampleOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	_, otherOk := decisionLists.CheckByUA("curl/7.68.0", "other.com")
	assert.False(t, exampleOk)
	assert.False(t, otherOk)
}

func TestHandleCommand_AltChaMaxNumber(t *testing.T) {
	// what each list stores for a given altcha_max_number JSON field ("" = field absent)
	cases := map[string]int64{
		"":                               0, // config.AltChaMaxNumber
		`, "altcha_max_number": 5000`:    5000,
		`, "altcha_max_number": 10`:      AltChaMaxNumberMin,
		`, "altcha_max_number": 0`:       AltChaMaxNumberMin,
		`, "altcha_max_number": -1`:      AltChaMaxNumberMin,
		`, "altcha_max_number": 5000000`: AltChaMaxNumberMax,
		`, "altcha_max_number": 20000`:   20000,
	}
	for field, want := range cases {
		t.Run(field, func(t *testing.T) {
			config := loadConfigString(kafkaTestConfString)
			decisionLists := NewDynamicDecisionLists()

			for _, raw := range []string{
				`{"name": "altcha_challenge_ip", "value": "1.2.3.4", "host": "example.com"` + field + `}`,
				`{"name": "altcha_challenge_subnet", "value": "5.6.7.0/24", "host": "example.com"` + field + `}`,
				`{"name": "altcha_challenge_session", "value": "1.2.3.4", "session_id": "session-a", "host": "example.com"` + field + `}`,
				`{"name": "altcha_challenge_all", "host": "example.com"` + field + `}`,
				`{"name": "altcha_challenge_ua", "ua": "curl/7.68.0", "host": "example.com"` + field + `}`,
			} {
				var command commandMessage
				assert.Nil(t, json.Unmarshal([]byte(raw), &command), raw)
				handleCommand(config, command, decisionLists)
			}

			ipDecision, ipOk := decisionLists.Check("", "1.2.3.4")
			subnetDecision, subnetOk := decisionLists.CheckBySubnet("5.6.7.8")
			sessionDecision, sessionOk := decisionLists.Check("session-a", "")
			hostDecision, hostOk := decisionLists.CheckByHost("example.com")
			uaDecision, uaOk := decisionLists.CheckByUA("curl/7.68.0", "example.com")
			assert.True(t, ipOk && subnetOk && sessionOk && hostOk && uaOk)
			for _, d := range []ExpiringDecision{ipDecision, subnetDecision, sessionDecision, hostDecision, uaDecision} {
				assert.Equal(t, AltChaChallenge, d.Decision)
				assert.Equal(t, want, d.altchaMaxNumber)
			}
		})
	}
}

func TestHandleCommand_AltChaMaxNumber_IgnoredByOtherCommands(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	maxNumber := int64(300000)

	handleCommand(config, commandMessage{Name: "challenge_all", Host: "example.com", AltChaMaxNumber: &maxNumber}, decisionLists)

	hostDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, hostDecision.Decision)
	assert.Equal(t, int64(0), hostDecision.altchaMaxNumber)
}

func TestHandleCommand_AltChaMaxNumber_ResendChangesDifficulty(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	easy, hard := int64(2000), int64(15000)

	handleCommand(config, commandMessage{Name: "altcha_challenge_all", Host: "example.com", AltChaMaxNumber: &easy}, decisionLists)
	handleCommand(config, commandMessage{Name: "altcha_challenge_all", Host: "example.com", AltChaMaxNumber: &hard}, decisionLists)

	hostDecision, _ := decisionLists.CheckByHost("example.com")
	assert.Equal(t, hard, hostDecision.altchaMaxNumber)
}
