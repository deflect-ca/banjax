// Copyright (c) 2025, eQualit.ie inc.
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
	handleCommand(config, commandMessage{Name: "challenge_ua", UA: "curl/7.68.0", TTL: 0}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", TTL: -1}, decisionLists)

	hostDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), hostDecision.Expires, 5*time.Second)

	uaDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
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

	handleCommand(config, commandMessage{Name: "challenge_ua", UA: "curl/7.68.0"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.True(t, expiringDecision.fromBaskerville)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeUA_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", UA: "curl/7.68.0", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_ChallengeUA_EmptyUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", UA: ""}, decisionLists)

	_, ok := decisionLists.CheckByUA("")
	assert.False(t, ok)
}

func TestHandleCommand_ChallengeUA_OtherUAUnaffected(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "challenge_ua", UA: "curl/7.68.0"}, decisionLists)

	_, ok := decisionLists.CheckByUA("other-agent")
	assert.False(t, ok)
}

func TestHandleCommand_BlockUA_DefaultTtl(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", UA: "curl/7.68.0"}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.True(t, expiringDecision.fromBaskerville)
	assert.WithinDuration(t, time.Now().Add(600*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockUA_TTLOverride(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", UA: "curl/7.68.0", TTL: 15}, decisionLists)

	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(15*time.Second), expiringDecision.Expires, 5*time.Second)
}

func TestHandleCommand_BlockUA_EmptyUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "block_ua", UA: ""}, decisionLists)

	_, ok := decisionLists.CheckByUA("")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com"}, decisionLists)

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByUA(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true)

	handleCommand(config, commandMessage{Name: "clear_rules", UA: "curl/7.68.0"}, decisionLists)

	_, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_ByIp(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com")

	handleCommand(config, commandMessage{Name: "clear_rules", Value: "1.2.3.4"}, decisionLists)

	_, ok := decisionLists.Check("", "1.2.3.4")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_BySessionId(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com")

	handleCommand(config, commandMessage{Name: "clear_rules", SessionId: "session-a"}, decisionLists)

	_, ok := decisionLists.Check("session-a", "")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_UrlEncodedSessionId(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session with spaces", time.Now().Add(time.Minute), Challenge, true, "example.com")

	handleCommand(config, commandMessage{Name: "clear_rules", SessionId: "session%20with%20spaces"}, decisionLists)

	_, ok := decisionLists.Check("session with spaces", "")
	assert.False(t, ok)
}

func TestHandleCommand_ClearRules_AllAtOnce(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com")
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com")
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)

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
	_, uaOk := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, hostOk)
	assert.False(t, ipOk)
	assert.False(t, sessionOk)
	assert.False(t, uaOk)
}

func TestHandleCommand_ClearRules_OnlyClearsGivenKeys(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateByHost(config, "other.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)
	decisionLists.UpdateByUA(config, "other-agent", time.Now().Add(time.Minute), NginxBlock, true)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com", UA: "curl/7.68.0"}, decisionLists)

	_, otherHostOk := decisionLists.CheckByHost("other.com")
	_, otherUAOk := decisionLists.CheckByUA("other-agent")
	assert.True(t, otherHostOk)
	assert.True(t, otherUAOk)
}

func TestHandleCommand_ClearRules_InvalidSessionIdStillClearsOthers(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "%zz", time.Now().Add(time.Minute), Challenge, true, "example.com")

	// "%zz" is not a valid url escape, so the session part is skipped but the host is still cleared
	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com", SessionId: "%zz"}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, sessionOk := decisionLists.Check("%zz", "")
	assert.False(t, hostOk)
	assert.True(t, sessionOk)
}

func TestHandleCommand_ClearRules_NoFieldsIsNoop(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com")

	handleCommand(config, commandMessage{Name: "clear_rules"}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	assert.True(t, hostOk)
	assert.True(t, ipOk)
}
