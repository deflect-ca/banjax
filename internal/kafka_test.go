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
`

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

func TestHandleCommand_ClearRules_ByHost(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)

	handleCommand(config, commandMessage{Name: "clear_rules", Host: "example.com"}, decisionLists)

	_, ok := decisionLists.CheckByHost("example.com")
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

func TestHandleCommand_ClearRules_AllThreeAtOnce(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.Update(config, "1.2.3.4", time.Now().Add(time.Minute), Challenge, true, "example.com")
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com")

	handleCommand(config, commandMessage{
		Name:      "clear_rules",
		Host:      "example.com",
		Value:     "1.2.3.4",
		SessionId: "session-a",
	}, decisionLists)

	_, hostOk := decisionLists.CheckByHost("example.com")
	_, ipOk := decisionLists.Check("", "1.2.3.4")
	_, sessionOk := decisionLists.Check("session-a", "")
	assert.False(t, hostOk)
	assert.False(t, ipOk)
	assert.False(t, sessionOk)
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
