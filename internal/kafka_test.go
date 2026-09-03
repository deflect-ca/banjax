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
