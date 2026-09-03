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

func TestDynamicDecisionLists_UpdateByHost_UpgradeOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	expiringDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a lower-severity decision should not downgrade the existing one
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Allow, true)
	expiringDecision, ok = decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a higher-severity decision should upgrade it
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), NginxBlock, true)
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

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(-time.Second), Challenge, true)

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveByHost(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.RemoveByHost("example.com")

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveBySessionId(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-a", time.Now().Add(time.Minute), Challenge, true, "example.com")
	decisionLists.UpdateBySessionId(config, "1.2.3.4", "session-b", time.Now().Add(time.Minute), Challenge, true, "example.com")

	decisionLists.RemoveBySessionId("session-a")

	_, okA := decisionLists.Check("session-a", "")
	_, okB := decisionLists.Check("session-b", "")
	assert.False(t, okA)
	assert.True(t, okB)
}

func TestDynamicDecisionLists_Clear_WipesHostMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.Clear()

	_, ok := decisionLists.CheckByHost("example.com")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveExpired_SweepsHostMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByHost(config, "expired.com", time.Now().Add(-time.Second), Challenge, true)
	decisionLists.UpdateByHost(config, "live.com", time.Now().Add(time.Minute), Challenge, true)

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

	decisionLists.UpdateByHost(config, "challenged.com", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateByHost(config, "blocked.com", time.Now().Add(time.Minute), NginxBlock, true)

	_, _, lenExpiringSitewideChallenges, lenExpiringSitewideBlocks, _, _ := decisionLists.Metrics()
	assert.Equal(t, 1, lenExpiringSitewideChallenges)
	assert.Equal(t, 1, lenExpiringSitewideBlocks)
}

func TestDynamicDecisionLists_UpdateByUA_UpgradeOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true)
	expiringDecision, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a lower-severity decision should not downgrade the existing one
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Allow, true)
	expiringDecision, ok = decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, Challenge, expiringDecision.Decision)

	// a higher-severity decision should upgrade it
	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)
	expiringDecision, ok = decisionLists.CheckByUA("curl/7.68.0")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, expiringDecision.Decision)
}

func TestDynamicDecisionLists_CheckByUA_NotFound(t *testing.T) {
	decisionLists := NewDynamicDecisionLists()

	_, ok := decisionLists.CheckByUA("unknown-agent")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_CheckByUA_LazyExpiry(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(-time.Second), Challenge, true)

	_, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_CheckByUA_ExactMatchOnly(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), NginxBlock, true)

	_, ok := decisionLists.CheckByUA("curl/7.68.0 extra")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveByUA(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.RemoveByUA("curl/7.68.0")

	_, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_Clear_WipesUAMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "curl/7.68.0", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.Clear()

	_, ok := decisionLists.CheckByUA("curl/7.68.0")
	assert.False(t, ok)
}

func TestDynamicDecisionLists_RemoveExpired_SweepsUAMap(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "expired-agent", time.Now().Add(-time.Second), Challenge, true)
	decisionLists.UpdateByUA(config, "live-agent", time.Now().Add(time.Minute), Challenge, true)

	decisionLists.removeExpired()

	decisionLists.mutex.Lock()
	_, expiredStillThere := decisionLists.value.expiringDecisionListsUA["expired-agent"]
	_, liveStillThere := decisionLists.value.expiringDecisionListsUA["live-agent"]
	decisionLists.mutex.Unlock()

	assert.False(t, expiredStillThere)
	assert.True(t, liveStillThere)
}

func TestDynamicDecisionLists_Metrics_CountsUAEntries(t *testing.T) {
	config := &Config{}
	decisionLists := NewDynamicDecisionLists()

	decisionLists.UpdateByUA(config, "challenged-agent", time.Now().Add(time.Minute), Challenge, true)
	decisionLists.UpdateByUA(config, "blocked-agent", time.Now().Add(time.Minute), NginxBlock, true)

	_, _, _, _, lenExpiringUAChallenges, lenExpiringUABlocks := decisionLists.Metrics()
	assert.Equal(t, 1, lenExpiringUAChallenges)
	assert.Equal(t, 1, lenExpiringUABlocks)
}
