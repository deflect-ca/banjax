// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// buildDecisionForNginxTestContext builds a gin.Context carrying the same
// X-Client-IP / X-Requested-Host / X-Requested-Path / X-Client-User-Agent headers
// (and session cookie) that nginx's auth_request sends to decisionForNginx2.
func buildDecisionForNginxTestContext(clientIp, host, path, userAgent, sessionId string) *gin.Context {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())

	req := httptest.NewRequest("GET", "/auth_request", nil)
	req.Header.Set("X-Client-IP", clientIp)
	req.Header.Set("X-Requested-Host", host)
	req.Header.Set("X-Requested-Path", path)
	req.Header.Set("X-Client-User-Agent", userAgent)
	if sessionId != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: sessionId})
	}
	c.Request = req

	return c
}

// TestDecisionForNginx2_ExpiringDecisionOrder verifies the expiring decision list is
// applied narrowest-scope first: session id, then user agent, then a challenge_all
// host-wide decision, then ip.
func TestDecisionForNginx2_ExpiringDecisionOrder(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()
	banner := &MockBanner{}

	const clientIp = "1.1.1.1"
	const host = "example.com"
	const path = "/"
	const userAgent = "some-ua"
	const sessionId = "session-a"

	t.Run("session id wins over user agent, host, and ip", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), Challenge, true, host)
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host)

		c := buildDecisionForNginxTestContext(clientIp, host, path, userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringChallenge, result.DecisionListResult)
	})

	t.Run("user agent wins over host and ip when there is no session decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host)

		c := buildDecisionForNginxTestContext(clientIp, host, path, userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringUAChallenge, result.DecisionListResult)
	})

	t.Run("challenge_all host decision wins over ip when there is no session or ua decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host)

		c := buildDecisionForNginxTestContext(clientIp, host, path, "unrelated-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringSiteWideChallenge, result.DecisionListResult)
	})

	t.Run("ip applies when nothing narrower matches", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host)

		c := buildDecisionForNginxTestContext(clientIp, "unrelated-host.com", path, "unrelated-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringChallenge, result.DecisionListResult)
	})
}
