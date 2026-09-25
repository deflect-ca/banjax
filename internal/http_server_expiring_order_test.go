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

// listDecisionRecordingBanner is a MockBanner that remembers the trigger of every
// LogListDecision call, so tests can check which list a decision was logged under.
type listDecisionRecordingBanner struct {
	MockBanner
	triggers []string
}

func (b *listDecisionRecordingBanner) LogListDecision(
	config *Config,
	ip string,
	userAgent string,
	host string,
	path string,
	method string,
	trigger string,
	decision Decision,
) {
	b.triggers = append(b.triggers, trigger)
}

func TestDecisionForNginx2_ExpiringUABlock(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	for _, decision := range []Decision{NginxBlock, IptablesBlock} {
		t.Run(decision.String(), func(t *testing.T) {
			banner := &listDecisionRecordingBanner{}
			decisionLists := NewDynamicDecisionLists()
			decisionLists.UpdateByUA(config, "bad-bot/1.0", time.Now().Add(time.Minute), decision, true)
			decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)

			c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "bad-bot/1.0", "")
			result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

			assert.Equal(t, ExpiringUABlock, result.DecisionListResult)
			assert.Equal(t, 403, c.Writer.Status())
			assert.Equal(t, "@access_denied", c.Writer.Header().Get("X-Accel-Redirect"))
			assert.Equal(t, "ExpiringUABlock", c.Writer.Header().Get("X-Banjax-Decision"))
			assert.Equal(t, []string{"expiring_ua_list"}, banner.triggers)
		})
	}
}

func TestDecisionForNginx2_ExpiringSessionDecision(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	const clientIp = "1.1.1.1"
	const host = "example.com"
	const userAgent = "some-ua"
	const sessionId = "session-a"

	t.Run("session allow short-circuits ua block and host challenge", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), Allow, false, host)
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true)
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringAccessGranted, result.DecisionListResult)
		assert.Equal(t, 200, c.Writer.Status())
		assert.Equal(t, "@access_granted", c.Writer.Header().Get("X-Accel-Redirect"))
		assert.Empty(t, banner.triggers)
	})

	t.Run("baskerville session block is denied and logged", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), NginxBlock, true, host)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.Equal(t, 403, c.Writer.Status())
		assert.Equal(t, []string{"baskerville"}, banner.triggers)
	})

	t.Run("regex session block is denied but not logged again", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), NginxBlock, false, host)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.Empty(t, banner.triggers)
	})

	t.Run("unknown session id falls through to the ip decision", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), NginxBlock, true, host)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "unknown-session")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.Equal(t, []string{"baskerville"}, banner.triggers)
	})
}

func TestDecisionForNginx2_ExpiringDecisionDisabledBaskerville(t *testing.T) {
	const host = "disabled.com"
	config := &Config{SitesToDisableBaskerville: map[string]bool{host: true}}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	const clientIp = "1.1.1.1"
	const userAgent = "some-ua"

	t.Run("baskerville ua challenge is skipped", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("baskerville ua block is skipped and not logged", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, NoMention, result.DecisionListResult)
		assert.Equal(t, 200, c.Writer.Status())
		assert.Empty(t, banner.triggers)
	})

	t.Run("baskerville challenge_all is skipped", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("skipped ua and host decisions fall through to a regex ip decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true)
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, false, host)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, &MockBanner{})

		assert.Equal(t, ExpiringChallenge, result.DecisionListResult)
	})
}

func TestDecisionForNginx2_ExpiringDecisionShaInvPathException(t *testing.T) {
	const host = "example.com"
	config := &Config{SitesToShaInvPathExceptions: map[string][]string{host: {"/wp-json"}}}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()
	banner := &MockBanner{}

	const clientIp = "1.1.1.1"
	const userAgent = "some-ua"

	t.Run("ua challenge is exempted on an exception path", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, PerSiteShaInvPathException, result.DecisionListResult)
	})

	t.Run("challenge_all is exempted on an exception path", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, PerSiteShaInvPathException, result.DecisionListResult)
	})

	t.Run("challenge_all still applies off the exception path", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/about", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringSiteWideChallenge, result.DecisionListResult)
	})

	t.Run("ua block is not exempted by a sha-inv path exception", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true)

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, banner)

		assert.Equal(t, ExpiringUABlock, result.DecisionListResult)
	})
}

func TestDecisionForNginx2_ExpiredUAAndHostDecisionsIgnored(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "some-ua", time.Now().Add(-time.Second), NginxBlock, true)
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(-time.Second), Challenge, true)

	c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "some-ua", "")
	result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, &MockBanner{})

	assert.Equal(t, NoMention, result.DecisionListResult)
}

func TestDecisionForNginx2_StaticListsWinOverExpiringUAAndHost(t *testing.T) {
	config := loadConfigString(`
per_site_decision_lists:
  example.com:
    allow:
      - 1.1.1.1
`)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "some-ua", time.Now().Add(time.Minute), NginxBlock, true)
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true)

	c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "some-ua", "")
	result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, &MockBanner{})

	assert.Equal(t, PerSiteAccessGranted, result.DecisionListResult)
}
