// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
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
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, path, userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringChallenge, result.DecisionListResult)
	})

	t.Run("user agent wins over host and ip when there is no session decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, path, userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringUAChallenge, result.DecisionListResult)
	})

	t.Run("challenge_all host decision wins over ip when there is no session or ua decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, path, "unrelated-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringSiteWideChallenge, result.DecisionListResult)
	})

	t.Run("ip applies when nothing narrower matches", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, "unrelated-host.com", path, "unrelated-ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

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
			decisionLists.UpdateByUA(config, "bad-bot/1.0", time.Now().Add(time.Minute), decision, true, "example.com", AltChaOptions{})
			decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

			c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "bad-bot/1.0", "")
			result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

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
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), Allow, false, host, AltChaOptions{})
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringAccessGranted, result.DecisionListResult)
		assert.Equal(t, 200, c.Writer.Status())
		assert.Equal(t, "@access_granted", c.Writer.Header().Get("X-Accel-Redirect"))
		assert.Empty(t, banner.triggers)
	})

	t.Run("baskerville session block is denied and logged", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.Equal(t, 403, c.Writer.Status())
		assert.Equal(t, []string{"baskerville"}, banner.triggers)
	})

	t.Run("regex session block is denied but not logged again", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySessionId(config, clientIp, sessionId, time.Now().Add(time.Minute), NginxBlock, false, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, sessionId)
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.Empty(t, banner.triggers)
	})

	t.Run("unknown session id falls through to the ip decision", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "unknown-session")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

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
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("baskerville ua block is skipped and not logged", func(t *testing.T) {
		banner := &listDecisionRecordingBanner{}
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, NoMention, result.DecisionListResult)
		assert.Equal(t, 200, c.Writer.Status())
		assert.Empty(t, banner.triggers)
	})

	t.Run("baskerville challenge_all is skipped", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("skipped ua and host decisions fall through to a regex ip decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, false, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

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
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, PerSiteShaInvPathException, result.DecisionListResult)
	})

	t.Run("challenge_all is exempted on an exception path", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, PerSiteShaInvPathException, result.DecisionListResult)
	})

	t.Run("challenge_all still applies off the exception path", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, host, time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/about", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

		assert.Equal(t, ExpiringSiteWideChallenge, result.DecisionListResult)
	})

	t.Run("ua block is not exempted by a sha-inv path exception", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByUA(config, userAgent, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext(clientIp, host, "/wp-json/v2/posts", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

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
	decisionLists.UpdateByUA(config, "some-ua", time.Now().Add(-time.Second), NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(-time.Second), Challenge, true, AltChaOptions{})

	c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "some-ua", "")
	result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

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
	decisionLists.UpdateByUA(config, "some-ua", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})
	decisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

	c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "some-ua", "")
	result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

	assert.Equal(t, PerSiteAccessGranted, result.DecisionListResult)
}

func TestDecisionForNginx2_ExpiringSubnetDecision(t *testing.T) {
	config := loadConfigString(`
sites_to_disable_baskerville:
  disabled.com: true
`)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	const host = "my.wiki"
	const userAgent = "some-ua"
	subnet, err := ParseSubnet("202.46.62.0/24")
	assert.Nil(t, err)

	t.Run("block_subnet blocks every ip in the subnet", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		for _, clientIp := range []string{"202.46.62.1", "202.46.62.254"} {
			banner := &listDecisionRecordingBanner{}
			c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
			result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)

			assert.Equal(t, ExpiringSubnetBlock, result.DecisionListResult, clientIp)
			assert.Equal(t, 403, c.Writer.Status())
			assert.Equal(t, "ExpiringSubnetBlock", c.Writer.Header().Get("X-Banjax-Decision"))
			assert.Equal(t, []string{"baskerville"}, banner.triggers)
		}
	})

	t.Run("ip outside the subnet is unaffected", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.63.1", host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("challenge_subnet challenges", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.62.7", host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, ExpiringSubnetChallenge, result.DecisionListResult)
	})

	t.Run("more serious subnet decision wins over the ip's own", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, "202.46.62.7", time.Now().Add(time.Minute), Challenge, false, host, AltChaOptions{})
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.62.7", host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, ExpiringSubnetBlock, result.DecisionListResult)
	})

	t.Run("ip's own decision wins when at least as serious", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, "202.46.62.7", time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.62.7", host, "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
	})

	t.Run("site with baskerville disabled skips the subnet decision", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(config, subnet, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.62.7", "disabled.com", "/", userAgent, "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, NoMention, result.DecisionListResult)
	})

	t.Run("static allow list wins over the subnet decision", func(t *testing.T) {
		allowConfig := loadConfigString(`
global_decision_lists:
  allow:
    - 202.46.62.7
`)
		allowStaticDecisionLists, err := NewStaticDecisionLists(allowConfig)
		assert.Nil(t, err)
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateBySubnet(allowConfig, subnet, time.Now().Add(time.Minute), NginxBlock, true, host, AltChaOptions{})

		c := buildDecisionForNginxTestContext("202.46.62.7", host, "/", userAgent, "")
		result := decisionForNginx2(c, allowConfig, allowStaticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, GlobalAccessGranted, result.DecisionListResult)
	})
}

func TestDecisionForNginx2_ExpiringUADecisionOnlyAppliesToItsHost(t *testing.T) {
	config := &Config{}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	failedChallengeStates := NewFailedChallengeRateLimitStates()

	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByUA(config, "bad-bot/1.0", time.Now().Add(time.Minute), NginxBlock, true, "example.com", AltChaOptions{})

	c := buildDecisionForNginxTestContext("1.1.1.1", "example.com", "/", "bad-bot/1.0", "")
	result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})
	assert.Equal(t, ExpiringUABlock, result.DecisionListResult)

	c = buildDecisionForNginxTestContext("1.1.1.1", "other.com", "/", "bad-bot/1.0", "")
	result = decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, failedChallengeStates, NewFailedChallengeRateLimitStates(), &MockBanner{})
	assert.Equal(t, NoMention, result.DecisionListResult)
}

func TestDecisionForNginx2_ExpiringAltChaServesStoredMaxNumber(t *testing.T) {
	// a config difficulty no test could solve, so a quick solve proves the stored one was used
	config := loadConfigString(`
altcha_max_number: 1000000000
altcha_cost: 10
hmac_secret: secret
altcha_cookie_ttl_seconds: 3600
altcha_too_many_failed_challenges_threshold: 10
altcha_too_many_failed_challenges_interval_seconds: 10
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)

	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "stored.com", time.Now().Add(time.Minute), AltChaChallenge, true, AltChaOptions{MaxNumber: 5})

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = buildDecisionForNginxTestContext("1.1.1.1", "stored.com", "/", "some-ua", "").Request
	decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

	challenge := altchaChallengeFromPage(t, recorder.Body.String())
	assert.LessOrEqual(t, solveAltCha(t, challenge).Counter, 5)
}

// Challenge pages must say why the client was challenged, so nginx can log it like it does
// for granted and denied requests.
func TestDecisionForNginx2_ChallengeResponsesCarryDecision(t *testing.T) {
	config := loadConfigString(`
hmac_secret: secret
altcha_cost: 10
altcha_max_number: 5
altcha_cookie_ttl_seconds: 3600
sha_inv_cookie_ttl_seconds: 3600
sha_inv_expected_zero_bits: 10
too_many_failed_challenges_threshold: 10
too_many_failed_challenges_interval_seconds: 10
altcha_too_many_failed_challenges_threshold: 10
altcha_too_many_failed_challenges_interval_seconds: 10
per_site_decision_lists:
  static.com:
    challenge:
      - 1.1.1.1
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	config.ChallengerBytes = shaInvChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	subnet, err := ParseSubnet("2.2.2.0/24")
	assert.Nil(t, err)

	decisionLists := NewDynamicDecisionLists()
	expires := time.Now().Add(time.Minute)
	decisionLists.UpdateByUA(config, "bad-bot/1.0", expires, AltChaChallenge, true, "ua.com", AltChaOptions{})
	decisionLists.UpdateByHost(config, "sitewide.com", expires, Challenge, true, AltChaOptions{})
	decisionLists.UpdateBySubnet(config, subnet, expires, AltChaChallenge, true, "subnet.com", AltChaOptions{})
	decisionLists.Update(config, "3.3.3.3", expires, Challenge, true, "ip.com", AltChaOptions{})

	serve := func(ip, host, ua string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = buildDecisionForNginxTestContext(ip, host, "/", ua, "").Request
		for _, cookie := range cookies {
			c.Request.AddCookie(cookie)
		}
		decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
		return recorder
	}

	cases := []struct {
		name, ip, host, ua, want string
	}{
		{"static per-site challenge", "1.1.1.1", "static.com", "ua", "PerSiteChallenge"},
		{"expiring ua altcha", "9.9.9.9", "ua.com", "bad-bot/1.0", "ExpiringUAAltChaChallenge"},
		{"expiring sitewide challenge", "9.9.9.9", "sitewide.com", "ua", "ExpiringSiteWideChallenge"},
		{"expiring subnet altcha", "2.2.2.7", "subnet.com", "ua", "ExpiringSubnetAltChaChallenge"},
		{"expiring ip challenge", "3.3.3.3", "ip.com", "ua", "ExpiringChallenge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := serve(tc.ip, tc.host, tc.ua)
			assert.Equal(t, 429, recorder.Code)
			assert.Equal(t, tc.want, recorder.Header().Get("X-Banjax-Decision"))
		})
	}

	// once solved, the header reports the pass instead of the trigger
	t.Run("solved altcha reports the pass", func(t *testing.T) {
		challenge := altchaChallengeFromPage(t, serve("9.9.9.9", "ua.com", "bad-bot/1.0").Body.String())
		recorder := serve("9.9.9.9", "ua.com", "bad-bot/1.0",
			&http.Cookie{Name: AltChaCookieName, Value: solveAltChaToCookie(t, challenge)})
		assert.Equal(t, 200, recorder.Code)
		assert.Equal(t, "AltChaChallengePassed", recorder.Header().Get("X-Banjax-Decision"))
	})
}

func TestSitewideAltChaList(t *testing.T) {
	config := loadConfigString(`
hmac_secret: secret
altcha_cost: 10
altcha_max_number: 5
altcha_cookie_ttl_seconds: 3600
sha_inv_cookie_ttl_seconds: 3600
sha_inv_expected_zero_bits: 10
too_many_failed_challenges_threshold: 1
too_many_failed_challenges_interval_seconds: 60
altcha_too_many_failed_challenges_threshold: 1
altcha_too_many_failed_challenges_interval_seconds: 60
sitewide_altcha_list:
  altcha.com: block
  both.com: block
  lenient.com: no_block
sitewide_sha_inv_list:
  sha.com: block
  both.com: block
password_protected_path_exceptions:
  altcha.com:
    - /public
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	config.ChallengerBytes = shaInvChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)

	newServer := func(decisionLists *DynamicDecisionLists) func(ip, host, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		// failure counters live across requests, as they do in banjax
		shaStates, altchaStates := NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates()
		return func(ip, host, path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = buildDecisionForNginxTestContext(ip, host, path, "ua", "").Request
			for _, cookie := range cookies {
				c.Request.AddCookie(cookie)
			}
			decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, shaStates, altchaStates, &MockBanner{})
			return recorder
		}
	}

	t.Run("listed site gets the altcha challenge", func(t *testing.T) {
		recorder := newServer(NewDynamicDecisionLists())("1.1.1.1", "altcha.com", "/")
		assert.Equal(t, 429, recorder.Code)
		assert.Equal(t, "SiteWideAltChaChallenge", recorder.Header().Get("X-Banjax-Decision"))
		assert.Contains(t, recorder.Body.String(), "<altcha-widget")
	})

	t.Run("checked before sitewide_sha_inv_list", func(t *testing.T) {
		serve := newServer(NewDynamicDecisionLists())
		recorder := serve("1.1.1.1", "both.com", "/")
		assert.Equal(t, "SiteWideAltChaChallenge", recorder.Header().Get("X-Banjax-Decision"))
		assert.NotContains(t, recorder.Body.String(), "deflect_challenge3")

		// sites only in the sha-inv list are unchanged
		recorder = serve("1.1.1.1", "sha.com", "/")
		assert.Equal(t, "SiteWideChallenge", recorder.Header().Get("X-Banjax-Decision"))
	})

	t.Run("solved challenge passes", func(t *testing.T) {
		serve := newServer(NewDynamicDecisionLists())
		challenge := altchaChallengeFromPage(t, serve("1.1.1.1", "altcha.com", "/").Body.String())
		recorder := serve("1.1.1.1", "altcha.com", "/", &http.Cookie{Name: AltChaCookieName, Value: solveAltChaToCookie(t, challenge)})
		assert.Equal(t, 200, recorder.Code)
		assert.Equal(t, "AltChaChallengePassed", recorder.Header().Get("X-Banjax-Decision"))
	})

	t.Run("password protected path exceptions apply", func(t *testing.T) {
		recorder := newServer(NewDynamicDecisionLists())("1.1.1.1", "altcha.com", "/public")
		assert.Equal(t, 200, recorder.Code)
		assert.Equal(t, "SiteWideAltChaChallengeException", recorder.Header().Get("X-Banjax-Decision"))
	})

	t.Run("block bans after too many failures, no_block never does", func(t *testing.T) {
		serve := newServer(NewDynamicDecisionLists())
		serve("1.1.1.1", "altcha.com", "/")
		assert.Equal(t, 403, serve("1.1.1.1", "altcha.com", "/").Code, "threshold 1: the second failure bans")

		for i := 0; i < 3; i++ {
			assert.Equal(t, 429, serve("2.2.2.2", "lenient.com", "/").Code)
		}
	})

	t.Run("expiring decisions are checked first", func(t *testing.T) {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.UpdateByHost(config, "altcha.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})
		recorder := newServer(decisionLists)("1.1.1.1", "altcha.com", "/")
		assert.Equal(t, "ExpiringSiteWideChallenge", recorder.Header().Get("X-Banjax-Decision"))
	})
}

func TestSitewideAltChaList_InvalidFailAction(t *testing.T) {
	_, err := NewStaticDecisionLists(loadConfigString(`
sitewide_altcha_list:
  altcha.com: sometimes
`))
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "sitewide_altcha_list[altcha.com]")
}

// Only a Kafka command with altcha_click or a *_click sitewide_altcha_list entry serves the
// one-click challenge; every other AltCha decision solves on page load.
func TestDecisionForNginx2_AltChaClickMode(t *testing.T) {
	config := loadConfigString(`
hmac_secret: secret
altcha_cost: 10
altcha_max_number: 5
altcha_cookie_ttl_seconds: 3600
altcha_too_many_failed_challenges_threshold: 10
altcha_too_many_failed_challenges_interval_seconds: 10
sitewide_altcha_list:
  sitewide.com: block
  sitewide-click.com: no_block_click
per_site_decision_lists:
  static.com:
    altcha_challenge:
      - 1.1.1.1
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)

	decisionLists := NewDynamicDecisionLists()
	expires := time.Now().Add(time.Minute)
	decisionLists.UpdateByHost(config, "kafka.com", expires, AltChaChallenge, true, AltChaOptions{})
	decisionLists.UpdateByHost(config, "kafka-click.com", expires, AltChaChallenge, true, AltChaOptions{Click: true})

	cases := []struct {
		host, ip string
		click    bool
	}{
		{"static.com", "1.1.1.1", false},
		{"kafka.com", "9.9.9.9", false},
		{"kafka-click.com", "9.9.9.9", true},
		{"sitewide.com", "9.9.9.9", false},
		{"sitewide-click.com", "9.9.9.9", true},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = buildDecisionForNginxTestContext(tc.ip, tc.host, "/", "ua", "").Request
			decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

			assert.Equal(t, 429, recorder.Code)
			if tc.click {
				assert.Contains(t, recorder.Body.String(), `<altcha-widget id="altcha" auto="off"`)
			} else {
				assert.Contains(t, recorder.Body.String(), `<altcha-widget id="altcha" auto="onload"`)
			}
		})
	}
}

// The decisionForNginx log line shows the AltCha settings that were applied, and nothing when
// the request did not reach an AltCha challenge.
func TestDecisionForNginx2_ResultIncludesAltChaOptions(t *testing.T) {
	config := loadConfigString(`
hmac_secret: secret
altcha_cost: 10
altcha_max_number: 7
altcha_cookie_ttl_seconds: 3600
altcha_too_many_failed_challenges_threshold: 10
altcha_too_many_failed_challenges_interval_seconds: 10
sitewide_altcha_list:
  sitewide-click.com: no_block_click
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "kafka.com", time.Now().Add(time.Minute), AltChaChallenge, true, AltChaOptions{MaxNumber: 5000})

	result := func(host string) DecisionForNginxResult {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = buildDecisionForNginxTestContext("9.9.9.9", host, "/", "ua", "").Request
		return decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
	}

	kafka := result("kafka.com")
	assert.Equal(t, &AltChaOptions{MaxNumber: 5000}, kafka.AltChaOptions)
	// unset difficulty is shown as the config value actually used
	sitewide := result("sitewide-click.com")
	assert.Equal(t, &AltChaOptions{MaxNumber: 7, Click: true}, sitewide.AltChaOptions)
	assert.Nil(t, result("nothing.com").AltChaOptions)

	logged, err := json.Marshal(sitewide)
	assert.Nil(t, err)
	assert.Contains(t, string(logged), `"AltChaOptions":{"MaxNumber":7,"Click":true}`)
	logged, err = json.Marshal(result("nothing.com"))
	assert.Nil(t, err)
	assert.Contains(t, string(logged), `"AltChaOptions":null`)
}

// A client that solved an AltCha challenge is not asked to also solve a sha-inv one; the
// reverse does not hold.
func TestDecisionForNginx2_AltChaCookiePassesShaInvChallenge(t *testing.T) {
	config := loadConfigString(`
hmac_secret: secret
altcha_cost: 10
altcha_max_number: 5
altcha_cookie_ttl_seconds: 3600
sha_inv_cookie_ttl_seconds: 3600
sha_inv_expected_zero_bits: 10
too_many_failed_challenges_threshold: 10
too_many_failed_challenges_interval_seconds: 10
altcha_too_many_failed_challenges_threshold: 10
altcha_too_many_failed_challenges_interval_seconds: 10
sitewide_sha_inv_list:
  sha-sitewide.com: block
sitewide_altcha_list:
  altcha-sitewide.com: block
per_site_decision_lists:
  sha-static.com:
    challenge:
      - 1.1.1.1
`)
	config.AltChaChallengerBytes = altchaChallengeEmbed
	config.ChallengerBytes = shaInvChallengeEmbed
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateByHost(config, "sha-expiring.com", time.Now().Add(time.Minute), Challenge, true, AltChaOptions{})

	serve := func(ip, host string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		c.Request = buildDecisionForNginxTestContext(ip, host, "/", "ua", "").Request
		for _, cookie := range cookies {
			c.Request.AddCookie(cookie)
		}
		decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths, NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
		return recorder
	}

	// solve a real AltCha challenge as 1.1.1.1
	challenge := altchaChallengeFromPage(t, serve("1.1.1.1", "altcha-sitewide.com").Body.String())
	altchaCookie := &http.Cookie{Name: AltChaCookieName, Value: solveAltChaToCookie(t, challenge)}

	for _, host := range []string{"sha-sitewide.com", "sha-static.com", "sha-expiring.com"} {
		t.Run("altcha cookie passes sha-inv on "+host, func(t *testing.T) {
			recorder := serve("1.1.1.1", host, altchaCookie)
			assert.Equal(t, 200, recorder.Code)
			assert.Equal(t, "ShaChallengePassedByAltCha", recorder.Header().Get("X-Banjax-Decision"))
		})
	}

	t.Run("an altcha cookie bound to another client does not", func(t *testing.T) {
		recorder := serve("2.2.2.2", "sha-sitewide.com", altchaCookie)
		assert.Equal(t, 429, recorder.Code)
		assert.Contains(t, recorder.Body.String(), "deflect_challenge3")
	})

	t.Run("a forged altcha cookie does not", func(t *testing.T) {
		recorder := serve("1.1.1.1", "sha-sitewide.com", &http.Cookie{Name: AltChaCookieName, Value: "Zm9yZ2Vk"})
		assert.Equal(t, 429, recorder.Code)
		assert.Equal(t, "SiteWideChallenge", recorder.Header().Get("X-Banjax-Decision"))
	})

	t.Run("a sha-inv cookie does not pass an altcha challenge", func(t *testing.T) {
		recorder := serve("1.1.1.1", "altcha-sitewide.com", &http.Cookie{Name: ChallengeCookieName, Value: "anything"})
		assert.Equal(t, 429, recorder.Code)
		assert.Equal(t, "SiteWideAltChaChallenge", recorder.Header().Get("X-Banjax-Decision"))
	})
}
