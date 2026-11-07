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
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

const (
	xhrTestIp   = "1.2.3.4"
	xhrTestHost = "example.com"
)

func xhrTestConfig(extraYaml string) *Config {
	config := loadConfigString(`
hmac_secret: secret
expiring_decision_ttl_seconds: 3600
sha_inv_cookie_ttl_seconds: 3600
sha_inv_expected_zero_bits: 10
too_many_failed_challenges_threshold: 3
too_many_failed_challenges_interval_seconds: 60
altcha_cost: 10
altcha_max_number: 5
altcha_cookie_ttl_seconds: 3600
altcha_too_many_failed_challenges_threshold: 3
altcha_too_many_failed_challenges_interval_seconds: 60
sitewide_sha_inv_list:
  sitewide.com: block
sitewide_altcha_list:
  altcha-sitewide.com: block
per_site_decision_lists:
  static.com:
    challenge:
      - 1.2.3.4
` + extraYaml)
	config.ChallengerBytes = shaInvChallengeEmbed
	config.AltChaChallengerBytes = altchaChallengeEmbed
	return config
}

// Request headers as nginx forwards them from the client.
var (
	fetchHeaders = map[string]string{
		"Accept":         "application/json",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "cors",
		"Sec-Fetch-Dest": "empty",
		"Referer":        "https://example.com/app",
	}
	jqueryXHRHeaders = map[string]string{
		"Accept":           "application/json, text/javascript, */*; q=0.01",
		"X-Requested-With": "XMLHttpRequest",
	}
	navigationRequestHeaders = map[string]string{
		"Accept":         chromeNavigationAccept,
		"Sec-Fetch-Site": "none",
		"Sec-Fetch-Mode": "navigate",
		"Sec-Fetch-Dest": "document",
	}
	imageHeaders = map[string]string{
		"Accept":         "image/avif,image/webp,*/*",
		"Sec-Fetch-Site": "same-origin",
		"Sec-Fetch-Mode": "no-cors",
		"Sec-Fetch-Dest": "image",
	}
	curlHeaders = map[string]string{"Accept": "*/*"}
)

func withHeader(headers map[string]string, name, value string) map[string]string {
	out := map[string]string{name: value}
	for k, v := range headers {
		if k != name {
			out[k] = v
		}
	}
	return out
}

type xhrHarness struct {
	config              *Config
	staticDecisionLists *StaticDecisionLists
	decisionLists       *DynamicDecisionLists
	paths               *PasswordProtectedPaths
	banner              *MockBanner
	failedStates        *FailedChallengeRateLimitStates
	altchaFailedStates  *FailedChallengeRateLimitStates
	tooMany403States    *FailedChallengeRateLimitStates
}

func newXHRHarness(t *testing.T, config *Config) *xhrHarness {
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	paths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	return &xhrHarness{
		config:              config,
		staticDecisionLists: staticDecisionLists,
		decisionLists:       NewDynamicDecisionLists(),
		paths:               paths,
		banner:              &MockBanner{},
		failedStates:        NewFailedChallengeRateLimitStates(),
		altchaFailedStates:  NewFailedChallengeRateLimitStates(),
		tooMany403States:    NewFailedChallengeRateLimitStates(),
	}
}

// serve runs a request through decisionForNginx2 and the 403 counter, as decisionForNginx
// does. Rate limit states are shared between calls on one harness.
func (h *xhrHarness) serve(host string, headers map[string]string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, *gin.Context, DecisionForNginxResult) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = buildDecisionForNginxTestContext(xhrTestIp, host, "/api/items", "ua", "").Request
	for name, value := range headers {
		c.Request.Header.Set(name, value)
	}
	for _, cookie := range cookies {
		c.Request.AddCookie(cookie)
	}
	result := decisionForNginx2(c, h.config, h.staticDecisionLists, h.decisionLists, h.paths,
		h.failedStates, h.altchaFailedStates, h.banner)
	result.XHRChallenge = isXHRChallenge(c)
	countTooMany403s(c, h.config, &result, h.tooMany403States, h.staticDecisionLists, h.banner)
	return recorder, c, result
}

func assertXHRChallenge(t *testing.T, recorder *httptest.ResponseRecorder, challengeType string, decision string) {
	t.Helper()
	assert.Equal(t, 403, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "application/json")
	assert.Equal(t, decision, recorder.Header().Get("X-Banjax-Decision"))
	assert.Equal(t, "", recorder.Header().Get("X-Accel-Redirect"), "answered by banjax, not nginx's @access_denied")
	assert.Equal(t, "no-cache,no-store", recorder.Header().Get("Cache-Control"))
	for _, cookie := range recorder.Result().Cookies() {
		assert.NotEqual(t, ChallengeCookieName, cookie.Name, "no challenge cookie from a background call")
		assert.NotEqual(t, AltChaCookieName, cookie.Name)
	}
	var body XHRChallengeResponse
	assert.Nil(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "challenge_required", body.Error)
	assert.Equal(t, challengeType, body.Challenge)
	assert.NotEmpty(t, body.Message)
}

func assertHTMLChallenge(t *testing.T, recorder *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, 429, recorder.Code)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "text/html")
}

func TestXHRChallengeResponseShape(t *testing.T) {
	tests := []struct {
		name          string
		setup         func(h *xhrHarness)
		host          string
		headers       map[string]string
		wantJSON      bool
		challengeType string
		decision      string
	}{
		{
			name: "fetch() to an expiring ip challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: fetchHeaders,
			wantJSON: true, challengeType: "sha_inv", decision: "ExpiringChallenge",
		},
		{
			name: "jQuery XHR without Sec-Fetch headers",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: jqueryXHRHeaders,
			wantJSON: true, challengeType: "sha_inv", decision: "ExpiringChallenge",
		},
		{
			name: "fetch() to a challenge_all host challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.UpdateByHost(h.config, xhrTestHost, time.Now().Add(time.Hour), Challenge, true, AltChaOptions{})
			},
			host: xhrTestHost, headers: fetchHeaders,
			wantJSON: true, challengeType: "sha_inv", decision: "ExpiringSiteWideChallenge",
		},
		{
			name: "fetch() to an altcha challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), AltChaChallenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: fetchHeaders,
			wantJSON: true, challengeType: "altcha", decision: "ExpiringAltChaChallenge",
		},
		{
			name:  "fetch() to a static per-site challenge",
			setup: func(h *xhrHarness) {},
			host:  "static.com", headers: fetchHeaders,
			wantJSON: true, challengeType: "sha_inv", decision: "PerSiteChallenge",
		},
		{
			name:  "fetch() to a sitewide sha-inv challenge",
			setup: func(h *xhrHarness) {},
			host:  "sitewide.com", headers: fetchHeaders,
			wantJSON: true, challengeType: "sha_inv", decision: "SiteWideChallenge",
		},
		{
			name:  "fetch() to a sitewide altcha challenge",
			setup: func(h *xhrHarness) {},
			host:  "altcha-sitewide.com", headers: fetchHeaders,
			wantJSON: true, challengeType: "altcha", decision: "SiteWideAltChaChallenge",
		},
		{
			name: "navigation gets the HTML challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: navigationRequestHeaders,
		},
		{
			name: "image load gets the HTML challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: imageHeaders,
		},
		{
			name: "curl gets the HTML challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: curlHeaders,
		},
		{
			name: "api client asking for json without browser headers gets the HTML challenge",
			setup: func(h *xhrHarness) {
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			},
			host: xhrTestHost, headers: map[string]string{"Accept": "application/json"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXHRHarness(t, xhrTestConfig(""))
			tt.setup(h)
			recorder, _, result := h.serve(tt.host, tt.headers)
			if tt.wantJSON {
				assertXHRChallenge(t, recorder, tt.challengeType, tt.decision)
				assert.True(t, result.XHRChallenge)
			} else {
				assertHTMLChallenge(t, recorder)
				assert.False(t, result.XHRChallenge)
			}
		})
	}
}

func TestXHRChallengeValidCookieGranted(t *testing.T) {
	h := newXHRHarness(t, xhrTestConfig(""))
	h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
	cookie := &http.Cookie{Name: ChallengeCookieName, Value: SolveChallengeForTesting(NewChallengeCookie("secret", 3600, xhrTestIp))}

	recorder, _, result := h.serve(xhrTestHost, fetchHeaders, cookie)
	assert.Equal(t, 200, recorder.Code)
	assert.Equal(t, "@access_granted", recorder.Header().Get("X-Accel-Redirect"))
	assert.False(t, result.XHRChallenge)

	// a bad cookie on an XHR is still the JSON 403
	recorder, _, _ = h.serve(xhrTestHost, fetchHeaders, &http.Cookie{Name: ChallengeCookieName, Value: "Zm9yZ2Vk"})
	assertXHRChallenge(t, recorder, "sha_inv", "ExpiringChallenge")
}

func TestXHRChallengeCORS(t *testing.T) {
	tests := []struct {
		name      string
		origin    string
		wantAllow bool
	}{
		{"no Origin (same-origin GET)", "", false},
		{"https origin of the requested host", "https://example.com", true},
		{"http origin of the requested host", "http://example.com", true},
		{"origin of the requested host on another port", "https://example.com:8443", true},
		{"mixed-case origin host", "https://EXAMPLE.com", true},
		{"subdomain of the requested host", "https://www.example.com", false},
		{"another site", "https://attacker.example.net", false},
		{"host that only ends with the requested host", "https://notexample.com", false},
		{"null origin", "null", false},
		{"non-http scheme", "file://example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXHRHarness(t, xhrTestConfig(""))
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			headers := fetchHeaders
			if tt.origin != "" {
				headers = withHeader(fetchHeaders, "Origin", tt.origin)
			}
			recorder, _, _ := h.serve(xhrTestHost, headers)
			assertXHRChallenge(t, recorder, "sha_inv", "ExpiringChallenge")
			assert.Equal(t, "Origin", recorder.Header().Get("Vary"))
			if tt.wantAllow {
				assert.Equal(t, tt.origin, recorder.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "true", recorder.Header().Get("Access-Control-Allow-Credentials"))
				assert.Equal(t, "X-Banjax-Decision", recorder.Header().Get("Access-Control-Expose-Headers"))
			} else {
				assert.Equal(t, "", recorder.Header().Get("Access-Control-Allow-Origin"))
				assert.Equal(t, "", recorder.Header().Get("Access-Control-Allow-Credentials"))
			}
		})
	}
}

// Repeated challenged XHRs are never a failed challenge: no ban, no ip_failed_challenge, and
// they don't move the counter, so the client's first real failure is counted as the first.
func TestXHRChallengeNotCountedAsFailedChallenge(t *testing.T) {
	for _, decision := range []Decision{Challenge, AltChaChallenge} {
		t.Run(decision.String(), func(t *testing.T) {
			h := newXHRHarness(t, xhrTestConfig(""))
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), decision, true, xhrTestHost, AltChaOptions{})

			// well past too_many_failed_challenges_threshold (3)
			for i := 0; i < 10; i++ {
				recorder, _, result := h.serve(xhrTestHost, fetchHeaders)
				assert.Equal(t, 403, recorder.Code)
				assert.True(t, result.XHRChallenge)
				assert.False(t, result.TooManyFailedChallengesResult.Exceeded)
			}
			assert.Equal(t, "", h.banner.bannedIp)

			recorder, _, result := h.serve(xhrTestHost, navigationRequestHeaders)
			assertHTMLChallenge(t, recorder)
			assert.Equal(t, FirstTime, result.TooManyFailedChallengesResult.MatchType)
			assert.False(t, result.TooManyFailedChallengesResult.Exceeded)
		})
	}
}

// The HTML challenge still bans as before, so a client can't avoid the ban by not looking
// like an XHR.
func TestHTMLChallengeStillCountedAsFailedChallenge(t *testing.T) {
	h := newXHRHarness(t, xhrTestConfig(""))
	h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})

	// the limiter resets once it trips, so look for the request that tripped it
	exceeded := false
	for i := 0; i < 5; i++ {
		_, _, result := h.serve(xhrTestHost, curlHeaders)
		exceeded = exceeded || result.TooManyFailedChallengesResult.Exceeded
	}
	assert.True(t, exceeded)
	assert.Equal(t, xhrTestIp, h.banner.bannedIp)
}

// With too_many_403_ban_to_iptables_ban, a challenged XHR's 403 is not counted, so a polling
// SPA is not iptables banned while it is challenged. A real block's 403 still is.
func TestXHRChallengeNotCountedAsTooMany403s(t *testing.T) {
	h := newXHRHarness(t, xhrTestConfig(`
too_many_403_ban_to_iptables_ban: true
too_many_403_ban_interval_seconds: 60
too_many_403_ban_threshold: 2
`))
	h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})

	for i := 0; i < 10; i++ {
		recorder, _, result := h.serve(xhrTestHost, fetchHeaders)
		assert.Equal(t, 403, recorder.Code)
		assert.Nil(t, result.TooMany403Result)
	}
	assert.Equal(t, "", h.banner.bannedIp)

	// a block's 403 is still counted
	h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), NginxBlock, true, xhrTestHost, AltChaOptions{})
	var result DecisionForNginxResult
	for i := 0; i < 3; i++ {
		_, _, result = h.serve(xhrTestHost, fetchHeaders)
		assert.False(t, result.XHRChallenge)
	}
	if assert.NotNil(t, result.TooMany403Result) {
		assert.True(t, result.TooMany403Result.Exceeded)
	}
	assert.Equal(t, IptablesBlock, h.banner.bannedDecision)
}

func TestXHRChallengeLoggedInDecisionResult(t *testing.T) {
	result := DecisionForNginxResult{DecisionListResult: ExpiringChallenge, XHRChallenge: true}
	bytes, err := json.Marshal(result)
	assert.Nil(t, err)
	assert.True(t, strings.Contains(string(bytes), `"XHRChallenge":true`))

	bytes, err = json.Marshal(DecisionForNginxResult{DecisionListResult: NoMention})
	assert.Nil(t, err)
	assert.False(t, strings.Contains(string(bytes), "XHRChallenge"), "omitted unless set, so other log lines are unchanged")
}
