// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// What a browser sends before a credentialed cross-origin PUT from a page on www.example.com.
var preflightHeaders = map[string]string{
	"Accept":                         "*/*",
	"Origin":                         "https://www.example.com",
	"Access-Control-Request-Method":  "PUT",
	"Access-Control-Request-Headers": "content-type",
	"Sec-Fetch-Site":                 "same-site",
	"Sec-Fetch-Mode":                 "cors",
	"Sec-Fetch-Dest":                 "empty",
}

// Every way a site or client can end up with a sha-inv or AltCha challenge lets a preflight
// through, and repeated preflights are not failed challenges, so they never ban.
func TestPreflightSkipsChallenge(t *testing.T) {
	tests := []struct {
		name  string
		host  string
		extra string              // extra config yaml
		setup func(h *xhrHarness) // expiring decisions
	}{
		{name: "per-site static ip challenge", host: "static.com"},
		{name: "per-site user agent challenge", host: xhrTestHost, extra: `
per_site_user_agent_decision_lists:
  example.com:
    altcha_challenge:
      - ua
`},
		{name: "global ip challenge", host: xhrTestHost, extra: `
global_decision_lists:
  challenge:
    - 1.2.3.4
`},
		{name: "global user agent challenge", host: xhrTestHost, extra: `
global_user_agent_decision_lists:
  altcha_click_challenge:
    - ua
`},
		{name: "expiring user agent challenge", host: xhrTestHost, setup: func(h *xhrHarness) {
			h.decisionLists.UpdateByUA(h.config, "ua", time.Now().Add(time.Hour), AltChaChallenge, true, xhrTestHost, AltChaOptions{})
		}},
		{name: "expiring challenge_all for the host", host: xhrTestHost, setup: func(h *xhrHarness) {
			h.decisionLists.UpdateByHost(h.config, xhrTestHost, time.Now().Add(time.Hour), Challenge, true, AltChaOptions{})
		}},
		{name: "expiring ip sha-inv challenge", host: xhrTestHost, setup: func(h *xhrHarness) {
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
		}},
		{name: "expiring ip AltCha click challenge", host: xhrTestHost, setup: func(h *xhrHarness) {
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), AltChaClickChallenge, true, xhrTestHost, AltChaOptions{})
		}},
		{name: "site-wide sha-inv challenge", host: "sitewide.com"},
		{name: "site-wide AltCha challenge", host: "altcha-sitewide.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXHRHarness(t, xhrTestConfig(tt.extra))
			if tt.setup != nil {
				tt.setup(h)
			}

			// well past both too_many_failed_challenges thresholds (3)
			for i := 0; i < 10; i++ {
				recorder, _, result := h.serveMethod(http.MethodOptions, tt.host, preflightHeaders)
				assert.Equal(t, 200, recorder.Code)
				assert.Equal(t, "@access_granted", recorder.Header().Get("X-Accel-Redirect"))
				assert.Equal(t, "CORSPreflightException", recorder.Header().Get("X-Banjax-Decision"))
				assert.Equal(t, CORSPreflightException, result.DecisionListResult)
				assert.Equal(t, "no-cache,no-store", recorder.Header().Get("Cache-Control"))
				assert.Nil(t, result.TooManyFailedChallengesResult)
				for _, cookie := range recorder.Result().Cookies() {
					assert.NotEqual(t, ChallengeCookieName, cookie.Name)
					assert.NotEqual(t, AltChaCookieName, cookie.Name)
				}
			}
			assert.Equal(t, "", h.banner.bannedIp)

			// the call the preflight was for is still challenged
			recorder, _, result := h.serve(tt.host, withHeader(fetchHeaders, "Origin", "https://www.example.com"))
			assert.Equal(t, 403, recorder.Code)
			assert.True(t, result.XHRChallenge)
		})
	}
}

// A skipped challenge falls through: a block checked after it still blocks the preflight,
// even though the challenge source is checked first. Before the fall-through, the earlier
// challenge answered the preflight and the later block was never reached.
func TestPreflightStillBlockedAfterSkippedChallenge(t *testing.T) {
	tests := []struct {
		name  string
		extra string
		setup func(h *xhrHarness)
	}{
		{"per-site user agent challenge, then global ip block", `
per_site_user_agent_decision_lists:
  example.com:
    challenge:
      - ua
global_decision_lists:
  nginx_block:
    - 1.2.3.4
`, nil},
		{"challenge_all for the host, then expiring ip block", "", func(h *xhrHarness) {
			h.decisionLists.UpdateByHost(h.config, xhrTestHost, time.Now().Add(time.Hour), AltChaChallenge, true, AltChaOptions{})
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), NginxBlock, true, xhrTestHost, AltChaOptions{})
		}},
		{"expiring user agent challenge, then expiring ip block", "", func(h *xhrHarness) {
			h.decisionLists.UpdateByUA(h.config, "ua", time.Now().Add(time.Hour), Challenge, true, xhrTestHost, AltChaOptions{})
			h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), NginxBlock, true, xhrTestHost, AltChaOptions{})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newXHRHarness(t, xhrTestConfig(tt.extra))
			if tt.setup != nil {
				tt.setup(h)
			}
			recorder, _, result := h.serveMethod(http.MethodOptions, xhrTestHost, preflightHeaders)
			assert.Equal(t, 403, recorder.Code)
			assert.Equal(t, "@access_denied", recorder.Header().Get("X-Accel-Redirect"))
			assert.NotEqual(t, CORSPreflightException, result.DecisionListResult)
		})
	}
}

// A skipped challenge does not hide an Allow checked later.
func TestPreflightSkippedChallengeThenAllow(t *testing.T) {
	h := newXHRHarness(t, xhrTestConfig(`
global_decision_lists:
  allow:
    - 1.2.3.4
`))
	recorder, _, result := h.serveMethod(http.MethodOptions, "static.com", preflightHeaders)
	assert.Equal(t, "@access_granted", recorder.Header().Get("X-Accel-Redirect"))
	assert.Equal(t, GlobalAccessGranted, result.DecisionListResult)
}

// Only a real preflight shape skips the challenge.
func TestNotPreflightStillChallenged(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{"plain OPTIONS", http.MethodOptions, map[string]string{"Origin": "https://www.example.com"}},
		{"OPTIONS without Origin", http.MethodOptions, map[string]string{"Access-Control-Request-Method": "PUT"}},
		{"GET with preflight headers", http.MethodGet, map[string]string{
			"Origin":                        "https://www.example.com",
			"Access-Control-Request-Method": "PUT",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, decision := range []Decision{Challenge, AltChaChallenge} {
				h := newXHRHarness(t, xhrTestConfig(""))
				h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), decision, true, xhrTestHost, AltChaOptions{})
				recorder, _, result := h.serveMethod(tt.method, xhrTestHost, tt.headers)
				assertHTMLChallenge(t, recorder)
				assert.NotEqual(t, CORSPreflightException, result.DecisionListResult)
			}
		})
	}
}

// The exemption is for challenges only: a blocked client's preflight is still blocked.
func TestPreflightNotExemptFromBlock(t *testing.T) {
	h := newXHRHarness(t, xhrTestConfig(""))
	h.decisionLists.Update(h.config, xhrTestIp, time.Now().Add(time.Hour), NginxBlock, true, xhrTestHost, AltChaOptions{})
	recorder, _, result := h.serveMethod(http.MethodOptions, xhrTestHost, preflightHeaders)
	assert.Equal(t, 403, recorder.Code)
	assert.Equal(t, "@access_denied", recorder.Header().Get("X-Accel-Redirect"))
	assert.NotEqual(t, CORSPreflightException, result.DecisionListResult)
}
