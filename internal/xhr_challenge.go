// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

// Challenged XHRs. A fetch()/XMLHttpRequest call (see IsXHR) can't display an HTML
// challenge page, so a challenged one gets a 403 JSON error instead, which the page's
// script can read and act on, e.g. by reloading so the challenge is shown as a page.
//
// A challenged XHR is not a failed challenge: it is not reported to baskerville as
// ip_failed_challenge, and counts toward neither too_many_failed_challenges_* nor
// too_many_403_ban_*, so an SPA that keeps polling while challenged is not banned for it.

// xhrChallengeContextKey marks a request answered with the XHR challenge, so
// countTooMany403s can leave its 403 out.
const xhrChallengeContextKey = "banjax_xhr_challenge"

// XHRChallengeResponse is the body of the 403 a challenged XHR gets.
type XHRChallengeResponse struct {
	Error     string `json:"error"`     // always "challenge_required"
	Challenge string `json:"challenge"` // "sha_inv" or "altcha": the challenge a navigation will get
	Message   string `json:"message"`
}

// xhrChallenge answers a challenged XHR. trigger is why it is challenged, sent as
// X-Banjax-Decision like the HTML challenge pages do. Unlike them it sets no challenge
// cookie: overwriting the cookie from a background call could break a challenge being
// solved in another tab.
func xhrChallenge(c *gin.Context, config *Config, trigger DecisionListResult, challengeType string) {
	c.Header("X-Banjax-Decision", DecisionListResultToString[trigger])
	c.Header("Cache-Control", "no-cache,no-store")
	allowRequestedHostOrigin(c)
	sessionCookieEndPoint(c, config)
	c.Set(xhrChallengeContextKey, true)
	c.JSON(http.StatusForbidden, XHRChallengeResponse{
		Error:     "challenge_required",
		Challenge: challengeType,
		Message:   "This request needs a browser check. Reload the page to complete it.",
	})
	c.Abort()
}

// isXHRChallenge reports whether c was answered by xhrChallenge.
func isXHRChallenge(c *gin.Context) bool {
	return c.GetBool(xhrChallengeContextKey)
}

// allowRequestedHostOrigin lets a page on the requested host read the response from a
// credentialed CORS request: when the request's Origin is the requested host (any scheme
// or port), it is echoed back with Access-Control-Allow-Credentials. Any other origin,
// including subdomains, gets no CORS headers. A same-origin request sends no Origin on GET
// and needs none.
func allowRequestedHostOrigin(c *gin.Context) {
	c.Header("Vary", "Origin")
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		return
	}
	originURL, err := url.Parse(origin)
	if err != nil || (originURL.Scheme != "http" && originURL.Scheme != "https") {
		return
	}
	requestedHost := normalizeHost(c.Request.Header.Get("X-Requested-Host"))
	if requestedHost == "" || normalizeHost(originURL.Hostname()) != requestedHost {
		return
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Access-Control-Expose-Headers", "X-Banjax-Decision")
}
