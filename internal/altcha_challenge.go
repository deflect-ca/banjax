// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/url"
	"strings"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go"
	"github.com/gin-gonic/gin"
)

const AltChaCookieName = "deflect_altcha"

// CreateAltChaChallenge mints an AltCha SHA-256 proof-of-work challenge bound to the
// caller-supplied binding (IP or UA, same selector as sha-inv). Expires MUST be set:
// altcha encodes it into the salt and VerifySolution enforces it only when present,
// otherwise the solved token would be replayable forever.
func CreateAltChaChallenge(config *Config, binding string) (altcha.Challenge, error) {
	expireTime := time.Now().Add(time.Duration(config.AltChaCookieTtlSeconds) * time.Second)
	return altcha.CreateChallenge(altcha.ChallengeOptions{
		Algorithm: altcha.SHA256,
		MaxNumber: config.AltChaMaxNumber,
		HMACKey:   config.HmacSecret,
		Expires:   &expireTime,
		Params:    url.Values{"binding": {binding}},
	})
}

// VerifyAltChaPayload validates the base64 payload from the deflect_altcha cookie.
// VerifySolution alone only proves "someone solved a banjax-minted challenge", not
// "this client did", so the binding embedded in the salt is checked too.
func VerifyAltChaPayload(config *Config, payloadB64 string, binding string) (bool, error) {
	// gin erroneously QueryUnescapes cookies, turning '+' into ' '. Repair before decoding.
	// https://github.com/gin-gonic/gin/issues/1717 (same workaround as ParseCookie).
	repaired := strings.ReplaceAll(payloadB64, " ", "+")

	// checkExpires=true: an expired payload verifies as false (no error).
	// VerifySolutionSafe uses a constant-time signature comparison.
	ok, err := altcha.VerifySolutionSafe(repaired, config.HmacSecret, true)
	if err != nil || !ok {
		return false, err
	}

	decoded, err := base64.StdEncoding.DecodeString(repaired)
	if err != nil {
		return false, err
	}
	var payload altcha.Payload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return false, err
	}
	return altcha.ExtractParams(payload).Get("binding") == binding, nil
}

// applyArgsToAltChaPage injects the per-request challenge JSON into the page and
// rewrites the cookie max-age, like applyArgsToShaInvPage.
func applyArgsToAltChaPage(config *Config, challenge altcha.Challenge) []byte {
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		log.Printf("ALTCHA: failed to marshal challenge: %v", err)
		challengeJSON = []byte("{}")
	}
	modifiedPageBytes := modifyHTMLContent(
		config.AltChaChallengerBytes,
		"var altcha_challenge = {};",
		"var altcha_challenge = "+string(challengeJSON)+";",
	)
	return applyCookieMaxAge(modifiedPageBytes, AltChaCookieName, config.AltChaCookieTtlSeconds)
}

func altchaChallenge(c *gin.Context, config *Config) {
	challenge, err := CreateAltChaChallenge(config, getUserAgentOrIp(c, config))
	if err != nil {
		// only fails on rand/algorithm errors; the client gets an unsolvable page
		log.Printf("ALTCHA: failed to create challenge: %v", err)
	}
	c.Header("Cache-Control", "no-cache,no-store")
	sessionCookieEndPoint(c, config)
	c.Data(429, "text/html", applyArgsToAltChaPage(config, challenge))
	c.Abort()
}

type AltChaChallengeResult uint

const (
	_ AltChaChallengeResult = iota
	AltChaChallengePassed
	AltChaChallengeFailedNoCookie
	AltChaChallengeFailedBadCookie
)

var AltChaChallengeResultToString = map[AltChaChallengeResult]string{
	AltChaChallengePassed:          "AltChaChallengePassed",
	AltChaChallengeFailedNoCookie:  "AltChaChallengeFailedNoCookie",
	AltChaChallengeFailedBadCookie: "AltChaChallengeFailedBadCookie",
}

func (acr AltChaChallengeResult) String() string {
	if s, ok := AltChaChallengeResultToString[acr]; ok {
		return s
	}
	return "Bad! unknown AltChaChallengeResult"
}

func (acr AltChaChallengeResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	if s, ok := AltChaChallengeResultToString[acr]; ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("nil")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type SendOrValidateAltChaChallengeResult struct {
	AltChaChallengeResult         AltChaChallengeResult
	TooManyFailedChallengesResult RateLimitResult
}

// sendOrValidateAltChaChallenge is sendOrValidateShaChallenge for AltCha. Failures are
// counted in their own rateLimitStates against the altcha_too_many_failed_challenges_*
// config, so they don't share a ban threshold with sha-inv or password failures.
func sendOrValidateAltChaChallenge(
	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,
) (result SendOrValidateAltChaChallengeResult) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	altchaCookie, err := c.Cookie(AltChaCookieName)
	integrityCheckCookie, _ := c.Cookie(IntegrityCheckCookieName)
	botScore, botScoreTopFactor, botFingerprint := integrityCheckCalcBotScoreWrapper(integrityCheckCookie)
	requestedMethod := c.Request.Method
	if err == nil {
		ok, err := VerifyAltChaPayload(config, altchaCookie, getUserAgentOrIp(c, config))
		if err == nil && ok {
			accessGranted(c, config, AltChaChallengeResultToString[AltChaChallengePassed], botScore, botScoreTopFactor, botFingerprint)
			ReportPassedFailedBannedMessage(config, "ip_passed_challenge", clientIp, requestedHost)
			result.AltChaChallengeResult = AltChaChallengePassed
			return result
		}
		result.AltChaChallengeResult = AltChaChallengeFailedBadCookie
	} else {
		result.AltChaChallengeResult = AltChaChallengeFailedNoCookie
	}
	ReportPassedFailedBannedMessage(config, "ip_failed_challenge", clientIp, requestedHost)
	if failAction == Block {
		tooManyFailedChallengesResult := tooManyFailedChallenges(
			config,
			clientIp,
			clientUserAgent,
			requestedHost,
			requestedPath,
			banner,
			"altcha",
			rateLimitStates,
			config.AltChaTooManyFailedChallengesIntervalSeconds,
			config.AltChaTooManyFailedChallengesThreshold,
			requestedMethod,
			decisionLists,
		)
		result.TooManyFailedChallengesResult = tooManyFailedChallengesResult
		if tooManyFailedChallengesResult.Exceeded {
			ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
			accessDenied(c, config, "TooManyFailedAltChaChallenges", botScore, botScoreTopFactor, botFingerprint)
			return result
		}
	}
	altchaChallenge(c, config)
	return result
}
