// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"math/big"
	"strconv"
	"strings"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/gin-gonic/gin"
)

const AltChaCookieName = "deflect_altcha"

// ALTCHA v2 proof of work: the client must find the counter whose PBKDF2/SHA-256 derived key
// starts with the key prefix in the challenge. banjax picks that counter, so the work is
// counter+1 key derivations of AltChaCost iterations each, split across the widget's workers.
const AltChaAlgorithm = "PBKDF2/SHA-256"

// defaults when the config leaves altcha_cost / altcha_max_number unset
const (
	AltChaDefaultCost      = 5000
	AltChaDefaultMaxNumber = 10000
)

// defaults when the config leaves altcha_too_many_failed_challenges_* unset. Zero is never
// what an operator means: a zero threshold bans on the first request (which has no cookie yet),
// and a zero interval resets the count on every request so the ban never triggers.
const (
	AltChaDefaultTooManyFailedChallengesIntervalSeconds = 10
	AltChaDefaultTooManyFailedChallengesThreshold       = 3
)

// bounds for the altcha_max_number field of altcha_challenge_* kafka commands: below the
// min a challenge is too cheap to matter, above the max a phone takes too long to solve it
const (
	AltChaMaxNumberMin int64 = 1000
	AltChaMaxNumberMax int64 = 20000
)

// AltChaOptions are the per-decision AltCha settings. The zero value is the default challenge:
// config.AltChaMaxNumber difficulty, solved on page load without a click.
type AltChaOptions struct {
	MaxNumber int64 // difficulty, 0 means config.AltChaMaxNumber
	Click     bool  // one-click checkbox: the proof of work only starts when the visitor ticks it
	// unix ms; a cookie whose challenge was minted before this is rejected, so clients must
	// solve a new challenge (kafka altcha_force_new). 0 accepts any valid cookie.
	NotBefore int64 `json:",omitempty"`
}

// effectiveAltChaMaxNumber is the difficulty a challenge is minted with: maxNumber from the
// decision if set, otherwise config.AltChaMaxNumber, otherwise AltChaDefaultMaxNumber.
func effectiveAltChaMaxNumber(config *Config, maxNumber int64) int64 {
	if maxNumber <= 0 {
		maxNumber = config.AltChaMaxNumber
	}
	if maxNumber <= 0 {
		maxNumber = AltChaDefaultMaxNumber
	}
	return maxNumber
}

// ClampAltChaMaxNumber forces a kafka-supplied altcha_max_number into
// [AltChaMaxNumberMin, AltChaMaxNumberMax]; out-of-range values become the nearest limit.
func ClampAltChaMaxNumber(maxNumber int64) int64 {
	return min(max(maxNumber, AltChaMaxNumberMin), AltChaMaxNumberMax)
}

// altchaKeySignatureSecret signs the derived key of each challenge, so a solution is checked
// with one HMAC instead of re-running the key derivation on every request with the cookie.
func altchaKeySignatureSecret(config *Config) string {
	return config.HmacSecret + "/altcha-key"
}

// CreateAltChaChallenge mints an ALTCHA v2 challenge bound to the caller-supplied binding
// (IP or UA, same selector as sha-inv). The binding goes in the signed data, and ExpiresAt
// MUST be set: VerifySolution only enforces expiry when present, otherwise the solved token
// would be replayable forever. maxNumber is the difficulty carried by the decision that
// triggered the challenge; 0 means config.AltChaMaxNumber.
func CreateAltChaChallenge(config *Config, binding string, maxNumber int64) (altcha.Challenge, error) {
	maxNumber = effectiveAltChaMaxNumber(config, maxNumber)
	cost := config.AltChaCost
	if cost <= 0 {
		cost = AltChaDefaultCost
	}
	// the counter must be unpredictable, or a client could skip straight to it
	n, err := rand.Int(rand.Reader, big.NewInt(maxNumber+1))
	if err != nil {
		return altcha.Challenge{}, err
	}
	counter := int(n.Int64())
	expireTime := time.Now().Add(time.Duration(config.AltChaCookieTtlSeconds) * time.Second)
	return altcha.CreateChallenge(altcha.CreateChallengeOptions{
		Algorithm:              AltChaAlgorithm,
		DeriveKey:              altcha.DeriveKeyPBKDF2(),
		Cost:                   cost,
		Counter:                &counter,
		HMACSignatureSecret:    config.HmacSecret,
		HMACKeySignatureSecret: altchaKeySignatureSecret(config),
		ExpiresAt:              &expireTime,
		Data: map[string]interface{}{
			"binding": binding,
			// signed, so AltChaOptions.NotBefore can reject cookies minted before a decision
			"issued_at": strconv.FormatInt(time.Now().UnixMilli(), 10),
		},
	})
}

// VerifyAltChaPayload validates the base64 payload from the deflect_altcha cookie.
// VerifySolution alone only proves "someone solved a banjax-minted challenge", not
// "this client did", so the binding in the signed challenge data is checked too.
func VerifyAltChaPayload(config *Config, payloadB64 string, binding string) (bool, error) {
	return verifyAltChaPayloadNotBefore(config, payloadB64, binding, 0)
}

// verifyAltChaPayloadNotBefore is VerifyAltChaPayload that also rejects a payload whose
// challenge was minted before notBefore (unix ms), or that predates the issued_at field.
// notBefore 0 skips that check.
func verifyAltChaPayloadNotBefore(config *Config, payloadB64 string, binding string, notBefore int64) (bool, error) {
	// gin erroneously QueryUnescapes cookies, turning '+' into ' '. Repair before decoding.
	// https://github.com/gin-gonic/gin/issues/1717 (same workaround as ParseCookie).
	repaired := strings.ReplaceAll(payloadB64, " ", "+")

	decoded, err := base64.StdEncoding.DecodeString(repaired)
	if err != nil {
		return false, err
	}
	var payload altcha.Payload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return false, err
	}
	// every banjax challenge carries a key signature, so verification takes the HMAC fast
	// path. DeriveKey is left nil on purpose: a payload without a key signature then fails
	// with an error instead of making banjax run a key derivation per request.
	result, err := altcha.VerifySolution(altcha.VerifySolutionOptions{
		Challenge:              payload.Challenge,
		Solution:               payload.Solution,
		HMACSignatureSecret:    config.HmacSecret,
		HMACKeySignatureSecret: altchaKeySignatureSecret(config),
	})
	// an expired payload verifies as false with no error
	if err != nil || !result.Verified {
		return false, err
	}
	boundTo, _ := payload.Challenge.Parameters.Data["binding"].(string)
	if boundTo != binding {
		return false, nil
	}
	if notBefore > 0 {
		issuedAtStr, _ := payload.Challenge.Parameters.Data["issued_at"].(string)
		issuedAt, err := strconv.ParseInt(issuedAtStr, 10, 64)
		if err != nil || issuedAt < notBefore {
			return false, nil
		}
	}
	return true, nil
}

// applyArgsToAltChaPage injects the per-request challenge JSON into the widget's challenge
// attribute and rewrites the cookie max-age, like applyArgsToShaInvPage. The JSON is
// HTML-escaped because the binding inside it can be the client's User-Agent. With click, the
// widget waits for its checkbox instead of solving on load.
func applyArgsToAltChaPage(config *Config, challenge altcha.Challenge, click bool) []byte {
	challengeJSON, err := json.Marshal(challenge)
	if err != nil {
		log.Printf("ALTCHA: failed to marshal challenge: %v", err)
		challengeJSON = []byte("{}")
	}
	modifiedPageBytes := modifyHTMLContent(
		config.AltChaChallengerBytes,
		`challenge="{}"`,
		fmt.Sprintf(`challenge="%s"`, html.EscapeString(string(challengeJSON))),
	)
	if click {
		modifiedPageBytes = modifyHTMLContent(modifiedPageBytes, `auto="onload"`, `auto="off"`)
	}
	return applyCookieMaxAge(modifiedPageBytes, AltChaCookieName, config.AltChaCookieTtlSeconds)
}

func altchaChallenge(c *gin.Context, config *Config, options AltChaOptions, trigger DecisionListResult) {
	challenge, err := CreateAltChaChallenge(config, getUserAgentOrIp(c, config), options.MaxNumber)
	if err != nil {
		// only fails on rand/key derivation errors; the client gets an unsolvable page
		log.Printf("ALTCHA: failed to create challenge: %v", err)
	}
	c.Header("X-Banjax-Decision", DecisionListResultToString[trigger])
	c.Header("Cache-Control", "no-cache,no-store")
	sessionCookieEndPoint(c, config)
	c.Data(429, "text/html", applyArgsToAltChaPage(config, challenge, options.Click))
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
	AltChaOptions                 AltChaOptions // as applied: MaxNumber resolved to the config default if unset
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
	altchaOptions AltChaOptions, // difficulty and click mode for a new challenge
	trigger DecisionListResult, // why the client is challenged, sent as X-Banjax-Decision
) (result SendOrValidateAltChaChallengeResult) {
	result.AltChaOptions = AltChaOptions{
		MaxNumber: effectiveAltChaMaxNumber(config, altchaOptions.MaxNumber),
		Click:     altchaOptions.Click,
		NotBefore: altchaOptions.NotBefore,
	}
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	altchaCookie, err := c.Cookie(AltChaCookieName)
	integrityCheckCookie, _ := c.Cookie(IntegrityCheckCookieName)
	botScore, botScoreTopFactor, botFingerprint := integrityCheckCalcBotScoreWrapper(integrityCheckCookie)
	requestedMethod := c.Request.Method
	if err == nil {
		ok, err := verifyAltChaPayloadNotBefore(config, altchaCookie, getUserAgentOrIp(c, config), altchaOptions.NotBefore)
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
	altchaChallenge(c, config, altchaOptions, trigger)
	return result
}
