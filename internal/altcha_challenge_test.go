// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go"
	"github.com/stretchr/testify/assert"
)

// solveAltChaToCookie solves a minted challenge and returns the base64 payload a
// browser would set as the deflect_altcha cookie value.
func solveAltChaToCookie(t *testing.T, challenge altcha.Challenge) string {
	sol, err := altcha.SolveChallenge(
		challenge.Challenge,
		challenge.Salt,
		altcha.Algorithm(challenge.Algorithm),
		int(challenge.MaxNumber),
		0,
		nil,
	)
	assert.Nil(t, err)
	assert.NotNil(t, sol)

	payload := altcha.Payload{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Number:    int64(sol.Number),
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
	}
	jsonBytes, err := json.Marshal(payload)
	assert.Nil(t, err)
	return base64.StdEncoding.EncodeToString(jsonBytes)
}

func altchaTestConfig() *Config {
	return &Config{
		HmacSecret:                                   "test-secret",
		AltChaMaxNumber:                              1000,
		AltChaCookieTtlSeconds:                       3600,
		AltChaChallengerBytes:                        altchaChallengeEmbed,
		AltChaTooManyFailedChallengesThreshold:       3,
		AltChaTooManyFailedChallengesIntervalSeconds: 60,
		TooManyFailedChallengesThreshold:             10,
		TooManyFailedChallengesIntervalSeconds:       60,
		ShaInvExpectedZeroBits:                       10,
		ShaInvCookieTtlSeconds:                       3600,
		ChallengerBytes:                              shaInvChallengeEmbed,
	}
}

func TestParseDecision_AltChaChallenge(t *testing.T) {
	d, err := ParseDecision("altcha_challenge")
	assert.Nil(t, err)
	assert.Equal(t, AltChaChallenge, d)
	assert.Equal(t, "AltChaChallenge", AltChaChallenge.String())

	d, err = ParseStaticListDecision("altcha_challenge")
	assert.Nil(t, err)
	assert.Equal(t, AltChaChallenge, d)
}

func TestAltChaChallenge_Ordering(t *testing.T) {
	assert.True(t, Challenge < AltChaChallenge)
	assert.True(t, AltChaChallenge < TooManyRequests)
}

func TestVerifyAltChaPayload_RoundTrip(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	ok, err := VerifyAltChaPayload(config, solveAltChaToCookie(t, challenge), "1.2.3.4")
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestVerifyAltChaPayload_WrongBinding(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	// a solved token bound to 1.2.3.4 must not be accepted for another client
	ok, err := VerifyAltChaPayload(config, solveAltChaToCookie(t, challenge), "9.9.9.9")
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestVerifyAltChaPayload_Expired(t *testing.T) {
	config := altchaTestConfig()
	config.AltChaCookieTtlSeconds = -3600
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	ok, err := VerifyAltChaPayload(config, solveAltChaToCookie(t, challenge), "1.2.3.4")
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestVerifyAltChaPayload_BadPayload(t *testing.T) {
	ok, err := VerifyAltChaPayload(altchaTestConfig(), "this is not base64 json !!!", "1.2.3.4")
	assert.NotNil(t, err)
	assert.False(t, ok)
}

func TestVerifyAltChaPayload_SpaceMangledCookieRepaired(t *testing.T) {
	config := altchaTestConfig()

	// gin turns '+' into ' ' when reading cookies. "~~~" base64-encodes to "fn5+" when
	// 3-byte aligned, so a UA-style binding with 6 of them always yields a '+' in the payload.
	const binding = "UA/1.0 ~~~~~~"
	challenge, err := CreateAltChaChallenge(config, binding, 0)
	assert.Nil(t, err)
	cookie := solveAltChaToCookie(t, challenge)
	assert.Contains(t, cookie, "+")

	ok, err := VerifyAltChaPayload(config, strings.ReplaceAll(cookie, "+", " "), binding)
	assert.Nil(t, err)
	assert.True(t, ok)
}

func TestApplyArgsToAltChaPage(t *testing.T) {
	config := altchaTestConfig()
	config.AltChaCookieTtlSeconds = 4321
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	page := string(applyArgsToAltChaPage(config, challenge))

	assert.Contains(t, page, "max-age=4321")
	assert.NotContains(t, page, "var altcha_challenge = {};")
	assert.Contains(t, page, challenge.Signature)
}

func TestCheckUADecision_AltChaChallengeBeatsChallenge(t *testing.T) {
	challengePattern, _ := newUAPattern("TestBot")
	altchaPattern, _ := newUAPattern("TestBot")
	rules := globalUAPatternToDecision{
		Challenge:       []uaPattern{challengePattern},
		AltChaChallenge: []uaPattern{altchaPattern},
	}

	decision, ok := checkUADecision(rules, "TestBot/1.0")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, decision)
}

func TestStaticDecisionLists_AltChaChallengeCidr(t *testing.T) {
	config := loadConfigString(`
global_decision_lists:
  altcha_challenge:
    - 10.0.0.0/24
per_site_decision_lists:
  example.com:
    altcha_challenge:
      - 10.1.0.0/24
`)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	decision, ok := staticDecisionLists.CheckGlobal(config, "10.0.0.7")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, decision)

	decision, ok = staticDecisionLists.CheckPerSite(config, "example.com", "10.1.0.7")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, decision)
}

func TestHandleCommand_AltChaChallenge(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "altcha_challenge_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "altcha_challenge_subnet", Value: "5.6.7.0/24", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "altcha_challenge_session", SessionId: "session-a", Value: "1.2.3.4", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "altcha_challenge_ua", UA: "curl/7.68.0", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "altcha_challenge_all", Host: "example.com"}, decisionLists)

	ipDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, ipDecision.Decision)
	assert.WithinDuration(t, time.Now().Add(300*time.Second), ipDecision.Expires, 5*time.Second)

	subnetDecision, ok := decisionLists.CheckBySubnet("5.6.7.8")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, subnetDecision.Decision)

	sessionDecision, ok := decisionLists.Check("session-a", "")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, sessionDecision.Decision)

	uaDecision, ok := decisionLists.CheckByUA("curl/7.68.0", "example.com")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, uaDecision.Decision)

	hostDecision, ok := decisionLists.CheckByHost("example.com")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, hostDecision.Decision)

	assert.Equal(t, 5, decisionLists.MetricsAltChaChallenges())
}

func TestHandleCommand_AltChaChallenge_NotDowngradedByChallenge(t *testing.T) {
	config := loadConfigString(kafkaTestConfString)
	decisionLists := NewDynamicDecisionLists()

	handleCommand(config, commandMessage{Name: "altcha_challenge_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)
	handleCommand(config, commandMessage{Name: "challenge_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	ipDecision, ok := decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, AltChaChallenge, ipDecision.Decision)

	handleCommand(config, commandMessage{Name: "block_ip", Value: "1.2.3.4", Host: "example.com"}, decisionLists)

	ipDecision, ok = decisionLists.Check("", "1.2.3.4")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, ipDecision.Decision)
}

func TestDecisionForNginx2_AltChaChallenge(t *testing.T) {
	config := altchaTestConfig()
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	const clientIp = "1.1.1.1"
	const host = "example.com"

	newDecisionLists := func() *DynamicDecisionLists {
		decisionLists := NewDynamicDecisionLists()
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), AltChaChallenge, true, host, 0)
		return decisionLists
	}

	t.Run("serves the altcha page without a cookie", func(t *testing.T) {
		c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, newDecisionLists(), passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, ExpiringAltChaChallenge, result.DecisionListResult)
		assert.Equal(t, AltChaChallengeFailedNoCookie, *result.AltChaChallengeResult)
		assert.Nil(t, result.ShaChallengeResult)
		assert.Equal(t, 429, c.Writer.Status())
	})

	t.Run("passes with a solved cookie", func(t *testing.T) {
		challenge, err := CreateAltChaChallenge(config, clientIp, 0)
		assert.Nil(t, err)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
		c.Request.AddCookie(&http.Cookie{Name: AltChaCookieName, Value: solveAltChaToCookie(t, challenge)})
		result := decisionForNginx2(c, config, staticDecisionLists, newDecisionLists(), passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, AltChaChallengePassed, *result.AltChaChallengeResult)
	})

	t.Run("a sha-inv cookie does not pass altcha", func(t *testing.T) {
		c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
		c.Request.AddCookie(&http.Cookie{Name: ChallengeCookieName, Value: "anything"})
		result := decisionForNginx2(c, config, staticDecisionLists, newDecisionLists(), passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})

		assert.Equal(t, AltChaChallengeFailedNoCookie, *result.AltChaChallengeResult)
	})

	t.Run("too many failures iptables bans using the altcha threshold only", func(t *testing.T) {
		decisionLists := newDecisionLists()
		failedChallengeStates := NewFailedChallengeRateLimitStates()
		altchaFailedChallengeStates := NewFailedChallengeRateLimitStates()
		banner := &MockBanner{}

		// threshold is 3: the 4th failure in the interval exceeds it
		for i := 0; i < 3; i++ {
			c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
			result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
				failedChallengeStates, altchaFailedChallengeStates, banner)
			assert.False(t, result.TooManyFailedChallengesResult.Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)

		c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			failedChallengeStates, altchaFailedChallengeStates, banner)

		assert.True(t, result.TooManyFailedChallengesResult.Exceeded)
		assert.Equal(t, clientIp, banner.bannedIp)
		assert.Equal(t, IptablesBlock, banner.bannedDecision)
		assert.Equal(t, 1, altchaFailedChallengeStates.Len())
		assert.Equal(t, 0, failedChallengeStates.Len())
	})

	t.Run("sha-inv failures don't count toward the altcha threshold", func(t *testing.T) {
		failedChallengeStates := NewFailedChallengeRateLimitStates()
		altchaFailedChallengeStates := NewFailedChallengeRateLimitStates()
		shaDecisionLists := NewDynamicDecisionLists()
		shaDecisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, 0)

		for i := 0; i < 5; i++ {
			c := buildDecisionForNginxTestContext(clientIp, host, "/", "ua", "")
			decisionForNginx2(c, config, staticDecisionLists, shaDecisionLists, passwordProtectedPaths,
				failedChallengeStates, altchaFailedChallengeStates, &MockBanner{})
		}
		assert.Equal(t, 1, failedChallengeStates.Len())
		assert.Equal(t, 0, altchaFailedChallengeStates.Len())
	})
}

func TestDecisionForNginx2_AltChaChallengeStaticAndHostLists(t *testing.T) {
	config := loadConfigString(`
global_decision_lists:
  altcha_challenge:
    - 2.2.2.2
global_user_agent_decision_lists:
  altcha_challenge:
    - AltChaBot
`)
	config.HmacSecret = "test-secret"
	config.AltChaCookieTtlSeconds = 3600
	config.AltChaChallengerBytes = altchaChallengeEmbed
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	run := func(clientIp, host, userAgent string, decisionLists *DynamicDecisionLists) DecisionForNginxResult {
		c := buildDecisionForNginxTestContext(clientIp, host, "/", userAgent, "")
		return decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{})
	}

	assert.Equal(t, GlobalAltChaChallenge, run("2.2.2.2", "example.com", "ua", NewDynamicDecisionLists()).DecisionListResult)
	assert.Equal(t, GlobalUAAltChaChallenge, run("3.3.3.3", "example.com", "AltChaBot/1.0", NewDynamicDecisionLists()).DecisionListResult)

	hostDecisionLists := NewDynamicDecisionLists()
	hostDecisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), AltChaChallenge, true, 0)
	assert.Equal(t, ExpiringSiteWideAltChaChallenge, run("3.3.3.3", "example.com", "ua", hostDecisionLists).DecisionListResult)
}

func TestClampAltChaMaxNumber(t *testing.T) {
	cases := map[int64]int64{
		-5:       AltChaMaxNumberMin,
		0:        AltChaMaxNumberMin,
		49999:    AltChaMaxNumberMin,
		50000:    50000,
		300000:   300000,
		1000000:  1000000,
		1000001:  AltChaMaxNumberMax,
		50000000: AltChaMaxNumberMax,
	}
	for requested, want := range cases {
		assert.Equal(t, want, ClampAltChaMaxNumber(requested), "requested %d", requested)
	}
}

func TestCreateAltChaChallenge_MaxNumber(t *testing.T) {
	config := altchaTestConfig()

	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)
	assert.Equal(t, config.AltChaMaxNumber, challenge.MaxNumber, "0 falls back to the config value")

	challenge, err = CreateAltChaChallenge(config, "1.2.3.4", 300000)
	assert.Nil(t, err)
	assert.Equal(t, int64(300000), challenge.MaxNumber)
}
