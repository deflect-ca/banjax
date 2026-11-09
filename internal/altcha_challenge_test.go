// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
	"github.com/stretchr/testify/assert"
)

// solveAltCha solves a minted challenge the way the widget does.
func solveAltCha(t *testing.T, challenge altcha.Challenge) *altcha.Solution {
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{
		Challenge: challenge,
		DeriveKey: altcha.DeriveKeyPBKDF2(),
		Timeout:   30 * time.Second,
	})
	assert.Nil(t, err)
	assert.NotNil(t, solution)
	return solution
}

// solveAltChaToCookie solves a minted challenge and returns the base64 payload a
// browser would set as the deflect_altcha cookie value.
func solveAltChaToCookie(t *testing.T, challenge altcha.Challenge) string {
	payload := altcha.Payload{Challenge: challenge, Solution: *solveAltCha(t, challenge)}
	jsonBytes, err := json.Marshal(payload)
	assert.Nil(t, err)
	return base64.StdEncoding.EncodeToString(jsonBytes)
}

var altchaChallengeAttr = regexp.MustCompile(`\schallenge="([^"]*)"`)

// altchaChallengeFromPage reads the challenge applyArgsToAltChaPage put into the widget.
func altchaChallengeFromPage(t *testing.T, page string) altcha.Challenge {
	m := altchaChallengeAttr.FindStringSubmatch(page)
	assert.NotNil(t, m)
	var challenge altcha.Challenge
	assert.Nil(t, json.Unmarshal([]byte(html.UnescapeString(m[1])), &challenge))
	return challenge
}

func altchaTestConfig() *Config {
	return &Config{
		HmacSecret:                             "test-secret",
		AltChaMaxNumber:                        100,
		AltChaCost:                             10, // keep test solves fast
		AltChaCookieTtlSeconds:                 3600,
		AltChaChallengerBytes:                  altchaChallengeEmbed,
		AltChaTooManyFailedChallengesThreshold: 3,
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

// modifyHTMLContent only replaces the first occurrence, so each injection target must
// appear exactly once in the page or the injection can land in a comment instead
func TestAltChaPage_InjectionTargetsAppearOnce(t *testing.T) {
	page := string(altchaChallengeEmbed)
	assert.Equal(t, 1, strings.Count(page, `challenge="{}"`))
	assert.Equal(t, 1, strings.Count(page, `"deflect_altcha=" + base64_cookie`))
}

// the inlined ALTCHA widget must be the exact upstream file named in the page's comment; a
// stray edit to that one huge line still parses but breaks the widget at runtime
func TestAltChaPage_InlineWidgetMatchesPinnedHash(t *testing.T) {
	page := string(altchaChallengeEmbed)
	pinned := regexp.MustCompile(`sha384:\s+(\S+)`).FindStringSubmatch(page)
	if !assert.NotNil(t, pinned, "sha384 pin comment not found") {
		return
	}
	script := regexp.MustCompile(`(?s)<script type="module">(const e=!1;.*?)</script>`).FindStringSubmatch(page)
	if !assert.NotNil(t, script, "inline ALTCHA widget script not found") {
		return
	}
	sum := sha512.Sum384([]byte(script[1]))
	assert.Equal(t, pinned[1], base64.StdEncoding.EncodeToString(sum[:]))
}

func TestApplyArgsToAltChaPage(t *testing.T) {
	config := altchaTestConfig()
	config.AltChaCookieTtlSeconds = 4321
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	page := string(applyArgsToAltChaPage(config, challenge, false))

	// the replacements hit the code, not a comment quoting the same text
	assert.Contains(t, page, `"deflect_altcha=" + base64_cookie + ";max-age=4321" + ";SameSite=Lax;path=/;"`)
	assert.NotContains(t, page, `challenge="{}"`)
	assert.Equal(t, challenge.Signature, altchaChallengeFromPage(t, page).Signature)
}

// the binding can be the client's User-Agent, which must not be able to break out of the
// widget's challenge attribute
func TestApplyArgsToAltChaPage_EscapesBinding(t *testing.T) {
	config := altchaTestConfig()
	const binding = `evil" onmouseover="alert(1)" x='<script>`
	challenge, err := CreateAltChaChallenge(config, binding, 0)
	assert.Nil(t, err)

	page := string(applyArgsToAltChaPage(config, challenge, false))

	assert.NotContains(t, page, `onmouseover="alert(1)"`)
	assert.NotContains(t, page, "<script>`")
	fromPage := altchaChallengeFromPage(t, page)
	assert.Equal(t, binding, fromPage.Parameters.Data["binding"])
	// and what the browser decodes still verifies
	ok, err := VerifyAltChaPayload(config, solveAltChaToCookie(t, fromPage), binding)
	assert.Nil(t, err)
	assert.True(t, ok)
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
		decisionLists.Update(config, clientIp, time.Now().Add(time.Minute), AltChaChallenge, true, host, AltChaOptions{})
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
		shaDecisionLists.Update(config, clientIp, time.Now().Add(time.Minute), Challenge, true, host, AltChaOptions{})

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
	hostDecisionLists.UpdateByHost(config, "example.com", time.Now().Add(time.Minute), AltChaChallenge, true, AltChaOptions{})
	assert.Equal(t, ExpiringSiteWideAltChaChallenge, run("3.3.3.3", "example.com", "ua", hostDecisionLists).DecisionListResult)
}

func TestClampAltChaMaxNumber(t *testing.T) {
	cases := map[int64]int64{
		-5:       AltChaMaxNumberMin,
		0:        AltChaMaxNumberMin,
		999:      AltChaMaxNumberMin,
		1000:     1000,
		5000:     5000,
		20000:    20000,
		20001:    AltChaMaxNumberMax,
		50000000: AltChaMaxNumberMax,
	}
	for requested, want := range cases {
		assert.Equal(t, want, ClampAltChaMaxNumber(requested), "requested %d", requested)
	}
}

func TestCreateAltChaChallenge_V2Parameters(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	params := challenge.Parameters
	assert.Equal(t, AltChaAlgorithm, params.Algorithm)
	assert.Equal(t, config.AltChaCost, params.Cost)
	assert.NotEmpty(t, params.KeySignature, "verification relies on the key signature fast path")
	assert.NotEmpty(t, challenge.Signature)
	assert.InDelta(t, time.Now().Add(time.Hour).Unix(), params.ExpiresAt, 5)
	assert.Equal(t, "1.2.3.4", params.Data["binding"])
}

func TestCreateAltChaChallenge_UnsetConfigUsesDefaults(t *testing.T) {
	config := altchaTestConfig()
	config.AltChaCost = 0
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)
	assert.Equal(t, AltChaDefaultCost, challenge.Parameters.Cost)
}

func TestCreateAltChaChallenge_MaxNumber(t *testing.T) {
	config := altchaTestConfig()

	// the counter the client has to find never exceeds the difficulty asked for
	for _, maxNumber := range []int64{0, 5} {
		limit := maxNumber
		if limit == 0 {
			limit = config.AltChaMaxNumber
		}
		for i := 0; i < 5; i++ {
			challenge, err := CreateAltChaChallenge(config, "1.2.3.4", maxNumber)
			assert.Nil(t, err)
			assert.LessOrEqual(t, int64(solveAltCha(t, challenge).Counter), limit)
		}
	}
}

func TestVerifyAltChaPayload_ForgedSolution(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	// the real signed challenge with a made-up key, as a client that skipped the work would send
	for _, derivedKey := range []string{strings.Repeat("00", 32), "not hex"} {
		payload := altcha.Payload{Challenge: challenge, Solution: altcha.Solution{Counter: 1, DerivedKey: derivedKey}}
		jsonBytes, _ := json.Marshal(payload)
		ok, err := VerifyAltChaPayload(config, base64.StdEncoding.EncodeToString(jsonBytes), "1.2.3.4")
		assert.Nil(t, err)
		assert.False(t, ok, derivedKey)
	}
}

func TestVerifyAltChaPayload_TamperedBinding(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)
	solution := solveAltCha(t, challenge)

	// rebinding a solved challenge to another client breaks the challenge signature
	challenge.Parameters.Data = map[string]interface{}{"binding": "9.9.9.9"}
	jsonBytes, _ := json.Marshal(altcha.Payload{Challenge: challenge, Solution: *solution})
	ok, err := VerifyAltChaPayload(config, base64.StdEncoding.EncodeToString(jsonBytes), "9.9.9.9")
	assert.Nil(t, err)
	assert.False(t, ok)
}

func TestApplyArgsToAltChaPage_ClickMode(t *testing.T) {
	config := altchaTestConfig()
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	// default: the widget solves on page load
	page := string(applyArgsToAltChaPage(config, challenge, false))
	assert.Contains(t, page, `<altcha-widget id="altcha" auto="onload"`)

	// click: the widget waits for its checkbox
	page = string(applyArgsToAltChaPage(config, challenge, true))
	assert.Contains(t, page, `<altcha-widget id="altcha" auto="off"`)
	assert.NotContains(t, page, `auto="onload"`)
}

func TestAltChaPage_ClickTargetAppearsOnce(t *testing.T) {
	// modifyHTMLContent only replaces the first occurrence
	assert.Equal(t, 1, strings.Count(string(altchaChallengeEmbed), `auto="onload"`))
}

func TestParseSitewideAltCha(t *testing.T) {
	cases := map[string]SitewideAltCha{
		"block":          {FailAction: Block},
		"no_block":       {FailAction: NoBlock},
		"block_click":    {FailAction: Block, Click: true},
		"no_block_click": {FailAction: NoBlock, Click: true},
	}
	for value, want := range cases {
		got, err := ParseSitewideAltCha(value)
		assert.Nil(t, err, value)
		assert.Equal(t, want, got, value)
	}
	for _, value := range []string{"", "click", "block_clic", "_click", "sometimes_click"} {
		_, err := ParseSitewideAltCha(value)
		assert.NotNil(t, err, value)
	}
}

// A config written before AltCha existed has no altcha_too_many_failed_challenges_* keys. Left
// at zero, the first cookie-less request would exceed the threshold and get the ip banned.
func TestLoad_OmittedAltChaFailureSettingsGetDefaults(t *testing.T) {
	for _, key := range []string{"KAFKA_BROKERS", "KAFKA_COMMAND_TOPIC", "DISABLE_KAFKA"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	configYaml := "hmac_secret: secret\nserver_log_file: unused.log\niptables_ban_seconds: 60\n" +
		"kafka_brokers: [localhost:9092]\ndisable_kafka: true\n"
	assert.Nil(t, os.WriteFile(path, []byte(configYaml), 0600))
	config, err := load(path, 0, false, false)
	assert.Nil(t, err)
	assert.Equal(t, AltChaDefaultTooManyFailedChallengesIntervalSeconds, config.AltChaTooManyFailedChallengesIntervalSeconds)
	assert.Equal(t, AltChaDefaultTooManyFailedChallengesThreshold, config.AltChaTooManyFailedChallengesThreshold)

	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	c := buildDecisionForNginxTestContext("1.2.3.4", "example.com", "/", "ua", "")
	banner := &MockBanner{}
	result := sendOrValidateAltChaChallenge(config, c, banner, NewFailedChallengeRateLimitStates(), Block,
		staticDecisionLists, AltChaOptions{}, GlobalAltChaChallenge)

	assert.False(t, result.TooManyFailedChallengesResult.Exceeded)
	assert.Equal(t, 429, c.Writer.Status())
	assert.Equal(t, "", banner.bannedIp)
}

func TestSendOrValidateAltChaChallenge_NotBefore(t *testing.T) {
	config := altchaTestConfig()
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	const clientIp = "1.2.3.4"

	validate := func(cookie string, options AltChaOptions) SendOrValidateAltChaChallengeResult {
		c := buildDecisionForNginxTestContext(clientIp, "example.com", "/", "ua", "")
		c.Request.AddCookie(&http.Cookie{Name: AltChaCookieName, Value: cookie})
		return sendOrValidateAltChaChallenge(config, c, &MockBanner{}, NewFailedChallengeRateLimitStates(), NoBlock,
			staticDecisionLists, options, GlobalAltChaChallenge)
	}

	old, err := CreateAltChaChallenge(config, clientIp, 0)
	assert.Nil(t, err)
	oldCookie := solveAltChaToCookie(t, old)
	time.Sleep(2 * time.Millisecond)
	forceNew := AltChaOptions{NotBefore: time.Now().UnixMilli()}

	assert.Equal(t, AltChaChallengePassed, validate(oldCookie, AltChaOptions{}).AltChaChallengeResult,
		"without force new an earlier cookie still passes")
	assert.Equal(t, AltChaChallengeFailedBadCookie, validate(oldCookie, forceNew).AltChaChallengeResult,
		"a cookie minted before the decision must be re-solved")

	fresh, err := CreateAltChaChallenge(config, clientIp, 0)
	assert.Nil(t, err)
	assert.Equal(t, AltChaChallengePassed, validate(solveAltChaToCookie(t, fresh), forceNew).AltChaChallengeResult,
		"a cookie minted after the decision passes")
}
