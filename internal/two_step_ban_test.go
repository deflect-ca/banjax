package internal

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTooManyFailedChallengesTwoStepBanEsculation(t *testing.T) {
	for _, tc := range []struct {
		name     string
		twoStep  bool
		expected Decision
	}{
		{"off keeps the iptables ban", false, IptablesBlock},
		{"on only blocks with nginx", true, NginxBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{TwoStepBanEsculation: tc.twoStep}
			staticDecisionLists, err := NewStaticDecisionLists(config)
			assert.Nil(t, err)
			states := NewFailedChallengeRateLimitStates()
			banner := &MockBanner{}

			for _, challengeType := range []string{"sha_inv", "password", "altcha"} {
				banner.bannedIp, banner.bannedDecision = "", 0
				result := tooManyFailedChallenges(config, "10.0.0.1", "ua", "example.com", "/", banner,
					challengeType, states, 60, 0, "GET", staticDecisionLists)
				assert.True(t, result.Exceeded, challengeType)
				assert.Equal(t, "10.0.0.1", banner.bannedIp, challengeType)
				assert.Equal(t, tc.expected, banner.bannedDecision, challengeType)
			}
		})
	}
}

func TestTooMany403s(t *testing.T) {
	newConfig := func(enabled bool) *Config {
		return &Config{
			TooMany403BanToIptablesBan:   enabled,
			TooMany403BanIntervalSeconds: 60,
			TooMany403BanThreshold:       3,
		}
	}

	t.Run("bans with iptables once over the threshold", func(t *testing.T) {
		config := newConfig(true)
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		states := NewFailedChallengeRateLimitStates()
		banner := &MockBanner{}

		for i := 0; i < 3; i++ {
			result := tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, staticDecisionLists)
			assert.False(t, result.Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)

		result := tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, staticDecisionLists)
		assert.True(t, result.Exceeded)
		assert.Equal(t, "10.0.0.1", banner.bannedIp)
		assert.Equal(t, IptablesBlock, banner.bannedDecision)
	})

	t.Run("off never counts", func(t *testing.T) {
		config := newConfig(false)
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		states := NewFailedChallengeRateLimitStates()
		banner := &MockBanner{}

		for i := 0; i < 10; i++ {
			assert.False(t, tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, staticDecisionLists).Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)
		assert.Equal(t, 0, states.Len())
	})

	t.Run("protected ip is never counted", func(t *testing.T) {
		config := withProtectedIPs(t, newConfig(true), "10.0.0.1")
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		states := NewFailedChallengeRateLimitStates()
		banner := &MockBanner{}

		for i := 0; i < 10; i++ {
			assert.False(t, tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, staticDecisionLists).Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)
	})

	t.Run("ip allowlisted on the host is never counted", func(t *testing.T) {
		config := loadConfigString(`
too_many_403_ban_to_iptables_ban: true
too_many_403_ban_interval_seconds: 60
too_many_403_ban_threshold: 3
per_site_decision_lists:
  example.com:
    allow: [10.0.0.1]
`)
		staticDecisionLists, err := NewStaticDecisionLists(config)
		assert.Nil(t, err)
		states := NewFailedChallengeRateLimitStates()
		banner := &MockBanner{}

		for i := 0; i < 10; i++ {
			assert.False(t, tooMany403s(config, "10.0.0.1", "ua", "example.com", "/", "GET", banner, states, staticDecisionLists).Exceeded)
		}
		assert.Equal(t, "", banner.bannedIp)

		// the allowlist is per site: the same ip on another host is counted
		for i := 0; i < 4; i++ {
			tooMany403s(config, "10.0.0.1", "ua", "other.com", "/", "GET", banner, states, staticDecisionLists)
		}
		assert.Equal(t, "10.0.0.1", banner.bannedIp)
		assert.Equal(t, IptablesBlock, banner.bannedDecision)
	})
}

// twoStepTestConfig turns both escalation steps on: an nginx block after 2 failed challenges
// (sha-inv, password or AltCha), and an iptables ban after 3 of the 403s that follow.
const twoStepTestConfig = `
standalone_testing: true
hmac_secret: secret
expiring_decision_ttl_seconds: 60
two_step_ban_esculation: true
too_many_403_ban_to_iptables_ban: true
too_many_403_ban_interval_seconds: 60
too_many_403_ban_threshold: 3
too_many_failed_challenges_interval_seconds: 60
too_many_failed_challenges_threshold: 2
altcha_too_many_failed_challenges_interval_seconds: 60
altcha_too_many_failed_challenges_threshold: 2
altcha_max_number: 1000
altcha_cost: 1
altcha_cookie_ttl_seconds: 60
`

// newStandaloneBanner is the production Banner, so bans really land in decisionLists. In
// standalone testing it never calls iptables.
func newStandaloneBanner(decisionLists *DynamicDecisionLists) Banner {
	discard := log.New(io.Discard, "", 0)
	return Banner{DecisionLists: decisionLists, Logger: discard, LoggerTemp: discard}
}

// With both flags on, failing too many challenges gets an nginx block first, which holds for
// every later request whatever challenged the ip, and the 403s served while blocked escalate
// to an iptables ban. Each case is a different challenge source; the ones checked before the
// expiring ip list used to keep serving challenges while the block was stored.
func TestTwoStepBanEscalationEveryChallengeSource(t *testing.T) {
	const ip = "10.0.0.1"
	const host = "example.com"
	const ua = "SomeBot"
	const sessionId = "session1"
	expires := time.Now().Add(time.Minute)

	for _, tc := range []struct {
		name       string
		extraYaml  string
		path       string
		sessionId  string
		setup      func(config *Config, lists *DynamicDecisionLists)
		challenged DecisionListResult // result of the requests before the nginx block
	}{
		{name: "static per-site sha-inv", extraYaml: "per_site_decision_lists:\n  example.com:\n    challenge: [10.0.0.1]\n",
			challenged: PerSiteChallenge},
		{name: "static per-site altcha", extraYaml: "per_site_decision_lists:\n  example.com:\n    altcha_challenge: [10.0.0.1]\n",
			challenged: PerSiteAltChaChallenge},
		{name: "static global sha-inv", extraYaml: "global_decision_lists:\n  challenge: [10.0.0.1]\n",
			challenged: GlobalChallenge},
		{name: "static global ua altcha", extraYaml: "global_user_agent_decision_lists:\n  altcha_challenge: [SomeBot]\n",
			challenged: GlobalUAAltChaChallenge},
		{name: "password protected path", path: "/wp-admin",
			extraYaml: "password_protected_paths:\n  example.com: [wp-admin]\n" +
				"password_hashes:\n  example.com: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n",
			challenged: PasswordProtectedPath},
		{name: "expiring session challenge", sessionId: sessionId,
			setup: func(config *Config, lists *DynamicDecisionLists) {
				lists.UpdateBySessionId(config, ip, sessionId, expires, Challenge, false, host, AltChaOptions{})
			},
			challenged: ExpiringChallenge},
		{name: "expiring ua challenge",
			setup: func(config *Config, lists *DynamicDecisionLists) {
				lists.UpdateByUA(config, ua, expires, AltChaChallenge, false, host, AltChaOptions{})
			},
			challenged: ExpiringUAAltChaChallenge},
		{name: "expiring host challenge",
			setup: func(config *Config, lists *DynamicDecisionLists) {
				lists.UpdateByHost(config, host, expires, Challenge, false, AltChaOptions{})
			},
			challenged: ExpiringSiteWideChallenge},
		{name: "expiring ip challenge",
			setup: func(config *Config, lists *DynamicDecisionLists) {
				lists.Update(config, ip, expires, Challenge, false, host, AltChaOptions{})
			},
			challenged: ExpiringChallenge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := loadConfigString(twoStepTestConfig + tc.extraYaml)
			staticDecisionLists, err := NewStaticDecisionLists(config)
			assert.Nil(t, err)
			passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
			assert.Nil(t, err)
			decisionLists := NewDynamicDecisionLists()
			if tc.setup != nil {
				tc.setup(config, decisionLists)
			}
			banner := newStandaloneBanner(decisionLists)
			failedChallengeStates := NewFailedChallengeRateLimitStates()
			altchaFailedChallengeStates := NewFailedChallengeRateLimitStates()
			tooMany403States := NewFailedChallengeRateLimitStates()
			path := tc.path
			if path == "" {
				path = "/"
			}

			request := func() (int, DecisionForNginxResult) {
				c := buildDecisionForNginxTestContext(ip, host, path, ua, tc.sessionId)
				result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
					failedChallengeStates, altchaFailedChallengeStates, banner)
				countTooMany403s(c, config, &result, tooMany403States, staticDecisionLists, banner)
				return c.Writer.Status(), result
			}

			// two failed challenges are under the threshold
			for i := 0; i < 2; i++ {
				status, result := request()
				assert.NotEqual(t, 403, status)
				assert.Equal(t, tc.challenged, result.DecisionListResult)
			}
			stored, ok := decisionLists.Check("", ip)
			assert.False(t, ok && stored.Decision.IsDenial(), "no block yet")

			// the third is step one: a 403 and a stored nginx block, no iptables
			status, result := request()
			assert.Equal(t, 403, status)
			assert.Equal(t, tc.challenged, result.DecisionListResult)
			stored, ok = decisionLists.Check("", ip)
			assert.True(t, ok)
			assert.Equal(t, NginxBlock, stored.Decision)
			assert.True(t, stored.IsFailedChallengeBan())

			// every later request is blocked by it, ahead of the challenge source
			for i := 0; i < 2; i++ {
				status, result := request()
				assert.Equal(t, 403, status)
				assert.Equal(t, FailedChallengeBlock, result.DecisionListResult)
				assert.False(t, result.TooMany403Result.Exceeded)
			}

			// the fourth 403 is step two: iptables, and the block keeps its precedence
			status, result = request()
			assert.Equal(t, 403, status)
			assert.Equal(t, FailedChallengeBlock, result.DecisionListResult)
			assert.True(t, result.TooMany403Result.Exceeded)
			stored, ok = decisionLists.Check("", ip)
			assert.True(t, ok)
			assert.Equal(t, IptablesBlock, stored.Decision)
			assert.True(t, stored.IsFailedChallengeBan())

			status, result = request()
			assert.Equal(t, 403, status)
			assert.Equal(t, FailedChallengeBlock, result.DecisionListResult)
		})
	}
}

func TestFailedChallengeBanExemptions(t *testing.T) {
	const ip = "10.0.0.1"
	expires := time.Now().Add(time.Minute)
	config := withProtectedIPs(t, loadConfigString(twoStepTestConfig+`
per_site_decision_lists:
  allowed.com:
    allow: [10.0.0.1, 10.0.0.2]
`), "10.0.0.2")
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()
	decisionLists.UpdateFailedChallengeBan(config, ip, expires, "example.com")

	run := func(ip, host string) DecisionListResult {
		c := buildDecisionForNginxTestContext(ip, host, "/", "ua", "")
		return decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{}).DecisionListResult
	}

	// blocked on every host, except one it is allowlisted on
	assert.Equal(t, FailedChallengeBlock, run(ip, "example.com"))
	assert.Equal(t, FailedChallengeBlock, run(ip, "other.com"))
	assert.Equal(t, PerSiteAccessGranted, run(ip, "allowed.com"))

	// a protected ip is never stored
	decisionLists.UpdateFailedChallengeBan(config, "10.0.0.2", expires, "example.com")
	_, ok := decisionLists.Check("", "10.0.0.2")
	assert.False(t, ok)
	assert.Equal(t, NoMention, run("10.0.0.2", "example.com"))
}

// Only a ban from failed challenges moves ahead of the static lists: other expiring blocks
// (kafka, regex rules, baskerville) keep their place, and an expired ban does not pass its
// precedence on.
func TestFailedChallengeBanPrecedenceIsNotShared(t *testing.T) {
	config := loadConfigString(twoStepTestConfig + "global_decision_lists:\n  challenge: [10.0.0.1, 10.0.0.2]\n")
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()

	run := func(ip string) DecisionListResult {
		c := buildDecisionForNginxTestContext(ip, "example.com", "/", "ua", "")
		return decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{}).DecisionListResult
	}

	decisionLists.Update(config, "10.0.0.1", time.Now().Add(time.Minute), NginxBlock, false, "example.com", AltChaOptions{})
	assert.Equal(t, GlobalChallenge, run("10.0.0.1"))

	decisionLists.UpdateFailedChallengeBan(config, "10.0.0.2", time.Now().Add(-time.Second), "example.com")
	decisionLists.Update(config, "10.0.0.2", time.Now().Add(time.Minute), IptablesBlock, false, "example.com", AltChaOptions{})
	stored, ok := decisionLists.Check("", "10.0.0.2")
	assert.True(t, ok)
	assert.False(t, stored.IsFailedChallengeBan())
	assert.Equal(t, GlobalChallenge, run("10.0.0.2"))
}

func TestLoad_OmittedTooMany403SettingsGetDefaults(t *testing.T) {
	for _, key := range []string{"KAFKA_BROKERS", "KAFKA_COMMAND_TOPIC", "DISABLE_KAFKA"} {
		t.Setenv(key, "")
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	configYaml := "hmac_secret: secret\nserver_log_file: unused.log\niptables_ban_seconds: 60\n" +
		"kafka_brokers: [localhost:9092]\ndisable_kafka: true\ntoo_many_403_ban_to_iptables_ban: true\n"
	assert.Nil(t, os.WriteFile(path, []byte(configYaml), 0600))
	config, err := load(path, 0, false, false)
	assert.Nil(t, err)
	assert.False(t, config.TwoStepBanEsculation)
	assert.True(t, config.TooMany403BanToIptablesBan)
	assert.Equal(t, TooMany403BanDefaultIntervalSeconds, config.TooMany403BanIntervalSeconds)
	assert.Equal(t, TooMany403BanDefaultThreshold, config.TooMany403BanThreshold)
}
