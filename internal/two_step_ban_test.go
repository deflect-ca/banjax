package internal

import (
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

// With both flags on, failing too many challenges gets an nginx block first, and only the
// 403s served while blocked escalate to an iptables ban.
func TestTwoStepBanEscalationEndToEnd(t *testing.T) {
	const ip = "10.0.0.1"
	const host = "example.com"
	config := loadConfigString(`
two_step_ban_esculation: true
too_many_403_ban_to_iptables_ban: true
too_many_403_ban_interval_seconds: 60
too_many_403_ban_threshold: 3
too_many_failed_challenges_interval_seconds: 60
too_many_failed_challenges_threshold: 2
`)
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)
	decisionLists := NewDynamicDecisionLists()
	failedChallengeStates := NewFailedChallengeRateLimitStates()
	tooMany403States := NewFailedChallengeRateLimitStates()
	banner := &MockBanner{}
	// as a regex rule would leave it
	decisionLists.Update(config, ip, time.Now().Add(time.Minute), Challenge, false, host, AltChaOptions{})

	request := func() DecisionForNginxResult {
		c := buildDecisionForNginxTestContext(ip, host, "/", "ua", "")
		result := decisionForNginx2(c, config, staticDecisionLists, decisionLists, passwordProtectedPaths,
			failedChallengeStates, NewFailedChallengeRateLimitStates(), banner)
		countTooMany403s(c, config, &result, tooMany403States, staticDecisionLists, banner)
		return result
	}

	// two failed challenges are under the threshold: challenge page, nothing counted
	for i := 0; i < 2; i++ {
		result := request()
		assert.False(t, result.TooManyFailedChallengesResult.Exceeded)
		assert.Nil(t, result.TooMany403Result)
	}
	assert.Equal(t, "", banner.bannedIp)

	// the third gets a 403 and step one: an nginx block, no iptables
	result := request()
	assert.True(t, result.TooManyFailedChallengesResult.Exceeded)
	assert.Equal(t, NginxBlock, banner.bannedDecision)
	assert.NotNil(t, result.TooMany403Result)
	assert.False(t, result.TooMany403Result.Exceeded)

	// MockBanner does not write to decisionLists, so put the nginx block there as Banner would
	decisionLists.Update(config, ip, time.Now().Add(time.Minute), NginxBlock, false, host, AltChaOptions{})

	// two more 403s from the expiring nginx block are still under the 403 threshold
	for i := 0; i < 2; i++ {
		result := request()
		assert.Equal(t, ExpiringBlock, result.DecisionListResult)
		assert.False(t, result.TooMany403Result.Exceeded)
	}
	assert.Equal(t, NginxBlock, banner.bannedDecision)

	// the fourth 403 is step two: iptables
	result = request()
	assert.Equal(t, ExpiringBlock, result.DecisionListResult)
	assert.True(t, result.TooMany403Result.Exceeded)
	assert.Equal(t, ip, banner.bannedIp)
	assert.Equal(t, IptablesBlock, banner.bannedDecision)
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
