// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const hotReloadBaseConfig = `
server_log_file: /dev/null
iptables_ban_seconds: 10
kafka_brokers: ["localhost:9092"]
expiring_decision_ttl_seconds: 3600
block_ip_ttl_seconds: 3600
`

// hotReloadFixture is the state main builds at startup and SIGHUP rebuilds, loaded from a
// config file the test can rewrite before calling reload.
type hotReloadFixture struct {
	path                   string
	configHolder           *ConfigHolder
	staticDecisionLists    *StaticDecisionLists
	dynamicDecisionLists   *DynamicDecisionLists
	passwordProtectedPaths *PasswordProtectedPaths
	deflectChallengeKeys   *DeflectChallengeKeys
	banner                 *MockBanner
}

func newHotReloadFixture(t *testing.T, yaml string) *hotReloadFixture {
	t.Helper()

	// load() lets the container's kafka env override the yaml; keep the test hermetic
	for _, name := range []string{"KAFKA_BROKERS", "KAFKA_COMMAND_TOPIC", "KAFKA_SASL_MECHANISM", "KAFKA_SASL_USERNAME", "KAFKA_SASL_PASSWORD", "DISABLE_KAFKA"} {
		t.Setenv(name, "")
	}

	f := &hotReloadFixture{path: filepath.Join(t.TempDir(), "banjax-config.yaml")}
	f.writeConfig(t, yaml)

	var err error
	f.configHolder, err = NewConfigHolder(f.path, true, false)
	require.NoError(t, err)
	config := f.configHolder.Get()
	f.staticDecisionLists, err = NewStaticDecisionLists(config)
	require.NoError(t, err)
	f.passwordProtectedPaths, err = NewPasswordProtectedPaths(config)
	require.NoError(t, err)
	f.deflectChallengeKeys, err = NewDeflectChallengeKeys(config)
	require.NoError(t, err)
	f.dynamicDecisionLists = NewDynamicDecisionLists()
	f.banner = &MockBanner{}
	return f
}

func (f *hotReloadFixture) writeConfig(t *testing.T, yaml string) {
	t.Helper()
	require.NoError(t, os.WriteFile(f.path, []byte(yaml), 0o600))
}

func (f *hotReloadFixture) reload(t *testing.T, yaml string) {
	t.Helper()
	f.writeConfig(t, yaml)
	require.NoError(t, HotReload(
		f.configHolder,
		f.staticDecisionLists,
		f.passwordProtectedPaths,
		f.deflectChallengeKeys,
		f.banner,
	))
}

func (f *hotReloadFixture) decide(ip, host, ua, sessionId string) DecisionListResult {
	c := buildDecisionForNginxTestContext(ip, host, "/", ua, sessionId)
	return decisionForNginx2(
		c,
		f.configHolder.Get(),
		f.staticDecisionLists,
		f.dynamicDecisionLists,
		f.passwordProtectedPaths,
		NewFailedChallengeRateLimitStates(),
		NewFailedChallengeRateLimitStates(),
		f.banner,
	).DecisionListResult
}

// Edges get a SIGHUP on every config push. Expiring decisions (Kafka commands from
// Baskerville, regex and failed-challenge bans) must last until their own expiry, not
// until the next push.
func TestHotReload(t *testing.T) {
	const host = "example.com"
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36"

	t.Run("an altcha click challenge on a user agent from kafka survives a reload", func(t *testing.T) {
		f := newHotReloadFixture(t, hotReloadBaseConfig)
		handleCommand(f.configHolder.Get(), commandMessage{
			Name: "altcha_challenge_ua", UA: ua, Host: host, TTL: 21600, AltChaClick: true,
		}, f.dynamicDecisionLists)
		assert.Equal(t, ExpiringUAAltChaClickChallenge, f.decide("192.0.2.10", host, ua, ""))

		f.reload(t, hotReloadBaseConfig)

		assert.Equal(t, ExpiringUAAltChaClickChallenge, f.decide("192.0.2.10", host, ua, ""))
	})

	t.Run("a decision in every expiring list survives a reload", func(t *testing.T) {
		f := newHotReloadFixture(t, hotReloadBaseConfig)
		config := f.configHolder.Get()
		for _, command := range []commandMessage{
			{Name: "challenge_ip", Value: "192.0.2.1", Host: host},
			{Name: "challenge_session", Value: "192.0.2.2", SessionId: "session-a", Host: host},
			{Name: "challenge_all", Host: host},
			{Name: "challenge_ua", UA: "SomeBot", Host: host},
			{Name: "challenge_subnet", Value: "198.51.100.0/24", Host: host},
		} {
			handleCommand(config, command, f.dynamicDecisionLists)
		}
		expires := time.Now().Add(time.Hour)
		f.dynamicDecisionLists.UpdateByIpHost(config, "192.0.2.3", host, expires, TooManyRequests)
		f.dynamicDecisionLists.UpdateFailedChallengeBan(config, "192.0.2.4", expires, host)

		f.reload(t, hotReloadBaseConfig)

		checks := map[string]func() (ExpiringDecision, bool){
			"ip":                   func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.CheckByHostIp("192.0.2.1", host) },
			"session":              func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.Check("session-a", "") },
			"host":                 func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.CheckByHost(host) },
			"user agent":           func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.CheckByUA("SomeBot", host) },
			"subnet":               func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.CheckBySubnet("198.51.100.7") },
			"ip and host":          func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.CheckByIpHost("192.0.2.3", host) },
			"failed challenge ban": func() (ExpiringDecision, bool) { return f.dynamicDecisionLists.Check("", "192.0.2.4") },
		}
		for list, check := range checks {
			_, ok := check()
			assert.True(t, ok, "the %s decision was dropped by the reload", list)
		}
	})

	// Clearing on reload used to drop these; the exemptions are applied per request, so a
	// decision kept across the reload must still honour the new config.
	t.Run("a kafka block on an ip that the reload makes protected is not applied", func(t *testing.T) {
		f := newHotReloadFixture(t, hotReloadBaseConfig)
		handleCommand(f.configHolder.Get(), commandMessage{Name: "block_ip", Value: "192.0.2.20", Host: host}, f.dynamicDecisionLists)
		assert.Equal(t, ExpiringBlock, f.decide("192.0.2.20", host, "some-ua", ""))

		f.reload(t, hotReloadBaseConfig+"protected_ips: [\"192.0.2.20\"]\n")

		assert.Equal(t, ProtectedIPException, f.decide("192.0.2.20", host, "some-ua", ""))
	})

	t.Run("a kafka block on an ip that the reload allowlists on the site is not applied", func(t *testing.T) {
		f := newHotReloadFixture(t, hotReloadBaseConfig)
		handleCommand(f.configHolder.Get(), commandMessage{Name: "block_ip", Value: "192.0.2.21", Host: host}, f.dynamicDecisionLists)
		assert.Equal(t, ExpiringBlock, f.decide("192.0.2.21", host, "some-ua", ""))

		f.reload(t, hotReloadBaseConfig+"per_site_decision_lists:\n  "+host+":\n    allow:\n      - 192.0.2.21\n")

		assert.Equal(t, PerSiteAccessGranted, f.decide("192.0.2.21", host, "some-ua", ""))
	})

	t.Run("a kafka decision on a site that the reload adds to sites_to_disable_baskerville is not applied", func(t *testing.T) {
		f := newHotReloadFixture(t, hotReloadBaseConfig)
		handleCommand(f.configHolder.Get(), commandMessage{Name: "challenge_all", Host: host}, f.dynamicDecisionLists)
		assert.Equal(t, ExpiringSiteWideChallenge, f.decide("192.0.2.30", host, "some-ua", ""))

		f.reload(t, hotReloadBaseConfig+"sites_to_disable_baskerville:\n  "+host+": true\n")

		assert.Equal(t, NoMention, f.decide("192.0.2.30", host, "some-ua", ""))
	})
}
