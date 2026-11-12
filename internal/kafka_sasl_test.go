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

	"github.com/stretchr/testify/assert"
)

// clearKafkaEnvForLoad blanks the .env overrides load() reads, so a load() test sees only
// its own yaml (the dev container gets the real .env through docker-compose env_file).
func clearKafkaEnvForLoad(t *testing.T) {
	for _, key := range []string{
		"KAFKA_BROKERS", "KAFKA_COMMAND_TOPIC", "DISABLE_KAFKA",
		"KAFKA_SASL_MECHANISM", "KAFKA_SASL_USERNAME", "KAFKA_SASL_PASSWORD",
	} {
		t.Setenv(key, "")
	}
}

func TestKafkaSASLMechanism(t *testing.T) {
	cases := []struct {
		name      string
		mechanism string
		username  string
		password  string
		wantName  string // "" means no SASL
		wantErr   bool
	}{
		{name: "no settings means no sasl", wantName: ""},
		{name: "plain uses the plain mechanism", mechanism: "PLAIN", username: "user", password: "pw", wantName: "PLAIN"},
		{name: "scram-sha-256 uses scram with sha-256", mechanism: "SCRAM-SHA-256", username: "user", password: "pw", wantName: "SCRAM-SHA-256"},
		{name: "scram-sha-512 uses scram with sha-512", mechanism: "SCRAM-SHA-512", username: "user", password: "pw", wantName: "SCRAM-SHA-512"},
		{name: "mechanism name is case insensitive", mechanism: "scram-sha-512", username: "user", password: "pw", wantName: "SCRAM-SHA-512"},
		{name: "credentials without a mechanism default to scram-sha-512", username: "user", password: "pw", wantName: "SCRAM-SHA-512"},
		{name: "none turns sasl off even with credentials set", mechanism: "none", username: "user", password: "pw", wantName: ""},
		{name: "none is case insensitive", mechanism: "NONE", username: "user", password: "pw", wantName: ""},
		{name: "none without credentials means no sasl", mechanism: "none", wantName: ""},
		{name: "a password alone is rejected", password: "pw", wantErr: true},
		{name: "a username alone is rejected", username: "user", wantErr: true},
		{name: "a mechanism without a password is rejected", mechanism: "PLAIN", username: "user", wantErr: true},
		{name: "a mechanism without a username is rejected", mechanism: "SCRAM-SHA-512", password: "pw", wantErr: true},
		{name: "an unknown mechanism is rejected", mechanism: "GSSAPI", username: "user", password: "pw", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := KafkaSASLMechanism(c.mechanism, c.username, c.password)
			if c.wantErr {
				assert.NotNil(t, err)
				assert.Nil(t, m)
				return
			}
			assert.Nil(t, err)
			if c.wantName == "" {
				assert.Nil(t, m)
				return
			}
			assert.NotNil(t, m)
			assert.Equal(t, c.wantName, m.Name())
		})
	}
}

func TestKafkaSASLConfig(t *testing.T) {
	writeConfig := func(t *testing.T, extraYaml string) string {
		path := filepath.Join(t.TempDir(), "config.yaml")
		configYaml := "hmac_secret: secret\nserver_log_file: unused.log\niptables_ban_seconds: 60\n" +
			"kafka_brokers: [localhost:9092]\ndisable_kafka: true\n" + extraYaml
		assert.Nil(t, os.WriteFile(path, []byte(configYaml), 0600))
		return path
	}

	t.Run("sasl settings from the environment override the yaml", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		t.Setenv("KAFKA_SASL_MECHANISM", "SCRAM-SHA-512")
		t.Setenv("KAFKA_SASL_USERNAME", "env-user")
		t.Setenv("KAFKA_SASL_PASSWORD", "env-pw")
		path := writeConfig(t, "kafka_sasl_mechanism: PLAIN\nkafka_sasl_username: yaml-user\nkafka_sasl_password: yaml-pw\n")

		config, err := load(path, 0, false, false)
		assert.Nil(t, err)
		assert.Equal(t, "SCRAM-SHA-512", config.KafkaSaslMechanism)
		assert.Equal(t, "env-user", config.KafkaSaslUsername)
		assert.Equal(t, "env-pw", config.KafkaSaslPassword)
	})

	t.Run("yaml sasl settings apply when the environment has none", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		path := writeConfig(t, "kafka_sasl_mechanism: PLAIN\nkafka_sasl_username: yaml-user\nkafka_sasl_password: yaml-pw\n")

		config, err := load(path, 0, false, false)
		assert.Nil(t, err)
		assert.Equal(t, "PLAIN", config.KafkaSaslMechanism)
		assert.Equal(t, "yaml-user", config.KafkaSaslUsername)
		assert.Equal(t, "yaml-pw", config.KafkaSaslPassword)
	})

	t.Run("credentials without a mechanism load and dial with scram-sha-512", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		t.Setenv("KAFKA_SASL_USERNAME", "env-user")
		t.Setenv("KAFKA_SASL_PASSWORD", "env-pw")
		path := writeConfig(t, "")

		config, err := load(path, 0, false, false)
		assert.Nil(t, err)
		dialer := getDialer(config)
		assert.NotNil(t, dialer.SASLMechanism)
		assert.Equal(t, "SCRAM-SHA-512", dialer.SASLMechanism.Name())
	})

	t.Run("mechanism none from the environment turns off the yaml credentials", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		t.Setenv("KAFKA_SASL_MECHANISM", "none")
		path := writeConfig(t, "kafka_sasl_mechanism: SCRAM-SHA-512\nkafka_sasl_username: yaml-user\nkafka_sasl_password: yaml-pw\n")

		config, err := load(path, 0, false, false)
		assert.Nil(t, err)
		assert.Nil(t, getDialer(config).SASLMechanism)
	})

	t.Run("load fails when a password is set without a username", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		t.Setenv("KAFKA_SASL_PASSWORD", "env-pw")
		path := writeConfig(t, "")

		_, err := load(path, 0, false, false)
		assert.NotNil(t, err)
	})

	t.Run("load fails on an unknown mechanism", func(t *testing.T) {
		clearKafkaEnvForLoad(t)
		path := writeConfig(t, "kafka_sasl_mechanism: GSSAPI\nkafka_sasl_username: u\nkafka_sasl_password: p\n")

		_, err := load(path, 0, false, false)
		assert.NotNil(t, err)
	})

	t.Run("the dialer carries the configured mechanism", func(t *testing.T) {
		dialer := getDialer(&Config{KafkaSaslMechanism: "SCRAM-SHA-256", KafkaSaslUsername: "u", KafkaSaslPassword: "p"})
		assert.NotNil(t, dialer.SASLMechanism)
		assert.Equal(t, "SCRAM-SHA-256", dialer.SASLMechanism.Name())
	})

	t.Run("the dialer has no mechanism when sasl is not configured", func(t *testing.T) {
		dialer := getDialer(&Config{})
		assert.Nil(t, dialer.SASLMechanism)
	})
}
