// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v2"
)

//go:embed sha-inverse-challenge.html
var shaInvChallengeEmbed []byte

//go:embed password-protected-path.html
var passProtPathEmbed []byte

// Thread-safe holder for config which supports hot-reloading.
type ConfigHolder struct {
	config atomic.Pointer[Config]
	path   string
}

func NewConfigHolder(path string, standaloneTesting bool, debug bool) (*ConfigHolder, error) {
	holder := &ConfigHolder{
		config: atomic.Pointer[Config]{},
		path:   path,
	}

	restartTime := int(time.Now().Unix())
	config, err := load(path, restartTime, standaloneTesting, debug)
	if err != nil {
		return nil, err
	}

	holder.config.Store(config)

	return holder, nil
}

// Get pointer to the latest read-only snapshot of the config.
func (h *ConfigHolder) Get() *Config {
	return h.config.Load()
}

// Reload config.
func (h *ConfigHolder) Reload() error {
	old := h.config.Load()
	new, err := load(h.path, old.RestartTime, old.StandaloneTesting, old.Debug)

	if err != nil {
		return err
	}

	h.config.Store(new)

	return nil
}

func load(path string, restartTime int, standaloneTesting bool, debug bool) (*Config, error) {
	config := &Config{
		RestartTime: restartTime,
	}

	config.ReloadTime = int(time.Now().Unix()) // XXX

	hostname, err := os.Hostname()
	if err != nil {
		log.Println("couldn't get hostname! using dummy")
		hostname = "unknown-hostname"
	}
	config.Hostname = hostname
	log.Printf("INIT: hostname: %s", hostname)

	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %v: %w", path, err)
	}
	// log.Printf("read %v\n", string(configBytes[:]))

	config.StandaloneTesting = standaloneTesting
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	// boolean default = false
	if config.Debug {
		log.Printf("read config %v\n", *config)
	}

	if config.ShaInvChallengeHTML != "" {
		log.Printf("INIT: Reading SHA-inverse challenge HTML from %s", config.ShaInvChallengeHTML)
		challengerBytes, err := os.ReadFile(config.ShaInvChallengeHTML)
		if err != nil {
			return nil, fmt.Errorf("couldn't read sha-inverse-challenge.html: %w", err)
		}
		config.ChallengerBytes = challengerBytes
	} else {
		log.Printf("INIT: Reading SHA-inverse challenge HTML from embed")
		config.ChallengerBytes = shaInvChallengeEmbed
	}

	if config.PasswordProtectedPathHTML != "" {
		log.Printf("INIT: Reading Password protected path HTML from %s", config.PasswordProtectedPathHTML)
		passwordPageBytes, err := os.ReadFile(config.PasswordProtectedPathHTML)
		if err != nil {
			return nil, fmt.Errorf("couldn't read password-protected-path.html: %w", err)
		}
		config.PasswordPageBytes = passwordPageBytes
	} else {
		log.Printf("INIT: Reading Password protected path HTML from embed")
		config.PasswordPageBytes = passProtPathEmbed
	}

	for site := range config.PerSiteRegexWithRates {
		log.Printf("PerSiteRegexWithRates: %s\n", site)
	}

	if config.Debug {
		for site, failAction := range config.SitewideShaInvList {
			log.Printf("load_config: sitewide site: %s, failAction: %s\n", site, failAction)
		}
	}

	if !config.Debug && debug {
		log.Printf("debug mode enabled by command line param")
		config.Debug = true
	}

	if config.StandaloneTesting {
		config.DisableKafka = true

		log.Println("!!! setting ServerLogFile to testing-log-file.txt")
		config.ServerLogFile = "testing-log-file.txt"
		config.BanningLogFile = "banning-log-file.txt"
	}

	if config.ServerLogFile == "" {
		return nil, fmt.Errorf("config needs server_log_file")
	}

	if config.IptablesBanSeconds == 0 {
		return nil, fmt.Errorf("config needs iptables_ban_seconds")
	}

	if len(config.KafkaBrokers) < 1 {
		return nil, fmt.Errorf("config needs kafka_brokers")
	}
	log.Println("INIT: Kafka brokers: ", config.KafkaBrokers)

	return config, nil
}
