// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v2"
)

//go:embed sha-inverse-challenge.html
var shaInvChallengeEmbed []byte

//go:embed puzzle_ui/dist/index.html
var puzzleChallengeIndexEmbed []byte

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

	log.Printf("INIT: Reading Puzzle challenge HTML from embed")
	config.PuzzleChallengeHTML = puzzleChallengeIndexEmbed

	if config.PuzzleDifficultyProfiles == nil { //type implements UnmarhsalYAML()
		return nil, errors.New("ErrFailedToLoadDifficultyProfiles")
	}

	/*
		right now I am assuming that there is just one image to be served for all challenges. However, if you wanted to make
		it such that each hostname has its own logo, there would need to be a map of "Image controllers" and "targets" indexed
		by hostnames such that each hostname has its own difficulty. Then modify the PuzzleDifficultyProfileByName such that it also
		takes as argument the hostname and performs the lookup to get the target before then using that to lookup the difficulty
		profile itself. The idea of having a "target" is to be able to create the difficulties ahead of time and then
		make looking up the profile more convenient by just specifying target.
	*/
	var targetDifficulty *PuzzleDifficultyProfile

	if config.PuzzleDifficultyProfiles != nil {
		difficultyProfiles, exists := config.PuzzleDifficultyProfiles.PuzzleDifficultyProfileByName(config.PuzzleDifficultyProfiles.Target, "")
		if !exists {
			return nil, fmt.Errorf("ErrTargetDifficultyDoesNotExist: %s", config.PuzzleDifficultyProfiles.Target)
		}
		targetDifficulty = &difficultyProfiles
	}

	if targetDifficulty == nil {
		return nil, errors.New("ErrFailedToLoadDifficultyProfiles")
	}

	/*
		if you wanted to store multiple images for example different hostnames have different logs & you wanted to issue a puzzle
		with that organizations hostname, this would be a map[string]*PuzzleImageController such that on challenge just lookup the appropriate one to use
		at the level of the Generate Puzzle function when invoking the PuzzleTileMapFromImage() and PuzzleThumbnailFromImage() functions
	*/

	if config.PuzzleImageController == nil {

		//init first time, otherwise reloading new state
		var imgController = &PuzzleImageController{}
		err = imgController.Load(targetDifficulty.NPartitions)
		if err != nil {
			return nil, fmt.Errorf("ErrFailedLoadingImageControllerState: %v", err)
		}
		config.PuzzleImageController = imgController

	} else {
		//reloading a new config
		if targetDifficulty.NPartitions != config.PuzzleImageController.numberOfPartitions {
			err = config.PuzzleImageController.Load(targetDifficulty.NPartitions)
			if err != nil {
				return nil, fmt.Errorf("ErrFailedLoadingImageControllerState: %v", err)
			}
		}
	}

	return config, nil
}
