// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"embed"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"

	"github.com/deflect-ca/banjax/internal"
	"gopkg.in/yaml.v2"
)

//go:embed internal/sha-inverse-challenge.html
var shaInvChallengeEmbed embed.FS

//go:embed internal/password-protected-path.html
var passProtPathEmbed embed.FS

func load_config(config *internal.Config, standaloneTestingPtr *bool, configFilenamePtr *string, restartTime int) {
	config.RestartTime = restartTime
	config.ReloadTime = int(time.Now().Unix()) // XXX

	hostname, err := os.Hostname()
	if err != nil {
		log.Println("couldn't get hostname! using dummy")
		hostname = "unknown-hostname"
	}
	config.Hostname = hostname
	log.Printf("hostname: %s", hostname)

	configBytes, err := ioutil.ReadFile(*configFilenamePtr) // XXX allow different location
	if err != nil {
		panic(err)
	}
	// log.Printf("read %v\n", string(configBytes[:]))

	config.StandaloneTesting = *standaloneTestingPtr
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("read %v\n", *config)

	if config.ShaInvChallengeHTML != "" {
		log.Printf("Reading SHA-inverse challenge HTML from %s", config.ShaInvChallengeHTML)
		challengerBytes, err := ioutil.ReadFile(config.ShaInvChallengeHTML)
		if err != nil {
			panic("!!! couldn't read sha-inverse-challenge.html")
		}
		config.ChallengerBytes = challengerBytes
	} else {
		log.Printf("Reading SHA-inverse challenge HTML from embed")
		challengerBytes, err := shaInvChallengeEmbed.ReadFile("internal/sha-inverse-challenge.html")
		if err != nil {
			panic("!!! couldn't read sha-inverse-challenge.html")
		}
		config.ChallengerBytes = challengerBytes
	}

	if config.PasswordProtectedPathHTML != "" {
		log.Printf("Reading Password protected path HTML from %s", config.PasswordProtectedPathHTML)
		passwordPageBytes, err := ioutil.ReadFile(config.PasswordProtectedPathHTML)
		if err != nil {
			panic("!!! couldn't read password-protected-path.html")
		}
		config.PasswordPageBytes = passwordPageBytes
	} else {
		log.Printf("Reading Password protected path HTML from embed")
		passwordPageBytes, err := passProtPathEmbed.ReadFile("internal/password-protected-path.html")
		if err != nil {
			panic("!!! couldn't read password-protected-path.html")
		}
		config.PasswordPageBytes = passwordPageBytes
	}

	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}
}

func main() {
	// XXX protects ipToRegexStates and failedChallengeStates
	// (why both? because there are too many parameters already?)
	var rateLimitMutex sync.Mutex
	ipToRegexStates := internal.IpToRegexStates{}
	failedChallengeStates := internal.FailedChallengeStates{}

	var passwordProtectedPaths internal.PasswordProtectedPaths

	// XXX protects decisionLists
	var decisionListsMutex sync.Mutex
	var decisionLists internal.DecisionLists

	standaloneTestingPtr := flag.Bool("standalone-testing", false, "makes it easy to test standalone")
	configFilenamePtr := flag.String("config-file", "/etc/banjax/banjax-config.yaml", "config file")
	flag.Parse()

	restartTime := int(time.Now().Unix()) // XXX

	log.Println("config file: ", *configFilenamePtr)

	config := internal.Config{}
	load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime)

	sighup_channel := make(chan os.Signal, 1)
	signal.Notify(sighup_channel, syscall.SIGHUP)
	// XXX i forgot i had this config reload functionality.
	// i don't think this will do everything it needs to. i think we'll need to restart
	// RunHttpServer, RunLogTailer, etc. because they might have internal state that
	// referenced old config values.
	go func() {
		for _ = range sighup_channel {
			log.Println("got SIGHUP; reloading config")
			rateLimitMutex.Lock()
			load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime)
			rateLimitMutex.Unlock()
			configToStructs(&config, &passwordProtectedPaths, &decisionLists, &decisionListsMutex)
		}
	}()

	if config.StandaloneTesting {
		log.Println("!!! setting ServerLogFile to testing-log-file.txt")
		config.ServerLogFile = "testing-log-file.txt"
		config.BanningLogFile = "banning-log-file.txt"
	}

	if config.ServerLogFile == "" {
		panic("config needs server_log_file!!")
	}

	// XXX should i verify all the config stuff is here before we get further?
	if config.IptablesBanSeconds == 0 {
		panic("config needs iptables_ban_seconds!!")
	}

	// XXX should i verify all the config stuff is here before we get further?
	if len(config.KafkaBrokers) < 1 {
		panic("config needs kafka_brokers!!")
	}
	log.Println(config.KafkaBrokers)

	configToStructs(&config, &passwordProtectedPaths, &decisionLists, &decisionListsMutex)

	// XXX this interface exists to make mocking out the iptables stuff
	// in testing easier. there might be a better way to do it.
	// at least it encapsulates the decisionlists and their mutex
	// together, which should probably happen for the other things
	// protected by a mutex.
	banningLogFile, err := os.OpenFile(config.BanningLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer banningLogFile.Close()
	banner := internal.Banner{
		&decisionListsMutex,
		&decisionLists,
		log.New(banningLogFile, "", 0),
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go internal.RunHttpServer(
		&config,
		&decisionListsMutex,
		&decisionLists,
		&passwordProtectedPaths,
		&rateLimitMutex,
		&ipToRegexStates,
		&failedChallengeStates,
		banner,
		&wg,
	)

	wg.Add(1)
	go internal.RunLogTailer(
		&config,
		banner,
		&rateLimitMutex,
		&ipToRegexStates,
		&wg,
	)

	wg.Add(1)
	go internal.RunIpBanExpirer(
		&config,
		&wg,
	)

	wg.Add(1)
	go internal.RunKafkaReader(
		&config,
		&decisionListsMutex,
		&decisionLists,
		&wg,
	)

	wg.Add(1)
	go internal.RunKafkaWriter(
		&config,
		&wg,
	)

	metricsLogFileName := ""
	if config.StandaloneTesting {
		metricsLogFileName = "list-metrics.log"
	} else {
		metricsLogFileName = config.MetricsLogFileName
	}

	metricsLogFile, _ := os.Create(metricsLogFileName)
	defer metricsLogFile.Close()
	metricsLogEncoder := json.NewEncoder(metricsLogFile)

	// statusTicker := time.NewTicker(5 * time.Second)
	expireTicker := time.NewTicker(9 * time.Second)
	statusTicker := time.NewTicker(19 * time.Second)
	metricsTicker := time.NewTicker(29 * time.Second)
	go func() {
		for {
			select {
			case <-statusTicker.C:
				log.Println("calling ReportStatusMessage")
				internal.ReportStatusMessage(
					&config,
				)
			case <-expireTicker.C:
				internal.RemoveExpiredDecisions(
					&decisionListsMutex,
					&decisionLists,
				)
			case <-metricsTicker.C:
				internal.WriteMetricsToEncoder(
					metricsLogEncoder,
					&decisionListsMutex,
					&decisionLists,
					&rateLimitMutex,
					&ipToRegexStates,
					&failedChallengeStates,
				)
			}
		}
	}()

	wg.Wait()
}

var configToStructsMutex sync.Mutex

func configToStructs(
	config *internal.Config,
	passwordProtectedPaths *internal.PasswordProtectedPaths,
	decisionLists *internal.DecisionLists,
	decisionListsMutex *sync.Mutex,
) {
	configToStructsMutex.Lock()
	defer configToStructsMutex.Unlock()

	*passwordProtectedPaths = internal.ConfigToPasswordProtectedPaths(config)
	decisionListsMutex.Lock()
	*decisionLists = internal.ConfigToDecisionLists(config)
	decisionListsMutex.Unlock()
}
