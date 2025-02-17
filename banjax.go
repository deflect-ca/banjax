// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/deflect-ca/banjax/internal"
	"github.com/gonetx/ipset"
	"gopkg.in/yaml.v2"
)

//go:embed internal/sha-inverse-challenge.html
var shaInvChallengeEmbed embed.FS

//go:embed internal/password-protected-path.html
var passProtPathEmbed embed.FS

func load_config(config *internal.Config, standaloneTestingPtr *bool, configFilenamePtr *string, restartTime int, debugPtr *bool) {
	config.RestartTime = restartTime
	config.ReloadTime = int(time.Now().Unix()) // XXX

	hostname, err := os.Hostname()
	if err != nil {
		log.Println("couldn't get hostname! using dummy")
		hostname = "unknown-hostname"
	}
	config.Hostname = hostname
	log.Printf("INIT: hostname: %s", hostname)

	configBytes, err := os.ReadFile(*configFilenamePtr) // XXX allow different location
	if err != nil {
		panic(err)
	}
	// log.Printf("read %v\n", string(configBytes[:]))

	config.StandaloneTesting = *standaloneTestingPtr
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		log.Fatal(err)
	}

	// boolean default = false
	if config.Debug {
		log.Printf("read config %v\n", *config)
	}

	if config.ShaInvChallengeHTML != "" {
		log.Printf("INIT: Reading SHA-inverse challenge HTML from %s", config.ShaInvChallengeHTML)
		challengerBytes, err := os.ReadFile(config.ShaInvChallengeHTML)
		if err != nil {
			panic("!!! couldn't read sha-inverse-challenge.html")
		}
		config.ChallengerBytes = challengerBytes
	} else {
		log.Printf("INIT: Reading SHA-inverse challenge HTML from embed")
		challengerBytes, err := shaInvChallengeEmbed.ReadFile("internal/sha-inverse-challenge.html")
		if err != nil {
			panic("!!! couldn't read sha-inverse-challenge.html")
		}
		config.ChallengerBytes = challengerBytes
	}

	if config.PasswordProtectedPathHTML != "" {
		log.Printf("INIT: Reading Password protected path HTML from %s", config.PasswordProtectedPathHTML)
		passwordPageBytes, err := os.ReadFile(config.PasswordProtectedPathHTML)
		if err != nil {
			panic("!!! couldn't read password-protected-path.html")
		}
		config.PasswordPageBytes = passwordPageBytes
	} else {
		log.Printf("INIT: Reading Password protected path HTML from embed")
		passwordPageBytes, err := passProtPathEmbed.ReadFile("internal/password-protected-path.html")
		if err != nil {
			panic("!!! couldn't read password-protected-path.html")
		}
		config.PasswordPageBytes = passwordPageBytes
	}

	for site, _ := range config.PerSiteRegexWithRates {
		log.Printf("PerSiteRegexWithRates: %s\n", site)
	}

	if config.Debug {
		for site, failAction := range config.SitewideShaInvList {
			log.Printf("load_config: sitewide site: %s, failAction: %s\n", site, failAction)
		}
	}

	if !config.Debug && *debugPtr {
		log.Printf("debug mode enabled by command line param")
		config.Debug = true
	}

	if config.StandaloneTesting {
		config.DisableKafka = true
	}
}

const (
	IPSetName = "banjax_ipset"
)

func init_ipset(config *internal.Config) ipset.IPSet {
	if config.StandaloneTesting {
		log.Println("init_ipset: Not init ipset in testing")
		return nil
	}
	if err := ipset.Check(); err != nil {
		log.Println("init_ipset: ipset.Check() failed")
		panic(err)
	}

	newIPset, err := ipset.New(
		IPSetName,
		ipset.HashIp,
		ipset.Exist(true),
		ipset.Timeout(time.Duration(config.IptablesBanSeconds)*time.Second))
	if err != nil {
		log.Println("init_ipset: ipset.New() failed")
		panic(err)
	}
	log.Println("init_ipset: new ipset:", newIPset.Name())

	// enable ipset with iptables
	// iptables -I INPUT -m set --match-set banjax_ipset src -j DROP
	ipt, err := iptables.New()
	if err != nil {
		log.Println("init_ipset: iptables.New() failed")
		panic(err)
	}
	err = ipt.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", IPSetName, "src", "-j", "DROP")
	if err != nil {
		log.Println("init_ipset: iptables.Insert() failed, did not enable ipset")
		panic(err)
	}

	return newIPset
}

func main() {
	standaloneTestingPtr := flag.Bool("standalone-testing", false, "makes it easy to test standalone")
	configFilenamePtr := flag.String("config-file", "/etc/banjax/banjax-config.yaml", "config file")
	debugPtr := flag.Bool("debug", false, "debug mode with verbose logging")
	flag.Parse()

	restartTime := int(time.Now().Unix()) // XXX

	log.Println("INIT: config file: ", *configFilenamePtr)

	// FIXME: config is not thread-safe
	config := internal.Config{}
	load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime, debugPtr)

	regexStates := internal.NewRegexRateLimitStates()
	failedChallengeStates := internal.NewFailedChallengeRateLimitStates()
	passwordProtectedPaths := internal.PasswordProtectedPaths{}

	staticDecisionLists, err := internal.NewStaticDecisionListsFromConfig(&config)
	if err != nil {
		panic(fmt.Sprintf("%v", err))
	}

	dynamicDecisionLists := internal.NewDynamicDecisionLists()

	sighup_channel := make(chan os.Signal, 1)
	signal.Notify(sighup_channel, syscall.SIGHUP)
	// XXX i forgot i had this config reload functionality.
	// i don't think this will do everything it needs to. i think we'll need to restart
	// RunHttpServer, RunLogTailer, etc. because they might have internal state that
	// referenced old config values.
	go func() {
		for range sighup_channel {
			log.Println("HOT-RELOAD: got SIGHUP; reloading config")

			config = internal.Config{}
			load_config(&config, standaloneTestingPtr, configFilenamePtr, restartTime, debugPtr)

			staticDecisionLists.UpdateFromConfig(&config)
			dynamicDecisionLists.Clear()

			configToStructs(&config, &passwordProtectedPaths)
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
	log.Println("INIT: Kafka brokers: ", config.KafkaBrokers)

	configToStructs(&config, &passwordProtectedPaths)

	// XXX this interface exists to make mocking out the iptables stuff
	// in testing easier. there might be a better way to do it.
	// at least it encapsulates the decisionlists and their mutex
	// together, which should probably happen for the other things
	// protected by a mutex.
	banningLogFile, err := os.OpenFile(config.BanningLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	if config.BanningLogFileTemp == "" {
		config.BanningLogFileTemp = fmt.Sprintf("%s.tmp", config.BanningLogFile)
	}
	banningLogFileTemp, err := os.OpenFile(config.BanningLogFileTemp, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer banningLogFile.Close()
	defer banningLogFileTemp.Close()

	banner := internal.Banner{
		DecisionLists: dynamicDecisionLists,
		Logger:        log.New(banningLogFile, "", 0),
		LoggerTemp:    log.New(banningLogFileTemp, "", 0),
		IPSetInstance: init_ipset(&config),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go internal.RunHttpServer(
		ctx,
		&config,
		staticDecisionLists,
		dynamicDecisionLists,
		&passwordProtectedPaths,
		regexStates,
		failedChallengeStates,
		banner,
	)

	go internal.RunLogTailer(
		ctx,
		&config,
		banner,
		staticDecisionLists,
		regexStates,
	)

	if !config.DisableKafka {
		log.Println("INIT: starting RunKafkaReader/RunKafkaWriter")

		go internal.RunKafkaReader(
			ctx,
			&config,
			dynamicDecisionLists,
		)

		go internal.RunKafkaWriter(
			ctx,
			&config,
		)
	} else {
		log.Println("INIT: not running RunKafkaReader/RunKafkaWriter due to config.DisableKafka")
	}

	go reportMetrics(
		ctx,
		29*time.Second,
		&config,
		dynamicDecisionLists,
		regexStates,
		failedChallengeStates,
	)

	if !config.DisableKafka {
		go reportKafkaStatusMessage(ctx, 19*time.Second, &config)
	}

	// Wait for SIGINT/SIGTERM
	<-ctx.Done()
}

func reportKafkaStatusMessage(ctx context.Context, interval time.Duration, config *internal.Config) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <- ctx.Done():
			return
		case <- ticker.C:
			if !config.DisableKafka {
				internal.ReportStatusMessage(config)
			}
		}
	}
}

func reportMetrics(
	ctx context.Context,
	interval time.Duration,
	config *internal.Config,
	decisionLists *internal.DynamicDecisionLists,
	regexStates *internal.RegexRateLimitStates,
	failedChallengeStates *internal.FailedChallengeRateLimitStates,
) {
	logFileName := ""
	if config.StandaloneTesting {
		logFileName = "list-metrics.log"
	} else {
		logFileName = config.MetricsLogFileName
	}

	if logFileName == "" {
		return
	}

	logFile, err := os.Create(logFileName)
	if err != nil {
		log.Println("failed to create metrics log file:", err)
		return
	}

	defer logFile.Close()

	logEncoder := json.NewEncoder(logFile)
	ticker := time.NewTicker(interval)

	for {
		select {
		case <- ctx.Done():
			return
		case <- ticker.C:
			internal.WriteMetricsToEncoder(
				logEncoder,
				decisionLists,
				regexStates,
				failedChallengeStates,
			)
		}
	}
}

var configToStructsMutex sync.Mutex

func configToStructs(
	config *internal.Config,
	passwordProtectedPaths *internal.PasswordProtectedPaths,
) {
	configToStructsMutex.Lock()
	defer configToStructsMutex.Unlock()

	*passwordProtectedPaths = internal.ConfigToPasswordProtectedPaths(config)
}
