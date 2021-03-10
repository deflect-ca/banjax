// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"flag"
	"github.com/equalitie/banjax-next/internal"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
)

func load_config(config *internal.Config, standaloneTestingPtr *bool, configFilenamePtr *string) {
	configBytes, err := ioutil.ReadFile(*configFilenamePtr) // XXX allow different location
	if err != nil {
		panic("couldn't read config file!")
	}
	// log.Printf("read %v\n", string(configBytes[:]))

	config.StandaloneTesting = *standaloneTestingPtr
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		log.Printf("%v\n", err)
		panic("couldn't parse config file!")
	}
	log.Printf("read %v\n", *config)
	// XXX config
	challengerBytes, err := ioutil.ReadFile("./internal/sha-inverse-challenge.html")
	if err != nil {
		panic("!!! couldn't read sha-inverse-challenge.html")
	}
	config.ChallengerBytes = challengerBytes

	passwordPageBytes, err := ioutil.ReadFile("./internal/password-protected-path.html")
	if err != nil {
		panic("!!! couldn't read password-protected-path.html")
	}
	config.PasswordPageBytes = passwordPageBytes

	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}
}

func main() {
	standaloneTestingPtr := flag.Bool("standalone-testing", false, "makes it easy to test standalone")
	configFilenamePtr := flag.String("config-file", "/etc/banjax-next/banjax-next-config.yaml", "config file")
	flag.Parse()

	log.Println("config file: ", *configFilenamePtr)

	config := internal.Config{}
	load_config(&config, standaloneTestingPtr, configFilenamePtr)

	sighup_channel := make(chan os.Signal, 1)
	signal.Notify(sighup_channel, syscall.SIGHUP)
	// XXX i forgot i had this config reload functionality.
	// i don't think this will do everything it needs to. i think we'll need to restart
	// RunHttpServer, RunLogTailer, etc. because they might have internal state that
	// referenced old config values.
	go func() {
		for _ = range sighup_channel {
			log.Println("got SIGHUP; reloading config")
			load_config(&config, standaloneTestingPtr, configFilenamePtr)
		}
	}()

	if config.StandaloneTesting {
		log.Println("!!! setting ServerLogFile to testing-log-file.txt")
		config.ServerLogFile = "testing-log-file.txt"
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

	decisionLists := internal.ConfigToDecisionLists(&config)
	passwordProtectedPaths := internal.ConfigToPasswordProtectedPaths(&config)
	ipToStates := internal.IpToStates{}
	failedChallengeStates := internal.FailedChallengeStates{}

	var wg sync.WaitGroup

	wg.Add(1)
	go internal.RunHttpServer(&config, &decisionLists, &passwordProtectedPaths, &ipToStates, &failedChallengeStates, &wg)

	wg.Add(1)
	go internal.RunLogTailer(&config, &decisionLists, &ipToStates, &wg)

	wg.Add(1)
	go internal.RunIpBanExpirer(&config, &wg)

	// wg.Add(1)
	// go internal.RunKafkaReader(&config, &decisionLists, &wg)

	// wg.Add(1)
	// go internal.RunKafkaWriter(&config, &wg)

	wg.Wait()
}
