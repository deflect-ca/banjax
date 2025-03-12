// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/deflect-ca/banjax/internal"
	"github.com/gonetx/ipset"
)

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

	log.Println("INIT: config file: ", *configFilenamePtr)

	configHolder, err := internal.NewConfigHolder(*configFilenamePtr, *standaloneTestingPtr, *debugPtr)
	if err != nil {
		panic(err)
	}
	config := configHolder.Get()

	regexStates := internal.NewRegexRateLimitStates()
	failedChallengeStates := internal.NewFailedChallengeRateLimitStates()

	passwordProtectedPaths, err := internal.NewPasswordProtectedPaths(config)
	if err != nil {
		panic(err)
	}

	staticDecisionLists, err := internal.NewStaticDecisionLists(config)
	if err != nil {
		panic(err)
	}

	puzzleImageController, err := internal.NewPuzzleImageController(config)
	if err != nil {
		panic(err)
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

			err := configHolder.Reload()
			if err != nil {
				log.Println("failed to reload config:", err)
				continue
			}

			config := configHolder.Get()

			puzzleImageController.UpdateFromConfig(config)
			staticDecisionLists.UpdateFromConfig(config)
			dynamicDecisionLists.Clear()
			passwordProtectedPaths.UpdateFromConfig(config)
		}
	}()

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
		IPSetInstance: init_ipset(config),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go internal.RunHttpServer(
		ctx,
		configHolder,
		staticDecisionLists,
		dynamicDecisionLists,
		passwordProtectedPaths,
		regexStates,
		failedChallengeStates,
		banner,
		puzzleImageController,
	)

	go internal.RunLogTailer(
		ctx,
		configHolder,
		banner,
		staticDecisionLists,
		regexStates,
	)

	if !config.DisableKafka {
		log.Println("INIT: starting RunKafkaReader/RunKafkaWriter")

		go internal.RunKafkaReader(
			ctx,
			configHolder,
			dynamicDecisionLists,
		)

		go internal.RunKafkaWriter(
			ctx,
			configHolder,
		)
	} else {
		log.Println("INIT: not running RunKafkaReader/RunKafkaWriter due to config.DisableKafka")
	}

	go reportMetrics(
		ctx,
		29*time.Second,
		configHolder,
		dynamicDecisionLists,
		regexStates,
		failedChallengeStates,
	)

	if !config.DisableKafka {
		go reportKafkaStatusMessage(ctx, 19*time.Second, configHolder)
	}

	// Wait for SIGINT/SIGTERM
	<-ctx.Done()
}

func reportKafkaStatusMessage(
	ctx context.Context,
	interval time.Duration,
	configHolder *internal.ConfigHolder,
) {
	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			config := configHolder.Get()
			if !config.DisableKafka {
				internal.ReportStatusMessage(config)
			}
		}
	}
}

func reportMetrics(
	ctx context.Context,
	interval time.Duration,
	configHolder *internal.ConfigHolder,
	decisionLists *internal.DynamicDecisionLists,
	regexStates *internal.RegexRateLimitStates,
	failedChallengeStates *internal.FailedChallengeRateLimitStates,
) {
	config := configHolder.Get()
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
		case <-ctx.Done():
			return
		case <-ticker.C:
			internal.WriteMetricsToEncoder(
				logEncoder,
				decisionLists,
				regexStates,
				failedChallengeStates,
			)
		}
	}
}
