// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"github.com/hpcloud/tail"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"
)

func RunLogTailer(config *Config, decisionLists *DecisionLists, ipToStates *IpToStates, wg *sync.WaitGroup) {
	banner := Banner{decisionLists} // XXX better way to mock this with an interface?

	log.Println("len(RegexesWithRates) is: ", len(config.RegexesWithRates))
	// if TailFile() fails or we hit EOF, we should retry
	for {
		defer wg.Done()
		t, err := tail.TailFile(config.ServerLogFile, tail.Config{Follow: true})
		if err != nil {
			log.Println("log tailer failed to start. waiting a bit and trying again.")
		} else {
			log.Println("log tailer started")
			for line := range t.Lines {
				consumeLine(line, ipToStates, banner, config)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

func consumeLine(line *tail.Line, ipToStates *IpToStates, banner BannerInterface, config *Config) {
	// log.Println(line.Text)

	firstSpace := strings.Index(line.Text, " ")
	// log.Println("firstSpace: ", firstSpace)
	timestampSeconds, err := strconv.ParseFloat(line.Text[:firstSpace], 64)
	if err != nil {
		log.Println("could not parse a float")
		return
	}
	timestampNanos := timestampSeconds * 1e9
	timestamp := time.Unix(0, int64(timestampNanos))
	secondSpace := strings.Index(line.Text[firstSpace+1:], " ")
	ipString := line.Text[firstSpace+1 : secondSpace+firstSpace+1]

	// XXX think about this
	if time.Now().Sub(timestamp) > time.Duration(10*time.Second) {
		return
	}

	// log.Println(line.Text[secondSpace+firstSpace+2:])
	for _, regex_with_rate := range config.RegexesWithRates {
		matched := regex_with_rate.CompiledRegex.Match([]byte(line.Text[secondSpace+firstSpace+2:]))
		if !matched {
			continue
		}

		states, ok := (*ipToStates)[ipString]
		if !ok {
			log.Println("we haven't seen this IP before")
			newIpStates := make(IpStates)
			(*ipToStates)[ipString] = &newIpStates
			(*(*ipToStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
		} else {
			state, ok := (*states)[regex_with_rate.Rule]
			if !ok {
				log.Println("we have seen this IP, but it hasn't triggered this regex before")
				(*(*ipToStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
			} else {
				if timestamp.Sub(state.IntervalStartTime) > time.Duration(time.Second*time.Duration(regex_with_rate.Interval)) {
					log.Println("this IP has triggered this regex, but longer ago than $interval")
					(*(*ipToStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
				} else {
					log.Println("this IP has triggered this regex within this $interval")
					(*(*ipToStates)[ipString])[regex_with_rate.Rule].NumHits++
				}
			}
		}

		if (*(*ipToStates)[ipString])[regex_with_rate.Rule].NumHits > regex_with_rate.HitsPerInterval {
			log.Println("!!! rate limit exceeded !!! ip: ", ipString)
			banner.BanOrChallengeIp(config, ipString, regex_with_rate)
		}
	}

	// XXX expose this in some debugging http endpoint
	// log.Println("ipToStates: ", ipToStates.String())
}
