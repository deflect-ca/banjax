// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hpcloud/tail"
)

func RunLogTailer(
	config *Config,
	banner BannerInterface,
	rateLimitMutex *sync.Mutex,
	ipToRegexStates *IpToRegexStates,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	wg *sync.WaitGroup,
) {
	if config.Debug {
		log.Println("len(RegexesWithRates) is: ", len(config.RegexesWithRates))
	}
	// if TailFile() fails or we hit EOF, we should retry
	for {
		defer wg.Done()
		t, err := tail.TailFile(config.ServerLogFile, tail.Config{
			Follow: true,
			Location: &tail.SeekInfo{
				Offset: 0,
				Whence: io.SeekEnd,
			},
		})
		if err != nil {
			log.Println("RunLogTailer: log tailer failed to start. waiting a bit and trying again.")
		} else {
			log.Println("RunLogTailer: log tailer started")
			for line := range t.Lines {
				consumeLineResult := consumeLine(
					line,
					rateLimitMutex,
					ipToRegexStates,
					banner,
					config,
					decisionListsMutex,
					decisionLists,
				)
				if config.Debug {
					bytes, err := json.MarshalIndent(consumeLineResult, "", "  ")
					if err != nil {
						log.Println("error marshalling consumeLineResult")
					} else {
						log.Println(string(bytes))
					}
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

type ConsumeLineResult struct {
	Error       bool
	OldLine     bool
	Exempted    bool
	RuleResults []RuleResult
}
type ruleMatchType uint

const (
	FirstTime ruleMatchType = iota
	OutsideInterval
	InsideInterval
)

type RuleResult struct {
	RuleName          string
	RegexMatch        bool
	SkipHost          bool
	SeenIp            bool
	RuleMatchType     ruleMatchType
	InsideInterval    bool
	RateLimitExceeded bool
}

var ruleMatchTypeToString = map[ruleMatchType]string{
	FirstTime:       "FirstTime",
	OutsideInterval: "OutsideInterval",
	InsideInterval:  "InsideInteravl",
}

func (rmt ruleMatchType) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	if s, ok := ruleMatchTypeToString[rmt]; ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("Bad! unknown ruleMatchType")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

func parseTimestamp(timeIpRest []string) (timestamp time.Time, err error) {
	timestampSeconds, err := strconv.ParseFloat(timeIpRest[0], 64)
	if err != nil {
		return time.Time{}, err
	}
	timestampNanos := timestampSeconds * 1e9
	timestamp = time.Unix(0, int64(timestampNanos))
	return timestamp, nil
}

// error: (3 words in log line, bad float, bad rest of log line, bad host, old line)
// regex match: true, false
// skip host: true, false
// seen ip: true false
// ip matched this rule: false, true outside interval, true inside interval
// rate limit exceeded: true, false
// XXX this is using the log line format + regex patterns that exist in ATS/banjax.
// parsing these unescaped space-separated strings is gross. maybe pass json instead.
func consumeLine(
	line *tail.Line,
	rateLimitMutex *sync.Mutex,
	ipToRegexStates *IpToRegexStates,
	banner BannerInterface,
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) (consumeLineResult ConsumeLineResult) {

	if config.Debug {
		log.Println("consumeLine:", line.Text)
	}

	// timeIpRest[2] is what we match the regex on
	// line.text = 1653565100.000000 11.11.11.11 GET localhost:8081 GET /45in60 HTTP/1.1 Go-http-client/1.1
	// timeIpRest[0] = 1653565100.000000
	// timeIpRest[1] = 11.11.11.11
	// timeIpRest[2] = GET localhost:8081 GET /45in60 HTTP/1.1 Go-http-client/1.1
	// XXX timeIpRest[2] is the regex test target
	timeIpRest := strings.SplitN(line.Text, " ", 3)
	// log.Printf("timeIpRest 0=%v 1=%v 2=%v\n", timeIpRest[0], timeIpRest[1], timeIpRest[2])
	if len(timeIpRest) < 3 {
		log.Println("expected at least 3 words in log line:", timeIpRest)
		consumeLineResult.Error = true
		return
	}

	ipString := timeIpRest[1]
	timestamp, err := parseTimestamp(timeIpRest)
	if err != nil {
		log.Println("could not parse a timestamp float:", timestamp)
		consumeLineResult.Error = true
		return
	}

	// Check if IP is in the global allow list that should be skipped
	decisionListsMutex.Lock()
	decision, ok := (*decisionLists).GlobalDecisionLists[ipString]
	decisionListsMutex.Unlock()
	foundInIpFilter := false

	// not found with direct match, try to match if contain within CIDR subnet
	_, globalIpfilterOk := (*decisionLists).GlobalDecisionListsIPFilter[Allow]
	if !ok && globalIpfilterOk {
		if (*decisionLists).GlobalDecisionListsIPFilter[Allow].Allowed(timeIpRest[1]) {
			// log.Printf("matched in ipfilter %v %s", Allow, timeIpRest[1])
			foundInIpFilter = true
		}
	}
	if (ok && decision == Allow) || foundInIpFilter {
		// log.Printf("matched in global decision list %v %s, exit regex banner", Allow, timeIpRest[1])
		// we exit here to prevent logging the ban for this IP
		consumeLineResult.Exempted = true
		return
	}

	// we need to parse the url and hostname out of timeIpRest[2]
	// methodUrlRest[0] = GET
	// methodUrlRest[1] = localhost:8081
	// methodUrlRest[2] = GET /45in60 HTTP/1.1 Go-http-client/1.1
	methodUrlRest := strings.SplitN(timeIpRest[2], " ", 3)
	// log.Printf("methodUrlRest 0=%v 1=%v 2=%v\n", methodUrlRest[0], methodUrlRest[1], methodUrlRest[2])
	if len(methodUrlRest) < 3 {
		log.Println("expected at least method, url, rest")
		consumeLineResult.Error = true
		return
	}
	// methodString := methodUrlRest[0]
	urlString := methodUrlRest[1]
	// XXX We don't do url.Parse here because the urlString format is not 'http://hostname/path' but hostname only

	// XXX think about this
	if time.Now().Sub(timestamp) > time.Duration(10*time.Second) {
		consumeLineResult.OldLine = true
		return
	}

	rateLimitMutex.Lock()
	// Apply per site regex first
	if perSiteRegex, exists := config.PerSiteRegexWithRates[urlString]; exists {
		for _, regex_with_rate := range perSiteRegex {
			applyRegexToLog(
				banner,
				config,
				regex_with_rate,
				ipToRegexStates,
				timeIpRest,
				timestamp,
				ipString,
				urlString,
				&consumeLineResult,
				false,
			)
		}
	}
	// Apply global regexes later
	for _, regex_with_rate := range config.RegexesWithRates {
		applyRegexToLog(
			banner,
			config,
			regex_with_rate,
			ipToRegexStates,
			timeIpRest,
			timestamp,
			ipString,
			urlString,
			&consumeLineResult,
			true,
		)
	}
	rateLimitMutex.Unlock()

	return
}

func applyRegexToLog(
	banner BannerInterface,
	config *Config,
	regex_with_rate RegexWithRate,
	ipToRegexStates *IpToRegexStates,
	timeIpRest []string,
	timestamp time.Time,
	ipString string,
	urlString string,
	consumeLineResult *ConsumeLineResult,
	globalRegex bool,
) {
	// log apply regex_with_rate.Rule
	if config.Debug {
		log.Printf("Apply regex (global %v): %s", globalRegex, regex_with_rate.Rule)
	}

	ruleResult := RuleResult{}
	ruleResult.RuleName = regex_with_rate.Rule
	matched := regex_with_rate.CompiledRegex.Match([]byte(timeIpRest[2]))
	if !matched {
		ruleResult.RegexMatch = false
		// XXX maybe show the non-matches during debug logging?
		// consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
		return
	}
	ruleResult.RegexMatch = true

	// log.Println(regex_with_rate.HostsToSkip)
	skip, ok := regex_with_rate.HostsToSkip[urlString] // drop parsedUrl.Host but use urlString
	if ok && skip {
		ruleResult.SkipHost = true
		consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
		return
	}
	ruleResult.SkipHost = false

	states, ok := (*ipToRegexStates)[ipString]
	if !ok {
		// log.Println("we haven't seen this IP before")
		ruleResult.SeenIp = false
		newRegexStates := make(RegexStates)
		(*ipToRegexStates)[ipString] = &newRegexStates
		(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
	} else {
		ruleResult.SeenIp = true
		state, ok := (*states)[regex_with_rate.Rule]
		if !ok {
			// log.Println("we have seen this IP, but it hasn't triggered this regex before")
			ruleResult.RuleMatchType = FirstTime
			(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
		} else {
			if timestamp.Sub(state.IntervalStartTime) > time.Duration(time.Second*time.Duration(regex_with_rate.Interval)) {
				// log.Println("this IP has triggered this regex, but longer ago than $interval")
				ruleResult.RuleMatchType = OutsideInterval
				(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
			} else {
				// log.Println("this IP has triggered this regex within this $interval")
				ruleResult.RuleMatchType = InsideInterval
				(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits++
			}
		}
	}

	if (*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits > regex_with_rate.HitsPerInterval {
		// log.Println("!!! rate limit exceeded !!! ip: ", ipString)
		ruleResult.RateLimitExceeded = true
		decision := stringToDecision[regex_with_rate.Decision] // XXX should be an enum already
		banner.BanOrChallengeIp(config, ipString, decision, urlString)
		// log.Println(line.Text)
		banner.LogRegexBan(config, timestamp, ipString, regex_with_rate.Rule, timeIpRest[2], decision)
		(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits = 0 // XXX should it be 1?...
	}

	consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
}
