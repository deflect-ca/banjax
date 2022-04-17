// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/json"
	"log"
	"net/url"
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
	wg *sync.WaitGroup,
) {
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
				consumeLineResult := consumeLine(
					line,
					rateLimitMutex,
					ipToRegexStates,
					banner,
					config,
				)
				bytes, err := json.MarshalIndent(consumeLineResult, "", "  ")
				if err != nil {
					log.Println("error marshalling consumeLineResult")
				} else {
					log.Println(string(bytes))
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
}

type ConsumeLineResult struct {
	Error       bool
	OldLine     bool
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
) (consumeLineResult ConsumeLineResult) {
	// log.Println(line.Text)

	// timeIpRest[2] is what we match the regex on
	timeIpRest := strings.SplitN(line.Text, " ", 3)
	if len(timeIpRest) < 3 {
		log.Println("expected at least 3 words in log line: time, ip, rest")
		consumeLineResult.Error = true
		return
	}
	timestampSeconds, err := strconv.ParseFloat(timeIpRest[0], 64)
	if err != nil {
		log.Println("could not parse a float")
		consumeLineResult.Error = true
		return
	}
	timestampNanos := timestampSeconds * 1e9
	timestamp := time.Unix(0, int64(timestampNanos))
	ipString := timeIpRest[1]

	// we need to parse the url and hostname out of timeIpRest[2]
	methodUrlRest := strings.SplitN(timeIpRest[2], " ", 3)
	if len(methodUrlRest) < 3 {
		log.Println("expected at least method, url, rest")
		consumeLineResult.Error = true
		return
	}
	// methodString := methodUrlRest[0]
	urlString := methodUrlRest[1]
	parsedUrl, err := url.Parse(urlString)
	if err != nil {
		log.Printf("could not parse a host from the url: %v\n", urlString)
		consumeLineResult.Error = true
		return
	}

	// log.Printf("ip=%v method=%v url=%v host=%v\n", ipString, methodString, urlString, parsedUrl.Host)

	// XXX think about this
	if time.Now().Sub(timestamp) > time.Duration(10*time.Second) {
		consumeLineResult.OldLine = true
		return
	}

	// log.Println(line.Text[secondSpace+firstSpace+2:])
	for _, regex_with_rate := range config.RegexesWithRates {
		ruleResult := RuleResult{}
		ruleResult.RuleName = regex_with_rate.Rule
		matched := regex_with_rate.CompiledRegex.Match([]byte(timeIpRest[2]))
		if !matched {
			ruleResult.RegexMatch = false
			// XXX maybe show the non-matches during debug logging?
			// consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
			continue
		}
		ruleResult.RegexMatch = true

		log.Println(regex_with_rate.HostsToSkip)
		skip, ok := regex_with_rate.HostsToSkip[parsedUrl.Host]
		if ok && skip {
			ruleResult.SkipHost = true
			consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
			continue
		}
		ruleResult.SkipHost = false

		rateLimitMutex.Lock()
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
			banner.BanOrChallengeIp(config, ipString, decision)
			// log.Println(line.Text)
			banner.LogRegexBan(timestamp, ipString, regex_with_rate.Rule, timeIpRest[2], decision)
			(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits = 0 // XXX should it be 1?...
		}

		rateLimitMutex.Unlock()
		consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, ruleResult)
	}

	return
}
