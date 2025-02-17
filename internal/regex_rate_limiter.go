// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
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
	decisionLists *StaticDecisionLists,
	rateLimitStates *RegexRateLimitStates,
	wg *sync.WaitGroup,
) {
	// log.Println("len(RegexesWithRates) is: ", len(config.RegexesWithRates))
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
					rateLimitStates,
					banner,
					config,
					decisionLists,
				)
				if config.Debug {
					bytes, err := json.MarshalIndent(consumeLineResult, "", "  ")
					if err != nil {
						log.Println("error marshalling consumeLineResult:", err)
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

type RuleResult struct {
	RuleName        string
	RegexMatch      bool
	SkipHost        bool
	SeenIp          bool
	RateLimitResult RateLimitResult
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
	rateLimitStates *RegexRateLimitStates,
	banner BannerInterface,
	config *Config,
	decisionLists *StaticDecisionLists,
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

	// NOTE: This is not necessary after we added Whence: io.SeekEnd,
	//       but we keep it here for a fail-safe.
	if time.Now().Sub(timestamp) > time.Duration(10*time.Second) {
		consumeLineResult.OldLine = true
		return
	}

	if decisionLists.CheckIsAllowed(urlString, ipString) {
		consumeLineResult.Exempted = true
		return
	}

	// Apply per site regex first
	if perSiteRegex, exists := config.PerSiteRegexWithRates[urlString]; exists {
		for _, regexWithRate := range perSiteRegex {
			result := applyRegexToLog(
				banner,
				config,
				regexWithRate,
				rateLimitStates,
				timeIpRest,
				timestamp,
				ipString,
				urlString,
				false,
			)

			if result.RegexMatch {
				consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, result)
			}
		}
	}
	// Apply global regexes later
	for _, regexWithRate := range config.RegexesWithRates {
		result := applyRegexToLog(
			banner,
			config,
			regexWithRate,
			rateLimitStates,
			timeIpRest,
			timestamp,
			ipString,
			urlString,
			true,
		)

		if result.RegexMatch {
			consumeLineResult.RuleResults = append(consumeLineResult.RuleResults, result)
		}
	}

	return
}

func applyRegexToLog(
	banner BannerInterface,
	config *Config,
	regexWithRate RegexWithRate,
	rateLimitStates *RegexRateLimitStates,
	timeIpRest []string,
	timestamp time.Time,
	ipString string,
	urlString string,
	globalRegex bool,
) (result RuleResult) {
	// log apply regex_with_rate.Rule
	if config.Debug {
		log.Printf("Apply regex (global %v): %s", globalRegex, regexWithRate.Rule)
	}

	result.RuleName = regexWithRate.Rule

	matched := regexWithRate.Regex.Match([]byte(timeIpRest[2]))
	if !matched {
		result.RegexMatch = false
		// XXX maybe show the non-matches during debug logging?
		return
	}
	result.RegexMatch = true

	// log.Println(regex_with_rate.HostsToSkip)
	skip, ok := regexWithRate.HostsToSkip[urlString] // drop parsedUrl.Host but use urlString
	if ok && skip {
		result.SkipHost = true
		return
	}
	result.SkipHost = false

	seenIp, rateLimitResult := rateLimitStates.Apply(ipString, regexWithRate, timestamp)
	result.SeenIp = seenIp
	result.RateLimitResult = rateLimitResult

	if result.RateLimitResult.Exceeded {
		// log.Println("!!! rate limit exceeded !!! ip: ", ipString)
		banner.BanOrChallengeIp(config, ipString, regexWithRate.Decision, urlString)
		// log.Println(line.Text)
		banner.LogRegexBan(
			config,
			timestamp,
			ipString,
			regexWithRate.Rule,
			timeIpRest[2],
			regexWithRate.Decision,
		)
	}

	return
}
