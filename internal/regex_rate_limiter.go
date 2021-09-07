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
	"net/url"
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
				consumeLine(
					line,
					rateLimitMutex,
					ipToRegexStates,
					banner,
					config,
				)
			}
		}
		time.Sleep(5 * time.Second)
	}
}

// XXX this is using the log line format + regex patterns that exist in ATS/banjax.
// parsing these unescaped space-separated strings is gross. maybe pass json instead.
func consumeLine(
	line *tail.Line,
	rateLimitMutex *sync.Mutex,
	ipToRegexStates *IpToRegexStates,
	banner BannerInterface,
	config *Config,
) {
	log.Println(line.Text)

    // timeIpRest[2] is what we match the regex on
    timeIpRest := strings.SplitN(line.Text, " ", 3)
    if len(timeIpRest) < 3 {
        log.Println("expected at least 3 words in log line: time, ip, rest")
        return
    }
	timestampSeconds, err := strconv.ParseFloat(timeIpRest[0], 64)
	if err != nil {
		log.Println("could not parse a float")
		return
	}
	timestampNanos := timestampSeconds * 1e9
	timestamp := time.Unix(0, int64(timestampNanos))
	ipString := timeIpRest[1]

    // we need to parse the url and hostname out of timeIpRest[2]
    methodUrlRest := strings.SplitN(timeIpRest[2], " ", 3)
    if len(methodUrlRest) < 3 {
        log.Println("expected at least method, url, rest")
        return
    }
    methodString := methodUrlRest[0]
    urlString := methodUrlRest[1]
    parsedUrl, err := url.Parse(urlString)
    if err != nil {
        log.Printf("could not parse a host from the url: %v\n", urlString)
        return
    }

    log.Printf("ip=%v method=%v url=%v host=%v\n", ipString, methodString, urlString, parsedUrl.Host)

	// XXX think about this
	if time.Now().Sub(timestamp) > time.Duration(10*time.Second) {
		return
	}

	// log.Println(line.Text[secondSpace+firstSpace+2:])
	for _, regex_with_rate := range config.RegexesWithRates {
		matched := regex_with_rate.CompiledRegex.Match([]byte(timeIpRest[2]))
		if !matched {
			continue
		}

        log.Println(regex_with_rate.HostsToSkip)
        skip, ok := regex_with_rate.HostsToSkip[parsedUrl.Host]
        if ok && skip {
            continue
        }

		rateLimitMutex.Lock()
		states, ok := (*ipToRegexStates)[ipString]
		if !ok {
			log.Println("we haven't seen this IP before")
			newRegexStates := make(RegexStates)
			(*ipToRegexStates)[ipString] = &newRegexStates
			(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
		} else {
			state, ok := (*states)[regex_with_rate.Rule]
			if !ok {
				log.Println("we have seen this IP, but it hasn't triggered this regex before")
				(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
			} else {
				if timestamp.Sub(state.IntervalStartTime) > time.Duration(time.Second*time.Duration(regex_with_rate.Interval)) {
					log.Println("this IP has triggered this regex, but longer ago than $interval")
					(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule] = &NumHitsAndIntervalStart{1, timestamp}
				} else {
					log.Println("this IP has triggered this regex within this $interval")
					(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits++
				}
			}
		}

		if (*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits > regex_with_rate.HitsPerInterval {
			log.Println("!!! rate limit exceeded !!! ip: ", ipString)
			decision := stringToDecision[regex_with_rate.Decision] // XXX should be an enum already
			banner.BanOrChallengeIp(config, ipString, decision)
            // log.Println(line.Text)
            banner.LogRegexBan(timestamp, ipString, regex_with_rate.Rule, timeIpRest[2], decision)
			(*(*ipToRegexStates)[ipString])[regex_with_rate.Rule].NumHits = 0 // XXX should it be 1?...
		}

		rateLimitMutex.Unlock()
	}

}
