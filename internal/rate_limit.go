// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// States for tracking rate limits triggered by matching regex rules or failed challenges.
type RateLimitStates struct {
	mutex                 sync.Mutex
	regexStates           ipToRegexStates
	failedChallengeStates ipToFailedChallengeStates
}

func NewRateLimitStates() *RateLimitStates {
	return &RateLimitStates{
		mutex:                 sync.Mutex{},
		regexStates:           make(ipToRegexStates),
		failedChallengeStates: make(ipToFailedChallengeStates),
	}
}

func (s *RateLimitStates) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return fmt.Sprintf("regexes:\n%v\nfailed challenges:\n%v",
		s.regexStates,
		s.failedChallengeStates,
	)
}

func (s *RateLimitStates) Metrics() (lenRegexStates int, lenFailedChallengeStates int) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	lenRegexStates = len(s.regexStates)
	lenFailedChallengeStates = len(s.failedChallengeStates)

	return
}

func (s *RateLimitStates) ApplyRegex(ip string, regexWithRate RegexWithRate, timestamp time.Time) (bool, RateLimitResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.regexStates.apply(ip, regexWithRate, timestamp)
}

// Returns a copy of the regex states for the given ip address.
func (s *RateLimitStates) GetRegexStates(ip string) (RegexStates, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if states, ok := s.regexStates[ip]; ok {
		statesCopy := make(RegexStates)
		for rule, state := range *states {
			stateCopy := *state
			statesCopy[rule] = &stateCopy
		}

		return statesCopy, true
	} else {
		return RegexStates{}, false
	}
}

func (s *RateLimitStates) ApplyFailedChallenge(ip string, config *Config) RateLimitResult {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.failedChallengeStates.apply(ip, config)
}

type NumHitsAndIntervalStart struct {
	NumHits           int
	IntervalStartTime time.Time
}

type RateLimitResult struct {
	MatchType RateLimitMatchType
	Exceeded  bool
}

type RateLimitMatchType int

const (
	FirstTime RateLimitMatchType = iota
	OutsideInterval
	InsideInterval
)

func (t RateLimitMatchType) MarshalJSON() ([]byte, error) {
	switch t {
	case FirstTime:
		return []byte("FirstTime"), nil
	case OutsideInterval:
		return []byte("OutsideInterval"), nil
	case InsideInterval:
		return []byte("InsideInterval"), nil
	default:
		return nil, fmt.Errorf("invalid RateLimitMatchType: %v", t)
	}
}

type RegexStates map[string]*NumHitsAndIntervalStart

type ipToRegexStates map[string]*RegexStates

func (s ipToRegexStates) String() string {
	buf := strings.Builder{}
	for ip, states := range s {
		buf.WriteString(fmt.Sprintf("%v", ip))
		buf.WriteString(":\n")
		for rule, state := range *states {
			buf.WriteString("\t")
			buf.WriteString(fmt.Sprintf("%v", rule))
			buf.WriteString(":\n")
			buf.WriteString("\t\t")
			buf.WriteString(fmt.Sprintf("%v", *state))
			buf.WriteString("\n")
		}
		buf.WriteString("\n")
	}
	return buf.String()
}

func (s *ipToRegexStates) apply(
	ip string,
	regexWithRate RegexWithRate,
	timestamp time.Time,
) (seenIp bool, result RateLimitResult) {
	states, ok := (*s)[ip]
	var state *NumHitsAndIntervalStart

	if !ok {
		seenIp = false
		state = &NumHitsAndIntervalStart{1, timestamp}
		(*s)[ip] = &RegexStates{regexWithRate.Rule: state}
	} else {
		seenIp = true
		if ruleState, ok := (*states)[regexWithRate.Rule]; ok {
			state = ruleState
			if timestamp.Sub(state.IntervalStartTime) > regexWithRate.Interval {
				result.MatchType = OutsideInterval
				*state = NumHitsAndIntervalStart{1, timestamp}
			} else {
				result.MatchType = InsideInterval
				state.NumHits++
			}
		} else {
			result.MatchType = FirstTime
			state = &NumHitsAndIntervalStart{1, timestamp}
			(*states)[regexWithRate.Rule] = state
		}
	}

	if state.NumHits > regexWithRate.HitsPerInterval {
		state.NumHits = 0 // XXX should it be 1?...
		result.Exceeded = true
	} else {
		result.Exceeded = false
	}

	return
}

type ipToFailedChallengeStates map[string]*NumHitsAndIntervalStart

func (s ipToFailedChallengeStates) String() string {
	buf := strings.Builder{}
	for ip, state := range s {
		buf.WriteString(
			fmt.Sprintf(
				"%v,: interval_start: %v, num hits: %v\n",
				ip,
				state.IntervalStartTime.Format("15:04:05"),
				state.NumHits,
			),
		)
	}
	return buf.String()
}

func (s *ipToFailedChallengeStates) apply(ip string, config *Config) (result RateLimitResult) {
	timestamp := time.Now()

	state, ok := (*s)[ip]
	if ok {
		if timestamp.Sub(state.IntervalStartTime) > time.Duration(config.TooManyFailedChallengesIntervalSeconds) * time.Second {
			// log.Println("IP has failed a challenge, but longer ago than $interval")
			result.MatchType = OutsideInterval
			*state = NumHitsAndIntervalStart{1, timestamp}
		} else {
			// log.Println("IP has failed a challenge in this $interval")
			result.MatchType = InsideInterval
			state.NumHits++
		}
	} else {
		result.MatchType = FirstTime
		state = &NumHitsAndIntervalStart{1, timestamp}
		(*s)[ip] = state
	}

	if state.NumHits > config.TooManyFailedChallengesThreshold {
		state.NumHits = 0 // XXX should it be 1?...
		result.Exceeded = true
	} else {
		result.Exceeded = false
	}

	return
}