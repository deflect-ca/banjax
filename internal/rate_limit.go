// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// States for tracking rate limits triggered by matching regex rules.
type RegexRateLimitStates struct {
	mutex  sync.Mutex
	states ipToRegexStates
}

func NewRegexRateLimitStates() *RegexRateLimitStates {
	return &RegexRateLimitStates{
		mutex:  sync.Mutex{},
		states: make(ipToRegexStates),
	}
}

func (s *RegexRateLimitStates) Len() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return len(s.states)
}

func (s *RegexRateLimitStates) Apply(
	ip string,
	regexWithRate RegexWithRate,
	timestamp time.Time,
) (seenIp bool, result RateLimitResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	states, ok := s.states[ip]
	var state *NumHitsAndIntervalStart

	if !ok {
		seenIp = false
		state = &NumHitsAndIntervalStart{1, timestamp}
		s.states[ip] = &RegexStates{regexWithRate.Rule: state}
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

// Returns a copy of the regex states for the given ip address.
func (s *RegexRateLimitStates) Get(ip string) (RegexStates, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if states, ok := s.states[ip]; ok {
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

func (s *RegexRateLimitStates) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.states.String()
}

// States for tracking rate limits triggered by failed challenges.
type FailedChallengeRateLimitStates struct {
	mutex  sync.Mutex
	states ipToFailedChallengeStates
}

func NewFailedChallengeRateLimitStates() *FailedChallengeRateLimitStates {
	return &FailedChallengeRateLimitStates{
		mutex:  sync.Mutex{},
		states: make(ipToFailedChallengeStates),
	}
}

func (s *FailedChallengeRateLimitStates) Len() int {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return len(s.states)
}

func (s *FailedChallengeRateLimitStates) Apply(ip string, config *Config) (result RateLimitResult) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	timestamp := time.Now()

	state, ok := s.states[ip]
	if ok {
		if timestamp.Sub(state.IntervalStartTime) > time.Duration(config.TooManyFailedChallengesIntervalSeconds)*time.Second {
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
		s.states[ip] = state
	}

	if state.NumHits > config.TooManyFailedChallengesThreshold {
		state.NumHits = 0 // XXX should it be 1?...
		result.Exceeded = true
	} else {
		result.Exceeded = false
	}

	return
}

func (s *FailedChallengeRateLimitStates) String() string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	return s.states.String()
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

func (t RateLimitMatchType) String() string {
	switch t {
	case FirstTime:
		return "FirstTime"
	case OutsideInterval:
		return "OutsideInterval"
	case InsideInterval:
		return "InsideInterval"
	default:
		panic("invalid RateLimitMatchType")
	}
}

func (t RateLimitMatchType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
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
