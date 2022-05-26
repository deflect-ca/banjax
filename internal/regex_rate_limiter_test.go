// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"

	"github.com/hpcloud/tail"
	"gopkg.in/yaml.v2"

	// "io/ioutil"
	"regexp"
	"sync"
	"testing"
	"time"
)

type MockBanner struct {
	bannedIp string
}

// XXX confused why this (with a pointer receiver) and the one in iptables.go
// (value receiver) both satisfy the Banner interface...
func (mb *MockBanner) BanOrChallengeIp(config *Config, ip string, decision Decision) {
	mb.bannedIp = ip
}

func (mb *MockBanner) LogFailedChallengeBan(
	ip string,
	challengeType string,
	host string,
	path string,
	tooManyFailedChallengesThreshold int,
	userAgent string,
	decision Decision,
) {
}

func (mb *MockBanner) LogRegexBan(
	logTime time.Time,
	ip string,
	ruleName string,
	logLine string,
	decision Decision,
) {
}

// XXX need think about how to test this well
// func TestRunLogTailer(t *testing.T) {
// 	config := Config{}
// 	configBytes, err := ioutil.ReadFile("banjax-config.yaml") // XXX allow different location
// 	if err != nil {
// 		panic("couldn't read config file!")
// 	}
// 	fmt.Printf("read %v\n", string(configBytes[:]))
//
// 	err = yaml.Unmarshal(configBytes, &config)
// 	if err != nil {
// 		fmt.Printf("%v\n", err)
// 		panic("couldn't parse config file!")
// 	}
//
// 	for i, _ := range config.RegexesWithRates {
// 		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
// 		if err != nil {
// 			panic("bad regex")
// 		}
// 		config.RegexesWithRates[i].CompiledRegex = *re
// 	}
//
// 	decisionLists := ConfigToDecisionLists(&config)
// 	var wg sync.WaitGroup
// 	wg.Add(1)
// 	RunLogTailer(&config, &decisionLists, &wg)
// 	//wg.Wait()
// }

func TestConsumeLine(t *testing.T) {
	var rateLimitMutex sync.Mutex
	configString := `
regexes_with_rates:
  - rule: 'rule1'
    regex: 'GET example\.com GET .*'
    interval: 5
    hits_per_interval: 2
  - rule: 'rule2'
    regex: 'POST .*'
    interval: 5
    hits_per_interval: 1
`

	config := Config{}
	err := yaml.Unmarshal([]byte(configString), &config)
	if err != nil {
		panic("couldn't parse config file!")
	}
	ipToRegexStates := IpToRegexStates{}
	mockBanner := MockBanner{}

	// XXX duplicated from main()
	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}

	nowNanos := float64(time.Now().UnixNano())
	nowSeconds := nowNanos / 1e9
	lineTime := fmt.Sprintf("%f", nowSeconds)
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	ipStates, ok := ipToRegexStates["1.2.3.4"]
	if !ok {
		t.Fatalf("fail1")
	}
	state, ok := (*ipStates)["rule1"]
	if !ok {
		t.Errorf("fail2")
	}
	if state.NumHits != 1 {
		t.Errorf("fail3")
	}
	if mockBanner.bannedIp != "" {
		t.Errorf("should not have banned this ip")
	}

	// 4 seconds after the first one
	lineTime = fmt.Sprintf("%f", nowSeconds+4)
	line = tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 2 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	ipStates, ok = ipToRegexStates["1.2.3.4"]
	if !ok {
		t.Fatalf("fail4")
	}
	state, ok = (*ipStates)["rule1"]
	if !ok {
		t.Errorf("fail5")
	}
	if state.NumHits != 2 {
		t.Errorf("fail6")
	}
	if mockBanner.bannedIp != "" {
		t.Errorf("should not have banned this ip")
	}

	// a bit more than 5 seconds after the first one
	lineTime = fmt.Sprintf("%f", nowSeconds+5.5)
	line = tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 3 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	ipStates, ok = ipToRegexStates["1.2.3.4"]
	if !ok {
		t.Fatalf("fail7")
	}
	state, ok = (*ipStates)["rule1"]
	if !ok {
		t.Errorf("fail8")
	}
	if state.NumHits != 1 {
		t.Errorf("fail9")
	}
	if mockBanner.bannedIp != "" {
		t.Errorf("should not have banned this ip")
	}

	// 1 second after the most recent one, but a POST instead of GET
	lineTime = fmt.Sprintf("%f", nowSeconds+6.5)
	line = tail.Line{Text: lineTime + " 1.2.3.4 POST example.com POST /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 4 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	ipStates, ok = ipToRegexStates["1.2.3.4"]
	if !ok {
		t.Fatalf("fail10")
	}
	state, ok = (*ipStates)["rule1"]
	if !ok {
		t.Errorf("fail11")
	}
	if state.NumHits != 1 {
		t.Errorf("fail12")
	}
	state, ok = (*ipStates)["rule2"]
	if !ok {
		t.Fatalf("fail13")
	}
	if state.NumHits != 1 {
		t.Errorf("fail14")
	}
	if mockBanner.bannedIp != "" {
		t.Errorf("should not have banned this ip")
	}

	// half a second after the most recent one, should exceed the rate limit
	lineTime = fmt.Sprintf("%f", nowSeconds+7.0)
	line = tail.Line{Text: lineTime + " 1.2.3.4 POST example.com POST /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 5 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	ipStates, ok = ipToRegexStates["1.2.3.4"]
	if !ok {
		t.Fatalf("fail15")
	}
	state, ok = (*ipStates)["rule1"]
	if !ok {
		t.Errorf("fail16")
	}
	if state.NumHits != 1 {
		t.Errorf("fail17")
	}
	state, ok = (*ipStates)["rule2"]
	if !ok {
		t.Fatalf("fail18")
	}
	// counter gets reset after rate limit exceeded. XXX but should it reset to 0 or 1?
	if state.NumHits != 0 {
		t.Errorf("fail19")
	}
	if mockBanner.bannedIp != "1.2.3.4" {
		t.Errorf("should have banned this ip")
	}
}

func TestConsumeLineHostsToSkip(t *testing.T) {
	var rateLimitMutex sync.Mutex
	configString := `
regexes_with_rates:
  - rule: 'rule1'
    regex: '^GET https?:\/\/\.*'
    interval: 5
    hits_per_interval: 2
    hosts_to_skip:
      skiphost.com: true
`

	config := Config{}
	err := yaml.Unmarshal([]byte(configString), &config)
	if err != nil {
		panic("couldn't parse config file!")
	}
	ipToRegexStates := IpToRegexStates{}
	mockBanner := MockBanner{}

	// XXX duplicated from main()
	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}

	nowNanos := float64(time.Now().UnixNano())
	nowSeconds := nowNanos / 1e9
	lineTime := fmt.Sprintf("%f", nowSeconds)
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET skiphost.com GET /whatever " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config)

	_, ok := ipToRegexStates["1.2.3.4"]
	if ok {
		t.Fatalf("should not have found a state since we skip this host")
	}
}
