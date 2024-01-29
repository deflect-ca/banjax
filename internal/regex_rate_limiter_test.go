// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"

	"github.com/brianvoe/gofakeit/v6"
	"github.com/hpcloud/tail"
	"gopkg.in/yaml.v2"

	// "io/ioutil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gonetx/ipset"
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
	config *Config,
	ip string,
	challengeType string,
	host string,
	path string,
	tooManyFailedChallengesThreshold int,
	userAgent string,
	decision Decision,
	method string,
) {
}

func (mb *MockBanner) LogRegexBan(
	config *Config,
	logTime time.Time,
	ip string,
	ruleName string,
	logLine string,
	decision Decision,
) {
	// log.Printf("LogRegexBan: %s %s %s\n", ip, ruleName, logLine)
}

func (mb *MockBanner) IPSetAdd(config *Config, ip string) error {
	return nil
}

func (mb *MockBanner) IPSetTest(config *Config, ip string) bool {
	return false
}

func (mb *MockBanner) IPSetList() (*ipset.Info, error) {
	return nil, nil
}

func (mb *MockBanner) IPSetDel(ip string) error {
	return nil
}

var configToStructsMutex sync.Mutex

func configToStructs(
	config *Config,
	passwordProtectedPaths *PasswordProtectedPaths,
	decisionLists *DecisionLists,
) {
	configToStructsMutex.Lock()
	defer configToStructsMutex.Unlock()

	*passwordProtectedPaths = ConfigToPasswordProtectedPaths(config)
	*decisionLists = ConfigToDecisionLists(config)
}

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
	var decisionListsMutex sync.Mutex
	var decisionLists DecisionLists
	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths, &decisionLists)

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
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

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
	line = tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 2 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

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
	line = tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 3 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

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
	line = tail.Line{Text: lineTime + " 1.2.3.4 POST example.com POST /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 4 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

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
	line = tail.Line{Text: lineTime + " 1.2.3.4 POST example.com POST /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 5 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

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
	var decisionListsMutex sync.Mutex
	var decisionLists DecisionLists
	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths, &decisionLists)

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
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET skiphost.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

	_, ok := ipToRegexStates["1.2.3.4"]
	if ok {
		t.Fatalf("should not have found a state since we skip this host")
	}
}

func TestPerSiteRegexStress(t *testing.T) {
	var rateLimitMutex sync.Mutex
	var domains []string
	var paths []string
	testCount := 10000
	configString := `
regexes_with_rates:
`
	// make yaml config file
	for i := 0; i < testCount; i++ {
		domain := gofakeit.DomainName()
		url, err := url.Parse(gofakeit.URL())
		if err != nil {
			panic(err)
		}
		path := url.Path
		configString += fmt.Sprintf(`
  - rule: 'rule%d'
    regex: 'GET %s GET \%s HTTP\/[0-2.]+ .*'
    interval: 1
    hits_per_interval: 0
`, i, strings.Replace(domain, ".", "\\.", -1), path)
		// save domain and path to generate log line
		domains = append(domains, domain)
		paths = append(paths, path)
	}
	// log.Printf(configString)

	config := Config{}
	err := yaml.Unmarshal([]byte(configString), &config)
	if err != nil {
		panic("couldn't parse config file!")
	}
	var decisionListsMutex sync.Mutex
	var decisionLists DecisionLists
	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths, &decisionLists)

	for i, _ := range config.RegexesWithRates {
		re, err := regexp.Compile(config.RegexesWithRates[i].Regex)
		if err != nil {
			panic("bad regex")
		}
		config.RegexesWithRates[i].CompiledRegex = *re
	}

	ipToRegexStates := IpToRegexStates{}
	mockBanner := MockBanner{}

	for j := 0; j < testCount; j++ {
		// make nginx logs
		// we must provide valid timestamp here as regex banner will check and drop old logs
		ip := gofakeit.IPv4Address()
		logLine := fmt.Sprintf("%f %s GET %s GET %s HTTP/2.0 %s",
			float64(time.Now().UnixNano()/1e9)+float64(j), ip, domains[j], paths[j], gofakeit.UserAgent())
		// log.Printf("Testing: " + logLine)
		lineTail := tail.Line{Text: logLine}

		consumeLine(&lineTail, &rateLimitMutex, &ipToRegexStates, &mockBanner, &config, &decisionListsMutex, &decisionLists)

		ipStates, ok := ipToRegexStates[ip]
		if !ok {
			t.Fatalf("fail1, IP not found in ipToRegexStates")
		}
		state, ok := (*ipStates)[fmt.Sprintf("rule%d", j)]
		if !ok {
			t.Errorf("fail2, rule not found in ipStates")
		}
		if state.NumHits != 0 {
			t.Errorf("fail3, Num hit should be 0, but is %d", state.NumHits)
		}
		if mockBanner.bannedIp != ip {
			t.Errorf("should have banned this ip, but mockBanner.bannedIp is %s", mockBanner.bannedIp)
		}
	}
}
