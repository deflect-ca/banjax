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
func (mb *MockBanner) BanOrChallengeIp(config *Config, ip string, decision Decision, domain string) {
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
) {
	configToStructsMutex.Lock()
	defer configToStructsMutex.Unlock()

	*passwordProtectedPaths = ConfigToPasswordProtectedPaths(config)
}

func TestConsumeLine(t *testing.T) {
	configString := `
regexes_with_rates:
  - decision: nginx_block
    rule: 'rule1'
    regex: 'GET example\.com GET .*'
    interval: 5
    hits_per_interval: 2
  - decision: challenge
    rule: 'rule2'
    regex: 'POST .*'
    interval: 5
    hits_per_interval: 1
per_site_regexes_with_rates:
  per-site.com:
    - decision: nginx_block
      hits_per_interval: 0
      interval: 1
      regex: .*blockme.*
      rule: "instant block"
`

	config := Config{}
	err := yaml.Unmarshal([]byte(configString), &config)
	if err != nil {
		panic(fmt.Sprintf("couldn't parse config file: %v", err))
	}
	rateLimitStates := NewRegexRateLimitStates()
	mockBanner := MockBanner{}

	decisionLists, err := NewStaticDecisionListsFromConfig(&config)
	if err != nil {
		panic(fmt.Sprintf("couldn't create decision list: %v", err))
	}

	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths)

	nowNanos := float64(time.Now().UnixNano())
	nowSeconds := nowNanos / 1e9
	lineTime := fmt.Sprintf("%f", nowSeconds)
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET example.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	ipStates, ok := rateLimitStates.Get("1.2.3.4")
	if !ok {
		t.Fatalf("fail1")
	}
	state, ok := ipStates["rule1"]
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
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	ipStates, ok = rateLimitStates.Get("1.2.3.4")
	if !ok {
		t.Fatalf("fail4")
	}
	state, ok = ipStates["rule1"]
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
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	ipStates, ok = rateLimitStates.Get("1.2.3.4")
	if !ok {
		t.Fatalf("fail7")
	}
	state, ok = ipStates["rule1"]
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
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	ipStates, ok = rateLimitStates.Get("1.2.3.4")
	if !ok {
		t.Fatalf("fail10")
	}
	state, ok = ipStates["rule1"]
	if !ok {
		t.Errorf("fail11")
	}
	if state.NumHits != 1 {
		t.Errorf("fail12")
	}
	state, ok = ipStates["rule2"]
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
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	ipStates, ok = rateLimitStates.Get("1.2.3.4")
	if !ok {
		t.Fatalf("fail15")
	}
	state, ok = ipStates["rule1"]
	if !ok {
		t.Errorf("fail16")
	}
	if state.NumHits != 1 {
		t.Errorf("fail17")
	}
	state, ok = ipStates["rule2"]
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

	// test per-site regex
	lineTime = fmt.Sprintf("%f", nowSeconds+20)
	line = tail.Line{Text: lineTime + " 1.6.6.6 GET per-site.com GET /blockme/?a HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 6 --")
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	// there should be a match for the per-site regex
	ipStates, ok = rateLimitStates.Get("1.6.6.6")
	if !ok {
		t.Fatalf("fail20")
	}

	lineTime = fmt.Sprintf("%f", nowSeconds+22)
	line = tail.Line{Text: lineTime + " 1.6.6.7 GET no-per-site.com GET /blockme/?a HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 7 --")
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	// there should NO match for the per-site regex
	ipStates, ok = rateLimitStates.Get("1.6.6.7")
	if ok {
		t.Fatalf("fail21")
	}
}

func TestConsumeLineHostsToSkip(t *testing.T) {
	configString := `
regexes_with_rates:
  - decision: nginx_block
    rule: 'rule1'
    regex: '^GET https?:\/\/\.*'
    interval: 5
    hits_per_interval: 2
    hosts_to_skip:
      skiphost.com: true
`

	config := Config{}
	err := yaml.Unmarshal([]byte(configString), &config)
	if err != nil {
		panic(fmt.Sprintf("couldn't parse config file: %v", err))
	}
	rateLimitStates := NewRegexRateLimitStates()
	mockBanner := MockBanner{}

	decisionLists, err := NewStaticDecisionListsFromConfig(&config)
	if err != nil {
		panic(fmt.Sprintf("couldn't create decision list: %v", err))
	}

	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths)

	nowNanos := float64(time.Now().UnixNano())
	nowSeconds := nowNanos / 1e9
	lineTime := fmt.Sprintf("%f", nowSeconds)
	line := tail.Line{Text: lineTime + " 1.2.3.4 GET skiphost.com GET /whatever HTTP/1.1 " +
		"AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36 -"}
	fmt.Println("-- 1 --")
	consumeLine(&line, rateLimitStates, &mockBanner, &config, decisionLists)

	_, ok := rateLimitStates.Get("1.2.3.4")
	if ok {
		t.Fatalf("should not have found a state since we skip this host")
	}
}

func TestPerSiteRegexStress(t *testing.T) {
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
  - decision: nginx_block
    rule: 'rule%d'
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
		panic(fmt.Sprintf("couldn't parse config file: %v", err))
	}

	decisionLists, err := NewStaticDecisionListsFromConfig(&config)
	if err != nil {
		panic(fmt.Sprintf("couldn't create decision lists: %v", err))
	}

	var passwordProtectedPaths PasswordProtectedPaths
	configToStructs(&config, &passwordProtectedPaths)

	rateLimitStates := NewRegexRateLimitStates()
	mockBanner := MockBanner{}

	for j := 0; j < testCount; j++ {
		// make nginx logs
		// we must provide valid timestamp here as regex banner will check and drop old logs
		ip := gofakeit.IPv4Address()
		logLine := fmt.Sprintf("%f %s GET %s GET %s HTTP/2.0 %s",
			float64(time.Now().UnixNano()/1e9)+float64(j), ip, domains[j], paths[j], gofakeit.UserAgent())
		// log.Printf("Testing: " + logLine)
		lineTail := tail.Line{Text: logLine}

		consumeLine(&lineTail, rateLimitStates, &mockBanner, &config, decisionLists)

		ipStates, ok := rateLimitStates.Get(ip)
		if !ok {
			t.Fatalf("fail1, IP not found in ipToRegexStates")
		}
		state, ok := ipStates[fmt.Sprintf("rule%d", j)]
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
