// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Config struct {
	RegexesWithRates                       []RegexWithRate                `yaml:"regexes_with_rates"`
	ServerLogFile                          string                         `yaml:"server_log_file"`
	IptablesBanSeconds                     int                            `yaml:"iptables_ban_seconds"`
	IptablesUnbannerSeconds                int                            `yaml:"iptables_unbanner_seconds"`
	KafkaBrokers                           []string                       `yaml:"kafka_brokers"`
	PerSiteDecisionLists                   map[string]map[string][]string `yaml:"per_site_decision_lists"`
	GlobalDecisionLists                    map[string][]string            `yaml:"global_decision_lists"`
	ConfigVersion                          string                         `yaml:"config_version"`
	StandaloneTesting                      bool
	ChallengerBytes                        []byte
	PasswordPageBytes                      []byte
	SitesToPasswordHashes                  map[string]string   `yaml:"password_hashes"`
	SitesToProtectedPaths                  map[string][]string `yaml:"password_protected_paths"`
	ExpiringDecisionTtlSeconds             int                 `yaml:"expiring_decision_ttl_seconds"`
	TooManyFailedChallengesIntervalSeconds int                 `yaml:"too_many_failed_challenges_interval_seconds"`
	TooManyFailedChallengesThreshold       int                 `yaml:"too_many_failed_challenges_threshold"`
	PasswordCookieTtlSeconds               int                 `yaml:"password_cookie_ttl_seconds"`
	ShaInvCookieTtlSeconds                 int                 `yaml:"sha_inv_cookie_ttl_seconds"`
	RestartTime                            int
	ReloadTime                             int
	Hostname                               string
}

type RegexWithRate struct {
	Rule            string `yaml:"rule"`
	Regex           string `yaml:"regex"`
	CompiledRegex   regexp.Regexp
	Interval        float64 `yaml:"interval"`
	HitsPerInterval int     `yaml:"hits_per_interval"`
	Decision        string  `yaml:"decision"`
}

type Decision int

type ExpiringDecision struct {
	Decision Decision
	Expires  time.Time
}

// XXX previously i had a DefaultAllow as the first enum, which fell through
// my case statements and into the default: switch elsewhere. scary bug.
// maybe use _ as first enum? but then remember to use it in the string conversion
// functions just below x_x
const (
	Allow         = iota
	Challenge     = iota
	NginxBlock    = iota
	IptablesBlock = iota
)

func (d Decision) String() string {
	return [...]string{"Allow", "Challenge", "NginxBlock", "IptablesBlock"}[d]
}

// XXX if a string in the config file isn't one of these Decision tokens,
// this map will default to returning the zero value (or something like that,
// think about this another time)
var stringToDecision = map[string]Decision{
	"allow":          Allow,
	"challenge":      Challenge,
	"nginx_block":    NginxBlock,
	"iptables_block": IptablesBlock,
}

type StringToDecision map[string]Decision
type StringToStringToDecision map[string]StringToDecision
type StringToExpiringDecision map[string]ExpiringDecision

type DecisionLists struct {
	PerSiteDecisionLists  StringToStringToDecision // XXX really site -> ip range -> Decision
	GlobalDecisionLists   StringToDecision         // XXX really ip range -> Decision
	ExpiringDecisionLists StringToExpiringDecision // XXX really ip range -> ExpiringDecision
}

type StringToBool map[string]bool
type StringToStringToBool map[string]StringToBool
type StringToBytes map[string][]byte

type PasswordProtectedPaths struct {
	SiteToPathToBool   StringToStringToBool
	SiteToPasswordHash StringToBytes
}

func ConfigToPasswordProtectedPaths(config *Config) PasswordProtectedPaths {
	siteToPathToBool := make(StringToStringToBool)
	siteToPasswordHash := make(StringToBytes)

	for site, paths := range config.SitesToProtectedPaths {
		for _, path := range paths {
			path = strings.Replace(path, "/", "", -1) // XXX lazy! think of a better way
			_, ok := siteToPathToBool[site]
			if !ok {
				siteToPathToBool[site] = make(StringToBool)
			}
			siteToPathToBool[site][path] = true
			log.Printf("password protected path: %s/%s\n", site, path)
		}
	}

	for site, passwordHashHex := range config.SitesToPasswordHashes {
		passwordHashBytes, err := hex.DecodeString(passwordHashHex)
		if err != nil {
			log.Fatal("bad password hash!")
		}
		siteToPasswordHash[site] = passwordHashBytes
		log.Println("passwordhashbytes:")
		log.Println(passwordHashBytes)
	}

	return PasswordProtectedPaths{siteToPathToBool, siteToPasswordHash}
}

func ConfigToDecisionLists(config *Config) DecisionLists {
	perSiteDecisionLists := make(StringToStringToDecision)
	globalDecisionLists := make(StringToDecision)
	expiringDecisionLists := make(StringToExpiringDecision)

	for site, decisionToIps := range config.PerSiteDecisionLists {
		for decisionString, ips := range decisionToIps {
			for _, ip := range ips {
				_, ok := perSiteDecisionLists[site]
				if !ok {
					perSiteDecisionLists[site] = make(StringToDecision)
				}
				perSiteDecisionLists[site][ip] = stringToDecision[decisionString]
				log.Printf("site: %s, decision: %s, ip: %s\n", site, decisionString, ip)
			}
		}
	}

	for decisionString, ips := range config.GlobalDecisionLists {
		for _, ip := range ips {
			globalDecisionLists[ip] = stringToDecision[decisionString]
			log.Printf("global decision: %s, ip: %s\n", decisionString, ip)
		}
	}

	log.Printf("per-site decisions: %v\n", perSiteDecisionLists)
	log.Printf("global decisions: %v\n", globalDecisionLists)
	return DecisionLists{perSiteDecisionLists, globalDecisionLists, expiringDecisionLists}
}

// XXX use string.Builder
func (ipToRegexStates IpToRegexStates) String() string {
	buf := bytes.Buffer{}
	for ip, states := range ipToRegexStates {
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

// XXX use string.Builder
func (perSiteDecisionLists StringToStringToDecision) String() string {
	buf := bytes.Buffer{}
	for host, ipsToDecisions := range perSiteDecisionLists {
		buf.WriteString(fmt.Sprintf("%v", host))
		buf.WriteString(":\n")
		for ip, decision := range ipsToDecisions {
			buf.WriteString("\t")
			buf.WriteString(fmt.Sprintf("%v", ip))
			buf.WriteString(":\n")
			buf.WriteString("\t\t")
			buf.WriteString(fmt.Sprintf("%v", decision.String()))
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

// XXX use string.Builder
func (globalDecisionLists StringToDecision) String() string {
	buf := bytes.Buffer{}
	for ip, decision := range globalDecisionLists {
		buf.WriteString(fmt.Sprintf("%v", ip))
		buf.WriteString(":\n")
		buf.WriteString("\t")
		buf.WriteString(fmt.Sprintf("%v", decision.String()))
		buf.WriteString("\n")
	}
	return buf.String()
}

// XXX use string.Builder
func (expiringDecisionLists StringToExpiringDecision) String() string {
	buf := bytes.Buffer{}
	for ip, expiringDecision := range expiringDecisionLists {
		buf.WriteString(fmt.Sprintf("%v", ip))
		buf.WriteString(":\n")
		buf.WriteString("\t")
		buf.WriteString(fmt.Sprintf("%v until %v", expiringDecision.Decision.String(), expiringDecision.Expires.Format("15:04:05")))
		buf.WriteString("\n")
	}
	return buf.String()
}

// one of these for each regex_with_rate for each IP
// XXX should this reference the whole rule so i can get the Decision later?
type NumHitsAndIntervalStart struct {
	NumHits           int
	IntervalStartTime time.Time
}

type RuleName = string

type IpAddress = string

type RegexStates map[RuleName]*NumHitsAndIntervalStart

type IpToRegexStates map[IpAddress]*RegexStates

type FailedChallengeStates map[IpAddress]*NumHitsAndIntervalStart

// XXX use string.Builder
func (failedChallengeStates FailedChallengeStates) String() string {
	buf := bytes.Buffer{}
	for ip, state := range failedChallengeStates {
		buf.WriteString(fmt.Sprintf("%v,: interval_start: %v, num hits: %v\n", ip, state.IntervalStartTime.Format("15:04:05"), state.NumHits))
	}
	return buf.String()
}

func checkExpiringDecisionLists(clientIp string, decisionLists *DecisionLists) (Decision, bool) {
	expiringDecision, ok := (*decisionLists).ExpiringDecisionLists[clientIp]
	if !ok {
		log.Println("no mention in expiring lists")
	} else {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete((*decisionLists).ExpiringDecisionLists, clientIp)
			log.Println("deleted expired decision from expiring lists")
			ok = false
		}
	}
	return expiringDecision.Decision, ok
}

func updateExpiringDecisionLists(
	config *Config,
	ip string,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	now time.Time,
	newDecision Decision,
) {
	decisionListsMutex.Lock()
	defer decisionListsMutex.Unlock()

	existingExpiringDecision, ok := (*decisionLists).ExpiringDecisionLists[ip]
	if !ok {
		log.Println("no existing expiringDecision")
	} else {
		if newDecision <= existingExpiringDecision.Decision {
			log.Println("not updating expiringDecision with less serious one", existingExpiringDecision.Decision, newDecision)
			return
		}
	}
	log.Println("!!! existing and new: ", existingExpiringDecision.Decision, newDecision)

	purgeNginxAuthCacheForIp(ip)
	expires := now.Add(time.Duration(config.ExpiringDecisionTtlSeconds) * time.Second)
	(*decisionLists).ExpiringDecisionLists[ip] = ExpiringDecision{newDecision, expires}
}
