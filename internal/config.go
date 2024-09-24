// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jeremy5189/ipfilter-no-iploc/v2"
)

type Config struct {
	RegexesWithRates                       []RegexWithRate                `yaml:"regexes_with_rates"`
	PerSiteRegexWithRates                  map[string][]RegexWithRate     `yaml:"per_site_regexes_with_rates"`
	ServerLogFile                          string                         `yaml:"server_log_file"`
	BanningLogFile                         string                         `yaml:"banning_log_file"`
	IptablesBanSeconds                     int                            `yaml:"iptables_ban_seconds"`
	IptablesUnbannerSeconds                int                            `yaml:"iptables_unbanner_seconds"`
	KafkaBrokers                           []string                       `yaml:"kafka_brokers"`
	KafkaSecurityProtocol                  string                         `yaml:"kafka_security_protocol"`
	KafkaSslCa                             string                         `yaml:"kafka_ssl_ca"`
	KafkaSslCert                           string                         `yaml:"kafka_ssl_cert"`
	KafkaSslKey                            string                         `yaml:"kafka_ssl_key"`
	KafkaSslKeyPassword                    string                         `yaml:"kafka_ssl_key_password"`
	KafkaCommandTopic                      string                         `yaml:"kafka_command_topic"`
	KafkaReportTopic                       string                         `yaml:"kafka_report_topic"`
	PerSiteDecisionLists                   map[string]map[string][]string `yaml:"per_site_decision_lists"`
	GlobalDecisionLists                    map[string][]string            `yaml:"global_decision_lists"`
	ConfigVersion                          string                         `yaml:"config_version"`
	StandaloneTesting                      bool                           `yaml:"standalone_testing"`
	ChallengerBytes                        []byte
	PasswordPageBytes                      []byte
	SitesToPasswordHashes                  map[string]string   `yaml:"password_hashes"`
	SitesToProtectedPaths                  map[string][]string `yaml:"password_protected_paths"`
	SitesToProtectedPathExceptions         map[string][]string `yaml:"password_protected_path_exceptions"`
	SitesToPasswordHashesRoaming           map[string]string   `yaml:"password_hash_roaming"`
	SitesToPasswordCookieTtlSeconds        map[string]int      `yaml:"password_persite_cookie_ttl_seconds"`
	SitesToUseUserAgentInCookie            map[string]bool     `yaml:"use_user_agent_in_cookie"`
	ExpiringDecisionTtlSeconds             int                 `yaml:"expiring_decision_ttl_seconds"`
	BlockIPTtlSeconds                      int                 `yaml:"block_ip_ttl_seconds"`
	BlockSessionTtlSeconds                 int                 `yaml:"block_session_ttl_seconds"`
	SitesToBlockIPTtlSeconds               map[string]int      `yaml:"sites_to_block_ip_ttl_seconds"`
	SitesToBlockSessionTtlSeconds          map[string]int      `yaml:"sites_to_block_session_ttl_seconds"`
	TooManyFailedChallengesIntervalSeconds int                 `yaml:"too_many_failed_challenges_interval_seconds"`
	TooManyFailedChallengesThreshold       int                 `yaml:"too_many_failed_challenges_threshold"`
	PasswordCookieTtlSeconds               int                 `yaml:"password_cookie_ttl_seconds"`
	ShaInvCookieTtlSeconds                 int                 `yaml:"sha_inv_cookie_ttl_seconds"`
	ShaInvExpectedZeroBits                 uint32              `yaml:"sha_inv_expected_zero_bits"`
	RestartTime                            int
	ReloadTime                             int
	Hostname                               string
	HmacSecret                             string            `yaml:"hmac_secret"`
	GinLogFile                             string            `yaml:"gin_log_file"`
	SitewideShaInvList                     map[string]string `yaml:"sitewide_sha_inv_list"`
	MetricsLogFileName                     string            `yaml:"metrics_log_file"`
	ShaInvChallengeHTML                    string            `yaml:"sha_inv_challenge_html"`
	PasswordProtectedPathHTML              string            `yaml:"password_protected_path_html"`
	Debug                                  bool              `yaml:"debug"`
	DisableLogging                         map[string]bool   `yaml:"disable_logging"`
	BanningLogFileTemp                     string            `yaml:"banning_log_file_temp"`
	DisableKafka                           bool              `yaml:"disable_kafka"`
	SessionCookieHmacSecret                string            `yaml:"session_cookie_hmac_secret"`
	SessionCookieTtlSeconds                int               `yaml:"session_cookie_ttl_seconds"`
	SessionCookieNotVerify                 bool              `yaml:"session_cookie_not_verify"`
	SitesToDisableBaskerville              map[string]bool   `yaml:"sites_to_disable_baskerville"`
}

type RegexWithRate struct {
	Rule            string `yaml:"rule"`
	Regex           string `yaml:"regex"`
	CompiledRegex   regexp.Regexp
	Interval        float64         `yaml:"interval"`
	HitsPerInterval int             `yaml:"hits_per_interval"`
	Decision        string          `yaml:"decision"`
	HostsToSkip     map[string]bool `yaml:"hosts_to_skip"`
}

// XXX previously i had a DefaultAllow as the first enum, which fell through
// my case statements and into the default: switch elsewhere. scary bug.
// maybe use _ as first enum? but then remember to use it in the string conversion
// functions just below x_x
type Decision int

const (
	Allow         = iota
	Challenge     = iota
	NginxBlock    = iota
	IptablesBlock = iota
)

type ExpiringDecision struct {
	Decision        Decision
	Expires         time.Time
	IpAddress       string
	fromBaskerville bool
	domain          string
}

// XXX is this really how you make an enum in go?
type FailAction int

const (
	Block   = iota
	NoBlock = iota
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
type StringToExpiringDecision map[string]ExpiringDecision
type StringToStringToDecision map[string]StringToDecision
type StringToFailAction map[string]FailAction
type DecisionToIPFilter map[Decision]*ipfilter.IPFilter
type StringToDecisionToIPFilter map[string]DecisionToIPFilter

type DecisionLists struct {
	// static blocklists, allowlists, challengelists populated from the config file
	GlobalDecisionLists  StringToDecision         // ip -> Decision
	PerSiteDecisionLists StringToStringToDecision // site -> ip -> Decision
	// dynamic lists populated from the regex rate limits + kafka
	ExpiringDecisionLists StringToExpiringDecision // ip -> ExpiringDecision
	// dynamic lists populated from the kafka, like ExpiringDecisionLists but session ID as index
	ExpiringDecisionListsSessionId StringToExpiringDecision
	// static site-wide lists (legacy banjax_sha_inv and user_banjax_sha_inv)
	// XXX someday need sha-inv *and* captcha
	// XXX could be merged with PerSiteDecisionLists if we matched on ip ranges
	SitewideShaInvList           StringToFailAction // site -> Challenge (block after many failures or don't)
	GlobalDecisionListsIPFilter  DecisionToIPFilter
	PerSiteDecisionListsIPFilter StringToDecisionToIPFilter
}

type StringToBool map[string]bool
type StringToStringToBool map[string]StringToBool
type StringToBytes map[string][]byte

type PasswordProtectedPaths struct {
	SiteToPathToBool          StringToStringToBool
	SiteToExceptionToBool     StringToStringToBool
	SiteToPasswordHash        StringToBytes
	SiteToRoamingPasswordHash StringToBytes
	SiteToExpandCookieDomain  StringToBool
}

func ConfigToPasswordProtectedPaths(config *Config) PasswordProtectedPaths {
	siteToPathToBool := make(StringToStringToBool)
	siteToExceptionToBool := make(StringToStringToBool)
	siteToPasswordHash := make(StringToBytes)
	siteToRoamingPasswordHash := make(StringToBytes)
	siteToExpandCookieDomain := make(StringToBool)

	for site, paths := range config.SitesToProtectedPaths {
		for _, path := range paths {
			path = "/" + strings.Trim(path, "/")
			_, ok := siteToPathToBool[site]
			if !ok {
				siteToPathToBool[site] = make(StringToBool)
			}
			siteToPathToBool[site][path] = true
			if config.Debug {
				log.Printf("password protected path: %s/%s\n", site, path)
			}
		}
	}

	for site, exceptions := range config.SitesToProtectedPathExceptions {
		for _, exception := range exceptions {
			exception = "/" + strings.Trim(exception, "/")
			_, ok := siteToExceptionToBool[site]
			if !ok {
				siteToExceptionToBool[site] = make(StringToBool)
			}
			siteToExceptionToBool[site][exception] = true
		}
	}

	for site, passwordHashHex := range config.SitesToPasswordHashes {
		passwordHashBytes, err := hex.DecodeString(passwordHashHex)
		if err != nil {
			log.Fatal("bad password hash!")
		}
		siteToPasswordHash[site] = passwordHashBytes
		if config.Debug {
			log.Println("passwordhashbytes:")
			log.Println(passwordHashBytes)
		}
	}

	for site, rootSiteToRoam := range config.SitesToPasswordHashesRoaming {
		// try to get the password hash from the root site
		passwordHashBytes, ok := siteToPasswordHash[rootSiteToRoam]
		if ok {
			siteToRoamingPasswordHash[site] = passwordHashBytes
			siteToExpandCookieDomain[rootSiteToRoam] = true // set this to let root domain cookie expand to subdomains
			// log.Printf("site %s has roaming password hash from root site %s\n", site, rootSiteToRoam)
		}
	}

	return PasswordProtectedPaths{
		siteToPathToBool,
		siteToExceptionToBool,
		siteToPasswordHash,
		siteToRoamingPasswordHash,
		siteToExpandCookieDomain,
	}
}

func ConfigToDecisionLists(config *Config) DecisionLists {
	perSiteDecisionLists := make(StringToStringToDecision)
	globalDecisionLists := make(StringToDecision)
	expiringDecisionLists := make(StringToExpiringDecision)
	expiringDecisionListsSessionId := make(StringToExpiringDecision)
	sitewideShaInvList := make(StringToFailAction)
	globalDecisionListsIPFilter := make(DecisionToIPFilter)
	perSiteDecisionListsIPFilter := make(StringToDecisionToIPFilter)

	for site, decisionToIps := range config.PerSiteDecisionLists {
		for decisionString, ips := range decisionToIps {
			decision := stringToDecision[decisionString]
			for _, ip := range ips {
				_, ok := perSiteDecisionLists[site]
				if !ok {
					perSiteDecisionLists[site] = make(StringToDecision)
					perSiteDecisionListsIPFilter[site] = make(DecisionToIPFilter)
				}
				if !strings.Contains(ip, "/") {
					perSiteDecisionLists[site][ip] = decision
					if config.Debug {
						log.Printf("site: %s, decision: %s, ip: %s\n", site, decisionString, ip)
					}
				} else {
					if config.Debug {
						log.Printf("per-site decision: %s, CIDR: %s, put in IPFilter\n", decisionString, ip)
					}
				}
			}
			if len(ips) > 0 {
				// only init ipfilter if there is IP
				// or there might be panic: assignment to entry in nil map
				perSiteDecisionListsIPFilter[site][decision] = ipfilter.New(ipfilter.Options{
					AllowedIPs:     ips,
					BlockByDefault: true,
				})
			}
		}
	}

	for decisionString, ips := range config.GlobalDecisionLists {
		decision := stringToDecision[decisionString]
		for _, ip := range ips {
			if !strings.Contains(ip, "/") {
				globalDecisionLists[ip] = decision
				if config.Debug {
					log.Printf("global decision: %s, ip: %s\n", decisionString, ip)
				}
			} else {
				if config.Debug {
					log.Printf("global decision: %s, CIDR: %s, put in IPFilter\n", decisionString, ip)
				}
			}
		}
		globalDecisionListsIPFilter[decision] = ipfilter.New(ipfilter.Options{
			AllowedIPs:     ips,
			BlockByDefault: true,
		})
	}

	for site, failAction := range config.SitewideShaInvList {
		if config.Debug {
			log.Printf("sitewide site: %s, failAction: %s\n", site, failAction)
		}
		if failAction == "block" {
			sitewideShaInvList[site] = Block
		} else if failAction == "no_block" {
			sitewideShaInvList[site] = NoBlock
		} else {
			panic("!!! sitewide_sha_inv_list action is block or no_block")
		}
	}

	// log.Printf("per-site decisions: %v\n", perSiteDecisionLists)
	// log.Printf("global decisions: %v\n", globalDecisionLists)
	return DecisionLists{
		globalDecisionLists, perSiteDecisionLists,
		expiringDecisionLists, expiringDecisionListsSessionId, sitewideShaInvList,
		globalDecisionListsIPFilter, perSiteDecisionListsIPFilter}
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
		buf.WriteString(fmt.Sprintf("%v %v until %v (baskerville: %v)",
			expiringDecision.domain,
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
			expiringDecision.fromBaskerville,
		))
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

type BannedEntry struct {
	IpOrSessionId   string `json:"ip"`
	domain          string
	Decision        string    `json:"decision"`
	Expires         time.Time `json:"expires"`
	FromBaskerville bool      `json:"from_baskerville"`
}

func (bannedEntry BannedEntry) String() string {
	return fmt.Sprintf("%v: %v until %v (baskerville: %v)",
		bannedEntry.IpOrSessionId,
		bannedEntry.Decision,
		bannedEntry.Expires.Format("15:04:05"),
		bannedEntry.FromBaskerville,
	)
}

func checkExpiringDecisionListsByDomain(domain string, decisionLists *DecisionLists) []BannedEntry {
	// interate (*decisionLists).ExpiringDecisionLists
	// if domain matches, append to []ExpiringDecision
	// return []BannedEntry
	var bannedEntries []BannedEntry
	for ip, expiringDecision := range (*decisionLists).ExpiringDecisionLists {
		if expiringDecision.domain == domain && expiringDecision.Decision >= Challenge {
			bannedEntries = append(bannedEntries, BannedEntry{
				IpOrSessionId:   ip,
				domain:          expiringDecision.domain,
				Decision:        expiringDecision.Decision.String(), // Convert Decision to string
				Expires:         expiringDecision.Expires,
				FromBaskerville: expiringDecision.fromBaskerville,
			})
		}
	}
	for sessionId, expiringDecision := range (*decisionLists).ExpiringDecisionListsSessionId {
		if expiringDecision.domain == domain && expiringDecision.Decision >= Challenge {
			bannedEntries = append(bannedEntries, BannedEntry{
				IpOrSessionId:   sessionId,
				domain:          expiringDecision.domain,
				Decision:        expiringDecision.Decision.String(), // Convert Decision to string
				Expires:         expiringDecision.Expires,
				FromBaskerville: expiringDecision.fromBaskerville,
			})
		}
	}
	return bannedEntries
}

// XXX mmm could hold the lock for a while?
func RemoveExpiredDecisions(
	decisionListsMutex *sync.RWMutex,
	decisionLists *DecisionLists,
) {
	decisionListsMutex.Lock()
	defer decisionListsMutex.Unlock()

	for ip, expiringDecision := range (*decisionLists).ExpiringDecisionLists {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete((*decisionLists).ExpiringDecisionLists, ip)
			// log.Println("deleted expired decision from expiring lists")
		}
	}
}

func removeExpiredDecisionsByIp(
	decisionListsMutex *sync.RWMutex,
	decisionLists *DecisionLists,
	ip string,
) {
	decisionListsMutex.Lock()
	defer decisionListsMutex.Unlock()

	delete((*decisionLists).ExpiringDecisionLists, ip)
	// log.Printf("deleted IP %v from expiring lists", ip)
}

func updateExpiringDecisionLists(
	config *Config,
	ip string,
	decisionListsMutex *sync.RWMutex,
	decisionLists *DecisionLists,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
) {
	decisionListsMutex.Lock()
	defer decisionListsMutex.Unlock()

	existingExpiringDecision, ok := (*decisionLists).ExpiringDecisionLists[ip]
	if ok {
		if newDecision <= existingExpiringDecision.Decision {
			if config.Debug {
				log.Println("updateExpiringDecisionLists: not with less serious", existingExpiringDecision.Decision, newDecision, ip, domain)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionLists: update with existing and new: ", existingExpiringDecision.Decision, newDecision, ip, domain)
		// log.Println("From baskerville", fromBaskerville)
	}

	// XXX We are not using nginx to banjax cache feature yet
	// purgeNginxAuthCacheForIp(ip)
	(*decisionLists).ExpiringDecisionLists[ip] = ExpiringDecision{
		newDecision, expires, ip, fromBaskerville, domain}
}

func updateExpiringDecisionListsSessionId(
	config *Config,
	ip string,
	sessionId string,
	decisionListsMutex *sync.RWMutex,
	decisionLists *DecisionLists,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
) {
	decisionListsMutex.Lock()
	defer decisionListsMutex.Unlock()

	existingExpiringDecision, ok := (*decisionLists).ExpiringDecisionListsSessionId[sessionId]
	if ok {
		if newDecision <= existingExpiringDecision.Decision {
			return
		}
	}

	if config.Debug {
		log.Printf("updateExpiringDecisionListsSessionId: Update session id decision with IP %s, session id %s, existing and new: %v, %v\n",
			ip, sessionId, existingExpiringDecision.Decision, newDecision)
	}

	(*decisionLists).ExpiringDecisionListsSessionId[sessionId] = ExpiringDecision{
		newDecision, expires, ip, fromBaskerville, domain}
}

type MetricsLogLine struct {
	Time                     string
	LenExpiringChallenges    int
	LenExpiringBlocks        int
	LenIpToRegexStates       int
	LenFailedChallengeStates int
}

func WriteMetricsToEncoder(
	metricsLogEncoder *json.Encoder,
	decisionListsMutex *sync.RWMutex,
	decisionLists *DecisionLists,
	rateLimitMutex *sync.Mutex,
	ipToRegexStates *IpToRegexStates,
	failedChallengeStates *FailedChallengeStates,
) {
	decisionListsMutex.RLock()
	defer decisionListsMutex.RUnlock()

	lenExpiringChallenges := 0
	lenExpiringBlocks := 0

	for _, expiringDecision := range (*decisionLists).ExpiringDecisionLists {
		if expiringDecision.Decision == Challenge {
			lenExpiringChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringBlocks += 1
		}
	}

	metricsLogLine := MetricsLogLine{
		Time:                     time.Now().Format(time.RFC1123),
		LenExpiringChallenges:    lenExpiringChallenges,
		LenExpiringBlocks:        lenExpiringBlocks,
		LenIpToRegexStates:       len(*ipToRegexStates),
		LenFailedChallengeStates: len(*failedChallengeStates),
	}

	err := metricsLogEncoder.Encode(metricsLogLine)
	if err != nil {
		log.Printf("!!! failed to encode metricsLogLine %v\n", err)
		return
	}
}
