// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
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
	HmacSecret                             string `yaml:"hmac_secret"`
	// Path to the file to write gin (http server) log to. Use "-" to log to the stdout or empty
	// string to disable logging.
	GinLogFile                  string              `yaml:"gin_log_file"`
	SitewideShaInvList          map[string]string   `yaml:"sitewide_sha_inv_list"`
	MetricsLogFileName          string              `yaml:"metrics_log_file"`
	ShaInvChallengeHTML         string              `yaml:"sha_inv_challenge_html"`
	PasswordProtectedPathHTML   string              `yaml:"password_protected_path_html"`
	Debug                       bool                `yaml:"debug"`
	DisableLogging              map[string]bool     `yaml:"disable_logging"`
	BanningLogFileTemp          string              `yaml:"banning_log_file_temp"`
	DisableKafka                bool                `yaml:"disable_kafka"`
	SessionCookieHmacSecret     string              `yaml:"session_cookie_hmac_secret"`
	SessionCookieTtlSeconds     int                 `yaml:"session_cookie_ttl_seconds"`
	SessionCookieNotVerify      bool                `yaml:"session_cookie_not_verify"`
	SitesToDisableBaskerville   map[string]bool     `yaml:"sites_to_disable_baskerville"`
	SitesToShaInvPathExceptions map[string][]string `yaml:"sha_inv_path_exceptions"`
}

type RegexWithRate struct {
	Rule            string
	Regex           regexp.Regexp
	Interval        time.Duration
	HitsPerInterval int
	Decision        Decision
	HostsToSkip     map[string]bool
}

func (r *RegexWithRate) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i struct {
		Rule            string          `yaml:"rule"`
		Regex           string          `yaml:"regex"`
		Interval        float64         `yaml:"interval"`
		HitsPerInterval int             `yaml:"hits_per_interval"`
		Decision        string          `yaml:"decision"`
		HostsToSkip     map[string]bool `yaml:"hosts_to_skip"`
	}

	if err := unmarshal(&i); err != nil {
		return err
	}

	regex, err := regexp.Compile(i.Regex)
	if err != nil {
		return err
	}

	// Convert from seconds as float to Duration
	interval := time.Duration(i.Interval * float64(time.Second.Nanoseconds()))

	decision, err := ParseDecision(i.Decision)
	if err != nil {
		return err
	}

	r.Rule = i.Rule
	r.Regex = *regex
	r.Interval = interval
	r.HitsPerInterval = i.HitsPerInterval
	r.Decision = decision
	r.HostsToSkip = i.HostsToSkip

	return nil
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

type MetricsLogLine struct {
	Time                     string
	LenExpiringChallenges    int
	LenExpiringBlocks        int
	LenIpToRegexStates       int
	LenFailedChallengeStates int
}

func WriteMetricsToEncoder(
	metricsLogEncoder *json.Encoder,
	decisionLists *DynamicDecisionLists,
	rateLimitStates *RateLimitStates,
) {
	lenExpiringChallenges, lenExpiringBlocks := decisionLists.Metrics()
	lenRegexStates, lenFailedChallengeStates := rateLimitStates.Metrics()

	metricsLogLine := MetricsLogLine{
		Time:                     time.Now().Format(time.RFC1123),
		LenExpiringChallenges:    lenExpiringChallenges,
		LenExpiringBlocks:        lenExpiringBlocks,
		LenIpToRegexStates:       lenRegexStates,
		LenFailedChallengeStates: lenFailedChallengeStates,
	}

	err := metricsLogEncoder.Encode(metricsLogLine)
	if err != nil {
		log.Printf("!!! failed to encode metricsLogLine %v\n", err)
		return
	}
}
