// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"os"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

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
	Profile                     bool                `yaml:"profile"`
	DisableLogging              map[string]bool     `yaml:"disable_logging"`
	BanningLogFileTemp          string              `yaml:"banning_log_file_temp"`
	DisableKafka                bool                `yaml:"disable_kafka"`
	SessionCookieHmacSecret     string              `yaml:"session_cookie_hmac_secret"`
	SessionCookieTtlSeconds     int                 `yaml:"session_cookie_ttl_seconds"`
	SessionCookieNotVerify      bool                `yaml:"session_cookie_not_verify"`
	SitesToDisableBaskerville   map[string]bool     `yaml:"sites_to_disable_baskerville"`
	SitesToShaInvPathExceptions map[string][]string `yaml:"sha_inv_path_exceptions"`
	//puzzle captcha requirements
	ThumbnailEntropySecret                string `yaml:"thumbnail_entropy_secret"`
	PuzzleEntropySecret                   string `yaml:"puzzle_entropy_secret"`
	ClickChainEntropySecret               string `yaml:"click_chain_entropy_secret"`
	EnableGameplayDataCollection          bool   `yaml:"enable_gameplay_data_collection"`
	RateLimitBruteForceSolutionTTLSeconds int    `yaml:"rate_limit_brute_force_solution_ttl_seconds"`
	UseFreshEntropyForDynamicTileRemoval  bool   `yaml:"use_fresh_entropy_for_dynamic_tile_removal"`

	PathToDifficultyProfiles string `yaml:"path_to_difficulty_profiles"` //stores path to file in etc that stores difficulty profiles

	DifficultyProfiles *DifficultyProfileConfig //stores the parsed difficulty profiles & provides getters
}

/*individual difficulty profiles as desired in the banjax-puzzle-difficulty-config.yaml file*/
type DifficultyProfile struct {
	NPartitions             int    `yaml:"nPartitions"`
	NShuffles               [2]int `yaml:"nShuffles"`
	MaxNumberOfMovesAllowed int    `yaml:"maxNumberOfMovesAllowed"`
	RemoveTileIndex         int    `yaml:"removeTileIndex"`
	TimeToSolveMs           int    `yaml:"timeToSolve_ms"`
	ShowCountdownTimer      bool   `yaml:"showCountdownTimer"`
}

/*
converts a specific index of a perfect square number of partitions into a (row, col)
is required due to the possibility of a 'random' RemoveTileIndex being supplied, requiring the ability
to recalculate a (row, col) pair for any given difficulty profile
*/
func (difficultyProfile DifficultyProfile) TileIndexToRowCol(index int) (row int, col int) {
	square := int(math.Sqrt(float64(difficultyProfile.NPartitions)))
	row = index / square
	col = index % square
	return
}

type DifficultyProfileConfig struct {
	Profiles   map[string]DifficultyProfile `yaml:"profiles"`
	Target     string                       `yaml:"target"`
	configLock sync.RWMutex
}

/*
Returns the profile associated with "target" key in the yaml

if the `useNewEntropy` is true, then on issuing the same difficulty challenge, each challenge will admit
a different missing tile location (assuming that the RemoveTileIndex is specified as -1 in the configs)

if the `userNewEntropy` is false, it will always use the same the same source of entropy (or the 0 <= RemoveTileIndex <= nPartitions
as specified at in the difficulty profile .yaml configurations)
*/
func (profileConfig *DifficultyProfileConfig) GetProfileByTarget(useNewEntropy bool) (DifficultyProfile, bool) {
	return profileConfig.GetProfileByName(profileConfig.Target, useNewEntropy)
}

/*
Returns the difficulty profile by name. Useful if you imlpement a dynamic means of determining the type of challenge to issue

if the `useNewEntropy` is true, then on issuing the same difficulty challenge, each challenge will admit
a different missing tile location (assuming that the RemoveTileIndex is specified as -1 in the configs)

if the `userNewEntropy` is false, it will always use the same the same source of entropy (or the 0 <= RemoveTileIndex <= nPartitions
as specified at in the difficulty profile .yaml configurations)
*/
func (profileConfig *DifficultyProfileConfig) GetProfileByName(difficulty string, useNewEntropy bool) (DifficultyProfile, bool) {
	profileConfig.configLock.RLock()
	difficultyProfile, exists := profileConfig.Profiles[difficulty]

	//if dne return early
	if !exists {
		profileConfig.configLock.RUnlock()
		return DifficultyProfile{}, false
	}

	//if we need not make changes, return the valid profile
	if difficultyProfile.RemoveTileIndex != -1 {
		profileConfig.configLock.RUnlock()
		return difficultyProfile, true
	}

	//if we need to pick a random tile to remove, we need to upgrade locks
	profileConfig.configLock.RUnlock()
	profileConfig.configLock.Lock()
	defer profileConfig.configLock.Unlock()

	if difficultyProfile.RemoveTileIndex == -1 { //just in case another thread in the time we upgraded changed it...
		difficultyProfile.RemoveTileIndex = profileConfig.getRandomTileIndex(difficultyProfile.NPartitions, useNewEntropy)
	}

	return difficultyProfile, true
}

/*
uses the rng as entropy to pick a random number ∈ [0, nPartitions] which will be used to replace the
removeTileIndex if it was specified as -1 in the configs
*/
func (profileConfig *DifficultyProfileConfig) getRandomTileIndex(nPartitions int, useNewEntropy bool) int {
	if useNewEntropy {
		//we reseed it the rng anytime we need new entropy, otherwise we use what already exists
		rng.Seed(time.Now().UnixNano())
	}
	return rng.Intn(nPartitions)
}

/*Loads the profiles from the yaml file and stores them in a map for user*/
func (profileConfig *DifficultyProfileConfig) UnmarshalYAML(path string) error {
	profileConfig.configLock.Lock()
	defer profileConfig.configLock.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read difficulty profiles: %w", err)
	}

	var loadedConfig DifficultyProfileConfig
	err = yaml.Unmarshal(data, &loadedConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal difficulty profiles: %w", err)
	}

	validProfiles := make(map[string]DifficultyProfile)
	for profileName, difficultyProfile := range loadedConfig.Profiles {
		if !loadedConfig.isValidProfile(difficultyProfile, profileName) {
			continue
		}
		validProfiles[profileName] = difficultyProfile
	}

	if len(validProfiles) == 0 {
		log.Println("Requires at least one valid profile!")
		return errors.New("ErrInvalidDifficultyProfileSettings: Require at least one valid profile")
	}

	_, ok := validProfiles[loadedConfig.Target]
	if !ok {
		log.Printf("Target profile '%s' does not exist in valid profiles. Aborting config load.", loadedConfig.Target)
		return fmt.Errorf("ErrTargetProfileDoesNotExist: %s", loadedConfig.Target)
	}

	profileConfig.Profiles = validProfiles
	profileConfig.Target = loadedConfig.Target

	return nil
}

/*
checks to see if the properties specified in the profile definitions are valid. In order to avoid
unnecessarily breaking due to a misconfiguration, the function returns boolean. However, this functionality
is tightly coupled with the calling function (UnmarshalYAML) as it will only return an error if none of the
profiles are valid or if the target profile difficulty you are issuing was invalid and therefore not registered
*/
func (profileConfig *DifficultyProfileConfig) isValidProfile(difficultyProfile DifficultyProfile, profileName string) bool {
	//check to see if profile nPartitions are perfect square
	sqrt := math.Sqrt(float64(difficultyProfile.NPartitions))
	if sqrt != float64(int(sqrt)) {
		log.Printf("Detected invalid nPartition specification. Expected perfect square, %d is not a perfect square. Skipping profile: %s", difficultyProfile.NPartitions, profileName)
		return false
	}

	//check to see if the difficulty is either -1 (meaning randomly choose what tile to remove), or is ∈ [0, nPartitions]
	if difficultyProfile.RemoveTileIndex < -1 || difficultyProfile.RemoveTileIndex >= difficultyProfile.NPartitions {
		log.Printf("Invalid RemoveTileIndex (%d) for profile %s. Must be in range [0, %d) or -1 (for random selection). Skipping profile.",
			difficultyProfile.RemoveTileIndex, profileName, difficultyProfile.NPartitions)
		return false
	}

	/*
		- Each click chain entry requires approx 350 bytes
		- with a cap of 4096 per cookie, we have 11 click chain entries per cookie
		- most browsers allow 50 cookies, but some stricter browsers (mobile in particular) allow only 25 and chrome caps aat 180kb
			=> at most 300 clicks before hitting limits of even the stricter browsers.
		- To avoid any issues of other domain cookies being evicted as well as latency issues, we set a cap for our puzzles to 100 clicks
			as its well within the safe limits of even the strictest browsers

		- however in order to avoid needing to allow nginx to accept 4 64k headers, we reduce this to 80 clicks max such we are guarenteed that nginx
		can handle it with no issue
	*/

	if difficultyProfile.MaxNumberOfMovesAllowed > 80 {
		log.Printf("Maximum number of clicks for any profile CANNOT exceed 80 due to cookie constraints. Got: %d", difficultyProfile.MaxNumberOfMovesAllowed)
		return false
	}

	//other validations as needed
	return true
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
	regexStates *RegexRateLimitStates,
	failedChallengeStates *FailedChallengeRateLimitStates,
) {
	lenExpiringChallenges, lenExpiringBlocks := decisionLists.Metrics()
	lenRegexStates := regexStates.Len()
	lenFailedChallengeStates := failedChallengeStates.Len()

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
