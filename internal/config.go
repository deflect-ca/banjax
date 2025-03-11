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
	"regexp"
	"sync"
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
	PuzzleThumbnailEntropySecret                string                         `yaml:"puzzle_thumbnail_entropy_secret"`
	PuzzleEntropySecret                         string                         `yaml:"puzzle_entropy_secret"`
	PuzzleClickChainEntropySecret               string                         `yaml:"puzzle_click_chain_entropy_secret"`
	PuzzleEnableGameplayDataCollection          bool                           `yaml:"puzzle_enable_gameplay_data_collection"`
	PuzzleRateLimitBruteForceSolutionTTLSeconds int                            `yaml:"puzzle_rate_limit_brute_force_solution_ttl_seconds"`
	PuzzleChallengeHTML                         []byte                         //see embed in config holder
	PuzzleDifficultyProfiles                    *PuzzleDifficultyProfileConfig `yaml:"puzzle_difficulty_profiles"` //stores the parsed difficulty profiles & provides getters
	PuzzleImageController                       *PuzzleImageController         //stores all the images we need access to for challeng issuance & validation purposes
}

/*individual difficulty profiles as desired in the banjax-puzzle-difficulty-config.yaml file*/
type PuzzleDifficultyProfile struct {
	NPartitions             int    `yaml:"nPartitions"`
	NShuffles               [2]int `yaml:"nShuffles"`
	MaxNumberOfMovesAllowed int    `yaml:"maxNumberOfMovesAllowed"`
	RemoveTileIndex         int    `yaml:"removeTileIndex"`
	TimeToSolveMs           int    `yaml:"timeToSolve_ms"`
	ShowCountdownTimer      bool   `yaml:"showCountdownTimer"`
}

type PuzzleDifficultyProfileConfig struct {
	Profiles   map[string]PuzzleDifficultyProfile `yaml:"profiles"`
	Target     string                             `yaml:"target"`
	configLock sync.RWMutex
}

/*
Returns the profile associated with "difficulty" key in the yaml
NOTE: You can access the target using configs.PuzzleDifficultyProfiles.Target and use that as the "difficulty" argument

accepts userChallengeCookie as argument such that if the profile specifies a random index,
the source of entropy used is the users challenge cookie
*/
func (profileConfig *PuzzleDifficultyProfileConfig) PuzzleDifficultyProfileByName(difficulty string, userChallengeCookie string) (PuzzleDifficultyProfile, bool) {
	profileConfig.configLock.RLock()
	difficultyProfile, exists := profileConfig.Profiles[difficulty]

	//if dne return early
	if !exists {
		profileConfig.configLock.RUnlock()
		return PuzzleDifficultyProfile{}, false
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

	if difficultyProfile.RemoveTileIndex == -1 { //check again just in case another thread in the time we upgraded changed it...
		/*
			We use the users challenge cookie so that we can guarentee given the same cookie we can
			produce the exact same result. This is required for validation!

			NOTE on initVector:
				- I would use profileConfig.Target as opposed to "tile_index_noise", but we first need to
				confirm we are going to be selecting difficulty that way and not dynamically otherwise we risk not being able to
				recreate their solution if it changes while the puzzle was being solved by a user
		*/
		initVector := "tile_index_noise"
		difficultyProfile.RemoveTileIndex = PuzzleEntropyFromRange(initVector, userChallengeCookie, 0, difficultyProfile.NPartitions)
	}

	return difficultyProfile, true
}

/*Loads the profiles from the yaml file and stores them in a map for user when the unmarshal is called by config_holder*/
func (profileConfig *PuzzleDifficultyProfileConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	profileConfig.configLock.Lock()
	defer profileConfig.configLock.Unlock()

	var loadedConfig struct {
		Target   string                             `yaml:"target"`
		Profiles map[string]PuzzleDifficultyProfile `yaml:"profiles"`
	}

	if err := unmarshal(&loadedConfig); err != nil {
		return fmt.Errorf("failed to unmarshal difficulty profiles: %w", err)
	}

	validProfiles := make(map[string]PuzzleDifficultyProfile)
	for profileName, difficultyProfile := range loadedConfig.Profiles {
		if !profileConfig.isValidProfile(difficultyProfile, profileName) {
			continue
		}
		validProfiles[profileName] = difficultyProfile
	}

	if len(validProfiles) == 0 {
		log.Println("Requires at least one valid profile!")
		return errors.New("ErrInvalidDifficultyProfileSettings: Require at least one valid profile")
	}

	if _, ok := validProfiles[loadedConfig.Target]; !ok {
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
func (profileConfig *PuzzleDifficultyProfileConfig) isValidProfile(difficultyProfile PuzzleDifficultyProfile, profileName string) bool {
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
