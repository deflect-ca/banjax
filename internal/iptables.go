// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/gonetx/ipset"
)

const (
	IPSetName = "banjax_ipset"
)

func init_ipset(config *Config) {
	log.Println("http_server: init_ipset()")
	if config.StandaloneTesting {
		log.Println("init_ipset: Not init ipset in testing")
		return
	}
	if err := ipset.Check(); err != nil {
		log.Println("init_ipset() ipset.Check() failed")
		panic(err)
	}

	var err error
	config.IPSetInstance, err = ipset.New(
		IPSetName,
		ipset.HashIp,
		ipset.Exist(true),
		ipset.Timeout(time.Duration(config.IptablesBanSeconds)*time.Second))
	if err != nil {
		log.Println("init_ipset() ipset.New() failed")
		panic(err)
	}
	// print name set.Name()
	log.Println("init_ipset() done, name:", config.IPSetInstance.Name())

	// enable ipset with iptables
	// iptables -I INPUT -m set --match-set banjax src -j DROP
	ipt, err := iptables.New()
	if err != nil {
		log.Println("IPTABLES: iptables.New() failed")
		panic(err)
	}
	err = ipt.Insert("filter", "INPUT", 1, "-m", "set", "--match-set", IPSetName, "src", "-j", "DROP")
	if err != nil {
		log.Println("IPTABLES: iptables.Insert() failed, did not enable ipset")
		panic(err)
	}
}

func ipAndTimestampToRuleSpec(ip string, timestamp int64) []string {
	return []string{"-s", ip, "-j", "DROP", "-m", "comment",
		"--comment", fmt.Sprintf("added:%d", timestamp)}
}

// to Delete a rule returned from List, we have to fix it up a little
// basically change this string: `-A INPUT -s 1.2.3.5/32 -m comment --comment "added:1599210074" -j DROP`
// into this slice: ["-s" "1.2.3.5/32" "-m" "comment" "--comment" "added:1599210074" "-j" "DROP"]
func ruleToRuleSpec(rule string) ([]string, error) {
	entryFields := strings.Split(rule, " ")
	if len(entryFields) < 3 {
		return entryFields, errors.New("Not enough fields in this rule")
	}
	// we want to skip the "-A" and "INPUT" fields
	entryFields = entryFields[2:]
	// alright, this is a bit annoying. the entries from List() have the comment string quoted,
	// like `--comment "added:1234"`, but Delete() requires each field to be unquoted...
	for i, _ := range entryFields {
		if strings.HasPrefix(entryFields[i], "\"added:") {
			unquotedField, err := strconv.Unquote(entryFields[i])
			if err != nil {
				return entryFields, errors.New("Unquote failed")
			}
			entryFields[i] = unquotedField
		}
	}
	return entryFields, nil
}

func RunIpBanExpirer(config *Config, wg *sync.WaitGroup) {
	ipt, err := iptables.New()
	if err != nil {
		log.Printf("iptables.New() failed: %v", err)
		return
	}

	for {
		ruleList, err := ipt.List("filter", "INPUT")
		if err != nil {
			log.Printf("List failed: %v", err)
			return
		}

		// ti := time.Now()
		// tiMs := int64(time.Nanosecond) * ti.UnixNano() / int64(time.Millisecond)
		// fmt.Printf("timeUnixMilli: %d\n", tiMs)
		// i := uint64(0)
		for _, rule := range ruleList {
			timestampRegex := regexp.MustCompile(`added:(\d*)`)
			timestampMatches := timestampRegex.FindStringSubmatch(rule)
			if len(timestampMatches) < 2 {
				continue
			}

			addedTimeInt, err := strconv.ParseInt(timestampMatches[1], 10, 64)
			if err != nil {
				log.Println("could not parse an int where the timestamp should be: ", timestampMatches[1])
				continue
			}

			addedTime := time.Unix(addedTimeInt, 0)

			if time.Now().Sub(addedTime) > (time.Second * time.Duration(config.IptablesBanSeconds)) {
				ruleSpec, err := ruleToRuleSpec(rule)
				if err != nil {
					log.Println(err)
					continue
				}

				err = ipt.Delete("filter", "INPUT", ruleSpec...)
				if err != nil {
					log.Printf("Delete failed")
					continue
				}

				// log.Println("Delete succeeded")
			}
			// i++
			// if i > 100 {
			// 	ti2 := time.Now()
			// 	ti2Ms := int64(time.Nanosecond) * ti2.UnixNano() / int64(time.Millisecond)
			// 	fmt.Printf("deleted 100 rules in %d ms\n", ti2Ms - tiMs)
			// 	tiMs = ti2Ms
			// 	i = 0
			// }
		}
		time.Sleep(time.Second * time.Duration(config.IptablesUnbannerSeconds))
	}
}

type BannerInterface interface {
	BanOrChallengeIp(config *Config, ip string, decision Decision)
	LogRegexBan(config *Config, logTime time.Time, ip string, ruleName string, logLine string, decision Decision)
	LogFailedChallengeBan(config *Config, ip string, challengeType string, host string, path string, tooManyFailedChallengesThreshold int,
		userAgent string, decision Decision, method string)
}

type Banner struct {
	DecisionListsMutex *sync.Mutex
	DecisionLists      *DecisionLists
	Logger             *log.Logger
	LoggerTemp         *log.Logger
}

func purgeNginxAuthCacheForIp(ip string) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:80/auth_requests/%s*", ip), nil) // XXX
	if err != nil {
		log.Println("purgeNginxAuthCacheForIp() NewRequest() failed!")
		return
	}

	req.Host = "cache_purge"
	response, err := client.Do(req)
	if err != nil {
		log.Println("purgeNginxAuthCacheForIp() Get() failed!")
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Println("ioutil.ReadAll() failed!")
		return
	}

	defer response.Body.Close()

	if !bytes.Contains(body, []byte("Successful purge")) {
		log.Println("purgeNginxAuthCacheForIp() DID NOT GET 'Successful purge' response'")
		log.Println("instead got: ", string(body))
	}
}

type LogJson struct {
	Path           string `json:"path"`
	Timestring     string `json:"timestring"`
	Trigger        string `json:"trigger"`
	Client_ua      string `json:"client_ua"`
	Client_ip      string `json:"client_ip"`
	Rule_type      string `json:"rule_type"`
	Http_method    string `json:"client_request_method"`
	Http_schema    string `json:"http_request_scheme"`
	Http_host      string `json:"client_request_host"`
	Action         string `json:"action"`
	NumberOfFails  int    `json:"number_of_fails"`
	DisableLogging int    `json:"disable_logging"`
}

func (b Banner) LogRegexBan(
	config *Config,
	logTime time.Time,
	ip string,
	ruleName string,
	logLine string,
	decision Decision,
) {
	timeString := logTime.Format("2006-01-02T15:04:05") // XXX should this be the log timestamp or time.Now()?

	// logLine = GET localhost:8081 GET /45in60 HTTP/1.1 Go-http-client/1.1
	words := strings.SplitN(logLine, " ", 6)
	if len(words) < 6 {
		log.Println("not enough words")
		return
	}

	disableLogging := 0
	if val, ok := config.DisableLogging[words[1]]; ok && val {
		disableLogging = 1
	}

	// we append "| <http status code>" at the end of banjax-format.log for special regex rule
	// here we split | and ignore everything on the right
	vertical_bar_split := strings.SplitN(words[5], "|", 2)

	logObj := LogJson{
		words[3], // path
		timeString,
		ruleName,
		strings.TrimSpace(vertical_bar_split[0]), // client_ua
		ip,
		"regex",
		words[0], // method
		"https",  // XXX nginx did not tell in log
		words[1], // host
		fmt.Sprintf("%s", decision),
		1, // there is actually no need for regex ban to have this, but put 1 here so it make sense
		disableLogging,
	}
	bytesJson, _ := json.Marshal(logObj)

	if disableLogging == 1 {
		// we still log it to file, but this will be treated differently
		// in filebeat to different ES index, and later deleted
		b.LoggerTemp.Println(string(bytesJson))
	} else {
		b.Logger.Println(string(bytesJson))
	}
}

func (b Banner) LogFailedChallengeBan(
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
	timeString := time.Now().Format("2006-01-02T15:04:05")

	disableLogging := 0
	if val, ok := config.DisableLogging[host]; ok && val {
		disableLogging = 1
	}

	logObj := LogJson{
		path,
		timeString,
		fmt.Sprintf("failed challenge %s", challengeType),
		userAgent,
		ip,
		"failed_challenge",
		method,
		"https", // XXX
		host,
		fmt.Sprintf("%s", decision),
		tooManyFailedChallengesThreshold,
		disableLogging,
	}
	bytesJson, _ := json.Marshal(logObj)

	if disableLogging == 1 {
		// we still log it to file, but this will be treated differently
		// in filebeat to different ES index, and later deleted
		b.LoggerTemp.Println(string(bytesJson))
	} else {
		b.Logger.Println(string(bytesJson))
	}
}

func (b Banner) BanOrChallengeIp(
	config *Config,
	ip string,
	decision Decision,
) {
	log.Println("IPTABLES: BanOrChallengeIp", ip, decision)

	updateExpiringDecisionLists(
		config,
		ip,
		&(*b.DecisionListsMutex),
		&(*b.DecisionLists),
		time.Now(),
		decision,
		false, // not from baskerville
	)

	if decision == IptablesBlock {
		banIp(config, ip)
	}
}

func banIp(config *Config, ip string) {
	log.Println("IPTABLES: banIp with ipset", ip, "timeout", config.IptablesBanSeconds)
	if ip == "127.0.0.1" {
		log.Println("IPTABLES: Not going to block localhost")
		return
	}
	if config.StandaloneTesting {
		log.Println("IPTABLES: Not calling iptables in testing")
		return
	}
	if bannedByIPset(config, ip) {
		log.Println("IPTABLES: no double ban", ip)
		return
	}
	banErr := config.IPSetInstance.Add(ip, ipset.Timeout(time.Duration(config.IptablesBanSeconds)*time.Second))
	if banErr != nil {
		log.Printf("banjaxIPSet.Add() failed: %v", banErr)
	}
}

func bannedByIPset(config *Config, ip string) (banned bool) {
	banned, _ = config.IPSetInstance.Test(ip)
	return
}

// XXX
func BanIp(config *Config, ip string) {
	banIp(config, ip)
}
