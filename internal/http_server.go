// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func RunHttpServer(
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	rateLimitMutex *sync.Mutex,
	ipToRegexStates *IpToRegexStates,
	failedChallengeStates *FailedChallengeStates,
	banner BannerInterface,
	wg *sync.WaitGroup,
) {
	defer wg.Done()

	ginLogFileName := ""
	if config.StandaloneTesting {
		ginLogFileName = "gin.log"
	} else {
		ginLogFileName = config.GinLogFile
	}

	ginLogFile, _ := os.Create(ginLogFileName)
	gin.DefaultWriter = io.MultiWriter(ginLogFile)

	if !config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()

	type LogLine struct {
		Time          string
		ClientIp      string
		ClientReqHost string
		ClientReqPath string
		Method        string
		Path          string
		Status        int
		Latency       int
	}

	r.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		logLine := LogLine{
			Time:          param.TimeStamp.Format(time.RFC1123),
			ClientIp:      param.Request.Header.Get("X-Client-IP"),
			ClientReqHost: param.Request.Header.Get("X-Requested-Host"),
			ClientReqPath: param.Request.Header.Get("X-Requested-Path"),
			Method:        param.Method,
			Path:          param.Path,
			Status:        param.StatusCode,
			Latency:       int(param.Latency / time.Microsecond),
		}
		bytes, err := json.Marshal(logLine)
		if err != nil {
			log.Println("!!! failed to marshal log line !!!")
			return "{\"error\": \"bad\"}"
		}
		return string(bytes) + "\n" // XXX ?
	}))

	/*
		example panic:

		runtime error: invalid memory address or nil pointer dereference
		[3] /usr/local/go/src/runtime/panic.go:221 (0x44aca6)
			panicmem: panic(memoryError)
		[4] /usr/local/go/src/runtime/signal_unix.go:735 (0x44ac76)
			sigpanic: panicmem()
		[5] /go/pkg/mod/github.com/jeremy5189/ipfilter-no-iploc/v2@v2.0.3/ipfilter.go:154 (0x6e6f5b)
			(*IPFilter).NetAllowed: f.mut.RLock()
		[6] /go/pkg/mod/github.com/jeremy5189/ipfilter-no-iploc/v2@v2.0.3/ipfilter.go:143 (0x6e6ebb)
			(*IPFilter).Allowed: return f.NetAllowed(net.ParseIP(ipstr))
	*/
	r.Use(gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		// getting error message
		errStr := "get error failed in CustomRecovery"
		traceSkip := 3
		if err, ok := recovered.(error); ok {
			errStr = err.Error()
			// getting the 5th line of stack trace, usually the first 4 is not helping
			// in CustomRecovery, skip = 3, thats why we do 3 + 2 here
			traceSkip = 3 + 2
		} else if err, ok := recovered.(string); ok {
			// this way of getting error is required when raised by panic()
			errStr = err
		}

		// getting stack trace
		_, file, line, stackOk := runtime.Caller(traceSkip)
		if stackOk {
			c.Header("X-Banjax-Error", fmt.Sprintf("%v (%s:%d)", errStr, file, line))
		} else {
			c.Header("X-Banjax-Error", errStr)
		}

		// ensure banjax panic don't block client viewing sites
		c.Header("X-Accel-Redirect", "@fail_open")
		c.AbortWithStatus(500)
	}))

	if config.StandaloneTesting {
		log.Println("!!! standalone-testing mode enabled. adding some X- headers here")
		r.Use(addOurXHeadersForTesting)
		r.GET("favicon.ico", func(c *gin.Context) {
			c.String(200, "")
		})
		// XXX think about these options?
		logFile, err := os.OpenFile(config.ServerLogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic("failed to open ServerLogFile for writing in StandaloneTesting mode")
		}
		defer logFile.Close()

		// XXX This is to simulate log coming from nginx to test regex banner
		// nginx format '$msec $remote_addr $request_method $host $request $http_user_agent'
		// nginx log example:
		//   1653561078.839 127.0.0.1 POST example.com POST / HTTP/1.1 -
		// standalone log example:
		//   1653562803.000000 81.84.95.145 GET localhost:8081 GET / HTTP/1.1 Go-http-client/1.1
		r.Use(func(c *gin.Context) {
			_, err = io.WriteString(logFile, fmt.Sprintf("%f %s %s %s %s %s HTTP/1.1 %s\n",
				float64(time.Now().Unix()),
				c.Request.Header.Get("X-Client-IP"), // integration test gen IP in this field
				c.Request.Method,
				c.Request.Host,
				c.Request.Method,
				c.Query("path"),
				c.Request.Header.Get("User-Agent")))
			if err != nil {
				log.Printf("failed to write? %v\n", err)
			}
		})
	} else {
	}

	r.Any("/auth_request",
		decisionForNginx(
			config,
			decisionListsMutex,
			decisionLists,
			passwordProtectedPaths,
			rateLimitMutex,
			failedChallengeStates,
			banner,
		),
	)

	r.GET("/info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"config_version": config.ConfigVersion,
		})
	})

	r.GET("/decision_lists", func(c *gin.Context) {
		c.String(200,
			fmt.Sprintf("per_site:\n%v\n\nglobal:\n%v\n\nexpiring:\n%v",
				(*decisionLists).PerSiteDecisionLists,
				(*decisionLists).GlobalDecisionLists,
				(*decisionLists).ExpiringDecisionLists,
			),
		)
	})

	r.GET("/rate_limit_states", func(c *gin.Context) {
		rateLimitMutex.Lock()
		c.String(200,
			fmt.Sprintf("regexes:\n%v\nfailed challenges:\n%v",
				ipToRegexStates.String(),
				failedChallengeStates.String(),
			),
		)
		rateLimitMutex.Unlock()
	})

	r.Run("127.0.0.1:8081") // XXX config
}

// this adds the headers that Nginx usually would in production
func addOurXHeadersForTesting(c *gin.Context) {
	if c.Request.Header.Get("X-Client-IP") == "" {
		c.Request.Header.Set("X-Client-IP", c.ClientIP())
	}
	c.Request.Header.Set("X-Requested-Host", c.Request.Host)
	c.Request.Header.Set("X-Requested-Path", c.Query("path"))
	c.Request.Header.Set("X-Client-User-Agent", "mozilla")
	c.Next()
}

func accessGranted(c *gin.Context, decisionListResultString string) {
	c.Header("X-Banjax-Decision", decisionListResultString)
	c.Header("X-Accel-Redirect", "@access_granted") // nginx named location that proxy_passes to origin
	c.String(200, "access granted\n")
}

func accessDenied(c *gin.Context, decisionListResultString string) {
	c.Header("X-Banjax-Decision", decisionListResultString)
	c.Header("Cache-Control", "no-cache,no-store") // XXX think about caching
	c.Header("X-Accel-Redirect", "@access_denied") // nginx named location that gives a ban page
	c.String(403, "access denied\n")
}

func challenge(c *gin.Context, cookieName string, cookieTtlSeconds int, secret string) {
	newCookie := NewChallengeCookie(secret, cookieTtlSeconds, c.Request.Header.Get("X-Client-IP"))
	// log.Println("Serving new cookie: ", newCookie)
	// Update: Provide "" to domain so that the cookie is not set for subdomains
	c.SetCookie(cookieName, newCookie, cookieTtlSeconds, "/", "", false, false)
	c.Header("Cache-Control", "no-cache,no-store")
}

func passwordChallenge(c *gin.Context, config *Config) {
	challenge(c, "deflect_password2", config.PasswordCookieTtlSeconds, config.HmacSecret)
	// custom status code, not defined in RFC
	c.Data(401, "text/html", config.PasswordPageBytes)
	c.Abort()
}

func shaInvChallenge(c *gin.Context, config *Config) {
	challenge(c, "deflect_challenge2", config.ShaInvCookieTtlSeconds, config.HmacSecret)
	// custom status code, not defined in RFC
	c.Data(429, "text/html", config.ChallengerBytes)
	c.Abort()
}

type FailedChallengeRateLimitResult uint

const (
	_ FailedChallengeRateLimitResult = iota
	FirstFailure
	PreviousFailureBeforeInterval
	PreviousFailureWithinInterval
)

type TooManyFailedChallengesResult struct {
	FailedChallengeRateLimitResult FailedChallengeRateLimitResult
	TooManyFailedChallenges        bool
}

var FailedChallengeRateLimitResultToString = map[FailedChallengeRateLimitResult]string{
	FirstFailure:                  "FirstFailure",
	PreviousFailureBeforeInterval: "PreviousFailureBeforeInterval",
	PreviousFailureWithinInterval: "PreviousFailureWithinInterval",
}

func (fcr FailedChallengeRateLimitResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	if s, ok := FailedChallengeRateLimitResultToString[fcr]; ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("nil")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

// XXX this is very close to how the regex rate limits work
func tooManyFailedChallenges(
	config *Config,
	ip string,
	userAgent string,
	host string,
	path string,
	banner BannerInterface,
	challengeType string,
	rateLimitMutex *sync.Mutex,
	failedChallengeStates *FailedChallengeStates,
	method string,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) (tooManyFailedChallengesResult TooManyFailedChallengesResult) {
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	state, ok := (*failedChallengeStates)[ip]
	if !ok {
		// log.Println("IP hasn't failed a challenge before")
		tooManyFailedChallengesResult.FailedChallengeRateLimitResult = FirstFailure
		(*failedChallengeStates)[ip] = &NumHitsAndIntervalStart{1, now}
	} else {
		if now.Sub(state.IntervalStartTime) > time.Duration(time.Duration(config.TooManyFailedChallengesIntervalSeconds)*time.Second) {
			// log.Println("IP has failed a challenge, but longer ago than $interval")
			tooManyFailedChallengesResult.FailedChallengeRateLimitResult = PreviousFailureBeforeInterval
			(*failedChallengeStates)[ip] = &NumHitsAndIntervalStart{1, now}
		} else {
			// log.Println("IP has failed a challenge in this $interval")
			tooManyFailedChallengesResult.FailedChallengeRateLimitResult = PreviousFailureWithinInterval
			(*failedChallengeStates)[ip].NumHits++
		}
	}

	if (*failedChallengeStates)[ip].NumHits > config.TooManyFailedChallengesThreshold {
		foundInPerSiteList, decision := checkPerSiteDecisionLists(
			config,
			decisionListsMutex,
			decisionLists,
			host,
			ip,
		)

		var decisionType Decision = IptablesBlock
		if foundInPerSiteList && decision == Allow {
			log.Printf("!! IP %s has failed too many challenges on host %s but in allowlisted, no iptable ban", ip, host)
			decisionType = NginxBlock
		}
		// log.Println("IP has failed too many challenges; blocking them")
		banner.BanOrChallengeIp(config, ip, decisionType)
		banner.LogFailedChallengeBan(
			config,
			ip,
			challengeType,
			host,
			path,
			config.TooManyFailedChallengesThreshold,
			userAgent,
			decisionType,
			method,
		)
		(*failedChallengeStates)[ip].NumHits = 0 // XXX should it be 1?...
		tooManyFailedChallengesResult.TooManyFailedChallenges = true
		return tooManyFailedChallengesResult
	}

	tooManyFailedChallengesResult.TooManyFailedChallenges = false
	return tooManyFailedChallengesResult
}

type ShaChallengeResult uint

const (
	_ ShaChallengeResult = iota
	ShaChallengePassed
	ShaChallengeFailedNoCookie
	ShaChallengeFailedBadCookie
)

var ShaChallengeResultToString = map[ShaChallengeResult]string{
	ShaChallengePassed:          "ShaChallengePassed",
	ShaChallengeFailedNoCookie:  "ShaChallengeFailedNoCookie",
	ShaChallengeFailedBadCookie: "ShaChallengeFailedBadCookie",
}

func (scr ShaChallengeResult) String() string {
	if s, ok := ShaChallengeResultToString[scr]; ok {
		return s
	}
	return "Bad! unknown ShaChallengeResult"
}
func (scr ShaChallengeResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	if s, ok := ShaChallengeResultToString[scr]; ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("nil")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type SendOrValidateShaChallengeResult struct {
	ShaChallengeResult            ShaChallengeResult
	TooManyFailedChallengesResult TooManyFailedChallengesResult
}

func sendOrValidateShaChallenge(
	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitMutex *sync.Mutex,
	failedChallengeStates *FailedChallengeStates,
	failAction FailAction,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) (sendOrValidateShaChallengeResult SendOrValidateShaChallengeResult) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	challengeCookie, err := c.Cookie("deflect_challenge2")
	requestedMethod := c.Request.Method
	if err == nil {
		err := ValidateShaInvCookie(config.HmacSecret, challengeCookie, time.Now(), clientIp, 10) // XXX config
		if err != nil {
			// log.Println("Sha-inverse challenge failed")
			// log.Println(err)
			sendOrValidateShaChallengeResult.ShaChallengeResult = ShaChallengeFailedBadCookie
		} else {
			accessGranted(c, ShaChallengeResultToString[ShaChallengePassed])
			ReportPassedFailedBannedMessage(config, "ip_passed_challenge", clientIp, requestedHost)
			// log.Println("Sha-inverse challenge passed")
			sendOrValidateShaChallengeResult.ShaChallengeResult = ShaChallengePassed
			return sendOrValidateShaChallengeResult
		}
	} else {
		sendOrValidateShaChallengeResult.ShaChallengeResult = ShaChallengeFailedNoCookie
	}
	ReportPassedFailedBannedMessage(config, "ip_failed_challenge", clientIp, requestedHost)
	if failAction == Block {
		tooManyFailedChallengesResult := tooManyFailedChallenges(
			config,
			clientIp,
			clientUserAgent,
			requestedHost,
			requestedPath,
			banner,
			"sha_inv",
			rateLimitMutex,
			failedChallengeStates,
			requestedMethod,
			decisionListsMutex,
			decisionLists,
		)
		sendOrValidateShaChallengeResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
		if tooManyFailedChallengesResult.TooManyFailedChallenges {
			ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
			accessDenied(c, "TooManyFailedChallenges")
			return sendOrValidateShaChallengeResult
		}
	}
	shaInvChallenge(c, config)
	return sendOrValidateShaChallengeResult
}

type PasswordChallengeResult uint

const (
	_ PasswordChallengeResult = iota
	ErrorNoPassword
	PasswordChallengePassed
	PasswordChallengeFailedNoCookie
	PasswordChallengeFailedBadCookie
)

var PasswordChallengeResultToString = map[PasswordChallengeResult]string{
	ErrorNoPassword:                  "ErrorNoPassword",
	PasswordChallengePassed:          "PasswordChallengePassed",
	PasswordChallengeFailedNoCookie:  "PasswordChallengeFailedNoCookie",
	PasswordChallengeFailedBadCookie: "PasswordChallengeFailedBadCookie",
}

func (pcr PasswordChallengeResult) String() string {
	if s, ok := PasswordChallengeResultToString[pcr]; ok {
		return s
	}
	return "Bad! unknown PasswordChallengeResult"
}
func (pcr PasswordChallengeResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	if s, ok := PasswordChallengeResultToString[pcr]; ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("nil")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type SendOrValidatePasswordResult struct {
	PasswordChallengeResult       PasswordChallengeResult
	TooManyFailedChallengesResult TooManyFailedChallengesResult
}

// XXX does it make sense to have separate password auth cookies and sha-inv cookies?
// maybe someday, we'd like behavior like "never serve sha-inv to someone with an admin cookie"
func sendOrValidatePassword(
	config *Config,
	passwordProtectedPaths *PasswordProtectedPaths,
	c *gin.Context,
	banner BannerInterface,
	rateLimitMutex *sync.Mutex,
	failedChallengeStates *FailedChallengeStates,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
) (sendOrValidatePasswordResult SendOrValidatePasswordResult) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	passwordCookie, err := c.Cookie("deflect_password2")
	requestedMethod := c.Request.Method
	// log.Println("passwordCookie: ", passwordCookie)
	if err == nil {
		expectedHashedPassword, ok := passwordProtectedPaths.SiteToPasswordHash[requestedHost]
		if !ok {
			log.Println("!!!! BAD - missing password in config") // XXX fail open or closed?
			sendOrValidatePasswordResult.PasswordChallengeResult = ErrorNoPassword
			return sendOrValidatePasswordResult
		}
		// XXX maybe don't call this err?
		err := ValidatePasswordCookie(config.HmacSecret, passwordCookie, time.Now(), clientIp, expectedHashedPassword)
		if err != nil {
			// log.Println("Password challenge failed")
			// log.Println(err)
			sendOrValidatePasswordResult.PasswordChallengeResult = PasswordChallengeFailedBadCookie
		} else {
			accessGranted(c, PasswordChallengeResultToString[PasswordChallengePassed])
			ReportPassedFailedBannedMessage(config, "ip_passed_challenge", clientIp, requestedHost)
			// log.Println("Password challenge passed")
			sendOrValidatePasswordResult.PasswordChallengeResult = PasswordChallengePassed
			return sendOrValidatePasswordResult
		}
	} else {
		sendOrValidatePasswordResult.PasswordChallengeResult = PasswordChallengeFailedNoCookie
	}
	ReportPassedFailedBannedMessage(config, "ip_failed_challenge", clientIp, requestedHost)
	tooManyFailedChallengesResult := tooManyFailedChallenges(
		config,
		clientIp,
		clientUserAgent,
		requestedHost,
		requestedPath,
		banner,
		"password",
		rateLimitMutex,
		failedChallengeStates,
		requestedMethod,
		decisionListsMutex,
		decisionLists,
	)
	sendOrValidatePasswordResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
	// log.Println(tooManyFailedChallengesResult)
	if tooManyFailedChallengesResult.TooManyFailedChallenges {
		ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
		accessDenied(c, "TooManyFailedPassword")
		return sendOrValidatePasswordResult
	}
	passwordChallenge(c, config)
	return sendOrValidatePasswordResult
}

type DecisionListResult uint

const (
	_ DecisionListResult = iota
	PasswordProtectedPath
	PasswordProtectedPathException
	PerSiteAccessGranted
	PerSiteChallenge
	PerSiteBlock
	GlobalAccessGranted
	GlobalChallenge
	GlobalBlock
	ExpiringAccessGranted // XXX should this even exist?
	ExpiringChallenge
	ExpiringBlock
	SiteWideChallenge
	SiteWideChallengeException
	NoMention
	NotSet
)

var DecisionListResultToString = map[DecisionListResult]string{
	PasswordProtectedPath:          "PasswordProtectedPath",
	PasswordProtectedPathException: "PasswordProtectedPathException",
	PerSiteAccessGranted:           "PerSiteAccessGranted",
	PerSiteChallenge:               "PerSiteChallenge",
	PerSiteBlock:                   "PerSiteBlock",
	GlobalAccessGranted:            "GlobalAccessGranted",
	GlobalChallenge:                "GlobalChallenge",
	GlobalBlock:                    "GlobalBlock",
	ExpiringAccessGranted:          "ExpiringAccessGranted",
	ExpiringChallenge:              "ExpiringChallenge",
	ExpiringBlock:                  "ExpiringBlock",
	SiteWideChallenge:              "SiteWideChallenge",
	SiteWideChallengeException:     "SiteWideChallengeException",
	NoMention:                      "NoMention",
	NotSet:                         "NotSet",
}

func (dfnr DecisionListResult) String() string {
	if s, ok := DecisionListResultToString[dfnr]; ok {
		return s
	}
	return "unknown DecisionListResult"
}

func (dfnr DecisionListResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	buffer.WriteString(dfnr.String())
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type DecisionForNginxResult struct {
	ClientIp                      string
	RequestedHost                 string
	RequestedPath                 string
	DecisionListResult            DecisionListResult
	PasswordChallengeResult       *PasswordChallengeResult // these are pointers so they can be optionally nil
	ShaChallengeResult            *ShaChallengeResult
	TooManyFailedChallengesResult *TooManyFailedChallengesResult
}

func decisionForNginx(
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	rateLimitMutex *sync.Mutex,
	failedChallengeStates *FailedChallengeStates,
	banner BannerInterface,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		decisionForNginxResult := decisionForNginx2(
			c,
			config,
			decisionListsMutex,
			decisionLists,
			passwordProtectedPaths,
			rateLimitMutex,
			failedChallengeStates,
			banner,
		)
		if config.Debug || decisionForNginxResult.DecisionListResult != NoMention {
			bytes, err := json.MarshalIndent(decisionForNginxResult, "", "  ")
			if err != nil {
				log.Println("error marshalling decisionForNginxResult")
			} else {
				log.Println("decisionForNginx:", string(bytes))
			}
		}
	}
}

func checkPerSiteDecisionLists(
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	requestedHost string,
	clientIp string,
) (bool, Decision) {
	// XXX ugh this locking is awful
	// i got bit by just checking against the zero value here, which is a valid iota enum
	decisionListsMutex.Lock()
	decision, ok := (*decisionLists).PerSiteDecisionLists[requestedHost][clientIp]
	decisionListsMutex.Unlock()

	// found as plain IP form, no need to check IPFilter
	if ok {
		return ok, decision
	}

	foundInIpPerSiteFilter := false

	// PerSiteDecisionListsIPFilter has different struct as PerSiteDecisionLists
	// decision must iterate in order, once found in one of the list, break the loop
	for _, iterateDecision := range []Decision{Allow, Challenge, NginxBlock, IptablesBlock} {
		if instanceIPFilter, ok := (*decisionLists).PerSiteDecisionListsIPFilter[requestedHost][iterateDecision]; ok && instanceIPFilter != nil {
			if instanceIPFilter.Allowed(clientIp) {
				if config.Debug {
					log.Printf("matched in per-site ipfilter %s %v %s", requestedHost, iterateDecision, clientIp)
				}
				decision = iterateDecision
				foundInIpPerSiteFilter = true
				break
			}
		}
	}

	return foundInIpPerSiteFilter, decision
}

func decisionForNginx2(
	c *gin.Context,
	config *Config,
	decisionListsMutex *sync.Mutex,
	decisionLists *DecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	rateLimitMutex *sync.Mutex,
	failedChallengeStates *FailedChallengeStates,
	banner BannerInterface,
) (decisionForNginxResult DecisionForNginxResult) {
	// XXX duplication
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	requestedProtectedPath := CleanRequestedPath(requestedPath)

	// log.Println("clientIp: ", clientIp, " requestedHost: ", requestedHost, " requestedPath: ", requestedPath)
	// log.Println("headers: ", c.Request.Header)
	decisionForNginxResult.ClientIp = clientIp
	decisionForNginxResult.RequestedHost = requestedHost
	decisionForNginxResult.RequestedPath = requestedPath
	decisionForNginxResult.DecisionListResult = NotSet

	pathToBools, ok := passwordProtectedPaths.SiteToPathToBool[requestedHost]
	if ok {
		exceptions, hasExceptions := passwordProtectedPaths.SiteToExceptionToBool[requestedHost]
		if !hasExceptions || !exceptions[requestedProtectedPath] {
			for protectedPath, boolFlag := range pathToBools {
				if boolFlag && strings.HasPrefix(requestedProtectedPath, protectedPath) {
					sendOrValidatePasswordResult := sendOrValidatePassword(
						config,
						passwordProtectedPaths,
						c,
						banner,
						rateLimitMutex,
						failedChallengeStates,
						decisionListsMutex,
						decisionLists,
					)
					decisionForNginxResult.DecisionListResult = PasswordProtectedPath
					decisionForNginxResult.PasswordChallengeResult = &sendOrValidatePasswordResult.PasswordChallengeResult
					decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidatePasswordResult.TooManyFailedChallengesResult
					return
				}
			}
		} else {
			decisionForNginxResult.DecisionListResult = PasswordProtectedPathException
		}
	}

	foundInPerSiteList, decision := checkPerSiteDecisionLists(
		config,
		decisionListsMutex,
		decisionLists,
		requestedHost,
		clientIp,
	)

	if foundInPerSiteList {
		switch decision {
		case Allow:
			accessGranted(c, DecisionListResultToString[PerSiteAccessGranted])
			// log.Println("access granted from per-site lists")
			decisionForNginxResult.DecisionListResult = PerSiteAccessGranted
			return
		case Challenge:
			// log.Println("challenge from per-site lists")
			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				rateLimitMutex,
				failedChallengeStates,
				Block, // FailAction
				decisionListsMutex,
				decisionLists,
			)
			decisionForNginxResult.DecisionListResult = PerSiteChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c, DecisionListResultToString[PerSiteBlock])
			// log.Println("block from per-site lists")
			decisionForNginxResult.DecisionListResult = PerSiteBlock
			return
		}
	}

	decisionListsMutex.Lock()
	decision, ok = (*decisionLists).GlobalDecisionLists[clientIp]
	decisionListsMutex.Unlock()
	foundInIpFilter := false
	if !ok {
		for _, iterateDecision := range []Decision{Allow, Challenge, NginxBlock, IptablesBlock} {
			// check if Ipfilter ref associated to this iterateDecision exists
			if _, globalOk := (*decisionLists).GlobalDecisionListsIPFilter[iterateDecision]; globalOk {
				if (*decisionLists).GlobalDecisionListsIPFilter[iterateDecision].Allowed(clientIp) {
					if config.Debug {
						log.Printf("matched in ipfilter %v %s", iterateDecision, clientIp)
					}
					decision = iterateDecision
					foundInIpFilter = true
					break
				}
			}
		}
	}
	if ok || foundInIpFilter {
		switch decision {
		case Allow:
			accessGranted(c, DecisionListResultToString[GlobalAccessGranted])
			// log.Println("access granted from global lists")
			decisionForNginxResult.DecisionListResult = GlobalAccessGranted
			return
		case Challenge:
			// log.Println("challenge from global lists")
			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				rateLimitMutex,
				failedChallengeStates,
				Block, // FailAction
				decisionListsMutex,
				decisionLists,
			)
			decisionForNginxResult.DecisionListResult = GlobalChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c, DecisionListResultToString[GlobalBlock])
			// log.Println("access denied from global lists")
			decisionForNginxResult.DecisionListResult = GlobalBlock
			return
		}
	}

	// i think this needs to point to a struct {decision: Decision, expires: Time}.
	// when we insert something into the list, really we might just be extending the expiry time and/or
	// changing the decision.
	// XXX i forget if that comment is stale^
	decisionListsMutex.Lock()
	decision, ok = checkExpiringDecisionLists(clientIp, decisionLists)
	decisionListsMutex.Unlock()
	if !ok {
		// log.Println("no mention in expiring lists")
	} else {
		switch decision {
		case Allow:
			accessGranted(c, DecisionListResultToString[ExpiringAccessGranted])
			// log.Println("access granted from expiring lists")
			decisionForNginxResult.DecisionListResult = ExpiringAccessGranted
			return
		case Challenge:
			// log.Println("challenge from expiring lists")
			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				rateLimitMutex,
				failedChallengeStates,
				Block, // FailAction
				decisionListsMutex,
				decisionLists,
			)
			decisionForNginxResult.DecisionListResult = ExpiringChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c, DecisionListResultToString[ExpiringBlock])
			// log.Println("access denied from expiring lists")
			decisionForNginxResult.DecisionListResult = ExpiringBlock
			return
		}
	}

	// the legacy banjax_sha_inv and user_banjax_sha_inv
	// difference is one blocks after many failures and the other doesn't
	decisionListsMutex.Lock()
	failAction, ok := (*decisionLists).SitewideShaInvList[requestedHost]
	decisionListsMutex.Unlock()
	if !ok {
		// log.Println("no mention in sitewide list")
	} else {
		// log.Println("challenge from sitewide list")
		// Reuse the exception from password prot for site-wide sha inv exceptions path
		exceptions, hasExceptions := passwordProtectedPaths.SiteToExceptionToBool[requestedHost]
		if !hasExceptions || !exceptions[requestedProtectedPath] {
			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				rateLimitMutex,
				failedChallengeStates,
				failAction,
				decisionListsMutex,
				decisionLists,
			)
			decisionForNginxResult.DecisionListResult = SiteWideChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		} else {
			decisionForNginxResult.DecisionListResult = SiteWideChallengeException
		}
	}

	// log.Println("no mention in any lists, access granted")
	if decisionForNginxResult.DecisionListResult == NotSet {
		decisionForNginxResult.DecisionListResult = NoMention
	}
	accessGranted(c, DecisionListResultToString[decisionForNginxResult.DecisionListResult])
	return
}

func CleanRequestedPath(requestedPath string) string {
	path := "/" + strings.Trim(requestedPath, "/")
	path = strings.Split(path, "?")[0]
	return path
}
