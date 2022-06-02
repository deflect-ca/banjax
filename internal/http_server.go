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

	r.Use(gin.Recovery())

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

func accessGranted(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store")  // XXX think about caching
	c.Header("X-Accel-Redirect", "@access_granted") // nginx named location that proxy_passes to origin
	c.String(200, "access granted\n")
}

func accessDenied(c *gin.Context) {
	c.Header("Cache-Control", "no-cache,no-store") // XXX think about caching
	c.Header("X-Accel-Redirect", "@access_denied") // nginx named location that proxy_passes to origin
	c.String(403, "access denied\n")
}

func challenge(c *gin.Context, pageBytes *[]byte, cookieName string, cookieTtlSeconds int, secret string) {
	newCookie := NewChallengeCookie(secret, cookieTtlSeconds, c.Request.Header.Get("X-Client-IP"))
	log.Println("Serving new cookie: ", newCookie)
	c.SetCookie(cookieName, newCookie, cookieTtlSeconds, "/", c.Request.Header.Get("X-Requested-Host"), false, false)
	c.Header("Cache-Control", "no-cache,no-store")
	c.Data(401, "text/html", *pageBytes)
	c.Abort() // XXX is this still needed, or was it just for my old middleware approach?
}

func passwordChallenge(c *gin.Context, config *Config) {
	challenge(c, &config.PasswordPageBytes, "deflect_password2", config.PasswordCookieTtlSeconds, config.HmacSecret)
}

func shaInvChallenge(c *gin.Context, config *Config) {
	challenge(c, &config.ChallengerBytes, "deflect_challenge2", config.ShaInvCookieTtlSeconds, config.HmacSecret)
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
		// log.Println("IP has failed too many challenges; blocking them")
		banner.BanOrChallengeIp(config, ip, IptablesBlock)
		banner.LogFailedChallengeBan(
			ip,
			challengeType,
			host,
			path,
			config.TooManyFailedChallengesThreshold,
			userAgent,
			IptablesBlock,
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
			accessGranted(c)
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
		)
		sendOrValidateShaChallengeResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
		if tooManyFailedChallengesResult.TooManyFailedChallenges {
			ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
			accessDenied(c)
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
			accessGranted(c)
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
	)
	sendOrValidatePasswordResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
	// log.Println(tooManyFailedChallengesResult)
	if tooManyFailedChallengesResult.TooManyFailedChallenges {
		ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
		accessDenied(c)
		return sendOrValidatePasswordResult
	}
	passwordChallenge(c, config)
	return sendOrValidatePasswordResult
}

type DecisionListResult uint

const (
	_ DecisionListResult = iota
	PasswordProtectedPath
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
	NoMention
)

var DecisionListResultToString = map[DecisionListResult]string{
	PasswordProtectedPath: "PasswordProtectedPath",
	PerSiteAccessGranted:  "PerSiteAccessGranted",
	PerSiteChallenge:      "PerSiteChallenge",
	PerSiteBlock:          "PerSiteBlock",
	GlobalAccessGranted:   "GlobalAccessGranted",
	GlobalChallenge:       "GlobalChallenge",
	GlobalBlock:           "GlobalBlock",
	ExpiringAccessGranted: "ExpiringAccessGranted",
	ExpiringChallenge:     "ExpiringChallenge",
	ExpiringBlock:         "ExpiringBlock",
	SiteWideChallenge:     "SiteWideChallenge",
	NoMention:             "NoMention",
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
		bytes, err := json.MarshalIndent(decisionForNginxResult, "", "  ")
		if err != nil {
			log.Println("error marshalling decisionForNginxResult")
		} else {
			log.Println(string(bytes))
		}
	}
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
					)
					decisionForNginxResult.DecisionListResult = PasswordProtectedPath
					decisionForNginxResult.PasswordChallengeResult = &sendOrValidatePasswordResult.PasswordChallengeResult
					decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidatePasswordResult.TooManyFailedChallengesResult
					return
				}
			}
		}
	}

	// XXX ugh this locking is awful
	// i got bit by just checking against the zero value here, which is a valid iota enum
	decisionListsMutex.Lock()
	decision, ok := (*decisionLists).PerSiteDecisionLists[requestedHost][clientIp]
	decisionListsMutex.Unlock()
	if !ok {
		// log.Println("no mention in per-site lists")
	} else {
		switch decision {
		case Allow:
			accessGranted(c)
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
			)
			decisionForNginxResult.DecisionListResult = PerSiteChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c)
			// log.Println("block from per-site lists")
			decisionForNginxResult.DecisionListResult = PerSiteBlock
			return
		}
	}

	decisionListsMutex.Lock()
	decision, ok = (*decisionLists).GlobalDecisionLists[clientIp]
	decisionListsMutex.Unlock()
	if !ok {
		// log.Println("no mention in global lists")
	} else {
		switch decision {
		case Allow:
			accessGranted(c)
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
			)
			decisionForNginxResult.DecisionListResult = GlobalChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c)
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
			accessGranted(c)
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
			)
			decisionForNginxResult.DecisionListResult = ExpiringChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c)
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
		sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
			config,
			c,
			banner,
			rateLimitMutex,
			failedChallengeStates,
			failAction,
		)
		decisionForNginxResult.DecisionListResult = SiteWideChallenge
		decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
		decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
		return
	}

	// log.Println("no mention in any lists, access granted")
	accessGranted(c)
	decisionForNginxResult.DecisionListResult = NoMention
	return
}

func CleanRequestedPath(requestedPath string) string {
	path := "/" + strings.Trim(requestedPath, "/")
	path = strings.Split(path, "?")[0]
	return path
}
