// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"

	puzzleCAPTCHA "github.com/deflect-ca/banjax/internal/puzzle-util"
)

const (
	PasswordCookieName        = "deflect_password3"
	ChallengeCookieName       = "deflect_challenge3"
	PuzzleChallengeCookieName = "deflect_challenge4"
)

const (
	CaptchaGeneratorKey = "CaptchaGenerator"
	CaptchaVerifierKey  = "CaptchaVerifier"
)

var USE_PUZZLE_CHALLENGE = true

func RunHttpServer(
	ctx context.Context,
	configHolder *ConfigHolder,
	staticDecisionLists *StaticDecisionLists,
	dynamicDecisionLists *DynamicDecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	regexStates *RegexRateLimitStates,
	failedChallengeStates *FailedChallengeRateLimitStates,
	banner BannerInterface,

	CaptchaGenerator *puzzleCAPTCHA.CAPTCHAGenerator,
	CaptchaVerifier *puzzleCAPTCHA.CAPTCHAVerifier,

) {
	addr := "127.0.0.1:8081" // XXX config

	config := configHolder.Get()

	ginLogFileName := ""
	if config.StandaloneTesting {
		ginLogFileName = "gin.log"
	} else {
		ginLogFileName = config.GinLogFile
	}

	if ginLogFileName != "" && ginLogFileName != "-" {
		if ginLogFile, err := os.Create(ginLogFileName); err == nil {
			gin.DefaultWriter = ginLogFile
		}
	}

	if !config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(captchaMiddleware(CaptchaGenerator, CaptchaVerifier))

	if ginLogFileName != "" {
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
	}

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
			log.Panic("failed to open ServerLogFile for writing in StandaloneTesting mode: ", err)
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
	}

	r.Any("/auth_request",
		decisionForNginx(
			configHolder,
			staticDecisionLists,
			dynamicDecisionLists,
			passwordProtectedPaths,
			failedChallengeStates,
			banner,
		),
	)

	//when users click the "refresh" button, to get a new puzzle state (not the entire challenge with index.html and embedded js just the puzzle itself)
	//the request will be handled by this endpoint. NOTE this is different from challenge issuance which still goes through the decisionForNginx endpoint
	r.GET("/refresh_puzzle_state", func(c *gin.Context) {
		handleRefreshPuzzleCAPTCHAState(
			config,
			c,
			banner,
			failedChallengeStates,
			Block, //fail action is a constant
			staticDecisionLists,
		)
	})

	//when users submit their solutions, we receive them on this endpoint
	r.POST("/validate_puzzle_solution", func(c *gin.Context) {
		handleVerifyPuzzleCAPTCHAState(
			config,
			c,
			banner,
			failedChallengeStates,
			Block, //fail action is a constant
			staticDecisionLists,
		)
	})

	//any non critical errors that do not break gameplay will be reported here by the entrypoint client side script with payloads
	//such that we create recreate the environment that gave rise to them
	r.POST("/__banjax/error/:errorType", func(c *gin.Context) {

		errorType := c.Param("errorType")
		log.Printf("Received error report: %s", errorType)

		handleLoggingPuzzleCAPTCHAErrorReport(
			config,
			c,
			banner,
			failedChallengeStates,
			Block, //fail action is a constant
			staticDecisionLists,
		)
	})

	r.GET("/info", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"config_version": configHolder.Get().ConfigVersion,
		})
	})

	r.GET("/decision_lists", func(c *gin.Context) {
		c.String(200, FormatDecisionLists(staticDecisionLists, dynamicDecisionLists))
	})

	r.GET("/rate_limit_states", func(c *gin.Context) {
		c.String(
			200,
			"regexes:\n%v\nfailed challenges:\n%v\n",
			regexStates,
			failedChallengeStates,
		)
	})

	// API to check if given IP was banned by iptables
	r.GET("/is_banned", func(c *gin.Context) {
		ip := c.Query("ip")
		if ip == "" {
			// return in json
			c.JSON(400, gin.H{
				"error": "ip query param is required",
			})
			return
		}
		banned, _ := banner.IPSetList()
		expiringDecision, ok := checkExpiringDecisionLists(c, ip, dynamicDecisionLists)
		if !ok {
			// not found in expiring list, but maybe still banned at ipset level
			c.JSON(200, gin.H{
				"ip":               ip,
				"banned":           banned,
				"expiringDecision": nil,
			})
			return
		}
		c.JSON(200, gin.H{
			"ip":               ip,
			"banned":           banned,
			"expiringDecision": expiringDecision,
		})
	})

	// API to list all banned IPs (internal use, not exposed to nginx)
	r.GET("/ipset/list", func(c *gin.Context) {
		ips, err := banner.IPSetList()
		if err != nil {
			c.JSON(500, gin.H{
				"error": err.Error(),
			})
			return
		}
		// Format will be:
		//   [172.19.0.1 timeout 298]
		c.JSON(200, gin.H{
			"entries": ips.Entries,
		})
	})

	// API to list expiring list and filter by domain
	r.GET("/banned", func(c *gin.Context) {
		domain := c.Query("domain")
		if domain == "" {
			// return in json
			c.JSON(400, gin.H{
				"error": "domain query param is required",
			})
			return
		}
		// search in decisionlist
		c.JSON(200, gin.H{
			"domain":  domain,
			"entries": dynamicDecisionLists.CheckByDomain(domain),
		})
	})

	// API to unban an IP
	r.POST("/unban", func(c *gin.Context) {
		config := configHolder.Get()

		// get ip from post data
		ip := strings.TrimSpace(c.PostForm("ip"))
		if ip == "" {
			// return in json
			c.JSON(400, gin.H{
				"error": "ip in post form is required",
			})
			return
		}
		// query decision list, check ban type
		decision, ok := checkExpiringDecisionLists(c, ip, dynamicDecisionLists)
		if !ok || decision.Decision == IptablesBlock {
			// not found in expiring list, but maybe still banned at ipset level
			if !banner.IPSetTest(config, ip) {
				c.JSON(400, gin.H{
					"ip":                     ip,
					"found_in_decision_list": ok,
					"decision":               decision.Decision.String(),
					"unban":                  false,
					"error":                  "ip is not banned",
				})
				return
			}
			// attempt to remove from ipset
			err := banner.IPSetDel(ip)
			if err != nil {
				c.JSON(500, gin.H{
					"ip":                     ip,
					"found_in_decision_list": ok,
					"decision":               decision.Decision.String(),
					"unban":                  false,
					"error":                  err.Error(),
				})
				return
			}
		}
		// if found, remove from expiring list, whether its nginx or iptables ban
		if ok {
			dynamicDecisionLists.RemoveByIp(ip)
		}
		c.JSON(200, gin.H{
			"ip":                     ip,
			"found_in_decision_list": ok,
			"decision":               decision.Decision.String(),
			"unban":                  true,
		})
	})

	if config.Profile {
		pprof.Register(r)
		runtime.SetMutexProfileFraction(1)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: r,
	}
	defer server.Close()

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http server failed: %v\n", err)
		}
	}()

	<-ctx.Done()
}

func captchaMiddleware(

	captchaGeneratorPtr *puzzleCAPTCHA.CAPTCHAGenerator,
	captchaVerifierPtr *puzzleCAPTCHA.CAPTCHAVerifier,

) gin.HandlerFunc {

	return func(c *gin.Context) {
		c.Set(CaptchaGeneratorKey, captchaGeneratorPtr)
		c.Set(CaptchaVerifierKey, captchaVerifierPtr)
		c.Next()
	}
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

func accessGranted(c *gin.Context, config *Config, decisionListResultString string) {
	c.Header("X-Banjax-Decision", decisionListResultString)
	c.Header("X-Accel-Redirect", "@access_granted") // nginx named location that proxy_passes to origin
	sessionCookieEndPoint(c, config)
	c.String(200, "access granted\n")
}

func accessDenied(c *gin.Context, config *Config, decisionListResultString string) {
	c.Header("X-Banjax-Decision", decisionListResultString)
	c.Header("Cache-Control", "no-cache,no-store") // XXX think about caching
	c.Header("X-Accel-Redirect", "@access_denied") // nginx named location that gives a ban page
	sessionCookieEndPoint(c, config)
	c.String(403, "access denied\n")
}

func accessThrottled(c *gin.Context, config *Config, decisionListResultString string, throttleDurationSeconds int) {
	msg := fmt.Sprintf("Too many failed attempts. Try again in %d seconds.", throttleDurationSeconds)

	c.Header("X-Banjax-Decision", decisionListResultString)
	c.Header("Cache-Control", "no-cache,no-store")    // XXX think about caching
	c.Header("X-Accel-Redirect", "@access_throttled") // nginx named location that gives a ban page
	c.Header("X-Throttle-Message", msg)               //msg to display
	sessionCookieEndPoint(c, config)
	c.String(403, msg)
}

func challenge(
	c *gin.Context,
	config *Config,
	cookieName string,
	cookieTtlSeconds int,
	secret string,
	setDomainScope bool) {
	newCookie := NewChallengeCookie(secret, cookieTtlSeconds, getUserAgentOrIp(c, config))
	// log.Println("Serving new cookie: ", newCookie)
	domainScope := "" // Provide "" to domain so that the cookie is not set for subdomains, EX: example.com
	if setDomainScope {
		// Provide the domain so that the cookie is set for subdomains, EX: .example.com
		domainScope = c.Request.Header.Get("X-Requested-Host")
	}
	c.SetCookie(cookieName, newCookie, cookieTtlSeconds, "/", domainScope, false, false)
	c.Header("Cache-Control", "no-cache,no-store")
}

func getUserAgentOrIp(c *gin.Context, config *Config) string {
	// Get binding either from IP or User-Agent base on config
	_, ok := config.SitesToUseUserAgentInCookie[c.Request.Header.Get("X-Requested-Host")]
	if ok {
		return c.Request.Header.Get("X-Client-User-Agent")
	}
	return c.Request.Header.Get("X-Client-IP")
}

func passwordChallenge(c *gin.Context, config *Config, roaming bool) {
	cookieTtl := getPerSiteCookieTtlOrDefault(config, c.Request.Header.Get("X-Requested-Host"), config.PasswordCookieTtlSeconds)
	challenge(c, config, PasswordCookieName, cookieTtl, config.HmacSecret, roaming)
	sessionCookieEndPoint(c, config)
	c.Data(401, "text/html", applyArgsToPasswordPage(config.PasswordPageBytes, roaming, cookieTtl))
	c.Abort()
}

func shaInvChallenge(c *gin.Context, config *Config) {
	challenge(c, config, ChallengeCookieName, config.ShaInvCookieTtlSeconds, config.HmacSecret, false)
	sessionCookieEndPoint(c, config)
	c.Data(429, "text/html", applyArgsToShaInvPage(config))
	c.Abort()
}

func getPerSiteCookieTtlOrDefault(config *Config, domain string, defaultTtl int) (cookieTtl int) {
	cookieTtl, ok := config.SitesToPasswordCookieTtlSeconds[domain]
	if ok {
		return
	}
	return defaultTtl
}

func modifyHTMLContent(pageBytes []byte, targetStr string, toReplace string) (modifiedPageBytes []byte) {
	return bytes.Replace(pageBytes, []byte(targetStr), []byte(toReplace), 1)
}

func applyCookieMaxAge(pageBytes []byte, cookieName string, ttlSeconds int) (modifiedPageBytes []byte) {
	/*
		Replace hardcoded JS code to control cookie conditions
		Target: document.cookie = "<cookieName>=" + base64_cookie + ";SameSite=Lax;path=/;";
	*/
	return modifyHTMLContent(
		pageBytes,
		fmt.Sprintf("\"%s=\" + base64_cookie", cookieName),
		fmt.Sprintf("\"%s=\" + base64_cookie + \";max-age=%d\"", cookieName, ttlSeconds),
	)
}

func applyCookieDomain(pageBytes []byte, cookieName string) (modifiedPageBytes []byte) {
	/*
		Replace hardcoded JS code to control cookie conditions
		Target: document.cookie = "<cookieName>=" + base64_cookie + ";SameSite=Lax;path=/;";
	*/
	return modifyHTMLContent(
		pageBytes,
		fmt.Sprintf("\"%s=\" + base64_cookie", cookieName),
		fmt.Sprintf("\"%s=\" + base64_cookie + \";domain=\" + window.location.hostname", cookieName),
	)
}

func applyArgsToPasswordPage(pageBytes []byte, roaming bool, cookieTtl int) (modifiedPageBytes []byte) {
	// apply default or site specific expire time
	modifiedPageBytes = applyCookieMaxAge(pageBytes, PasswordCookieName, cookieTtl)

	if !roaming {
		return
	}

	// apply domain scope if allow banjax roaming
	modifiedPageBytes = applyCookieDomain(modifiedPageBytes, PasswordCookieName)
	return
}

func applyArgsToShaInvPage(config *Config) (modifiedPageBytes []byte) {
	modifiedPageBytes = applyCookieMaxAge(
		config.ChallengerBytes,
		ChallengeCookieName,
		config.ShaInvCookieTtlSeconds,
	)
	modifiedPageBytes = modifyHTMLContent(
		modifiedPageBytes,
		"new_solver(10)",
		fmt.Sprintf("new_solver(%d)", config.ShaInvExpectedZeroBits),
	)
	return
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
	rateLimitStates *FailedChallengeRateLimitStates,
	method string,
	decisionLists *StaticDecisionLists,
) RateLimitResult {
	result := rateLimitStates.Apply(ip, config)

	if result.Exceeded {
		decision, foundInPerSiteList := decisionLists.CheckPerSite(config, host, ip)

		decisionType := IptablesBlock
		if foundInPerSiteList && decision == Allow {
			log.Printf("!! IP %s has failed too many challenges on host %s but in allowlisted, no iptable ban", ip, host)
			decisionType = NginxBlock
		}

		// log.Println("IP has failed too many challenges; blocking them")
		banner.BanOrChallengeIp(config, ip, decisionType, host)

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
	}

	return result
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
	TooManyFailedChallengesResult RateLimitResult
}

func sendOrValidateShaChallenge(
	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,
) (sendOrValidateShaChallengeResult SendOrValidateShaChallengeResult) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	challengeCookie, err := c.Cookie(ChallengeCookieName)
	requestedMethod := c.Request.Method
	if err == nil {
		err := ValidateShaInvCookie(config.HmacSecret, challengeCookie, time.Now(), getUserAgentOrIp(c, config), config.ShaInvExpectedZeroBits)
		if err != nil {
			// log.Println("Sha-inverse challenge failed")
			// log.Println(err)
			sendOrValidateShaChallengeResult.ShaChallengeResult = ShaChallengeFailedBadCookie
		} else {
			accessGranted(c, config, ShaChallengeResultToString[ShaChallengePassed])
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
			rateLimitStates,
			requestedMethod,
			decisionLists,
		)
		sendOrValidateShaChallengeResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
		if tooManyFailedChallengesResult.Exceeded {
			ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
			accessDenied(c, config, "TooManyFailedChallenges")
			return sendOrValidateShaChallengeResult
		}
	}
	log.Println("issuing the shaInvChallenge here")
	shaInvChallenge(c, config)
	return sendOrValidateShaChallengeResult
}

type PuzzleCAPTCHAResult uint

const (
	_ PuzzleCAPTCHAResult = iota
	PuzzleCAPTCHAPass
	PuzzleCAPTCHAFailNoCookie
	PuzzleCAPTCHAFailBadCookie
	PuzzleCAPTCHAFailIntegrityCheck         //detected tampering
	PuzzleCAPTCHAFailPuzzleGeneration       //failed to generate new puzzle
	PuzzleCAPTCHAFailMissingDependency      //missing generator | validator pointer
	PuzzleCAPTCHAFailIncorrectSolution      //solution to puzzle is not correct
	PuzzleCAPTCHAFailMissingSolutionBody    //solution was not sent
	PuzzleCAPTCHAFailMissingDesiredEndpoint //missing user desired endpoint
)

var PuzzleCAPTCHAResultToString = map[PuzzleCAPTCHAResult]string{
	PuzzleCAPTCHAPass:                       "PuzzleCAPTCHAPass",
	PuzzleCAPTCHAFailNoCookie:               "PuzzleCAPTCHAFailNoCookie",
	PuzzleCAPTCHAFailBadCookie:              "PuzzleCAPTCHAFailBadCookie",
	PuzzleCAPTCHAFailIntegrityCheck:         "PuzzleCAPTCHAFailIntegrityCheck",
	PuzzleCAPTCHAFailPuzzleGeneration:       "PuzzleCAPTCHAFailPuzzleGeneration",
	PuzzleCAPTCHAFailMissingDependency:      "PuzzleCAPTCHAFailMissingDependency",
	PuzzleCAPTCHAFailIncorrectSolution:      "PuzzleCAPTCHAFailIncorrectSolution",
	PuzzleCAPTCHAFailMissingSolutionBody:    "PuzzleCAPTCHAFailMissingSolutionBody",
	PuzzleCAPTCHAFailMissingDesiredEndpoint: "PuzzleCAPTCHAFailMissingDesiredEndpoint",
}

func (pcr PuzzleCAPTCHAResult) String() string {
	s, ok := PuzzleCAPTCHAResultToString[pcr]
	if ok {
		return s
	}
	return "Bad! unknown PuzzleCAPTCHAResult"
}
func (pcr PuzzleCAPTCHAResult) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString(`"`)
	s, ok := PuzzleCAPTCHAResultToString[pcr]
	if ok {
		buffer.WriteString(s)
	} else {
		buffer.WriteString("nil")
	}
	buffer.WriteString(`"`)
	return buffer.Bytes(), nil
}

type SendOrValidatePuzzleCAPTCHAResult struct {
	PuzzleCaptchaResult           PuzzleCAPTCHAResult
	TooManyFailedChallengesResult RateLimitResult
}

/*
issuePuzzleCAPTCHA sends the index.html (which has also had the css and js bundle injected into it at build) and
subsequently injects the initial puzzle state such that there are no follow up requests.

This issuePuzzleCAPTCHA function is very different from the newPuzzleChallenge handler as it serves the entire challenge
including the index.html, css and js whereas the handleNewPuzzleChallenge will ONLY generate the actual puzzle itself
(ie the state of the challenge).
*/
func sendPuzzleCAPTCHA(

	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,

) SendOrValidatePuzzleCAPTCHAResult {

	var sendOrValidatePuzzleCAPTCHAResult SendOrValidatePuzzleCAPTCHAResult

	filePath := "./puzzle_ui/dist/index.html"
	htmlContent, err := os.ReadFile(filePath)
	if err != nil {
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDependency
		return sendOrValidatePuzzleCAPTCHAResult
	}

	puzzleGeneratorInterface, exists := c.Get(CaptchaGeneratorKey)
	if !exists {
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDependency
		return sendOrValidatePuzzleCAPTCHAResult
	}

	puzzleGenerator := puzzleGeneratorInterface.(*puzzleCAPTCHA.CAPTCHAGenerator)

	challengeCookieValue, err := c.Cookie(PuzzleChallengeCookieName)
	if err == nil {
		// If cookie exists, remove the previous solution from cache then reissue challenge
		//this happens if the user clicks on "request new puzzle" or refreshes on their own (assuming we determine to challenges again)
		puzzleGenerator.SolutionCache.Delete(challengeCookieValue)
	}

	cookieExpiryMS := 600_000 //a default expiry 10 minutes
	targetDifficultyProfile, exists := puzzleGenerator.DifficultyConfigController.GetTargetProfile()
	if exists {
		cookieExpiryMS = targetDifficultyProfile.TimeToSolveMs
	}

	userChallengeCookieValue := NewChallengeCookie(config.HmacSecret, cookieExpiryMS, getUserAgentOrIp(c, config))

	b64PngImage := puzzleCAPTCHA.LoadDefaultImageBase64()

	//captcha challenger and client side expect a "userDesiredEndpoint" that is parsable as a URL
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	sanitizedPath := strings.TrimPrefix(requestedPath, "/")
	userDesiredEndpoint := fmt.Sprintf("https://%s/%s", requestedHost, sanitizedPath)

	targetDifficulty := puzzleGenerator.DifficultyConfigController.Target
	newCaptcha, err := puzzleGenerator.NewCAPTCHAChallenge(userChallengeCookieValue, userDesiredEndpoint, b64PngImage, targetDifficulty)
	if err != nil {
		log.Printf("Error generating CAPTCHA: %v", err)
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailPuzzleGeneration
		return sendOrValidatePuzzleCAPTCHAResult
	}

	serializedGameState, err := json.Marshal(newCaptcha)
	if err != nil {
		log.Printf("Error marshalling CAPTCHA: %v", err)
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailPuzzleGeneration
		return sendOrValidatePuzzleCAPTCHAResult
	}

	var escapedGameState bytes.Buffer
	json.HTMLEscape(&escapedGameState, serializedGameState)
	scriptTag := fmt.Sprintf(`<script id="initial-game-state" type="application/json">%s</script>`, escapedGameState.String())

	modifiedHTML := strings.Replace(
		string(htmlContent),
		"<!-- INITIAL_STATE_PLACEHOLDER: this will be replaced by the initial state containing script when serving the CAPTCHA -->",
		scriptTag,
		1, //replace only the first occurrence
	)

	c.SetCookie(PuzzleChallengeCookieName, userChallengeCookieValue, cookieExpiryMS/1000, "/", "", true, false)
	c.Header("Content-Type", "text/html")
	c.String(http.StatusTooManyRequests, modifiedHTML)
	return sendOrValidatePuzzleCAPTCHAResult
}

/*
handlePuzzleCAPTCHAErrorReport handles any error we receive based on the endpoint as well as
the rateLimitStates.

Error reports are generated by the client side when it detects an inability to attach one (or more) of the
event listeners required. Most errors are non critical and the puzzle will be able to continue to function
the only errors that matter are sent to critical error endpoint which can be handled accordingly. The rest
are mostly to give us the capability to getting info about their environment and be able to recreate the issue
to improve the puzzle later.

For now it will log the error, but later we can take into consideration the other options we have
*/
func handleLoggingPuzzleCAPTCHAErrorReport(

	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,

) SendOrValidatePuzzleCAPTCHAResult {

	var sendOrValidatePuzzleCAPTCHAResult SendOrValidatePuzzleCAPTCHAResult

	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	challengeCookie, err := c.Cookie(PuzzleChallengeCookieName)
	if err != nil {
		log.Println("Err looking up challenge cookie: ", err)
	}
	requestedMethod := c.Request.Method

	log.Printf("\nERROR: %s", requestedPath)
	log.Println("IP Address: ", clientIp)
	log.Println("Host: ", requestedHost)
	log.Println("User Agent: ", clientUserAgent)
	log.Println("Challenge Cookie: ", challengeCookie)
	log.Println("Method: ", requestedMethod)

	sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDependency

	// handleSendPuzzleChallenge(config, c, banner, rateLimitStates, failAction, decisionLists)
	return sendOrValidatePuzzleCAPTCHAResult
}

/*
handleRefreshPuzzleCAPTCHAState generates a new CAPTCHA challenge for the client. This is only used
when the user clicks on the new challenge button as it doesnt require anything other than the challenge payload itself

the issueCAPTCHAPuzzle handles injecting the initial puzzle state and sending it off in one request so there are no subsequent
requests that are necessary as all css and js are also bundled with the index.html

Workflow:
1. Checks if the user already has a challenge cookie. If so, deletes the previous solution from cache
2. Generates a new challenge cookie uniquely tied to the user
3. Loads a base64 PNG image / company logo (or other by lookup TODO)
4. Determines challenge difficulty (default or dynamically adjusted TODO)
5. Generates a new CAPTCHA challenge and returns it as JSON
6. Sets a new challenge cookie for tracking

Responses:
- 200: Successfully issued a challenge
- 500: Failed to generate a challenge

NOTE1: For now it will always just issue a challenge, but we can implement the rate limiting logic like sending back the dedicated
response codes to show the user that they are being rate limited and to wait before trying again - (this is built into the UI as based
based on response codes)

--

Why do we lookup the userDesiredEndpoint from the previous attempts solution cache when responding to a request for a new puzzle state?

Because of how deflect works, when a user currently has a challenge and clicks on refresh button
to get a new puzzle, the request is sent to this /new_challenge endpoint which generates only the
captcha puzzle state itself. Unlike the issueCaptchaChallenge endpoint, here we do not inject
the state into the index.html and respond, instead we are only send back the state.

The problem is that deflect doesn't remember what endpoint they were actually trying to visit, instead you see that
the RequestedPath is /new_puzzle_challenge. This is a problem because the UserDesiredEndpoint is one of the
key properties we are integrity checking to detect tampering. To get around this, since we already have a cache storing
solutions, I added the UserDesiredEndpoint to the payload being cached. The upside is we need not change the entire
integrity checking or weaken it to just integrity checking the hostname. The downside is that the cache entry gets purged
automatically as soon as the user runs of of time as specified in the difficulty configuration. This means that if the user
tries to ask for a new puzzle after the amount of time allotted to solve the puzzles rules out, we won't find the entry.

So in order to ensure that we know what endpoint to redirect the user to and that they pass when they submit their solution
even if they requested a different puzzle to solve, we need to lookup the userDesiredEndpoint from cache. If it has been
purged, we will just send back a 404.

NOTE:
this is not only extremely unlikely because they would have had to not solve it for like 20 minutes and then click new puzzle
but the puzzle itself triggers a refresh automatically on the client side when it detects it ran out of time preventing this from occuring
*/
func handleRefreshPuzzleCAPTCHAState(

	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,

) SendOrValidatePuzzleCAPTCHAResult {

	var sendOrValidatePuzzleCAPTCHAResult SendOrValidatePuzzleCAPTCHAResult

	puzzleGeneratorInterface, exists := c.Get(CaptchaGeneratorKey)
	if !exists {
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDependency
		return sendOrValidatePuzzleCAPTCHAResult
	}

	puzzleGenerator := puzzleGeneratorInterface.(*puzzleCAPTCHA.CAPTCHAGenerator)

	userDesiredEndpoint := ""

	challengeCookieValue, err := c.Cookie(PuzzleChallengeCookieName)
	if err == nil {
		/*
			If cookie exists, remove the previous solution from cache then reissue challenge
			this happens if the user clicks on "request new puzzle" or refreshes on their own (assuming we determine to challenges again)
		*/
		cachedPayloed, exists := puzzleGenerator.SolutionCache.Get(challengeCookieValue)
		if !exists {
			log.Println("Error: user desired endpoint cannot be ''")
			sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDesiredEndpoint
			return sendOrValidatePuzzleCAPTCHAResult
		}

		userDesiredEndpoint = cachedPayloed.UserDesiredEndpoint
		puzzleGenerator.SolutionCache.Delete(challengeCookieValue)
	}

	if userDesiredEndpoint == "" {
		/*
			this shouldn't happen, if it does, we would need to fail their existing
			challenge and subsequently issue an entirely new challenge to them
		*/
		log.Println("Error: user desired endpoint cannot be ''")
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDesiredEndpoint
		return sendOrValidatePuzzleCAPTCHAResult
	}

	TimeAllowedToSolvePuzzleMs := 600_000 //a default expiry 10 minutes
	targetDifficultyProfile, exists := puzzleGenerator.DifficultyConfigController.GetTargetProfile()
	if exists {
		TimeAllowedToSolvePuzzleMs = targetDifficultyProfile.TimeToSolveMs
	}

	/*
		Since the objective of this endpoint is to be able to get a new puzzle state, we protect it by assuming each click is a failed entry
		ie they couldnt solve it. After n failures, we simply prevent them from aaccessing this endpoint for the duration of the current challenge
		difficulty forcing them to solve this puzzle that they currently have. IE, we allow them to get new puzzle state a handful of times before
		banning them from doing so again for the duration of this particular puzzles lifetime. We do so just after we know what the difficulty is, but before
		we actually do the work of calculating a new puzzle for them to solve
	*/

	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	requestedMethod := c.Request.Method

	ReportPassedFailedBannedMessage(config, "ip_failed_challenge", clientIp, requestedHost)
	if failAction == Block {

		tooManyFailedChallengesResult := tooManyFailedChallenges(
			config,
			clientIp,
			clientUserAgent,
			requestedHost,
			requestedPath,
			banner,
			"captcha_puzzle",
			rateLimitStates,
			requestedMethod,
			decisionLists,
		)

		if tooManyFailedChallengesResult.Exceeded {
			log.Printf("Throttling users ability to fetch new puzzle for: %d ms", TimeAllowedToSolvePuzzleMs)
			banner.OverwriteBanWithRateLimit(config, clientIp, TimeAllowedToSolvePuzzleMs)
			accessThrottled(c, config, "TooManyFailedChallenges", TimeAllowedToSolvePuzzleMs)
			return sendOrValidatePuzzleCAPTCHAResult
		}
	}

	userChallengeCookieValue := NewChallengeCookie(config.HmacSecret, TimeAllowedToSolvePuzzleMs, getUserAgentOrIp(c, config))

	/*
		load either the default image, or use path + a hostname? to identify
		the logo of a company, then load that b64 png logo and it will work
	*/
	b64PngImage := puzzleCAPTCHA.LoadDefaultImageBase64()

	/*
		make a decision on difficulty by implementing something on this, you can also make a dynamic decision
		and invoke GetProfileByName() instead of relying on the default (target) profile
		ie targetDifficulty := puzzleGenerator.DifficultyConfigController.GetProfileByName("medium")
	*/
	targetDifficulty := puzzleGenerator.DifficultyConfigController.Target
	newCaptcha, err := puzzleGenerator.NewCAPTCHAChallenge(userChallengeCookieValue, userDesiredEndpoint, b64PngImage, targetDifficulty)
	if err != nil {
		log.Printf("Error generating CAPTCHA: %v", err)
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailPuzzleGeneration
		return sendOrValidatePuzzleCAPTCHAResult
	}

	c.SetCookie(PuzzleChallengeCookieName, userChallengeCookieValue, TimeAllowedToSolvePuzzleMs/1000, "/", "", true, false)
	c.JSON(http.StatusOK, newCaptcha)
	return sendOrValidatePuzzleCAPTCHAResult
}

/*
handleVerifyCAPTCHAPuzzleState validates the user's submitted solution to the CAPTCHA challenge.

Workflow:
1. Retrieves the puzzle verifier from context
2. Checks if the user has a challenge cookie. If missing, issues a new challenge
3. Validates the integrity of the cookie
4. Parses the user's JSON submission
5. Verifies the solution using the CAPTCHA verifier
6. If correct:
  - Grants access and logs
  - Expires the challenge cookie
  - Responds with 202 Accepted and a Location header

7. If incorrect:
  - Responds with 400 Bad Request
  - Users can retry, but excessive failures may be rate-limited (TODO)

Responses:
- 202: Successfully validated, grants access
- 400: Incorrect solution
- 500: Missing dependencies

NOTE: For now it will always just verify a challenge solution, but we can implement the rate limiting logic like sending back the dedicated
response codes to show the user that they are being rate limited and to wait before trying again - (this is built into the UI as based
based on response codes)
*/
func handleVerifyPuzzleCAPTCHAState(

	config *Config,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	failAction FailAction,
	decisionLists *StaticDecisionLists,

) SendOrValidatePuzzleCAPTCHAResult {

	var sendOrValidatePuzzleCAPTCHAResult SendOrValidatePuzzleCAPTCHAResult

	puzzleVerifierInterface, exists := c.Get(CaptchaVerifierKey)
	if !exists {
		log.Println("Failed to get dependencies")
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingDependency
		accessDenied(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAFailMissingDependency])
		return sendOrValidatePuzzleCAPTCHAResult
	}

	puzzleVerifier := puzzleVerifierInterface.(*puzzleCAPTCHA.CAPTCHAVerifier)

	/*
		if the cookie dne on verification, we need to issue a new puzzle since their
		cookie is an important part of ensuring this puzzle belong to them in particular as its
		coded to them through their cookie. So if it's missing, issue the challenge again
	*/
	userChallengeCookieValue, err := c.Cookie(PuzzleChallengeCookieName)
	if err != nil {
		log.Println("Unable to verify challenge without cookie")
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailNoCookie
		accessDenied(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAFailNoCookie])
		return sendOrValidatePuzzleCAPTCHAResult
	}

	/*
		since I am using the sha cookie generator I just want to integrity check it, but this is not necessary
		just a heads up as to why I put 0 expected bits because we are not solving PoW
	*/
	err = ValidateShaInvCookie(config.HmacSecret, userChallengeCookieValue, time.Now(), getUserAgentOrIp(c, config), 0)
	if err != nil {
		log.Println("Failed cookie validation")
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailBadCookie
		accessDenied(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAFailBadCookie])
		return sendOrValidatePuzzleCAPTCHAResult
	}

	var userSubmission puzzleCAPTCHA.ClientSolutionSubmissionPayload
	err = c.ShouldBindJSON(&userSubmission)
	if err != nil {
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailMissingSolutionBody
		return sendOrValidatePuzzleCAPTCHAResult
	}

	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	requestedMethod := c.Request.Method

	err = puzzleVerifier.VerifySolution(userChallengeCookieValue, userSubmission)
	if err != nil {
		// log.Printf("User solution incorrect for challenge: %s", userChallengeCookieValue)
		/*
			they can keep retrying but it should obviously subject to rate limit
			if they keep spamming, or try to brute force we could also ramp up the
			difficulty and serve them a new challenge instead?
		*/
		ReportPassedFailedBannedMessage(config, "ip_failed_challenge", clientIp, requestedHost)
		if failAction == Block {

			tooManyFailedChallengesResult := tooManyFailedChallenges(
				config,
				clientIp,
				clientUserAgent,
				requestedHost,
				requestedPath,
				banner,
				"captcha_puzzle",
				rateLimitStates,
				requestedMethod,
				decisionLists,
			)

			sendOrValidatePuzzleCAPTCHAResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult

			if tooManyFailedChallengesResult.Exceeded {
				/*
					instead of blindly banning, use RateLimitWithBan with incremental timing
					that being said, we shouldn't use a magic number. Instead, we should lookup how much time they are allotted given the
					difficulty profile and divide it in 4. This way they can have 4 intervals with rate limits in between. Anything more
					and the puzzle will run out of time and force a restart.
				*/
				throttleTimeSeconds := 60
				//so that we can apply rate limiting using the existing banning tools
				banner.OverwriteBanWithRateLimit(config, clientIp, throttleTimeSeconds)
				ReportPassedFailedBannedMessage(config, "block_ip", clientIp, requestedHost)
				accessThrottled(c, config, "TooManyFailedChallenges", throttleTimeSeconds)
				return sendOrValidatePuzzleCAPTCHAResult
			}
		}

		integrityErrors := []error{
			puzzleCAPTCHA.ErrFailedClickChainIntegrity,
			puzzleCAPTCHA.ErrFailedCaptchaPropertiesIntegrity,
			puzzleCAPTCHA.ErrFailedGameboardIntegrity,
		}
		for _, integrityError := range integrityErrors {
			if errors.Is(err, integrityError) {
				sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailIntegrityCheck
				accessDenied(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAFailIntegrityCheck])
				return sendOrValidatePuzzleCAPTCHAResult
			}
		}

		accessDenied(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAFailIncorrectSolution])
		sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAFailIncorrectSolution
		return sendOrValidatePuzzleCAPTCHAResult
	}

	/*
		Since the solution was valid, we expire the challenge cookie, attach a
		challenge passed cookie (if needed?) and then invoke the accessGranted
	*/

	c.SetCookie(PuzzleChallengeCookieName, "", -1, "/", "", false, false)
	accessGranted(c, config, PuzzleCAPTCHAResultToString[PuzzleCAPTCHAPass])
	ReportPassedFailedBannedMessage(config, "ip_passed_challenge", clientIp, requestedHost)
	// log.Println("puzzle captcha challenge passed")
	sendOrValidatePuzzleCAPTCHAResult.PuzzleCaptchaResult = PuzzleCAPTCHAPass
	return sendOrValidatePuzzleCAPTCHAResult
}

type PasswordChallengeResult uint

const (
	_ PasswordChallengeResult = iota
	ErrorNoPassword
	PasswordChallengePassed
	PasswordChallengeRoamingPassed
	PasswordChallengeFailedNoCookie
	PasswordChallengeFailedBadCookie
)

var PasswordChallengeResultToString = map[PasswordChallengeResult]string{
	ErrorNoPassword:                  "ErrorNoPassword",
	PasswordChallengePassed:          "PasswordChallengePassed",
	PasswordChallengeFailedNoCookie:  "PasswordChallengeFailedNoCookie",
	PasswordChallengeFailedBadCookie: "PasswordChallengeFailedBadCookie",
	PasswordChallengeRoamingPassed:   "PasswordChallengeRoamingPassed",
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
	TooManyFailedChallengesResult RateLimitResult
}

// XXX does it make sense to have separate password auth cookies and sha-inv cookies?
// maybe someday, we'd like behavior like "never serve sha-inv to someone with an admin cookie"
func sendOrValidatePassword(
	config *Config,
	passwordProtectedPaths *PasswordProtectedPaths,
	c *gin.Context,
	banner BannerInterface,
	rateLimitStates *FailedChallengeRateLimitStates,
	decisionLists *StaticDecisionLists,
) (sendOrValidatePasswordResult SendOrValidatePasswordResult) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	requestedPath := c.Request.Header.Get("X-Requested-Path")
	clientUserAgent := c.Request.Header.Get("X-Client-User-Agent")
	passwordCookie, err := c.Cookie(PasswordCookieName)
	requestedMethod := c.Request.Method
	// log.Println("passwordCookie: ", passwordCookie)
	if err == nil {
		expectedHashedPassword, ok := passwordProtectedPaths.GetPasswordHash(requestedHost)
		if !ok {
			log.Println("!!!! BAD - missing password in config") // XXX fail open or closed?
			sendOrValidatePasswordResult.PasswordChallengeResult = ErrorNoPassword
			return sendOrValidatePasswordResult
		}
		// XXX maybe don't call this err?
		err := ValidatePasswordCookie(config.HmacSecret, passwordCookie, time.Now(), getUserAgentOrIp(c, config), expectedHashedPassword)
		if err != nil {
			// Password fail, but provide second chance if password_hash_roaming is set
			expectedHashedPassword2, hasPasswordRoaming := passwordProtectedPaths.GetRoamingPasswordHash(requestedHost)
			if hasPasswordRoaming {
				// log.Printf("Password challenge failed, but password_hash_roaming is set for %s, checking that", requestedHost)
				err := ValidatePasswordCookie(config.HmacSecret, passwordCookie, time.Now(), getUserAgentOrIp(c, config), expectedHashedPassword2)
				if err == nil {
					// roaming password passed, we do not record fail specifically for roaming fail
					accessGranted(c, config, PasswordChallengeResultToString[PasswordChallengeRoamingPassed])
					ReportPassedFailedBannedMessage(config, "ip_passed_challenge", clientIp, requestedHost)
					sendOrValidatePasswordResult.PasswordChallengeResult = PasswordChallengeRoamingPassed
					return sendOrValidatePasswordResult
				}
			} else {
				sendOrValidatePasswordResult.PasswordChallengeResult = PasswordChallengeFailedBadCookie
			}
		} else {
			accessGranted(c, config, PasswordChallengeResultToString[PasswordChallengePassed])
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
		rateLimitStates,
		requestedMethod,
		decisionLists,
	)
	sendOrValidatePasswordResult.TooManyFailedChallengesResult = tooManyFailedChallengesResult
	// log.Println(tooManyFailedChallengesResult)
	if tooManyFailedChallengesResult.Exceeded {
		ReportPassedFailedBannedMessage(config, "ip_banned", clientIp, requestedHost)
		accessDenied(c, config, "TooManyFailedPassword")
		return sendOrValidatePasswordResult
	}
	_, allowRoaming := passwordProtectedPaths.GetExpandCookieDomain(requestedHost)
	// log.Println("passwordChallenge: allowRoaming: ", allowRoaming)
	passwordChallenge(c, config, allowRoaming)
	return sendOrValidatePasswordResult
}

type DecisionListResult uint

const (
	_ DecisionListResult = iota
	PasswordProtectedPriorityPass
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
	PerSiteShaInvPathException
	SiteWideChallenge
	SiteWideChallengeException
	NoMention
	NotSet
)

var DecisionListResultToString = map[DecisionListResult]string{
	PasswordProtectedPriorityPass:  "PasswordProtectedPriorityPass",
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
	PerSiteShaInvPathException:     "PerSiteShaInvPathException",
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
	PuzzleCAPTCHAResult           *PuzzleCAPTCHAResult
	TooManyFailedChallengesResult *RateLimitResult
}

func decisionForNginx(
	configHolder *ConfigHolder,
	staticDecisionLists *StaticDecisionLists,
	dynamicDecisionLists *DynamicDecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	failedChallengeStates *FailedChallengeRateLimitStates,
	banner BannerInterface,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		config := configHolder.Get()
		decisionForNginxResult := decisionForNginx2(
			c,
			config,
			staticDecisionLists,
			dynamicDecisionLists,
			passwordProtectedPaths,
			failedChallengeStates,
			banner,
		)
		if config.Debug {
			bytes, err := json.MarshalIndent(decisionForNginxResult, "", "  ")
			if err == nil {
				log.Println("decisionForNginx:", string(bytes))
			}
		} else if decisionForNginxResult.DecisionListResult != NoMention {
			// if not in debug mode, print limited log without newline
			bytes, err := json.Marshal(decisionForNginxResult)
			if err == nil {
				log.Println("decisionForNginx:", string(bytes))
			}
		}
	}
}

func decisionForNginx2(
	c *gin.Context,
	config *Config,
	staticDecisionLists *StaticDecisionLists,
	dynamicDecisionLists *DynamicDecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	failedChallengeStates *FailedChallengeRateLimitStates,
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

	// check if user has a valid password cookie, if so, allow them through
	passwordCookie, passwordCookieErr := c.Cookie(PasswordCookieName)
	if passwordCookieErr == nil {
		var grantPriorityPass bool = false
		expectedHashedPassword, hasPasswordHash := passwordProtectedPaths.GetPasswordHash(requestedHost)
		expectedHashedPassword2, hasPasswordRoaming := passwordProtectedPaths.GetRoamingPasswordHash(requestedHost)
		if hasPasswordHash {
			err := ValidatePasswordCookie(config.HmacSecret, passwordCookie, time.Now(), clientIp, expectedHashedPassword)
			if err == nil {
				grantPriorityPass = true
			}
		} else if hasPasswordRoaming {
			err := ValidatePasswordCookie(config.HmacSecret, passwordCookie, time.Now(), clientIp, expectedHashedPassword2)
			if err == nil {
				grantPriorityPass = true
			}
		}
		if grantPriorityPass {
			decisionForNginxResult.DecisionListResult = PasswordProtectedPriorityPass
			accessGranted(c, config, DecisionListResultToString[PasswordProtectedPriorityPass])
			return
		}
	}

	switch passwordProtectedPaths.ClassifyPath(requestedHost, requestedProtectedPath) {
	case PasswordProtected:
		sendOrValidatePasswordResult := sendOrValidatePassword(
			config,
			passwordProtectedPaths,
			c,
			banner,
			failedChallengeStates,
			staticDecisionLists,
		)
		decisionForNginxResult.DecisionListResult = PasswordProtectedPath
		decisionForNginxResult.PasswordChallengeResult = &sendOrValidatePasswordResult.PasswordChallengeResult
		decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidatePasswordResult.TooManyFailedChallengesResult
		return
	case PasswordProtectedException:
		decisionForNginxResult.DecisionListResult = PasswordProtectedPathException
		// FIXED: prevent password challenge exception path getting challenge
		accessGranted(c, config, DecisionListResultToString[PasswordProtectedPathException])
		return
	case NotPasswordProtected:
	default:
	}

	decision, foundInPerSiteList := staticDecisionLists.CheckPerSite(config, requestedHost, clientIp)
	if foundInPerSiteList {
		switch decision {
		case Allow:
			accessGranted(c, config, DecisionListResultToString[PerSiteAccessGranted])
			// log.Println("access granted from per-site lists")
			decisionForNginxResult.DecisionListResult = PerSiteAccessGranted
			return
		case Challenge:
			// log.Println("challenge from per-site lists")

			if USE_PUZZLE_CHALLENGE {
				puzzleCAPTCHAResult := sendPuzzleCAPTCHA(
					config,
					c,
					banner,
					failedChallengeStates,
					Block, // FailAction
					staticDecisionLists,
				)

				decisionForNginxResult.DecisionListResult = PerSiteChallenge
				decisionForNginxResult.PuzzleCAPTCHAResult = &puzzleCAPTCHAResult.PuzzleCaptchaResult
				decisionForNginxResult.TooManyFailedChallengesResult = &puzzleCAPTCHAResult.TooManyFailedChallengesResult
				return
			}

			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				failedChallengeStates,
				Block, // FailAction
				staticDecisionLists,
			)
			decisionForNginxResult.DecisionListResult = PerSiteChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c, config, DecisionListResultToString[PerSiteBlock])
			// log.Println("block from per-site lists")
			decisionForNginxResult.DecisionListResult = PerSiteBlock
			return
		}
	}

	decision, foundInGlobalList := staticDecisionLists.CheckGlobal(config, clientIp)
	if foundInGlobalList {
		switch decision {
		case Allow:
			accessGranted(c, config, DecisionListResultToString[GlobalAccessGranted])
			// log.Println("access granted from global lists")
			decisionForNginxResult.DecisionListResult = GlobalAccessGranted
			return
		case Challenge:
			// log.Println("challenge from global lists")

			if USE_PUZZLE_CHALLENGE {
				puzzleCAPTCHAResult := sendPuzzleCAPTCHA(
					config,
					c,
					banner,
					failedChallengeStates,
					Block, // FailAction
					staticDecisionLists,
				)

				decisionForNginxResult.DecisionListResult = PerSiteChallenge
				decisionForNginxResult.PuzzleCAPTCHAResult = &puzzleCAPTCHAResult.PuzzleCaptchaResult
				decisionForNginxResult.TooManyFailedChallengesResult = &puzzleCAPTCHAResult.TooManyFailedChallengesResult
				return
			}

			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				failedChallengeStates,
				Block, // FailAction
				staticDecisionLists,
			)
			decisionForNginxResult.DecisionListResult = GlobalChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
			return
		case NginxBlock, IptablesBlock:
			accessDenied(c, config, DecisionListResultToString[GlobalBlock])
			// log.Println("access denied from global lists")
			decisionForNginxResult.DecisionListResult = GlobalBlock
			return
		}
	}

	// i think this needs to point to a struct {decision: Decision, expires: Time}.
	// when we insert something into the list, really we might just be extending the expiry time and/or
	// changing the decision.
	// XXX i forget if that comment is stale^
	expiringDecision, ok := checkExpiringDecisionLists(c, clientIp, dynamicDecisionLists)
	if !ok {
		// log.Println("no mention in expiring lists")
	} else {
		switch expiringDecision.Decision {
		case Allow:
			accessGranted(c, config, DecisionListResultToString[ExpiringAccessGranted])
			// log.Println("access granted from expiring lists")
			decisionForNginxResult.DecisionListResult = ExpiringAccessGranted
			return
		case Challenge:

			if USE_PUZZLE_CHALLENGE {
				log.Println("I need more clarification on this endpoint, I don't really get what its doing... it seems like were meant to check for exceptions?")
				// puzzleCAPTCHAResult := sendPuzzleCAPTCHA(
				// 	config,
				// 	c,
				// 	banner,
				// 	failedChallengeStates,
				// 	Block, // FailAction
				// 	staticDecisionLists,
				// )

				// decisionForNginxResult.DecisionListResult = PerSiteChallenge
				// decisionForNginxResult.PuzzleCAPTCHAResult = &puzzleCAPTCHAResult.PuzzleCaptchaResult
				// decisionForNginxResult.TooManyFailedChallengesResult = &puzzleCAPTCHAResult.TooManyFailedChallengesResult
				// return
			}

			// apply exception to both challenge from baskerville and regex banner
			if checkPerSiteShaInvPathExceptions(config, requestedHost, requestedPath) {
				accessGranted(c, config, DecisionListResultToString[PerSiteShaInvPathException])
				decisionForNginxResult.DecisionListResult = PerSiteShaInvPathException
				return
			}
			// Check if expiringDecision.fromBaskerville, if true, check if domain disabled baskerville
			_, disabled := config.SitesToDisableBaskerville[requestedHost]
			if expiringDecision.fromBaskerville && disabled {
				log.Printf("DIS-BASK: domain %s disabled baskerville, skip expiring challenge for %s", requestedHost, clientIp)
			} else {
				// log.Println("challenge from expiring lists")
				sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
					config,
					c,
					banner,
					failedChallengeStates,
					Block, // FailAction
					staticDecisionLists,
				)
				decisionForNginxResult.DecisionListResult = ExpiringChallenge
				decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
				decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
				return
			}
		case NginxBlock, IptablesBlock:
			accessDenied(c, config, DecisionListResultToString[ExpiringBlock])
			// log.Println("access denied from expiring lists")
			decisionForNginxResult.DecisionListResult = ExpiringBlock
			return
		}
	}

	// the legacy banjax_sha_inv and user_banjax_sha_inv
	// difference is one blocks after many failures and the other doesn't
	failAction, ok := staticDecisionLists.CheckSitewideShaInv(requestedHost)
	if !ok {
		// log.Println("no mention in sitewide list")
	} else {
		// log.Println("challenge from sitewide list")
		// Reuse the exception from password prot for site-wide sha inv exceptions path
		if passwordProtectedPaths.IsException(requestedHost, requestedProtectedPath) {
			decisionForNginxResult.DecisionListResult = SiteWideChallengeException
			accessGranted(c, config, DecisionListResultToString[SiteWideChallengeException])
		} else {
			sendOrValidateShaChallengeResult := sendOrValidateShaChallenge(
				config,
				c,
				banner,
				failedChallengeStates,
				failAction,
				staticDecisionLists,
			)
			decisionForNginxResult.DecisionListResult = SiteWideChallenge
			decisionForNginxResult.ShaChallengeResult = &sendOrValidateShaChallengeResult.ShaChallengeResult
			decisionForNginxResult.TooManyFailedChallengesResult = &sendOrValidateShaChallengeResult.TooManyFailedChallengesResult
		}

		return
	}

	// log.Println("no mention in any lists, access granted")
	if decisionForNginxResult.DecisionListResult == NotSet {
		decisionForNginxResult.DecisionListResult = NoMention
	}
	accessGranted(c, config, DecisionListResultToString[decisionForNginxResult.DecisionListResult])
	return
}

func CleanRequestedPath(requestedPath string) string {
	path := "/" + strings.Trim(requestedPath, "/")
	path = strings.Split(path, "?")[0]
	return path
}

func checkExpiringDecisionLists(c *gin.Context, clientIp string, decisionLists *DynamicDecisionLists) (ExpiringDecision, bool) {
	sessionId, _ := c.Cookie(SessionCookieName)
	return decisionLists.Check(sessionId, clientIp)
}

func checkPerSiteShaInvPathExceptions(
	config *Config,
	requestedHost string,
	requestedPath string,
) bool {
	// check against config.SitesToShaInvPathExceptions
	pathExceptions, hasExceptions := config.SitesToShaInvPathExceptions[requestedHost]
	if hasExceptions {
		for _, pException := range pathExceptions {
			if strings.HasPrefix(requestedPath, pException) {
				log.Println("checkPerSiteShaInvPathExceptions:", requestedPath, "pException:", pException)
				return true
			}
		}
	}
	return false
}
