// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

func RunHttpServer(config *Config,
	decisionLists *DecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	ipToStates *IpToStates,
	failedChallengeStates *FailedChallengeStates,
	wg *sync.WaitGroup) {
	defer wg.Done()

	r := gin.Default()

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

		r.Use(func(c *gin.Context) {
			_, err = io.WriteString(logFile, fmt.Sprintf("%f 127.0.0.1 %s %s HTTP/1.1 Mozilla -\n",
				float64(time.Now().Unix()),
				c.Request.Method,
				c.Query("path")))
			if err != nil {
				log.Println("failed to write? %v", err)
			}
		})
	}

	r.Any("/auth_request", decisionForNginx(config, decisionLists, passwordProtectedPaths, failedChallengeStates))

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
			))
	})

	r.GET("/rate_limit_states", func(c *gin.Context) {
		c.String(200,
			fmt.Sprintf("regexes:\n%v\nfailed challenges:\n%v",
				ipToStates.String(),
				failedChallengeStates.String(),
			))
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

func challenge(c *gin.Context, pageBytes *[]byte, cookieName string, cookieTtlSeconds int) {
	newCookie := NewChallengeCookie(time.Now(), c.Request.Header.Get("X-Client-IP"))
	log.Println("Serving new cookie: ", newCookie)
	c.SetCookie(cookieName, newCookie, cookieTtlSeconds, "/", c.Request.Header.Get("X-Requested-Host"), false, false)
	c.Header("Cache-Control", "no-cache,no-store")
	c.Data(401, "text/html", *pageBytes)
	c.Abort() // XXX is this still needed, or was it just for my old middleware approach?
}

func passwordChallenge(c *gin.Context, config *Config) {
	challenge(c, &config.PasswordPageBytes, "deflect_password", config.PasswordCookieTtlSeconds)
}

func shaInvChallenge(c *gin.Context, config *Config) {
	challenge(c, &config.ChallengerBytes, "deflect_challenge", config.ShaInvCookieTtlSeconds)
}

// XXX this is very close to how the regex rate limits work
func tooManyFailedChallenges(config *Config, ip string, decisionLists *DecisionLists, failedChallengeStates *FailedChallengeStates) bool {
	now := time.Now()
	state, ok := (*failedChallengeStates)[ip]
	if !ok {
		log.Println("IP hasn't failed a challenge before")
		(*failedChallengeStates)[ip] = &NumHitsAndIntervalStart{1, now} // XXX why is this a pointer again?
	} else {
		if now.Sub(state.IntervalStartTime) > time.Duration(time.Duration(config.TooManyFailedChallengesIntervalSeconds)*time.Second) {
			log.Println("IP has failed a challenge, but longer ago than $interval")
			(*failedChallengeStates)[ip] = &NumHitsAndIntervalStart{1, now}
		} else {
			log.Println("IP has failed a challenge in this $interval")
			(*failedChallengeStates)[ip].NumHits++
		}
	}

	if (*failedChallengeStates)[ip].NumHits > config.TooManyFailedChallengesThreshold {
		log.Println("IP has failed too many challenges; blocking them")
		updateExpiringDecisionLists(config, ip, decisionLists, now, NginxBlock)
		(*failedChallengeStates)[ip].NumHits = 0 // XXX should it be 1?...
		return true
	}

	return false
}

func sendOrValidateChallenge(config *Config, c *gin.Context, failedChallengeStates *FailedChallengeStates, decisionLists *DecisionLists) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	challengeCookie, err := c.Cookie("deflect_challenge")
	if err == nil {
		err := ValidateShaInvCookie("password", challengeCookie, time.Now(), clientIp, 10) // XXX config
		if err != nil {
			log.Println("Sha-inverse challenge failed")
			log.Println(err)
		} else {
			accessGranted(c)
            ReportChallengePassedOrFailed(config, true, clientIp, requestedHost)
			log.Println("Sha-inverse challenge passed")
			return
		}
	}
    ReportChallengePassedOrFailed(config, false, clientIp, requestedHost)
	if tooManyFailedChallenges(config, clientIp, decisionLists, failedChallengeStates) {
		accessDenied(c)
		return
	}
	shaInvChallenge(c, config)
}

// XXX does it make sense to have separate password auth cookies and sha-inv cookies?
// maybe someday, we'd like behavior like "never serve sha-inv to someone with an admin cookie"
func sendOrValidatePassword(config *Config, passwordProtectedPaths *PasswordProtectedPaths, c *gin.Context, failedChallengeStates *FailedChallengeStates, decisionLists *DecisionLists) {
	clientIp := c.Request.Header.Get("X-Client-IP")
	requestedHost := c.Request.Header.Get("X-Requested-Host")
	passwordCookie, err := c.Cookie("deflect_password")
	log.Println("passwordCookie: ", passwordCookie)
	if err == nil {
		expectedHashedPassword, ok := passwordProtectedPaths.SiteToPasswordHash[requestedHost]
		if !ok {
			log.Println("!!!! BAD - missing password in config") // XXX fail open or closed?
			return
		}
		err := ValidatePasswordCookie("password", passwordCookie, time.Now(), clientIp, expectedHashedPassword) // XXX config
		if err != nil {
			log.Println("Password challenge failed")
			log.Println(err)
		} else {
			accessGranted(c)
            ReportChallengePassedOrFailed(config, true, clientIp, requestedHost)
			log.Println("Password challenge passed")
			return
		}
	}
    ReportChallengePassedOrFailed(config, false, clientIp, requestedHost)
	if tooManyFailedChallenges(config, clientIp, decisionLists, failedChallengeStates) {
		accessDenied(c)
		return
	}
	passwordChallenge(c, config)
}

func decisionForNginx(config *Config,
	decisionLists *DecisionLists,
	passwordProtectedPaths *PasswordProtectedPaths,
	failedChallengeStates *FailedChallengeStates) gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIp := c.Request.Header.Get("X-Client-IP")
		requestedHost := c.Request.Header.Get("X-Requested-Host")
		requestedPath := c.Request.Header.Get("X-Requested-Path")
		requestedPath = strings.Replace(requestedPath, "/", "", -1)

		log.Println("clientIp: ", clientIp, " requestedHost: ", requestedHost, " requestedPath: ", requestedPath)
		log.Println("headers: ", c.Request.Header)

		pathToBool, ok := passwordProtectedPaths.SiteToPathToBool[requestedHost]
		if ok && pathToBool[requestedPath] {
			sendOrValidatePassword(config, passwordProtectedPaths, c, failedChallengeStates, decisionLists)
			log.Println("password-protected path")
			return
		}

		// i got bit by just checking against the zero value here, which is a valid iota enum
		decision, ok := (*decisionLists).PerSiteDecisionLists[requestedHost][clientIp]
		if !ok {
			log.Println("no mention in per-site lists")
		} else {
			switch decision {
			case Allow:
				accessGranted(c)
				log.Println("access granted from per-site lists")
				return
			case Challenge:
				log.Println("challenge from per-site lists")
				sendOrValidateChallenge(config, c, failedChallengeStates, decisionLists)
				return
			case NginxBlock, IptablesBlock:
				accessDenied(c)
				log.Println("block from per-site lists")
				return
			}
		}

		decision, ok = (*decisionLists).GlobalDecisionLists[clientIp]
		if !ok {
			log.Println("no mention in global lists")
		} else {
			switch decision {
			case Allow:
				accessGranted(c)
				log.Println("access denied from global lists")
				return
			case Challenge:
				log.Println("challenge from global lists")
				sendOrValidateChallenge(config, c, failedChallengeStates, decisionLists)
				return
			case NginxBlock, IptablesBlock:
				accessDenied(c)
				log.Println("access denied from global lists")
				return
			}
		}

		// i think this needs to point to a struct {decision: Decision, expires: Time}.
		// when we insert something into the list, really we might just be extending the expiry time and/or
		// changing the decision.
		decision, ok = checkExpiringDecisionLists(clientIp, decisionLists)
		if !ok {
			log.Println("no mention in expiring lists")
		} else {
			switch decision {
			case Allow:
				accessGranted(c)
				log.Println("access denied from expiring lists")
				return
			case Challenge:
				log.Println("challenge from expiring lists")
				sendOrValidateChallenge(config, c, failedChallengeStates, decisionLists)
				return
			case NginxBlock, IptablesBlock:
				accessDenied(c)
				log.Println("access denied from expiring lists")
				return
			}
		}

		log.Println("no mention in any lists, access granted")
		accessGranted(c)
	}
}
