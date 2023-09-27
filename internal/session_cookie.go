// Copyright (c) 2023, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

func newID() uint32 {
	return rand.Uint32()
}

func sessionCookieHmac(secretKey string, expireTime time.Time, clientIp string, id uint32) []byte {
	derivedKey := sha256.New()
	derivedKey.Write([]byte(secretKey))

	expireTimeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expireTimeBytes, uint64(expireTime.Unix()))

	mac := hmac.New(sha1.New, derivedKey.Sum(nil))
	mac.Write(expireTimeBytes)
	mac.Write([]byte(clientIp))

	idBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(idBytes, id)
	mac.Write(idBytes)
	return mac.Sum(nil)
}

func newSessionCookie(secretKey string, cookieTtlSeconds int, clientIp string) string {
	expireTime := time.Now().Add(time.Duration(cookieTtlSeconds) * time.Second)
	cookieBytes := make([]byte, 20+4+8)
	id := newID()
	hmacBytes := sessionCookieHmac(secretKey, expireTime, clientIp, id)
	copy(cookieBytes[0:20], hmacBytes[0:20])
	binary.BigEndian.PutUint32(cookieBytes[20:24], id)
	binary.BigEndian.PutUint64(cookieBytes[24:32], uint64(expireTime.Unix()))

	return base64.StdEncoding.EncodeToString(cookieBytes)
}

func validateSessionCookie(cookieString string, secretKey string, nowTime time.Time, clientIp string) error {
	cookieBytes := make([]byte, 32)
	cookieBytes, err := base64.StdEncoding.DecodeString(cookieString)
	if err != nil {
		// gin erroneously does a QueryUnescape() on the cookie, which turns '+' into ' '.
		// https://github.com/gin-gonic/gin/issues/1717
		cookieString = strings.ReplaceAll(cookieString, " ", "+")
		cookieBytes, err = base64.StdEncoding.DecodeString(cookieString)
		if err != nil {
			return errors.New("Session cookie base64 decoding error")
		}
	}

	if len(cookieBytes) != 32 {
		return errors.New("Bad session cookie length")
	}

	hmacFromClient := cookieBytes[0:20]
	idBytes := cookieBytes[20:24]
	expirationBytes := cookieBytes[24:32]

	expirationInt := binary.BigEndian.Uint64(expirationBytes)
	expirationTime := time.Unix(int64(expirationInt), 0)
	if expirationTime.Sub(nowTime) < 0 {
		return errors.New(fmt.Sprintf("Session cookie expired: %v", expirationTime))
	}

	id := binary.BigEndian.Uint32(idBytes)

	expectedHmac := sessionCookieHmac(secretKey, expirationTime, clientIp, id)
	if !bytes.Equal(expectedHmac, hmacFromClient) {
		return errors.New("Hmac validation failed")
	}

	return nil
}

func sessionCookieEndPoint(c *gin.Context, config *Config) error {
	/*
		Endpoint for session cookie, actually get/set the cookie

		*dsc = deflect session cookie
		*dsc_new = a newly issued deflect session cookie, not confirmed by banjax yet

		For every query:
			validate the existing cookie(if any): err := validateSessionCookie(cookie, 'a secret key', time_now, ip)
			if validation failed: i.e. err != nil:
				create new cookie: cookie := wewSessionCookie('secret key', expiration_time, ip)
				set in the logs: dsc=cookie, dsc_new=True
			else:
				set in the logs: dsc=cookie, dsc_new=False
	*/
	clientIp := c.Request.Header.Get("X-Client-IP")
	dsc, err := c.Cookie("deflect_session")

	if err == nil {
		// cookie exists, validate it
		validateErr := validateSessionCookie(dsc, config.SessionCookieHmacSecret, time.Now(), clientIp)
		if validateErr == nil {
			// cookie is valid, do not attach cookie but only report dsc_new=false
			// fmt.Printf("DSC: [%s] cookie %s is valid, report dsc_new=false\n", clientIp, dsc)
			attachSessionCookie(c, config, dsc, false)
		} else {
			// cookie is invalid, create a new one
			newDsc := newSessionCookie(config.SessionCookieHmacSecret, config.SessionCookieTtlSeconds, clientIp)
			fmt.Printf("DSC: [%s] cookie %s is not valid, issue new: %s\n", clientIp, dsc, newDsc)
			attachSessionCookie(c, config, newDsc, true)
		}
		return nil
	}

	// no cookie, create a new one
	newDsc := newSessionCookie(config.SessionCookieHmacSecret, config.SessionCookieTtlSeconds, clientIp)
	// fmt.Printf("DSC: [%s] issue new cookie: %s\n", clientIp, newDsc)
	attachSessionCookie(c, config, newDsc, true)
	return nil
}

func attachSessionCookie(c *gin.Context, config *Config, dsc string, dsc_new bool) {
	if dsc_new {
		c.SetCookie("deflect_session", dsc, config.SessionCookieTtlSeconds, "/", "", false, true)
	}
	// for nginx log
	c.Header("X-Deflect-Session", dsc)
	c.Header("X-Deflect-Session-New", strconv.FormatBool(dsc_new))
}
