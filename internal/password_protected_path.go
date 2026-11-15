// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"encoding/hex"
	"fmt"
	"log"
	"net/url"
	"path"
	"strings"
	"sync/atomic"
	"unicode"
)

type PasswordProtectedPaths struct {
	content atomic.Pointer[content]
}

func NewPasswordProtectedPaths(config *Config) (*PasswordProtectedPaths, error) {
	result := &PasswordProtectedPaths{
		content: atomic.Pointer[content]{},
	}

	content, err := fromConfig(config)
	if err != nil {
		return nil, err
	}
	result.content.Store(content)

	return result, nil
}

func (p *PasswordProtectedPaths) UpdateFromConfig(config *Config) error {
	content, err := fromConfig(config)
	if err != nil {
		return err
	}

	p.content.Store(content)

	return nil
}

func (p *PasswordProtectedPaths) GetPasswordHash(site string) ([]byte, bool) {
	v, ok := p.content.Load().siteToPasswordHash[site]
	return v, ok
}

func (p *PasswordProtectedPaths) GetRoamingPasswordHash(site string) ([]byte, bool) {
	v, ok := p.content.Load().siteToRoamingPasswordHash[site]
	return v, ok
}

func (p *PasswordProtectedPaths) GetExpandCookieDomain(site string) (bool, bool) {
	v, ok := p.content.Load().siteToExpandCookieDomain[site]
	return v, ok
}

// IsException reports whether the raw request path is at or under a configured exception
// for the site. A path without a canonical form is never an exception.
func (p *PasswordProtectedPaths) IsException(site string, rawPath string) bool {
	content := p.content.Load()
	if _, ok := content.siteToExceptionToBool[site]; !ok {
		return false
	}
	canonical, ok := canonicalPath(rawPath)
	return ok && content.isException(site, canonical)
}

// isException matches case-sensitively: an exception grants access, so it must not
// widen to other spellings that a case-sensitive origin serves as other resources.
func (c *content) isException(site string, canonical string) bool {
	for exception, boolFlag := range c.siteToExceptionToBool[site] {
		if boolFlag && isAtOrUnder(canonical, exception) {
			return true
		}
	}
	return false
}

// ClassifyPath takes the raw request path (nginx's $request_uri). Protected paths match
// case-insensitively (some origins are), exceptions case-sensitively; both on a segment
// boundary of the canonical path.
//
// A path without a canonical form is never an exception, and is protected when any
// reading an origin might use starts with a protected path: this is an access control,
// so it fails closed for those paths without prompting for ordinary odd URLs elsewhere
// on the site.
func (p *PasswordProtectedPaths) ClassifyPath(site string, rawPath string) PathType {
	content := p.content.Load()

	pathToBools, ok := content.siteToPathToBool[site]
	if !ok {
		return NotPasswordProtected
	}
	canonical, ok := canonicalPath(rawPath)
	if !ok {
		for _, reading := range ambiguousReadings(rawPath) {
			for protectedPath, boolFlag := range pathToBools {
				if boolFlag && strings.HasPrefix(reading, protectedPath) {
					return PasswordProtected
				}
			}
		}
		return NotPasswordProtected
	}
	if content.isException(site, canonical) {
		return PasswordProtectedException
	}
	lower := strings.ToLower(canonical)
	for protectedPath, boolFlag := range pathToBools {
		if boolFlag && isAtOrUnder(lower, protectedPath) {
			return PasswordProtected
		}
	}

	return NotPasswordProtected
}

// canonicalPath turns a raw request path into the one form that path rules are matched
// against, so that every spelling an origin resolves to the same resource gets the same
// decision: query string dropped, percent-decoded once, dot segments and repeated
// slashes resolved. Case is kept; callers decide how to compare it.
//
// ok is false when the path holds something origins disagree on, so no single form is
// safe: an encoded slash, a backslash, a control character, a '%' left after one decode (origins that
// decode twice), a fragment marker, a bad escape, a ';' path parameter (Tomcat strips
// it, others do not), or a segment ending in a dot or space (Windows strips them).
func canonicalPath(raw string) (string, bool) {
	p, _, _ := strings.Cut(raw, "?")
	// An encoded slash must be caught before decoding, after which it is indistinguishable
	// from a separator.
	if strings.Contains(strings.ToLower(p), "%2f") {
		return "", false
	}
	decoded, err := url.PathUnescape(p)
	if err != nil {
		return "", false
	}
	if strings.ContainsAny(decoded, "%#;?\\") || strings.IndexFunc(decoded, unicode.IsControl) >= 0 {
		return "", false
	}
	for _, segment := range strings.Split(decoded, "/") {
		if segment != "." && segment != ".." && (strings.HasSuffix(segment, ".") || strings.HasSuffix(segment, " ")) {
			return "", false
		}
	}
	return path.Clean("/" + decoded), true
}

// ambiguousReadings returns, lower-cased and resolved, the ways origins may read a path
// that has no canonical form: decoded once with encoded slashes kept as text (origins
// that do not split on %2F); decoded until stable with %2F and backslash as separators
// (origins that decode twice, Windows); and that again with ';' parameters and trailing
// dots and spaces stripped from each segment (Tomcat, Windows).
func ambiguousReadings(raw string) []string {
	p, _, _ := strings.Cut(raw, "?")
	p = strings.ToLower(p)

	literal := lenientUnescape(strings.ReplaceAll(p, "%2f", "%252f"))

	separated := p
	for i := 0; i < 4; i++ {
		next := lenientUnescape(separated)
		if next == separated {
			break
		}
		separated = next
	}
	separated = strings.ReplaceAll(separated, "\\", "/")

	segments := strings.Split(separated, "/")
	for i, segment := range segments {
		segment, _, _ = strings.Cut(segment, ";")
		if segment != "." && segment != ".." {
			segment = strings.TrimRight(segment, ". ")
		}
		segments[i] = segment
	}
	stripped := strings.Join(segments, "/")

	readings := []string{literal, separated, stripped}
	for i, reading := range readings {
		readings[i] = strings.ToLower(path.Clean("/" + reading))
	}
	return readings
}

// lenientUnescape decodes every valid %XX escape once and leaves anything else as is.
func lenientUnescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if decoded, err := hex.DecodeString(s[i+1 : i+3]); err == nil {
				b.WriteByte(decoded[0])
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isAtOrUnder reports whether canonical is rule or a path below it, so /wp-admin covers
// /wp-admin and /wp-admin/x but not /wp-admin-public.
func isAtOrUnder(canonical string, rule string) bool {
	if rule == "/" {
		return true
	}
	return canonical == rule || strings.HasPrefix(canonical, rule+"/")
}

// canonicalExceptionRule canonicalizes a configured exception. An entry with a query
// string or without a canonical form cannot be matched as written, so it is dropped:
// a missing exception only means a password prompt or challenge, never a bypass.
func canonicalExceptionRule(configured string) (string, bool) {
	if strings.ContainsAny(configured, "?#") {
		return "", false
	}
	return canonicalPath("/" + configured)
}

type PathType int

func (t PathType) String() string {
	switch t {
	case NotPasswordProtected:
		return "NotPasswordProtected"
	case PasswordProtected:
		return "PasswordProtected"
	case PasswordProtectedException:
		return "PasswordProtectedException"
	}

	panic("invalid PathType")
}

const (
	NotPasswordProtected PathType = iota
	PasswordProtected
	PasswordProtectedException
)

type stringToBool map[string]bool
type stringToStringToBool map[string]stringToBool
type stringToBytes map[string][]byte

type content struct {
	siteToPathToBool          stringToStringToBool
	siteToExceptionToBool     stringToStringToBool
	siteToPasswordHash        stringToBytes
	siteToRoamingPasswordHash stringToBytes
	siteToExpandCookieDomain  stringToBool
}

func fromConfig(config *Config) (*content, error) {
	siteToPathToBool := make(stringToStringToBool)
	siteToExceptionToBool := make(stringToStringToBool)
	siteToPasswordHash := make(stringToBytes)
	siteToRoamingPasswordHash := make(stringToBytes)
	siteToExpandCookieDomain := make(stringToBool)

	// Protected paths are never rejected: dropping one would expose it. An entry with
	// odd characters is kept in a lenient form and logged, since requests in canonical
	// form may never match it.
	for site, paths := range config.SitesToProtectedPaths {
		for _, configured := range paths {
			if _, ok := canonicalExceptionRule(configured); !ok {
				log.Printf("CONFIG: password protected path %q for %s has characters that requests do not carry once canonicalized; it may not match\n", configured, site)
			}
			protectedPath := strings.ToLower(path.Clean("/" + strings.ReplaceAll(lenientUnescape(configured), "\\", "/")))
			if _, ok := siteToPathToBool[site]; !ok {
				siteToPathToBool[site] = make(stringToBool)
			}
			siteToPathToBool[site][protectedPath] = true
			if config.Debug {
				log.Printf("password protected path: %s%s\n", site, protectedPath)
			}
		}
	}

	for site, exceptions := range config.SitesToProtectedPathExceptions {
		for _, configured := range exceptions {
			exception, ok := canonicalExceptionRule(configured)
			if !ok {
				log.Printf("CONFIG: dropping password protected path exception %q for %s: it has a query string or characters that cannot be matched safely\n", configured, site)
				continue
			}
			if _, ok := siteToExceptionToBool[site]; !ok {
				siteToExceptionToBool[site] = make(stringToBool)
			}
			siteToExceptionToBool[site][exception] = true
		}
	}

	for site, passwordHashHex := range config.SitesToPasswordHashes {
		passwordHashBytes, err := hex.DecodeString(passwordHashHex)
		if err != nil {
			return nil, fmt.Errorf("bad password hash: %w", err)
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

	content := &content{
		siteToPathToBool,
		siteToExceptionToBool,
		siteToPasswordHash,
		siteToRoamingPasswordHash,
		siteToExpandCookieDomain,
	}

	return content, nil
}
