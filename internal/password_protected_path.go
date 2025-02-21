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
	"strings"
	"sync/atomic"
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

func (p *PasswordProtectedPaths) IsException(site string, path string) bool {
	content := p.content.Load()

	exceptions, hasExceptions := content.siteToExceptionToBool[site]
	if hasExceptions && exceptions[path] {
		return true
	} else {
		return false
	}
}

func (p *PasswordProtectedPaths) ClassifyPath(site string, path string) PathType {
	content := p.content.Load()

	pathToBools, ok := content.siteToPathToBool[site]
	if ok {
		exceptions, hasExceptions := content.siteToExceptionToBool[site]
		if !hasExceptions || !exceptions[path] {
			for protectedPath, boolFlag := range pathToBools {
				if boolFlag && strings.HasPrefix(path, protectedPath) {
					return PasswordProtected
				}
			}
		} else {
			return PasswordProtectedException
		}
	}

	return NotPasswordProtected
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

	for site, paths := range config.SitesToProtectedPaths {
		for _, path := range paths {
			path = "/" + strings.Trim(path, "/")
			_, ok := siteToPathToBool[site]
			if !ok {
				siteToPathToBool[site] = make(stringToBool)
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
