// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

const passwordProtectedConfString = `
password_protected_paths:
  "localhost:8081":
    - wp-admin
    - app/protected
  "localhost":
    - wp-admin
password_protected_path_exceptions:
  "localhost:8081":
    - wp-admin/admin-ajax.php
  "localhost":
    - app/admin/no-ban.php
password_hashes:
  "localhost:8081": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
  "localhost": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
`

type TestPaths struct {
	hostname string
	paths    []string
}

func TestConfigToPasswordProtectedPaths(t *testing.T) {
	config := loadConfigString(passwordProtectedConfString)
	passwordProtectedPaths := ConfigToPasswordProtectedPaths(config)

	testProtectedPaths := []TestPaths{
		{"localhost:8081", []string{"/wp-admin", "/app/protected"}},
		{"localhost", []string{"/wp-admin"}},
	}
	pathTester(testProtectedPaths, passwordProtectedPaths.SiteToPathToBool)

	testExceptionPaths := []TestPaths{
		{"localhost:8081", []string{"/wp-admin/admin-ajax.php"}},
		{"localhost", []string{"/app/admin/no-ban.php"}},
	}
	pathTester(testExceptionPaths, passwordProtectedPaths.SiteToExceptionToBool)
}

const regexWithRateString = `
decision: nginx_block
hits_per_interval: 800
interval: 30
regex: .*
rule: "All sites/methods: 800 req/30 sec"
hosts_to_skip:
  localhost: true
`

func TestRegexWithRate(t *testing.T) {
	var r RegexWithRate
	err := yaml.Unmarshal([]byte(regexWithRateString), &r)
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	assert.Equal(t, NginxBlock, r.Decision)
	assert.Equal(t, 800, r.HitsPerInterval)
	assert.Equal(t, 30*time.Second, r.Interval)
	assert.Equal(t, ".*", r.Regex.String())
	assert.Equal(t, "All sites/methods: 800 req/30 sec", r.Rule)
	assert.Equal(t, 1, len(r.HostsToSkip))
	assert.Equal(t, true, r.HostsToSkip["localhost"])
}

func loadConfigString(configStr string) *Config {
	config := &Config{}
	err := yaml.Unmarshal([]byte(configStr), config)
	if err != nil {
		panic(fmt.Sprintf("Couldn't parse config file: %v", err))
	}
	return config
}

func pathTester(
	testPaths []TestPaths,
	toBool StringToStringToBool,
) {
	for _, testProtectedPath := range testPaths {
		requestedHost := testProtectedPath.hostname
		for _, requestedResource := range testProtectedPath.paths {
			pathToBools, ok := toBool[requestedHost]
			if !ok {
				log.Fatal("The host entry was not loaded: ", requestedHost)
			}
			boolValue, ok2 := pathToBools[requestedResource]
			if !ok2 {
				log.Fatal("The resource value was not loaded for ", requestedHost, "/", requestedResource)
			}
			if boolValue != true {
				log.Fatal("The expected bool value was not loaded for ", requestedHost, "/", requestedResource)
			}
		}
	}
}
