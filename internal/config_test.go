// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"log"
	"testing"

	"gopkg.in/yaml.v2"
)

const passwordProtectedConfString = `
password_protected_paths:
  "localhost:8081":
    - wp-admin
    - app/protected
  "localhost":
    - wp-admin
password_hashes:
  "localhost:8081": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
  "localhost": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
`

type TestProtectedPaths struct {
	hostname string
	paths    []string
}

func TestConfigToPasswordProtectedPaths(t *testing.T) {
	config := loadConfigString(passwordProtectedConfString)
	passwordProtectedPaths := ConfigToPasswordProtectedPaths(config)
	testPaths := []TestProtectedPaths{
		{"localhost:8081", []string{"/wp-admin", "/app/protected"}},
		{"localhost", []string{"/wp-admin"}},
	}
	passwordProtectedPathTester(testPaths, passwordProtectedPaths)
}

func loadConfigString(configStr string) *Config {
	config := &Config{}
	err := yaml.Unmarshal([]byte(configStr), config)
	if err != nil {
		panic("Couldn't parse config file.")
	}
	return config
}

func passwordProtectedPathTester(
	testPaths []TestProtectedPaths,
	passwordProtectedPaths PasswordProtectedPaths,
) {
	for _, testProtectedPath := range testPaths {
		requestedHost := testProtectedPath.hostname
		for _, requestedResource := range testProtectedPath.paths {
			pathToBools, ok := passwordProtectedPaths.SiteToPathToBool[requestedHost]
			if !ok {
				log.Fatal("The host entry was not loaded in SiteToPathToBool for: ", requestedHost)
			}
			boolValue, ok2 := pathToBools[requestedResource]
			if !ok2 {
				log.Fatal("The protected resource value was not loaded for ", requestedHost, "/", requestedResource)
			}
			if boolValue != true {
				log.Fatal("The expected bool value was not loaded for ", requestedHost, "/", requestedResource)
			}
		}
	}
}
