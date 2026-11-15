// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// The path banjax sees is nginx's raw $request_uri, while the origin resolves its own
// normalized form. Every spelling below reaches the protected resource on some origin,
// so each one must get the same decision as the plain spelling.
func TestDecisionForNginx2_PasswordProtectedPathSpellings(t *testing.T) {
	const protectedHost = "example.com"
	config := &Config{
		TooManyFailedChallengesIntervalSeconds: 60,
		TooManyFailedChallengesThreshold:       1000,
		SitesToProtectedPaths:                  map[string][]string{protectedHost: {"wp-admin"}},
		SitesToProtectedPathExceptions:         map[string][]string{protectedHost: {"wp-admin/admin-ajax.php"}},
		SitesToPasswordHashes:                  map[string]string{protectedHost: "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
	}
	staticDecisionLists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)
	passwordProtectedPaths, err := NewPasswordProtectedPaths(config)
	assert.Nil(t, err)

	decide := func(host, path string) DecisionListResult {
		c := buildDecisionForNginxTestContext("10.0.0.1", host, path, "some-ua", "")
		return decisionForNginx2(c, config, staticDecisionLists, NewDynamicDecisionLists(), passwordProtectedPaths,
			NewFailedChallengeRateLimitStates(), NewFailedChallengeRateLimitStates(), &MockBanner{}).DecisionListResult
	}

	cases := []struct {
		name string
		path string
		want DecisionListResult
	}{
		// plain spellings
		{"the protected directory asks for the password", "/wp-admin/", PasswordProtectedPath},
		{"the protected path without a trailing slash asks for the password", "/wp-admin", PasswordProtectedPath},
		{"a query string does not change the decision", "/wp-admin?x=1", PasswordProtectedPath},
		{"a static file under the protected path asks for the password", "/wp-admin/secret.js", PasswordProtectedPath},
		{"path info under the protected path asks for the password", "/wp-admin/index.php/x.css", PasswordProtectedPath},

		// spellings the origin resolves to the protected path (F-02)
		{"a percent-encoded letter asks for the password", "/%77p-admin/", PasswordProtectedPath},
		{"a percent-encoded dash asks for the password", "/wp%2Dadmin/", PasswordProtectedPath},
		{"a dot-dot segment into the protected path asks for the password", "/foo/../wp-admin/", PasswordProtectedPath},
		{"a dot segment before the protected path asks for the password", "/./wp-admin/", PasswordProtectedPath},
		{"a percent-encoded dot-dot segment asks for the password", "/foo/%2e%2e/wp-admin/", PasswordProtectedPath},
		{"a doubled slash before the protected path asks for the password", "//wp-admin/", PasswordProtectedPath},
		{"a doubled slash inside the path asks for the password", "/foo//../wp-admin/", PasswordProtectedPath},
		{"upper case asks for the password", "/WP-ADMIN/", PasswordProtectedPath},
		{"mixed case asks for the password", "/Wp-Admin/options.php", PasswordProtectedPath},

		// escaping the exception into the protected path
		{"a dot-dot out of the exception asks for the password", "/wp-admin/admin-ajax.php/../secret", PasswordProtectedPath},
		{"an encoded dot-dot out of the exception asks for the password", "/wp-admin/admin-ajax.php/%2e%2e/secret", PasswordProtectedPath},
		{"a name that only starts with the exception asks for the password", "/wp-admin/admin-ajax.phpx", PasswordProtectedPath},

		// paths origins disagree on fail closed on a protected site
		{"an encoded slash asks for the password", "/wp-admin%2Fsecret", PasswordProtectedPath},
		{"an encoded slash out of the exception asks for the password", "/wp-admin/admin-ajax.php%2F..%2Fsecret", PasswordProtectedPath},
		{"an encoded slash anywhere on a protected site asks for the password", "/foo%2f..%2fwp-admin/", PasswordProtectedPath},
		// decoded and resolved this is /public, but an origin that does not split on %2F
		// routes it under /wp-admin
		{"an encoded slash that decodes out of the protected path asks for the password", "/wp-admin%2F..%2Fpublic", PasswordProtectedPath},
		{"double percent-encoding asks for the password", "/%2577p-admin/", PasswordProtectedPath},
		{"an encoded NUL asks for the password", "/wp-admin%00/", PasswordProtectedPath},
		{"a double-encoded dot-dot inside the protected path asks for the password", "/wp-admin/%252e%252e/public", PasswordProtectedPath},
		{"a double-encoded slash into the protected path asks for the password", "/foo%252f..%252fwp-admin/", PasswordProtectedPath},
		{"a backslash asks for the password", `/foo\..\wp-admin/`, PasswordProtectedPath},
		{"an encoded backslash asks for the password", "/foo%5c..%5cwp-admin/", PasswordProtectedPath},
		{"a fragment marker asks for the password", "/wp-admin/admin-ajax.php#/../secret", PasswordProtectedPath},
		{"an invalid escape with a dot-dot into the protected path asks for the password", "/%zz/../wp-admin/", PasswordProtectedPath},
		{"an encoded control character asks for the password", "/wp-admin%0a/", PasswordProtectedPath},
		{"a path parameter asks for the password", "/wp-admin;x/secret", PasswordProtectedPath},
		{"a path parameter on a dot-dot asks for the password", "/wp-admin/admin-ajax.php/..;/secret", PasswordProtectedPath},
		{"a path parameter on a dot-dot into the protected path asks for the password", "/foo/..;/wp-admin/", PasswordProtectedPath},
		{"a trailing dot on a segment asks for the password", "/wp-admin./secret", PasswordProtectedPath},
		{"a trailing encoded space on a segment asks for the password", "/wp-admin%20/secret", PasswordProtectedPath},

		// the exception still works in its own spellings
		{"the exception is granted", "/wp-admin/admin-ajax.php", PasswordProtectedPathException},
		{"the exception with a query string is granted", "/wp-admin/admin-ajax.php?action=x", PasswordProtectedPathException},
		{"the exception with a trailing slash is granted", "/wp-admin/admin-ajax.php/", PasswordProtectedPathException},
		{"a sub-path of the exception is granted", "/wp-admin/admin-ajax.php/x", PasswordProtectedPathException},
		{"the exception with an encoded letter is granted", "/wp-admin/%61dmin-ajax.php", PasswordProtectedPathException},
		{"the exception matches only in its configured case", "/WP-ADMIN/ADMIN-AJAX.PHP", PasswordProtectedPath},
		{"an ambiguous spelling of the exception is never an exception", "/wp-admin/admin-ajax.php;x", PasswordProtectedPath},

		// paths outside the protected path are not protected
		{"the site root is not protected", "/", NoMention},
		{"another page is not protected", "/hello", NoMention},
		{"a sibling that shares the prefix is not protected", "/wp-admin-public/", NoMention},
		{"a longer name that shares the prefix is not protected", "/wp-adminx", NoMention},
		{"a dot-dot out of the protected path is not protected", "/wp-admin/../public", NoMention},

		// odd but ordinary paths elsewhere on a protected site do not get the password page
		{"a trailing dot elsewhere is not protected", "/wiki/Washington,_D.C.", NoMention},
		{"a literal percent elsewhere is not protected", "/shop/100%25-cotton", NoMention},
		{"a path parameter elsewhere is not protected", "/page;jsessionid=abc", NoMention},
		{"an encoded slash elsewhere is not protected", "/search/a%2Fb", NoMention},
		{"an invalid escape elsewhere is not protected", "/%zz", NoMention},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, DecisionListResultToString[tc.want], DecisionListResultToString[decide(protectedHost, tc.path)], "path %q", tc.path)
		})
	}

	t.Run("an odd path on a site without protected paths is not protected", func(t *testing.T) {
		assert.Equal(t, "NoMention", DecisionListResultToString[decide("other.example", "/foo%2f..%2fwp-admin/")])
	})
}

func TestNewPasswordProtectedPaths_ConfiguredEntries(t *testing.T) {
	const host = "example.com"
	classify := func(t *testing.T, protected, exceptions []string, path string) PathType {
		p, err := NewPasswordProtectedPaths(&Config{
			SitesToProtectedPaths:          map[string][]string{host: protected},
			SitesToProtectedPathExceptions: map[string][]string{host: exceptions},
		})
		assert.Nil(t, err, "odd entries must not stop banjax from starting or reloading")
		return p.ClassifyPath(host, path)
	}

	t.Run("an exception with a query string is dropped, so the path stays protected", func(t *testing.T) {
		assert.Equal(t, PasswordProtected, classify(t, []string{"wp-admin"}, []string{"wp-admin/admin-ajax.php?action=heartbeat"}, "/wp-admin/admin-ajax.php"))
	})
	t.Run("an exception with a path parameter is dropped, so the path stays protected", func(t *testing.T) {
		assert.Equal(t, PasswordProtected, classify(t, []string{"wp-admin"}, []string{"wp-admin/x;y"}, "/wp-admin/x"))
	})
	t.Run("a mixed-case exception matches its own case", func(t *testing.T) {
		assert.Equal(t, PasswordProtectedException, classify(t, []string{"app"}, []string{"app/Public"}, "/app/Public/x"))
	})
	t.Run("a mixed-case exception does not match another case", func(t *testing.T) {
		assert.Equal(t, PasswordProtected, classify(t, []string{"app"}, []string{"app/Public"}, "/app/public"))
	})
	t.Run("a protected path written in upper case protects every case", func(t *testing.T) {
		assert.Equal(t, PasswordProtected, classify(t, []string{"/WP-Admin/"}, nil, "/wp-admin/x"))
	})
	t.Run("a protected path with odd characters still loads and protects its spelling", func(t *testing.T) {
		assert.Equal(t, PasswordProtected, classify(t, []string{"downloads/v1."}, nil, "/downloads/v1./x"))
	})
}
