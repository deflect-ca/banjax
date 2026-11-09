// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"crypto/sha512"
	"encoding/base64"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMinifyChallengePage_EmbeddedPagesShrinkAndKeepMarkers(t *testing.T) {
	cases := []struct {
		name    string
		page    []byte
		markers []string
	}{
		{"sha-inverse", shaInvChallengeEmbed, shaInvPageMarkers()},
		{"altcha", altchaChallengeEmbed, altchaPageMarkers()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			minified, err := minifyWithMarkers(c.page, c.markers)
			if !assert.Nil(t, err) {
				return
			}
			assert.Less(t, len(minified), len(c.page))
			// source comments are gone, so the "replace the first match only" rule can
			// no longer be tripped by a comment quoting a marker
			assert.NotContains(t, string(minified), "XXX:")
			for _, marker := range c.markers {
				assert.Equal(t, 1, strings.Count(string(minified), marker), marker)
			}
			assert.NotContains(t, string(minified), "bjxkeep")
		})
	}
}

// the ALTCHA bundle is already minified and pinned by hash, so it must pass through
func TestMinifyChallengePage_KeepsPinnedAltChaBundle(t *testing.T) {
	pinned := regexp.MustCompile(`sha384:\s+(\S+)`).FindStringSubmatch(string(altchaChallengeEmbed))
	if !assert.NotNil(t, pinned) {
		return
	}
	minified := minifyChallengePage("altcha", altchaChallengeEmbed, altchaPageMarkers())
	script := regexp.MustCompile(`(?s)<script type="?module"?>(const e=!1;.*?)</script>`).FindStringSubmatch(string(minified))
	if !assert.NotNil(t, script, "inline ALTCHA widget script not found in minified page") {
		return
	}
	sum := sha512.Sum384([]byte(script[1]))
	assert.Equal(t, pinned[1], base64.StdEncoding.EncodeToString(sum[:]))
}

func TestApplyArgs_OnMinifiedPages(t *testing.T) {
	config := altchaTestConfig()
	config.AltChaCookieTtlSeconds = 4321
	config.AltChaChallengerBytes = minifyChallengePage("altcha", altchaChallengeEmbed, altchaPageMarkers())
	challenge, err := CreateAltChaChallenge(config, "1.2.3.4", 0)
	assert.Nil(t, err)

	page := string(applyArgsToAltChaPage(config, challenge, true))
	assert.Contains(t, page, `"deflect_altcha=" + base64_cookie + ";max-age=4321"`)
	assert.Contains(t, page, `auto="off"`)
	assert.NotContains(t, page, `challenge="{}"`)
	assert.Equal(t, challenge.Signature, altchaChallengeFromPage(t, page).Signature)

	config.ShaInvCookieTtlSeconds = 1234
	config.ShaInvExpectedZeroBits = 12
	config.ChallengerBytes = minifyChallengePage("sha-inverse", shaInvChallengeEmbed, shaInvPageMarkers())
	page = string(applyArgsToShaInvPage(config))
	assert.Contains(t, page, `"deflect_challenge3=" + base64_cookie + ";max-age=1234"`)
	assert.Contains(t, page, `new_solver(12)`)
}

// a custom page the minifier would mangle a marker in is served as is
func TestMinifyChallengePage_FallsBackToSource(t *testing.T) {
	page := []byte(`<html><body><p>bjxkeep0x</p><script>document.cookie = "a=" + base64_cookie;</script></body></html>`)
	assert.Equal(t, page, minifyChallengePage("test", page, []string{`"a=" + base64_cookie`}))
}

func TestMinifyChallengePage_PageWithoutMarkers(t *testing.T) {
	page := []byte("<html>\n  <body>\n    <!-- comment -->\n    <p>hi</p>\n  </body>\n</html>\n")
	minified := minifyChallengePage("test", page, altchaPageMarkers())
	assert.NotContains(t, string(minified), "comment")
	assert.Less(t, len(minified), len(page))
}
