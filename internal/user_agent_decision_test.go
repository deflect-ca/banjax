// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- uaPattern / matchUserAgent ---

func TestMatchUserAgent_Substring(t *testing.T) {
	p, err := newUAPattern("GPTBot")
	assert.Nil(t, err)
	assert.Nil(t, p.compiledRegex)

	assert.True(t, matchUserAgent(p, "Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"))
	assert.False(t, matchUserAgent(p, "Mozilla/5.0 (compatible; Googlebot/2.1)"))
}

func TestMatchUserAgent_Regex(t *testing.T) {
	p, err := newUAPattern(`Macintosh.*Firefox/\d+`)
	assert.Nil(t, err)
	assert.NotNil(t, p.compiledRegex)

	assert.True(t, matchUserAgent(p, "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0"))
	assert.False(t, matchUserAgent(p, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"))
}

func TestMatchUserAgent_RegexCaseInsensitive(t *testing.T) {
	p, err := newUAPattern(`(?i)scrapy|mechanize`)
	assert.Nil(t, err)
	assert.NotNil(t, p.compiledRegex)

	assert.True(t, matchUserAgent(p, "Scrapy/2.11.2 (+https://scrapy.org)"))
	assert.True(t, matchUserAgent(p, "Python-Mechanize/0.4.9"))
	assert.False(t, matchUserAgent(p, "Mozilla/5.0 (compatible; Googlebot/2.1)"))
}

func TestNewUAPattern_InvalidRegex(t *testing.T) {
	_, err := newUAPattern(`(?invalid`)
	assert.NotNil(t, err)
}

// --- checkUADecision severity order ---

func TestCheckUADecision_SeverityOrder(t *testing.T) {
	// Both Allow and NginxBlock match "TestBot" — NginxBlock should win (higher severity)
	allowPattern, _ := newUAPattern("TestBot")
	blockPattern, _ := newUAPattern("TestBot")
	rules := globalUAPatternToDecision{
		Allow:      []uaPattern{allowPattern},
		NginxBlock: []uaPattern{blockPattern},
	}

	decision, ok := checkUADecision(rules, "TestBot/1.0")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision)
}

func TestCheckUADecision_NoMatch(t *testing.T) {
	p, _ := newUAPattern("AhrefsBot")
	rules := globalUAPatternToDecision{
		NginxBlock: []uaPattern{p},
	}

	_, ok := checkUADecision(rules, "Mozilla/5.0 (compatible; Googlebot/2.1)")
	assert.False(t, ok)
}

// --- StaticDecisionLists UA checks via config ---

const uaDecisionListsConfString = `
global_user_agent_decision_lists:
  nginx_block:
    - "AhrefsBot"
    - "SemrushBot"
  challenge:
    - "(?i)scrapy|mechanize"
  allow:
    - "Googlebot"
per_site_user_agent_decision_lists:
  "example.com":
    allow:
      - "GPTBot"
    nginx_block:
      - "AhrefsBot"
  "other.com":
    challenge:
      - "Macintosh.*Firefox/\\d+"
`

func TestCheckGlobalUserAgent(t *testing.T) {
	config := loadConfigString(uaDecisionListsConfString)
	lists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	decision, ok := lists.CheckGlobalUserAgent("Mozilla/5.0 (compatible; AhrefsBot/7.0)")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision)

	decision, ok = lists.CheckGlobalUserAgent("Mozilla/5.0 (compatible; SemrushBot/7.0)")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision)

	decision, ok = lists.CheckGlobalUserAgent("Scrapy/2.11.2 (+https://scrapy.org)")
	assert.True(t, ok)
	assert.Equal(t, Challenge, decision)

	decision, ok = lists.CheckGlobalUserAgent("Mozilla/5.0 (compatible; Googlebot/2.1)")
	assert.True(t, ok)
	assert.Equal(t, Allow, decision)

	_, ok = lists.CheckGlobalUserAgent("Mozilla/5.0 (compatible; GPTBot/1.0)")
	assert.False(t, ok)
}

func TestCheckPerSiteUserAgent(t *testing.T) {
	config := loadConfigString(uaDecisionListsConfString)
	lists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	// GPTBot is allowed on example.com (per-site override)
	decision, ok := lists.CheckPerSiteUserAgent("example.com", "Mozilla/5.0 (compatible; GPTBot/1.0)")
	assert.True(t, ok)
	assert.Equal(t, Allow, decision)

	// AhrefsBot is blocked on example.com
	decision, ok = lists.CheckPerSiteUserAgent("example.com", "Mozilla/5.0 (compatible; AhrefsBot/7.0)")
	assert.True(t, ok)
	assert.Equal(t, NginxBlock, decision)

	// Firefox on Mac is challenged on other.com
	decision, ok = lists.CheckPerSiteUserAgent("other.com", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:149.0) Gecko/20100101 Firefox/149.0")
	assert.True(t, ok)
	assert.Equal(t, Challenge, decision)

	// Firefox on Windows does not match the Macintosh pattern
	_, ok = lists.CheckPerSiteUserAgent("other.com", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0")
	assert.False(t, ok)

	// No per-site rules for unknown.com
	_, ok = lists.CheckPerSiteUserAgent("unknown.com", "Mozilla/5.0 (compatible; AhrefsBot/7.0)")
	assert.False(t, ok)
}

func TestCheckPerSiteUserAgent_NoRulesForSite(t *testing.T) {
	config := loadConfigString(uaDecisionListsConfString)
	lists, err := NewStaticDecisionLists(config)
	assert.Nil(t, err)

	_, ok := lists.CheckPerSiteUserAgent("notconfigured.com", "anything")
	assert.False(t, ok)
}

// --- Config parsing with invalid decision ---

const uaBadDecisionConfString = `
global_user_agent_decision_lists:
  bad_decision:
    - "SomeBot"
`

func TestNewStaticDecisionLists_InvalidUADecision(t *testing.T) {
	config := loadConfigString(uaBadDecisionConfString)
	_, err := NewStaticDecisionLists(config)
	assert.NotNil(t, err)
}

// --- Config parsing with invalid regex ---

const uaBadRegexConfString = `
global_user_agent_decision_lists:
  nginx_block:
    - "(?invalid"
`

func TestNewStaticDecisionLists_InvalidUARegex(t *testing.T) {
	config := loadConfigString(uaBadRegexConfString)
	_, err := NewStaticDecisionLists(config)
	assert.NotNil(t, err)
}
