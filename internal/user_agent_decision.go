// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"regexp"
	"strings"
)

// uaPattern holds a pre-compiled optional regex alongside the raw pattern string.
// If compiledRegex is nil, substring matching is used.
type uaPattern struct {
	raw           string
	compiledRegex *regexp.Regexp
}

func newUAPattern(raw string) (uaPattern, error) {
	// Attempt to detect if the pattern is intended as a regex by trying to compile it.
	// Simple substrings that happen to be valid regex (e.g. "GPTBot") compile fine and
	// strings.Contains will be used for them since they contain no metacharacters.
	// We only use regex when the string contains metacharacters.
	if containsRegexMetachar(raw) {
		compiled, err := regexp.Compile(raw)
		if err != nil {
			return uaPattern{}, fmt.Errorf("invalid UA regex pattern %q: %w", raw, err)
		}
		return uaPattern{raw: raw, compiledRegex: compiled}, nil
	}
	return uaPattern{raw: raw}, nil
}

func containsRegexMetachar(s string) bool {
	return strings.ContainsAny(s, `\.+*?[]{}()|^$`)
}

func matchUserAgent(p uaPattern, userAgent string) bool {
	if p.compiledRegex != nil {
		return p.compiledRegex.MatchString(userAgent)
	}
	return strings.Contains(userAgent, p.raw)
}

// globalUAPatternToDecision maps decision → []pattern for global UA rules.
type globalUAPatternToDecision map[Decision][]uaPattern

// perSiteUAPatternToDecision maps site → decision → []pattern for per-site UA rules.
type perSiteUAPatternToDecision map[string]globalUAPatternToDecision

// checkUADecision iterates decisions in severity order and returns the first match.
func checkUADecision(rules globalUAPatternToDecision, userAgent string) (Decision, bool) {
	for _, d := range []Decision{IptablesBlock, NginxBlock, Challenge, Allow} {
		for _, p := range rules[d] {
			if matchUserAgent(p, userAgent) {
				return d, true
			}
		}
	}
	return 0, false
}

// buildGlobalUAPatternToDecision builds a globalUAPatternToDecision from the raw config map.
func buildGlobalUAPatternToDecision(raw map[string][]string) (globalUAPatternToDecision, error) {
	out := make(globalUAPatternToDecision)
	for decisionString, patterns := range raw {
		decision, err := ParseDecision(decisionString)
		if err != nil {
			return nil, fmt.Errorf("user_agent_decision_lists: %w", err)
		}
		for _, rawPattern := range patterns {
			p, err := newUAPattern(rawPattern)
			if err != nil {
				return nil, err
			}
			out[decision] = append(out[decision], p)
		}
	}
	return out, nil
}

// buildPerSiteUAPatternToDecision builds a perSiteUAPatternToDecision from the raw config map.
func buildPerSiteUAPatternToDecision(raw map[string]map[string][]string) (perSiteUAPatternToDecision, error) {
	out := make(perSiteUAPatternToDecision)
	for site, decisionToPatterns := range raw {
		global, err := buildGlobalUAPatternToDecision(decisionToPatterns)
		if err != nil {
			return nil, fmt.Errorf("per_site_user_agent_decision_lists[%s]: %w", site, err)
		}
		out[site] = global
	}
	return out, nil
}
