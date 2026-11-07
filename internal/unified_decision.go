// Copyright (c) 2026, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Unified rules come from the unified_challenge / unified_altcha_challenge / unified_block kafka
// commands. Each one is scoped to a host and narrowed by any combination of ip (or subnet),
// session id and user agent: it applies to a request for that host only when every field it
// has matches. Unlike the older *_ip / *_subnet / *_session commands, a unified rule never
// applies to other hosts, so it can't spread to every site on the edge.

// unifiedRuleKey is a unified rule within its host. A zero field matches any request.
type unifiedRuleKey struct {
	prefix    netip.Prefix // a single ip is a full-length prefix; invalid (zero) means any ip
	sessionId string
	ua        string
}

// fields is how many of ip, session id and user agent the rule is narrowed by.
func (k unifiedRuleKey) fields() int {
	n := 0
	if k.prefix.IsValid() {
		n++
	}
	if k.sessionId != "" {
		n++
	}
	if k.ua != "" {
		n++
	}
	return n
}

// moreSpecificThan orders rules by how narrowly they apply: more fields first, then, between
// two rules that both have an ip, the narrower prefix (a single ip before the subnet holding it).
// Otherwise, e.g. host+ip against host+ua, the rules are as specific as each other.
func (k unifiedRuleKey) moreSpecificThan(other unifiedRuleKey) bool {
	if k.fields() != other.fields() {
		return k.fields() > other.fields()
	}
	if k.prefix.IsValid() && other.prefix.IsValid() {
		return k.prefix.Bits() > other.prefix.Bits()
	}
	return false
}

func (k unifiedRuleKey) matches(addr netip.Addr, addrOk bool, sessionId string, ua string) bool {
	if k.prefix.IsValid() && (!addrOk || !k.prefix.Contains(addr)) {
		return false
	}
	if k.sessionId != "" && k.sessionId != sessionId {
		return false
	}
	if k.ua != "" && k.ua != ua {
		return false
	}
	return true
}

// String is the rule's fields, for logs and the /banned API.
func (k unifiedRuleKey) String() string {
	parts := []string{}
	if k.prefix.IsValid() {
		if k.prefix.IsSingleIP() {
			parts = append(parts, "ip="+k.prefix.Addr().String())
		} else {
			parts = append(parts, "subnet="+k.prefix.String())
		}
	}
	if k.sessionId != "" {
		parts = append(parts, "session_id="+k.sessionId)
	}
	if k.ua != "" {
		parts = append(parts, fmt.Sprintf("ua=%q", k.ua))
	}
	if len(parts) == 0 {
		return "all"
	}
	return strings.Join(parts, " ")
}

// parseUnifiedRuleKey reads the fields of a unified_* command. value is an ip or a subnet
// (IPv4 CIDR, no broader than /16, as for block_subnet), sessionId may be url-encoded.
func parseUnifiedRuleKey(value string, sessionId string, ua string) (unifiedRuleKey, error) {
	key := unifiedRuleKey{ua: ua}

	value = strings.TrimSpace(value)
	if strings.Contains(value, "/") {
		subnet, err := ParseSubnet(value)
		if err != nil {
			return unifiedRuleKey{}, fmt.Errorf("invalid subnet %q: %w", value, err)
		}
		key.prefix = subnet
	} else if value != "" {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return unifiedRuleKey{}, fmt.Errorf("invalid ip %q: %w", value, err)
		}
		addr = addr.Unmap()
		key.prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	// gin does urldecode on cookie, so decode a possibly urlencoded session id from kafka
	if sessionId != "" {
		decoded, err := url.QueryUnescape(sessionId)
		if err != nil {
			return unifiedRuleKey{}, fmt.Errorf("invalid session_id %q: %w", sessionId, err)
		}
		key.sessionId = decoded
	}

	return key, nil
}

var errUnifiedHostOnlyBlock = errors.New("unified_block needs an ip, subnet, session_id or ua besides host, it would block the whole site")

type hostToUnifiedRules map[string]map[unifiedRuleKey]ExpiringDecision

func (m hostToUnifiedRules) String() string {
	b := strings.Builder{}
	for host, rules := range m {
		b.WriteString(host)
		b.WriteString(":\n")
		for key, expiringDecision := range rules {
			b.WriteString(fmt.Sprintf("\t%v: %v until %v (baskerville: %v)\n",
				key,
				expiringDecision.Decision.String(),
				expiringDecision.Expires.Format("15:04:05"),
				expiringDecision.fromBaskerville,
			))
		}
	}
	return b.String()
}

// UpdateUnified stores a unified rule for host. Like the other expiring lists, an existing rule
// with the same fields is only replaced by a more serious decision (or new AltCha settings).
func (h *DynamicDecisionLists) UpdateUnified(
	config *Config,
	host string,
	key unifiedRuleKey,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) error {
	if host == "" {
		return errors.New("unified rule needs a host")
	}
	if newDecision.IsDenial() && key.fields() == 0 {
		return errUnifiedHostOnlyBlock
	}
	// a block on a protected subnet is still stored, and skipped per request for protected ips
	if newDecision.IsDenial() && key.prefix.IsSingleIP() && config.IsProtectedIP(key.prefix.Addr().String()) {
		log.Println("updateUnified: not blocking protected ip", newDecision, host, key)
		return nil
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	rules, ok := h.value.expiringDecisionListsUnified[host]
	if !ok {
		rules = make(map[unifiedRuleKey]ExpiringDecision)
		h.value.expiringDecisionListsUnified[host] = rules
	}

	if existing, ok := rules[key]; ok && time.Now().Before(existing.Expires) && !existing.supersededBy(newDecision, altcha) {
		if config.Debug {
			log.Println("updateUnified: not with less serious", existing.Decision, newDecision, host, key)
		}
		return nil
	}
	if config.Debug {
		log.Println("updateUnified:", newDecision, host, key)
	}

	ipAddress := ""
	if key.prefix.IsValid() {
		ipAddress = key.prefix.String()
	}
	rules[key] = ExpiringDecision{
		Decision:        newDecision,
		Expires:         expires,
		IpAddress:       ipAddress,
		fromBaskerville: fromBaskerville,
		domain:          host,
		altcha:          altcha,
	}
	return nil
}

// CheckUnified returns the most specific unexpired unified rule on host matching the request
// (most fields, then the narrowest ip prefix, then the most serious decision). With
// skipDenials, block rules are left out, for protected ips.
func (h *DynamicDecisionLists) CheckUnified(
	host string,
	clientIp string,
	sessionId string,
	ua string,
	skipDenials bool,
) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	rules := h.value.expiringDecisionListsUnified[host]
	if len(rules) == 0 {
		return ExpiringDecision{}, false
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(clientIp))
	addrOk := err == nil
	if addrOk {
		addr = addr.Unmap()
	}

	now := time.Now()
	var found ExpiringDecision
	var foundKey unifiedRuleKey
	foundOk := false
	for key, expiringDecision := range rules {
		if now.After(expiringDecision.Expires) {
			delete(rules, key)
			continue
		}
		if skipDenials && expiringDecision.Decision.IsDenial() {
			continue
		}
		if !key.matches(addr, addrOk, sessionId, ua) {
			continue
		}
		if !foundOk ||
			key.moreSpecificThan(foundKey) ||
			(!foundKey.moreSpecificThan(key) && expiringDecision.Decision > found.Decision) {
			found, foundKey, foundOk = expiringDecision, key, true
		}
	}
	if len(rules) == 0 {
		delete(h.value.expiringDecisionListsUnified, host)
	}
	return found, foundOk
}

// RemoveUnified removes every unified rule on host that has all the given fields (an exact
// match on each one given): with no fields every unified rule on host is removed, with an ip
// the rules for that ip, with or without a session id or user agent. It returns how many
// unexpired rules were removed.
func (h *DynamicDecisionLists) RemoveUnified(host string, filter unifiedRuleKey) int {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	rules := h.value.expiringDecisionListsUnified[host]
	removed := 0
	now := time.Now()
	for key, expiringDecision := range rules {
		if filter.prefix.IsValid() && key.prefix != filter.prefix {
			continue
		}
		if filter.sessionId != "" && key.sessionId != filter.sessionId {
			continue
		}
		if filter.ua != "" && key.ua != filter.ua {
			continue
		}
		delete(rules, key)
		if !now.After(expiringDecision.Expires) {
			removed++
		}
	}
	if len(rules) == 0 {
		delete(h.value.expiringDecisionListsUnified, host)
	}
	return removed
}

// MetricsUnified counts the unified rules by kind.
func (h *DynamicDecisionLists) MetricsUnified() (challenges int, altchaChallenges int, blocks int) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, rules := range h.value.expiringDecisionListsUnified {
		for _, expiringDecision := range rules {
			switch expiringDecision.Decision {
			case Challenge:
				challenges++
			case AltChaChallenge:
				altchaChallenges++
			case NginxBlock, IptablesBlock:
				blocks++
			}
		}
	}
	return
}
