// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"log"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Decision int

const (
	_ Decision = iota
	Allow
	Challenge
	AltChaChallenge
	TooManyRequests
	NginxBlock
	IptablesBlock
)

func ParseDecision(s string) (Decision, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "challenge":
		return Challenge, nil
	case "altcha_challenge":
		return AltChaChallenge, nil
	case "too_many_requests":
		return TooManyRequests, nil
	case "nginx_block":
		return NginxBlock, nil
	case "iptables_block":
		return IptablesBlock, nil
	default:
		return 0, fmt.Errorf("invalid decision: %v", s)
	}
}

// ParseStaticListDecision parses a decision from a static (config file) decision list.
// TooManyRequests is only produced by the regex rate limits, so the static lists reject it.
func ParseStaticListDecision(s string) (Decision, error) {
	decision, err := ParseDecision(s)
	if err != nil {
		return 0, err
	}
	if decision == TooManyRequests {
		return 0, fmt.Errorf("decision %v is only valid in regex rules, not in static decision lists", s)
	}
	return decision, nil
}

// IsDenial reports whether d denies access: a block (nginx 403 or iptables) or a rate limit
// (429). These are never applied to an ip in protected_ips.
func (d Decision) IsDenial() bool {
	return d == NginxBlock || d == IptablesBlock || d == TooManyRequests
}

func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case Challenge:
		return "Challenge"
	case AltChaChallenge:
		return "AltChaChallenge"
	case TooManyRequests:
		return "TooManyRequests"
	case NginxBlock:
		return "NginxBlock"
	case IptablesBlock:
		return "IptablesBlock"
	default:
		return ""
	}
}

type ExpiringDecision struct {
	Decision        Decision
	Expires         time.Time
	IpAddress       string
	fromBaskerville bool
	domain          string
	// settings of the challenge served for an AltChaChallenge decision, zero value for the
	// config defaults
	altcha AltChaOptions
	// an ip block from too many failed challenges under two_step_ban_esculation. Unlike other
	// expiring decisions, decisionForNginx2 applies it before the static lists and challenges.
	fromFailedChallenge bool
}

// IsFailedChallengeBan reports whether d is a block from too many failed challenges (see
// two_step_ban_esculation).
func (d ExpiringDecision) IsFailedChallengeBan() bool {
	return d.fromFailedChallenge && d.Decision.IsDenial()
}

// supersededBy reports whether an update should replace this decision: only with a more
// serious decision, or, for AltChaChallenge, the same decision with different settings
// (so a repeated altcha command can change its difficulty or click mode, and each
// altcha_force_new command moves NotBefore forward, forcing another new challenge).
func (d ExpiringDecision) supersededBy(newDecision Decision, altcha AltChaOptions) bool {
	if newDecision != d.Decision {
		return newDecision > d.Decision
	}
	return newDecision == AltChaChallenge && altcha != d.altcha
}

type FailAction int

const (
	_ FailAction = iota
	Block
	NoBlock
)

func ParseFailAction(s string) (FailAction, error) {
	switch s {
	case "block":
		return Block, nil
	case "no_block":
		return NoBlock, nil
	default:
		return 0, fmt.Errorf("invalid fail action: %v", s)
	}
}

// Decision lists that don't change until the program is restarted or the config is hot-reloaded.
type StaticDecisionLists struct {
	content atomic.Pointer[staticDecisionLists]
}

func NewStaticDecisionLists(config *Config) (*StaticDecisionLists, error) {
	content, err := newStaticDecisionListsFromConfig(config)
	if err != nil {
		return nil, err
	}

	lists := &StaticDecisionLists{}
	lists.content.Store(&content)

	return lists, nil
}

func (l *StaticDecisionLists) UpdateFromConfig(config *Config) error {
	content, err := newStaticDecisionListsFromConfig(config)
	if err != nil {
		return fmt.Errorf("failed to update static decision lists from config: %w", err)
	}

	l.content.Store(&content)

	return nil
}

func (l *StaticDecisionLists) CheckPerSite(config *Config, site string, clientIp string) (Decision, bool) {
	c := l.content.Load()

	decision, ok := c.perSiteDecisionLists[site][clientIp]

	// found as plain IP form, no need to check the ipMatcher
	if ok {
		return decision, true
	}

	// perSiteDecisionListsIPMatcher has different struct as perSiteDecisionLists
	// decision must iterate in order, once found in one of the list, break the loop
	for _, iterateDecision := range []Decision{Allow, Challenge, AltChaChallenge, NginxBlock, IptablesBlock} {
		if c.perSiteDecisionListsIPMatcher[site][iterateDecision].Contains(clientIp) {
			if config.Debug {
				log.Printf("matched in per-site ipMatcher %s %v %s", site, iterateDecision, clientIp)
			}
			return iterateDecision, true
		}
	}

	return decision, false
}

func (l *StaticDecisionLists) CheckGlobal(config *Config, clientIp string) (Decision, bool) {
	c := l.content.Load()

	decision, ok := c.globalDecisionLists[clientIp]

	if ok {
		return decision, true
	} else {
		for _, iterateDecision := range []Decision{Allow, Challenge, AltChaChallenge, NginxBlock, IptablesBlock} {
			if c.globalDecisionListsIPMatcher[iterateDecision].Contains(clientIp) {
				if config.Debug {
					log.Printf("matched in ipMatcher %v %s", iterateDecision, clientIp)
				}
				return iterateDecision, true
			}
		}

		return decision, false
	}
}

func (l *StaticDecisionLists) CheckPerSiteUserAgent(site string, userAgent string) (Decision, bool) {
	c := l.content.Load()
	rules, ok := c.perSiteUserAgentDecisionLists[site]
	if !ok {
		return 0, false
	}
	return checkUADecision(rules, userAgent)
}

func (l *StaticDecisionLists) CheckGlobalUserAgent(userAgent string) (Decision, bool) {
	c := l.content.Load()
	return checkUADecision(c.globalUserAgentDecisionLists, userAgent)
}

func (l *StaticDecisionLists) CheckSitewideAltCha(site string) (SitewideAltCha, bool) {
	c := l.content.Load()

	entry, ok := c.sitewideAltChaList[site]
	return entry, ok
}

func (l *StaticDecisionLists) CheckSitewideShaInv(site string) (FailAction, bool) {
	c := l.content.Load()

	failAction, ok := c.sitewideShaInvList[site]
	return failAction, ok
}

// Reports whether the per-site decision lists allow the client ip on the given site.
func (l *StaticDecisionLists) CheckIsPerSiteAllowed(site string, clientIp string) bool {
	c := l.content.Load()

	// check per-site decision list first
	decision, ok := c.perSiteDecisionLists[site][clientIp]
	if ok && decision == Allow {
		// log.Printf("checkIpInPerSiteDecisionList: matched %s %s", urlString, ipString)
		return true
	}

	if c.perSiteDecisionListsIPMatcher[site][Allow].Contains(clientIp) {
		// log.Printf("checkIpInPerSiteDecisionList: matched in per-site ipMatcher %s %s", urlString, ipString)
		return true
	}

	return false
}

// Reports whether the global decision lists allow the client ip.
func (l *StaticDecisionLists) CheckIsGlobalAllowed(clientIp string) bool {
	c := l.content.Load()

	decision, ok := c.globalDecisionLists[clientIp]
	if ok && decision == Allow {
		// log.Printf("checkIpInGlobalDecisionList: matched %s", ipString)
		return true
	}

	// not found with direct match, try to match if contain within CIDR subnet
	if c.globalDecisionListsIPMatcher[Allow].Contains(clientIp) {
		// log.Printf("checkIpInGlobalDecisionList: matched in ipMatcher %s", ipString)
		return true
	}

	return false
}

type ipAddrToDecision map[string]Decision

func (m ipAddrToDecision) String() string {
	b := strings.Builder{}
	for ip, decision := range m {
		b.WriteString(fmt.Sprintf("%v", ip))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v", decision.String()))
		b.WriteString("\n")
	}
	return b.String()
}

type siteToIPAddrToDecision map[string]map[string]Decision

func (m siteToIPAddrToDecision) String() string {
	b := strings.Builder{}
	for site, ipsToDecisions := range m {
		b.WriteString(fmt.Sprintf("%v", site))
		b.WriteString(":\n")
		for ip, decision := range ipsToDecisions {
			b.WriteString("\t")
			b.WriteString(fmt.Sprintf("%v", ip))
			b.WriteString(":\n")
			b.WriteString("\t\t")
			b.WriteString(fmt.Sprintf("%v", decision.String()))
			b.WriteString("\n")
		}
	}
	return b.String()
}

type siteToFailAction map[string]FailAction

// SitewideAltCha is one sitewide_altcha_list entry: block / no_block, optionally with a
// _click suffix for the one-click checkbox challenge.
type SitewideAltCha struct {
	FailAction FailAction
	Click      bool
}

type siteToSitewideAltCha map[string]SitewideAltCha

func ParseSitewideAltCha(s string) (SitewideAltCha, error) {
	click := strings.HasSuffix(s, "_click")
	failAction, err := ParseFailAction(strings.TrimSuffix(s, "_click"))
	if err != nil {
		return SitewideAltCha{}, fmt.Errorf("invalid sitewide altcha value %q, want block, no_block, block_click or no_block_click", s)
	}
	return SitewideAltCha{FailAction: failAction, Click: click}, nil
}

type decisionToIPMatcher map[Decision]*ipMatcher
type siteToDecisionToIPMatcher map[string]map[Decision]*ipMatcher

// ipMatcher matches an ip against a decision list's entries, which can be plain ips or subnets in
// CIDR notation (IPv4 or IPv6). Like the rest of staticDecisionLists it is never modified after
// it is built, so it needs no locking.
type ipMatcher struct {
	addrs   map[netip.Addr]struct{}
	subnets []netip.Prefix
}

// newIPMatcher builds an ipMatcher, skipping (and logging) entries that are neither an ip nor a
// subnet.
func newIPMatcher(entries []string) *ipMatcher {
	m := &ipMatcher{addrs: make(map[netip.Addr]struct{})}
	for _, entry := range entries {
		if strings.Contains(entry, "/") {
			subnet, err := netip.ParsePrefix(entry)
			if err != nil {
				log.Printf("decision lists: ignoring invalid CIDR %q: %v\n", entry, err)
				continue
			}
			// Contains compares unmapped ips, so do the same to an IPv4-mapped IPv6 subnet,
			// e.g. ::ffff:1.2.3.0/120 becomes 1.2.3.0/24
			if subnet.Addr().Is4In6() && subnet.Bits() >= 96 {
				subnet = netip.PrefixFrom(subnet.Addr().Unmap(), subnet.Bits()-96)
			}
			if subnet.IsSingleIP() {
				m.addrs[subnet.Addr()] = struct{}{}
			} else {
				m.subnets = append(m.subnets, subnet.Masked())
			}
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			log.Printf("decision lists: ignoring invalid ip %q: %v\n", entry, err)
			continue
		}
		m.addrs[addr.Unmap()] = struct{}{}
	}
	return m
}

// Contains reports whether ip is one of the matcher's ips or inside one of its subnets. IPv4-mapped
// IPv6 addresses match their IPv4 form. A nil matcher contains nothing.
func (m *ipMatcher) Contains(ip string) bool {
	if m == nil {
		return false
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if _, ok := m.addrs[addr]; ok {
		return true
	}
	for _, subnet := range m.subnets {
		if subnet.Contains(addr) {
			return true
		}
	}
	return false
}

// Decision lists that don't change unless the program is restarted or the config is hot-reloaded.
type staticDecisionLists struct {
	globalDecisionLists           ipAddrToDecision
	perSiteDecisionLists          siteToIPAddrToDecision
	sitewideShaInvList            siteToFailAction
	sitewideAltChaList            siteToSitewideAltCha
	globalDecisionListsIPMatcher  decisionToIPMatcher
	perSiteDecisionListsIPMatcher siteToDecisionToIPMatcher
	perSiteUserAgentDecisionLists perSiteUAPatternToDecision
	globalUserAgentDecisionLists  globalUAPatternToDecision
}

func newStaticDecisionLists() staticDecisionLists {
	return staticDecisionLists{
		globalDecisionLists:           make(ipAddrToDecision),
		perSiteDecisionLists:          make(siteToIPAddrToDecision),
		sitewideShaInvList:            make(siteToFailAction),
		sitewideAltChaList:            make(siteToSitewideAltCha),
		globalDecisionListsIPMatcher:  make(decisionToIPMatcher),
		perSiteDecisionListsIPMatcher: make(siteToDecisionToIPMatcher),
		perSiteUserAgentDecisionLists: make(perSiteUAPatternToDecision),
		globalUserAgentDecisionLists:  make(globalUAPatternToDecision),
	}
}

func newStaticDecisionListsFromConfig(config *Config) (staticDecisionLists, error) {
	out := newStaticDecisionLists()

	for decisionString, ips := range config.GlobalDecisionLists {
		decision, err := ParseStaticListDecision(decisionString)
		if err != nil {
			return staticDecisionLists{}, fmt.Errorf("failed to create static decision lists from config: %w", err)
		}

		for _, ip := range ips {
			if !strings.Contains(ip, "/") {
				out.globalDecisionLists[ip] = decision
				if config.Debug {
					log.Printf("global decision: %s, ip: %s\n", decisionString, ip)
				}
			} else {
				if config.Debug {
					log.Printf("global decision: %s, CIDR: %s, put in ipMatcher\n", decisionString, ip)
				}
			}
		}

		out.globalDecisionListsIPMatcher[decision] = newIPMatcher(ips)
	}

	for site, decisionToIps := range config.PerSiteDecisionLists {
		for decisionString, ips := range decisionToIps {
			decision, err := ParseStaticListDecision(decisionString)
			if err != nil {
				return staticDecisionLists{}, fmt.Errorf("failed to create static decision lists from config: %w", err)
			}

			for _, ip := range ips {
				_, ok := out.perSiteDecisionLists[site]
				if !ok {
					out.perSiteDecisionLists[site] = make(ipAddrToDecision)
					out.perSiteDecisionListsIPMatcher[site] = make(decisionToIPMatcher)
				}
				if !strings.Contains(ip, "/") {
					out.perSiteDecisionLists[site][ip] = decision
					if config.Debug {
						log.Printf("site: %s, decision: %s, ip: %s\n", site, decisionString, ip)
					}
				} else {
					if config.Debug {
						log.Printf("per-site decision: %s, CIDR: %s, put in ipMatcher\n", decisionString, ip)
					}
				}
			}
			if len(ips) > 0 {
				// only init ipMatcher if there is IP
				// or there might be panic: assignment to entry in nil map
				out.perSiteDecisionListsIPMatcher[site][decision] = newIPMatcher(ips)
			}
		}
	}

	for site, failActionString := range config.SitewideShaInvList {
		if config.Debug {
			log.Printf("sitewide site: %s, failAction: %s\n", site, failActionString)
		}

		failAction, err := ParseFailAction(failActionString)
		if err != nil {
			return staticDecisionLists{}, err
		}

		out.sitewideShaInvList[site] = failAction
	}

	for site, failActionString := range config.SitewideAltChaList {
		if config.Debug {
			log.Printf("sitewide altcha site: %s, failAction: %s\n", site, failActionString)
		}

		entry, err := ParseSitewideAltCha(failActionString)
		if err != nil {
			return staticDecisionLists{}, fmt.Errorf("sitewide_altcha_list[%s]: %w", site, err)
		}

		out.sitewideAltChaList[site] = entry
	}

	if len(config.GlobalUserAgentDecisionLists) > 0 {
		globalUA, err := buildGlobalUAPatternToDecision(config.GlobalUserAgentDecisionLists)
		if err != nil {
			return staticDecisionLists{}, fmt.Errorf("failed to build global user agent decision lists: %w", err)
		}
		out.globalUserAgentDecisionLists = globalUA
	}

	if len(config.PerSiteUserAgentDecisionLists) > 0 {
		perSiteUA, err := buildPerSiteUAPatternToDecision(config.PerSiteUserAgentDecisionLists)
		if err != nil {
			return staticDecisionLists{}, fmt.Errorf("failed to build per-site user agent decision lists: %w", err)
		}
		out.perSiteUserAgentDecisionLists = perSiteUA
	}

	log.Printf("global decisions: %v\n", out.globalDecisionLists)
	log.Printf("per-site decisions: %v\n", out.perSiteDecisionLists)

	return out, nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////

// Decision lists that are updated frequently during the runtime of the program.
type DynamicDecisionLists struct {
	value dynamicDecisionLists
	mutex sync.Mutex
}

func NewDynamicDecisionLists() *DynamicDecisionLists {
	value := dynamicDecisionLists{
		expiringDecisionLists:          make(ipAddrToExpiringDecision),
		expiringDecisionListsSessionId: make(sessionIdToExpiringDecision),
		expiringDecisionListsHost:      make(hostToExpiringDecision),
		expiringDecisionListsUA:        make(uaToExpiringDecision),
		expiringDecisionListsSubnet:    make(subnetToExpiringDecision),
		expiringDecisionListsIpHost:    make(ipHostToExpiringDecision),
	}

	lists := &DynamicDecisionLists{
		value: value,
		mutex: sync.Mutex{},
	}

	go func() {
		for range time.NewTicker(9 * time.Second).C {
			lists.removeExpired()
		}
	}()

	return lists
}

func (h *DynamicDecisionLists) Update(
	config *Config,
	ip string,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) {
	h.update(config, ip, expires, newDecision, fromBaskerville, domain, altcha, false)
}

// UpdateFailedChallengeBan stores an nginx block for an ip that failed too many challenges
// under two_step_ban_esculation. decisionForNginx2 applies it ahead of the static lists and
// challenges, so the ip can't keep being served challenges while it is blocked.
func (h *DynamicDecisionLists) UpdateFailedChallengeBan(config *Config, ip string, expires time.Time, domain string) {
	h.update(config, ip, expires, NginxBlock, false, domain, AltChaOptions{}, true)
}

func (h *DynamicDecisionLists) update(
	config *Config,
	ip string,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
	altcha AltChaOptions,
	fromFailedChallenge bool,
) {
	if newDecision.IsDenial() && config.IsProtectedIP(ip) {
		log.Println("updateExpiringDecisionLists: not blocking or rate limiting protected ip", newDecision, ip, domain)
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionLists[ip]
	if ok {
		if !existingExpiringDecision.supersededBy(newDecision, altcha) {
			if config.Debug {
				log.Println("updateExpiringDecisionLists: not with less serious", existingExpiringDecision.Decision, newDecision, ip, domain)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionLists: update with existing and new: ", existingExpiringDecision.Decision, newDecision, ip, domain)
		// log.Println("From baskerville", fromBaskerville)
	}

	// XXX We are not using nginx to banjax cache feature yet
	// purgeNginxAuthCacheForIp(ip)

	// a failed challenge ban escalated to a more serious block (an iptables ban from
	// too_many_403_ban_to_iptables_ban, say) keeps its precedence until it expires
	if ok && existingExpiringDecision.IsFailedChallengeBan() && newDecision.IsDenial() &&
		time.Now().Before(existingExpiringDecision.Expires) {
		fromFailedChallenge = true
	}

	h.value.expiringDecisionLists[ip] = ExpiringDecision{
		newDecision,
		expires,
		ip,
		fromBaskerville,
		domain,
		altcha,
		fromFailedChallenge,
	}
}

func (h *DynamicDecisionLists) UpdateBySessionId(
	config *Config,
	ip string,
	sessionId string,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) {
	// ip is the session's ip as reported by baskerville; the session cookie can also turn up
	// from another ip, which decisionForNginx checks on each request
	if newDecision.IsDenial() && config.IsProtectedIP(ip) {
		log.Printf("updateExpiringDecisionListsSessionId: not blocking or rate limiting session %s of protected ip %s\n", sessionId, ip)
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionListsSessionId[sessionId]
	if ok {
		if !existingExpiringDecision.supersededBy(newDecision, altcha) {
			return
		}
	}

	if config.Debug {
		log.Printf("updateExpiringDecisionListsSessionId: Update session id decision with IP %s, session id %s, existing and new: %v, %v\n",
			ip, sessionId, existingExpiringDecision.Decision, newDecision)
	}

	h.value.expiringDecisionListsSessionId[sessionId] = ExpiringDecision{
		newDecision,
		expires,
		ip,
		fromBaskerville,
		domain,
		altcha,
		false, // not from failed challenges
	}
}

func (h *DynamicDecisionLists) Check(sessionId string, clientIp string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if sessionId != "" {
		expiringDecision, ok := h.value.expiringDecisionListsSessionId[sessionId]
		if ok {
			log.Printf("DSC: found expiringDecision from session %s (%s)", sessionId, expiringDecision.Decision)
			if time.Now().Sub(expiringDecision.Expires) > 0 {
				delete(h.value.expiringDecisionListsSessionId, sessionId)
				// log.Println("deleted expired decision from expiring lists")
				ok = false
			}
			return expiringDecision, ok
		}
	}

	expiringDecision, ok := h.value.expiringDecisionLists[clientIp]
	if ok {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionLists, clientIp)
			// log.Println("deleted expired decision from expiring lists")
			ok = false
		}
	}
	return expiringDecision, ok
}

func (h *DynamicDecisionLists) UpdateByHost(
	config *Config,
	host string,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionListsHost[host]
	if ok {
		if !existingExpiringDecision.supersededBy(newDecision, altcha) {
			if config.Debug {
				log.Println("updateExpiringDecisionListsHost: not with less serious", existingExpiringDecision.Decision, newDecision, host)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionListsHost: update with existing and new: ", existingExpiringDecision.Decision, newDecision, host)
	}

	h.value.expiringDecisionListsHost[host] = ExpiringDecision{
		newDecision,
		expires,
		"",
		fromBaskerville,
		host,
		altcha,
		false, // not from failed challenges
	}
}

func (h *DynamicDecisionLists) CheckByHost(host string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	expiringDecision, ok := h.value.expiringDecisionListsHost[host]
	if ok {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsHost, host)
			ok = false
		}
	}
	return expiringDecision, ok
}

func (h *DynamicDecisionLists) UpdateByUA(
	config *Config,
	ua string,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	host string,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	key := uaHostKey{ua, host}
	existingExpiringDecision, ok := h.value.expiringDecisionListsUA[key]
	if ok {
		if !existingExpiringDecision.supersededBy(newDecision, altcha) {
			if config.Debug {
				log.Println("updateExpiringDecisionListsUA: not with less serious", existingExpiringDecision.Decision, newDecision, ua, host)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionListsUA: update with existing and new: ", existingExpiringDecision.Decision, newDecision, ua, host)
	}

	h.value.expiringDecisionListsUA[key] = ExpiringDecision{
		newDecision,
		expires,
		"",
		fromBaskerville,
		host,
		altcha,
		false, // not from failed challenges
	}
}

func (h *DynamicDecisionLists) CheckByUA(ua string, host string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	key := uaHostKey{ua, host}
	expiringDecision, ok := h.value.expiringDecisionListsUA[key]
	if ok {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsUA, key)
			ok = false
		}
	}
	return expiringDecision, ok
}

// expiring ip decisions apply to every site, so refuse subnets so broad that a malformed
// command (e.g. 0.0.0.0/0) would block a large part of the internet everywhere
const minSubnetPrefixBits = 16

// ParseSubnet parses an IPv4 subnet in CIDR notation, as sent by block_subnet/challenge_subnet,
// normalized to its network address so that 1.2.3.4/24 and 1.2.3.0/24 are the same entry.
func ParseSubnet(s string) (netip.Prefix, error) {
	subnet, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, err
	}
	if !subnet.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("not an IPv4 subnet: %s", s)
	}
	if subnet.Bits() < minSubnetPrefixBits {
		return netip.Prefix{}, fmt.Errorf("subnet %s is broader than /%d", s, minSubnetPrefixBits)
	}
	return subnet.Masked(), nil
}

func (h *DynamicDecisionLists) UpdateBySubnet(
	config *Config,
	subnet netip.Prefix,
	expires time.Time,
	newDecision Decision,
	fromBaskerville bool,
	domain string,
	altcha AltChaOptions, // AltChaChallenge settings, zero value for the config defaults
) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionListsSubnet[subnet]
	if ok {
		if !existingExpiringDecision.supersededBy(newDecision, altcha) {
			if config.Debug {
				log.Println("updateExpiringDecisionListsSubnet: not with less serious", existingExpiringDecision.Decision, newDecision, subnet, domain)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionListsSubnet: update with existing and new: ", existingExpiringDecision.Decision, newDecision, subnet, domain)
	}

	h.value.expiringDecisionListsSubnet[subnet] = ExpiringDecision{
		newDecision,
		expires,
		subnet.String(),
		fromBaskerville,
		domain,
		altcha,
		false, // not from failed challenges
	}
}

// CheckBySubnet returns the most serious unexpired subnet decision covering clientIp.
func (h *DynamicDecisionLists) CheckBySubnet(clientIp string) (ExpiringDecision, bool) {
	return h.checkBySubnet(clientIp, false)
}

// CheckBySubnetNonDenial is CheckBySubnet for a protected ip: blocks and rate limits never
// apply to it, so they are left out before ranking, and a block on a wider (or narrower)
// subnet can't hide a challenge on another one.
func (h *DynamicDecisionLists) CheckBySubnetNonDenial(clientIp string) (ExpiringDecision, bool) {
	return h.checkBySubnet(clientIp, true)
}

func (h *DynamicDecisionLists) checkBySubnet(clientIp string, skipDenials bool) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if len(h.value.expiringDecisionListsSubnet) == 0 {
		return ExpiringDecision{}, false
	}

	addr, err := netip.ParseAddr(clientIp)
	if err != nil {
		return ExpiringDecision{}, false
	}
	addr = addr.Unmap()
	if !addr.Is4() {
		return ExpiringDecision{}, false
	}

	// keys are normalized network addresses, so look up each prefix length that could hold one
	var found ExpiringDecision
	foundOk := false
	for bits := addr.BitLen(); bits >= minSubnetPrefixBits; bits-- {
		subnet, _ := addr.Prefix(bits)
		expiringDecision, ok := h.value.expiringDecisionListsSubnet[subnet]
		if !ok {
			continue
		}
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsSubnet, subnet)
			continue
		}
		if skipDenials && expiringDecision.Decision.IsDenial() {
			continue
		}
		if !foundOk || expiringDecision.Decision > found.Decision {
			found = expiringDecision
			foundOk = true
		}
	}
	return found, foundOk
}

// RemoveBySubnet removes the exact subnet entry, returning it if it was present and unexpired.
func (h *DynamicDecisionLists) RemoveBySubnet(subnet netip.Prefix) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	expiringDecision, ok := h.value.expiringDecisionListsSubnet[subnet]
	delete(h.value.expiringDecisionListsSubnet, subnet)
	if ok && time.Now().Sub(expiringDecision.Expires) > 0 {
		ok = false
	}
	return expiringDecision, ok
}

// UpdateByIpHost stores a decision that only applies to one ip on one host. It is used to
// rate limit globally allowlisted ips (verified bots share their ips across every site, so
// a decision keyed on the ip alone would cut them off from sites they are not overloading).
func (h *DynamicDecisionLists) UpdateByIpHost(
	config *Config,
	ip string,
	host string,
	expires time.Time,
	newDecision Decision,
) {
	if newDecision.IsDenial() && config.IsProtectedIP(ip) {
		log.Println("updateExpiringDecisionListsIpHost: not rate limiting protected ip", newDecision, ip, host)
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	key := ipHostKey{ip, host}
	existingExpiringDecision, ok := h.value.expiringDecisionListsIpHost[key]
	if ok {
		if newDecision <= existingExpiringDecision.Decision {
			if config.Debug {
				log.Println("updateExpiringDecisionListsIpHost: not with less serious", existingExpiringDecision.Decision, newDecision, ip, host)
			}
			return
		}
	}
	if config.Debug {
		log.Println("updateExpiringDecisionListsIpHost: update with existing and new: ", existingExpiringDecision.Decision, newDecision, ip, host)
	}

	h.value.expiringDecisionListsIpHost[key] = ExpiringDecision{
		newDecision,
		expires,
		ip,
		false,
		host,
		AltChaOptions{}, // allowlist rate limits never serve altcha
		false,           // not from failed challenges
	}
}

func (h *DynamicDecisionLists) CheckByIpHost(ip string, host string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	key := ipHostKey{ip, host}
	expiringDecision, ok := h.value.expiringDecisionListsIpHost[key]
	if ok {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsIpHost, key)
			ok = false
		}
	}
	return expiringDecision, ok
}

// CheckAnyByIpHost returns an unexpired per-host decision for the ip on any host.
func (h *DynamicDecisionLists) CheckAnyByIpHost(ip string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for key, expiringDecision := range h.value.expiringDecisionListsIpHost {
		if key.ip == ip && time.Now().Sub(expiringDecision.Expires) <= 0 {
			return expiringDecision, true
		}
	}
	return ExpiringDecision{}, false
}

// CheckByDomain lists every unexpired Challenge-or-worse decision that applies to domain, from
// all the expiring lists, for the /banned API.
func (h *DynamicDecisionLists) CheckByDomain(domain string) []BannedEntry {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	now := time.Now()
	var bannedEntries []BannedEntry
	add := func(entryType string, key string, ua string, expiringDecision ExpiringDecision) {
		// expired entries linger until the next removeExpired sweep
		if expiringDecision.Decision < Challenge || now.Sub(expiringDecision.Expires) > 0 {
			return
		}
		bannedEntries = append(bannedEntries, BannedEntry{
			IpOrSessionId:   key,
			UA:              ua,
			Type:            entryType,
			domain:          domain,
			Decision:        expiringDecision.Decision.String(),
			Expires:         expiringDecision.Expires,
			FromBaskerville: expiringDecision.fromBaskerville,
		})
	}

	for ip, expiringDecision := range h.value.expiringDecisionLists {
		if expiringDecision.domain == domain {
			add("ip", ip, "", expiringDecision)
		}
	}
	for sessionId, expiringDecision := range h.value.expiringDecisionListsSessionId {
		if expiringDecision.domain == domain {
			add("session", sessionId, "", expiringDecision)
		}
	}
	for subnet, expiringDecision := range h.value.expiringDecisionListsSubnet {
		if expiringDecision.domain == domain {
			add("subnet", subnet.String(), "", expiringDecision)
		}
	}
	for key, expiringDecision := range h.value.expiringDecisionListsIpHost {
		if key.host == domain {
			add("ip_host", key.ip, "", expiringDecision)
		}
	}
	// challenge_all / altcha_challenge_all: applies to every client of the site
	if expiringDecision, ok := h.value.expiringDecisionListsHost[domain]; ok {
		add("host", "", "", expiringDecision)
	}
	for key, expiringDecision := range h.value.expiringDecisionListsUA {
		if key.host == domain {
			add("ua", "", key.ua, expiringDecision)
		}
	}
	return bannedEntries
}

func (h *DynamicDecisionLists) RemoveByIp(ip string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	delete(h.value.expiringDecisionLists, ip)
	for key := range h.value.expiringDecisionListsIpHost {
		if key.ip == ip {
			delete(h.value.expiringDecisionListsIpHost, key)
		}
	}
	// log.Printf("deleted IP %v from expiring lists", ip)
}

func (h *DynamicDecisionLists) RemoveByHost(host string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	delete(h.value.expiringDecisionListsHost, host)
}

// RemoveByUA clears the expiring decision for ua on host, or on every host when host is empty.
// It returns the most serious unexpired decision removed.
func (h *DynamicDecisionLists) RemoveByUA(ua string, host string) (ExpiringDecision, bool) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var removed ExpiringDecision
	found := false
	for key, expiringDecision := range h.value.expiringDecisionListsUA {
		if key.ua != ua || (host != "" && key.host != host) {
			continue
		}
		delete(h.value.expiringDecisionListsUA, key)
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			continue
		}
		if !found || expiringDecision.Decision > removed.Decision {
			removed = expiringDecision
		}
		found = true
	}
	return removed, found
}

func (h *DynamicDecisionLists) RemoveBySessionId(sessionId string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	delete(h.value.expiringDecisionListsSessionId, sessionId)
}

func (h *DynamicDecisionLists) Clear() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	clear(h.value.expiringDecisionLists)
	clear(h.value.expiringDecisionListsSessionId)
	clear(h.value.expiringDecisionListsHost)
	clear(h.value.expiringDecisionListsUA)
	clear(h.value.expiringDecisionListsSubnet)
	clear(h.value.expiringDecisionListsIpHost)
}

func (h *DynamicDecisionLists) Metrics() (lenExpiringChallenges int, lenExpiringBlocks int, lenExpiringSitewideChallenges int, lenExpiringSitewideBlocks int, lenExpiringUAChallenges int, lenExpiringUABlocks int, lenExpiringSubnetChallenges int, lenExpiringSubnetBlocks int) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	lenExpiringChallenges = 0
	lenExpiringBlocks = 0
	lenExpiringSitewideChallenges = 0
	lenExpiringSitewideBlocks = 0
	lenExpiringUAChallenges = 0
	lenExpiringUABlocks = 0
	lenExpiringSubnetChallenges = 0
	lenExpiringSubnetBlocks = 0

	for _, expiringDecision := range h.value.expiringDecisionLists {
		if expiringDecision.Decision == Challenge {
			lenExpiringChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringBlocks += 1
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsHost {
		if expiringDecision.Decision == Challenge {
			lenExpiringSitewideChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringSitewideBlocks += 1
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsUA {
		if expiringDecision.Decision == Challenge {
			lenExpiringUAChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringUABlocks += 1
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsSubnet {
		if expiringDecision.Decision == Challenge {
			lenExpiringSubnetChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringSubnetBlocks += 1
		}
	}

	return
}

func (h *DynamicDecisionLists) removeExpired() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for ip, expiringDecision := range h.value.expiringDecisionLists {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionLists, ip)
			// log.Println("deleted expired decision from expiring lists")
		}
	}

	for host, expiringDecision := range h.value.expiringDecisionListsHost {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsHost, host)
		}
	}

	for key, expiringDecision := range h.value.expiringDecisionListsUA {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsUA, key)
		}
	}

	for subnet, expiringDecision := range h.value.expiringDecisionListsSubnet {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsSubnet, subnet)
		}
	}

	for key, expiringDecision := range h.value.expiringDecisionListsIpHost {
		if time.Now().Sub(expiringDecision.Expires) > 0 {
			delete(h.value.expiringDecisionListsIpHost, key)
		}
	}
}

// Number of TooManyRequests decisions, whether keyed on the ip alone or on ip+host.
func (h *DynamicDecisionLists) MetricsTooManyRequests() (lenExpiringTooManyRequests int) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, expiringDecision := range h.value.expiringDecisionLists {
		if expiringDecision.Decision == TooManyRequests {
			lenExpiringTooManyRequests += 1
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsIpHost {
		if expiringDecision.Decision == TooManyRequests {
			lenExpiringTooManyRequests += 1
		}
	}

	return
}

// Number of AltChaChallenge decisions across the ip, session, host, UA and subnet lists.
func (h *DynamicDecisionLists) MetricsAltChaChallenges() (lenExpiringAltChaChallenges int) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	for _, list := range []map[string]ExpiringDecision{
		h.value.expiringDecisionLists,
		h.value.expiringDecisionListsSessionId,
		h.value.expiringDecisionListsHost,
	} {
		for _, expiringDecision := range list {
			if expiringDecision.Decision == AltChaChallenge {
				lenExpiringAltChaChallenges += 1
			}
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsUA {
		if expiringDecision.Decision == AltChaChallenge {
			lenExpiringAltChaChallenges += 1
		}
	}

	for _, expiringDecision := range h.value.expiringDecisionListsSubnet {
		if expiringDecision.Decision == AltChaChallenge {
			lenExpiringAltChaChallenges += 1
		}
	}

	return
}

type ipAddrToExpiringDecision map[string]ExpiringDecision

func (m ipAddrToExpiringDecision) String() string {
	b := strings.Builder{}
	for ip, expiringDecision := range m {
		b.WriteString(fmt.Sprintf("%v", ip))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v %v until %v (baskerville: %v)",
			expiringDecision.domain,
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
			expiringDecision.fromBaskerville,
		))
		b.WriteString("\n")
	}
	return b.String()
}

type sessionIdToExpiringDecision map[string]ExpiringDecision

type hostToExpiringDecision map[string]ExpiringDecision

func (m hostToExpiringDecision) String() string {
	b := strings.Builder{}
	for host, expiringDecision := range m {
		b.WriteString(fmt.Sprintf("%v", host))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v until %v (baskerville: %v)",
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
			expiringDecision.fromBaskerville,
		))
		b.WriteString("\n")
	}
	return b.String()
}

type ipHostKey struct {
	ip   string
	host string
}

type ipHostToExpiringDecision map[ipHostKey]ExpiringDecision

func (m ipHostToExpiringDecision) String() string {
	b := strings.Builder{}
	for key, expiringDecision := range m {
		b.WriteString(fmt.Sprintf("%v %v", key.ip, key.host))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v until %v",
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
		))
		b.WriteString("\n")
	}
	return b.String()
}

type uaHostKey struct {
	ua   string
	host string
}

type uaToExpiringDecision map[uaHostKey]ExpiringDecision

func (m uaToExpiringDecision) String() string {
	b := strings.Builder{}
	for key, expiringDecision := range m {
		b.WriteString(fmt.Sprintf("%v %v", key.host, key.ua))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v until %v (baskerville: %v)",
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
			expiringDecision.fromBaskerville,
		))
		b.WriteString("\n")
	}
	return b.String()
}

type subnetToExpiringDecision map[netip.Prefix]ExpiringDecision

func (m subnetToExpiringDecision) String() string {
	b := strings.Builder{}
	for subnet, expiringDecision := range m {
		b.WriteString(fmt.Sprintf("%v", subnet))
		b.WriteString(":\n")
		b.WriteString("\t")
		b.WriteString(fmt.Sprintf("%v %v until %v (baskerville: %v)",
			expiringDecision.domain,
			expiringDecision.Decision.String(),
			expiringDecision.Expires.Format("15:04:05"),
			expiringDecision.fromBaskerville,
		))
		b.WriteString("\n")
	}
	return b.String()
}

// Decision lists that can update frequently during the runtime of the program. Updated from kafka
// or the log tailer.
type dynamicDecisionLists struct {
	expiringDecisionLists          ipAddrToExpiringDecision
	expiringDecisionListsSessionId sessionIdToExpiringDecision
	expiringDecisionListsHost      hostToExpiringDecision
	expiringDecisionListsUA        uaToExpiringDecision
	expiringDecisionListsSubnet    subnetToExpiringDecision
	expiringDecisionListsIpHost    ipHostToExpiringDecision
}

func FormatDecisionLists(s *StaticDecisionLists, d *DynamicDecisionLists) string {
	sc := s.content.Load()

	d.mutex.Lock()
	defer d.mutex.Unlock()

	return fmt.Sprintf("per_site:\n%v\n\nglobal:\n%v\n\nexpiring:\n%v\n\nexpiring_sitewide:\n%v\n\nexpiring_ua:\n%v\n\nexpiring_subnet:\n%v\n\nexpiring_ip_host:\n%v",
		sc.perSiteDecisionLists,
		sc.globalDecisionLists,
		d.value.expiringDecisionLists,
		d.value.expiringDecisionListsHost,
		d.value.expiringDecisionListsUA,
		d.value.expiringDecisionListsSubnet,
		d.value.expiringDecisionListsIpHost,
	)
}
