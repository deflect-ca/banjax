// Copyright (c) 2025, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package internal

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremy5189/ipfilter-no-iploc/v2"
)

type Decision int

const (
	_ Decision = iota
	Allow
	Challenge
	NginxBlock
	IptablesBlock
)

func ParseDecision(s string) (Decision, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "challenge":
		return Challenge, nil
	case "nginx_block":
		return NginxBlock, nil
	case "iptables_block":
		return IptablesBlock, nil
	default:
		return 0, fmt.Errorf("invalid decision: %v", s)
	}
}

func (d Decision) String() string {
	switch d {
	case Allow:
		return "Allow"
	case Challenge:
		return "Challenge"
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

	// found as plain IP form, no need to check IPFilter
	if ok {
		return decision, true
	}

	// PerSiteDecisionListsIPFilter has different struct as PerSiteDecisionLists
	// decision must iterate in order, once found in one of the list, break the loop
	for _, iterateDecision := range []Decision{Allow, Challenge, NginxBlock, IptablesBlock} {
		if instanceIPFilter, ok := c.perSiteDecisionListsIPFilter[site][iterateDecision]; ok && instanceIPFilter != nil {
			if instanceIPFilter.Allowed(string(clientIp)) {
				if config.Debug {
					log.Printf("matched in per-site ipfilter %s %v %s", site, iterateDecision, clientIp)
				}
				return iterateDecision, true
			}
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
		for _, iterateDecision := range []Decision{Allow, Challenge, NginxBlock, IptablesBlock} {
			// check if Ipfilter ref associated to this iterateDecision exists
			filter, ok := c.globalDecisionListsIPFilter[iterateDecision]
			if ok && filter.Allowed(clientIp) {
				if config.Debug {
					log.Printf("matched in ipfilter %v %s", iterateDecision, clientIp)
				}
				return iterateDecision, true
			}
		}

		return decision, false
	}
}

func (l *StaticDecisionLists) CheckSitewideShaInv(site string) (FailAction, bool) {
	c := l.content.Load()

	failAction, ok := c.sitewideShaInvList[site]
	return failAction, ok
}

func (l *StaticDecisionLists) CheckIsAllowed(site string, clientIp string) bool {
	c := l.content.Load()

	// check per-site decision list first
	decision, ok := c.perSiteDecisionLists[site][clientIp]
	if ok && decision == Allow {
		// log.Printf("checkIpInPerSiteDecisionList: matched %s %s", urlString, ipString)
		return true
	}

	filter, ok := c.perSiteDecisionListsIPFilter[site][Allow]
	if ok && filter.Allowed(clientIp) {
		// log.Printf("checkIpInPerSiteDecisionList: matched in per-site ipfilter %s %s", urlString, ipString)
		return true
	}

	// check global decision list
	decision, ok = c.globalDecisionLists[clientIp]
	if ok && decision == Allow {
		// log.Printf("checkIpInGlobalDecisionList: matched %s", ipString)
		return true
	}

	// not found with direct match, try to match if contain within CIDR subnet
	filter, ok = c.globalDecisionListsIPFilter[Allow]
	if ok && filter.Allowed(clientIp) {
		// log.Printf("checkIpInGlobalDecisionList: matched in ipfilter %s", ipString)
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
type decisionToIPFilter map[Decision]*ipfilter.IPFilter
type siteToDecisionToIPFilter map[string]map[Decision]*ipfilter.IPFilter

// Decision lists that don't change unless the program is restarted or the config is hot-reloaded.
type staticDecisionLists struct {
	globalDecisionLists          ipAddrToDecision
	perSiteDecisionLists         siteToIPAddrToDecision
	sitewideShaInvList           siteToFailAction
	globalDecisionListsIPFilter  decisionToIPFilter
	perSiteDecisionListsIPFilter siteToDecisionToIPFilter
}

func newStaticDecisionLists() staticDecisionLists {
	return staticDecisionLists{
		globalDecisionLists:          make(ipAddrToDecision),
		perSiteDecisionLists:         make(siteToIPAddrToDecision),
		sitewideShaInvList:           make(siteToFailAction),
		globalDecisionListsIPFilter:  make(decisionToIPFilter),
		perSiteDecisionListsIPFilter: make(siteToDecisionToIPFilter),
	}
}

func newStaticDecisionListsFromConfig(config *Config) (staticDecisionLists, error) {
	out := newStaticDecisionLists()

	for decisionString, ips := range config.GlobalDecisionLists {
		decision, err := ParseDecision(decisionString)
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
					log.Printf("global decision: %s, CIDR: %s, put in IPFilter\n", decisionString, ip)
				}
			}
		}

		out.globalDecisionListsIPFilter[decision] = ipfilter.New(ipfilter.Options{
			AllowedIPs:     ips,
			BlockByDefault: true,
		})
	}

	for site, decisionToIps := range config.PerSiteDecisionLists {
		for decisionString, ips := range decisionToIps {
			decision, err := ParseDecision(decisionString)
			if err != nil {
				return staticDecisionLists{}, fmt.Errorf("failed to create static decision lists from config: %w", err)
			}

			for _, ip := range ips {
				_, ok := out.perSiteDecisionLists[site]
				if !ok {
					out.perSiteDecisionLists[site] = make(ipAddrToDecision)
					out.perSiteDecisionListsIPFilter[site] = make(decisionToIPFilter)
				}
				if !strings.Contains(ip, "/") {
					out.perSiteDecisionLists[site][ip] = decision
					if config.Debug {
						log.Printf("site: %s, decision: %s, ip: %s\n", site, decisionString, ip)
					}
				} else {
					if config.Debug {
						log.Printf("per-site decision: %s, CIDR: %s, put in IPFilter\n", decisionString, ip)
					}
				}
			}
			if len(ips) > 0 {
				// only init ipfilter if there is IP
				// or there might be panic: assignment to entry in nil map
				out.perSiteDecisionListsIPFilter[site][decision] = ipfilter.New(ipfilter.Options{
					AllowedIPs:     ips,
					BlockByDefault: true,
				})
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
) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionLists[ip]
	if ok {
		if newDecision <= existingExpiringDecision.Decision {
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

	h.value.expiringDecisionLists[ip] = ExpiringDecision{
		newDecision,
		expires,
		ip,
		fromBaskerville,
		domain,
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
) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	existingExpiringDecision, ok := h.value.expiringDecisionListsSessionId[sessionId]
	if ok {
		if newDecision <= existingExpiringDecision.Decision {
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

func (h *DynamicDecisionLists) CheckByDomain(domain string) []BannedEntry {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	var bannedEntries []BannedEntry
	for ip, expiringDecision := range h.value.expiringDecisionLists {
		if expiringDecision.domain == domain && expiringDecision.Decision >= Challenge {
			bannedEntries = append(bannedEntries, BannedEntry{
				IpOrSessionId:   string(ip),
				domain:          expiringDecision.domain,
				Decision:        expiringDecision.Decision.String(), // Convert Decision to string
				Expires:         expiringDecision.Expires,
				FromBaskerville: expiringDecision.fromBaskerville,
			})
		}
	}
	for sessionId, expiringDecision := range h.value.expiringDecisionListsSessionId {
		if expiringDecision.domain == domain && expiringDecision.Decision >= Challenge {
			bannedEntries = append(bannedEntries, BannedEntry{
				IpOrSessionId:   string(sessionId),
				domain:          expiringDecision.domain,
				Decision:        expiringDecision.Decision.String(), // Convert Decision to string
				Expires:         expiringDecision.Expires,
				FromBaskerville: expiringDecision.fromBaskerville,
			})
		}
	}
	return bannedEntries
}

func (h *DynamicDecisionLists) RemoveByIp(ip string) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	delete(h.value.expiringDecisionLists, ip)
	// log.Printf("deleted IP %v from expiring lists", ip)
}

func (h *DynamicDecisionLists) Clear() {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	clear(h.value.expiringDecisionLists)
	clear(h.value.expiringDecisionListsSessionId)
}

func (h *DynamicDecisionLists) Metrics() (lenExpiringChallenges int, lenExpiringBlocks int) {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	lenExpiringChallenges = 0
	lenExpiringBlocks = 0

	for _, expiringDecision := range h.value.expiringDecisionLists {
		if expiringDecision.Decision == Challenge {
			lenExpiringChallenges += 1
		} else if (expiringDecision.Decision == NginxBlock) || (expiringDecision.Decision == IptablesBlock) {
			lenExpiringBlocks += 1
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

// Decision lists that can update frequently during the runtime of the program. Updated from kafka
// or the log tailer.
type dynamicDecisionLists struct {
	expiringDecisionLists          ipAddrToExpiringDecision
	expiringDecisionListsSessionId sessionIdToExpiringDecision
}

func FormatDecisionLists(s *StaticDecisionLists, d *DynamicDecisionLists) string {
	sc := s.content.Load()

	d.mutex.Lock()
	defer d.mutex.Unlock()

	return fmt.Sprintf("per_site:\n%v\n\nglobal:\n%v\n\nexpiring:\n%v",
		sc.perSiteDecisionLists,
		sc.globalDecisionLists,
		d.value.expiringDecisionLists,
	)
}
